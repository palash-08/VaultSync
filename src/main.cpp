#include "Credential.h"
#include "WebCredential.h"
#include "WiFiCredential.h"
#include "SSHCredential.h"
#include "CredentialFactory.h"
#include "MasterVault.h"
#include "PasswordGenerator.h"
#include "PasswordStrength.h"
#include "PasswordAnalyzer.h"
#include "TerminalUtils.h"
#include "VaultExceptions.h"

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

/**
 * @brief Returns a short 4-5 character badge representing the polymorphic credential type.
 * @param credential Shared pointer to the credential.
 * @return Badge string such as "[WEB]", "[WIFI]", "[SSH]", or "[GEN]".
 */
std::string getCredentialTypeBadge(const std::shared_ptr<Credential>& credential) {
    if (!credential) {
        return "[???]";
    }
    const std::string credentialType = credential->getType();
    if (credentialType == "web") {
        return "[WEB] ";
    }
    if (credentialType == "wifi") {
        return "[WIFI]";
    }
    if (credentialType == "ssh") {
        return "[SSH] ";
    }
    return "[GEN] ";
}

/**
 * @brief Formats an epoch timestamp into a human-readable local date/time string.
 * @param timestampSeconds Epoch timestamp in seconds.
 * @return Formatted date string (YYYY-MM-DD HH:MM:SS) or "Not recorded".
 */
std::string formatTimestamp(int64_t timestampSeconds) {
    if (timestampSeconds <= 0) {
        return "Not recorded";
    }
    std::time_t rawTime = static_cast<std::time_t>(timestampSeconds);
    std::tm* timeInfo = std::localtime(&rawTime);
    if (!timeInfo) {
        return "Unknown";
    }
    char buffer[64];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeInfo);
    return std::string(buffer);
}

/**
 * @brief Prompts user for a password, offering manual entry or automatic generator.
 * @param promptLabel Contextual prompt label to display to the user.
 * @return The chosen or generated password string.
 */
std::string promptPasswordWithGeneratorOption(const std::string& promptLabel) {
    while (true) {
        std::cout << "\nPassword options for " << promptLabel << ":\n";
        std::cout << "  [1] Enter password manually\n";
        std::cout << "  [2] Generate secure random password\n";
        std::cout << "Choose option (1-2, default 1): ";

        std::string choice;
        if (!std::getline(std::cin, choice)) {
            return {};
        }

        if (choice == "2" || choice == "G" || choice == "g") {
            std::cout << "Enter desired password length (8-128, default 16): ";
            std::string lengthInput;
            size_t length = 16;
            if (std::getline(std::cin, lengthInput) && !lengthInput.empty()) {
                try {
                    length = std::stoul(lengthInput);
                    if (length < 8) length = 8;
                    if (length > 128) length = 128;
                } catch (...) {
                    length = 16;
                }
            }

            std::string generatedPassword = PasswordGenerator::generate(length);
            PasswordStrengthResult strength = PasswordStrength::analyze(generatedPassword);
            std::cout << "\nGenerated Password: " << generatedPassword << "\n";
            std::cout << "Strength Score    : " << strength.score << "/100 ("
                      << strength.entropy << " bits) - " << strength.feedback << "\n";
            return generatedPassword;
        }

        // Manual entry (default)
        if (!std::cin.good()) {
            return {};
        }
        std::string password = TerminalUtils::readHiddenPassword("Enter " + promptLabel + ": ");
        if (!std::cin.good()) {
            return {};
        }
        if (password.empty()) {
            std::cout << "Error: Password cannot be empty. Please try again.\n";
            continue;
        }

        std::string confirmPassword = TerminalUtils::readHiddenPassword("Confirm " + promptLabel + ": ");
        if (!std::cin.good()) {
            return {};
        }
        if (password != confirmPassword) {
            std::cout << "Error: Passwords do not match. Please try again.\n";
            continue;
        }

        return password;
    }
}

/**
 * @brief Ensures the Credential Vault tier is unlocked before performing data operations.
 * @param vault Reference to the active MasterVault.
 * @return True if unlocked and ready; false if cancelled or access denied.
 */
bool ensureCredentialVaultUnlocked(MasterVault& vault) {
    if (vault.isCredentialsUnlocked()) {
        return true;
    }

    // Delayed setup: configure credential vault password if not yet configured
    if (!vault.hasCredentialPassword()) {
        std::cout << "\nNo credential vault password has been configured.\n";
        while (true) {
            if (!std::cin.good()) {
                return false;
            }
            std::string credentialPassword = TerminalUtils::readHiddenPassword("Create credential vault password: ");
            if (!std::cin.good()) {
                return false;
            }
            if (credentialPassword.empty()) {
                std::cout << "Error: Password cannot be empty.\n";
                continue;
            }

            std::string confirmPassword = TerminalUtils::readHiddenPassword("Confirm credential vault password: ");
            if (!std::cin.good()) {
                return false;
            }
            if (credentialPassword != confirmPassword) {
                std::cout << "Error: Passwords do not match. Please try again.\n";
                continue;
            }

            if (!vault.setupCredentialPassword(credentialPassword)) {
                std::cout << "Credential vault password must be different from the master password.\n";
                continue;
            }

            std::cout << "\nCredential vault password configured successfully.\n";
            return true;
        }
    }

    // Authenticate existing credential vault password (3 attempts maximum)
    vault.resetCredentialsAttempts();
    while (true) {
        if (!std::cin.good()) {
            return false;
        }
        std::string credentialPassword = TerminalUtils::readHiddenPassword("Enter credential vault password: ");
        if (!std::cin.good()) {
            return false;
        }
        int attemptsRemaining = 0;
        if (vault.unlockCredentials(credentialPassword, attemptsRemaining)) {
            std::cout << "\nCredential vault unlocked.\n";
            return true;
        }

        std::cout << "Invalid credential vault password.\n";
        if (attemptsRemaining <= 0) {
            std::cout << "\nMaximum attempts exceeded. Credential vault access denied.\n";
            return false;
        }
    }
}

/**
 * @brief Prompts the user to create one of four polymorphic credential types.
 * @return Shared pointer to newly created Credential instance, or nullptr if cancelled.
 */
std::shared_ptr<Credential> promptCreatePolymorphicCredential() {
    std::cout << "\n================ Add New Credential ================\n";
    std::cout << "Select Credential Type:\n";
    std::cout << "  [1] Web Account (Website, Login, URL)\n";
    std::cout << "  [2] Wi-Fi Network (SSID, Security Type, Passphrase)\n";
    std::cout << "  [3] SSH Key / Server (Host, Port, User, Passphrase)\n";
    std::cout << "  [4] Generic Credential (Service, User, Password, Notes)\n";
    std::cout << "  [0] Cancel\n";
    std::cout << "Enter choice (0-4): ";

    std::string typeChoice;
    if (!std::getline(std::cin, typeChoice) || typeChoice == "0") {
        std::cout << "Creation cancelled.\n";
        return nullptr;
    }

    if (typeChoice == "1") {
        std::cout << "\n--- Web Account Details ---\n";
        std::cout << "Enter service / site name (e.g. GitHub): ";
        std::string service;
        if (!std::getline(std::cin, service) || service.empty()) {
            std::cout << "Error: Service name cannot be empty.\n";
            return nullptr;
        }

        std::cout << "Enter username or email: ";
        std::string username;
        if (!std::getline(std::cin, username)) return nullptr;

        std::string password = promptPasswordWithGeneratorOption("web account password");
        if (password.empty()) return nullptr;

        std::cout << "Enter website URL (e.g. https://github.com/login): ";
        std::string url;
        if (!std::getline(std::cin, url)) return nullptr;

        std::cout << "Enter notes (optional): ";
        std::string notes;
        if (!std::getline(std::cin, notes)) return nullptr;

        return std::make_shared<WebCredential>(service, username, password, notes, url);
    }

    if (typeChoice == "2") {
        std::cout << "\n--- Wi-Fi Network Details ---\n";
        std::cout << "Enter network SSID (e.g. HomeNet): ";
        std::string ssid;
        if (!std::getline(std::cin, ssid) || ssid.empty()) {
            std::cout << "Error: SSID cannot be empty.\n";
            return nullptr;
        }

        std::cout << "Enter service label (press Enter to use SSID): ";
        std::string service;
        if (!std::getline(std::cin, service)) return nullptr;
        if (service.empty()) {
            service = ssid;
        }

        std::string password = promptPasswordWithGeneratorOption("Wi-Fi network passphrase");
        if (password.empty()) return nullptr;

        std::cout << "Select Security Protocol:\n";
        std::cout << "  [1] WPA2 (default)\n";
        std::cout << "  [2] WPA3\n";
        std::cout << "  [3] WEP\n";
        std::cout << "  [4] Open\n";
        std::cout << "Enter choice (1-4, default 1): ";
        std::string securityChoice;
        std::string securityType = "WPA2";
        if (std::getline(std::cin, securityChoice)) {
            if (securityChoice == "2") securityType = "WPA3";
            else if (securityChoice == "3") securityType = "WEP";
            else if (securityChoice == "4") securityType = "Open";
        }

        std::cout << "Enter notes (optional): ";
        std::string notes;
        if (!std::getline(std::cin, notes)) return nullptr;

        return std::make_shared<WiFiCredential>(service, "", password, notes, ssid, securityType);
    }

    if (typeChoice == "3") {
        std::cout << "\n--- SSH Server / Key Details ---\n";
        std::cout << "Enter server label (e.g. Production VPS): ";
        std::string service;
        if (!std::getline(std::cin, service) || service.empty()) {
            std::cout << "Error: Server label cannot be empty.\n";
            return nullptr;
        }

        std::cout << "Enter username (e.g. root): ";
        std::string username;
        if (!std::getline(std::cin, username)) return nullptr;

        std::string password = promptPasswordWithGeneratorOption("SSH password / passphrase");
        if (password.empty()) return nullptr;

        std::cout << "Enter remote host or IP (e.g. server.example.com): ";
        std::string host;
        if (!std::getline(std::cin, host) || host.empty()) {
            std::cout << "Error: Host cannot be empty.\n";
            return nullptr;
        }

        std::cout << "Enter remote port (default 22): ";
        std::string portInput;
        uint16_t port = 22;
        if (std::getline(std::cin, portInput) && !portInput.empty()) {
            try {
                unsigned long p = std::stoul(portInput);
                if (p > 0 && p <= 65535) {
                    port = static_cast<uint16_t>(p);
                }
            } catch (...) {
                port = 22;
            }
        }

        std::cout << "Enter notes (optional): ";
        std::string notes;
        if (!std::getline(std::cin, notes)) return nullptr;

        return std::make_shared<SSHCredential>(service, username, password, notes, host, port);
    }

    if (typeChoice == "4") {
        std::cout << "\n--- Generic Credential Details ---\n";
        std::cout << "Enter service name: ";
        std::string service;
        if (!std::getline(std::cin, service) || service.empty()) {
            std::cout << "Error: Service name cannot be empty.\n";
            return nullptr;
        }

        std::cout << "Enter username: ";
        std::string username;
        if (!std::getline(std::cin, username)) return nullptr;

        std::string password = promptPasswordWithGeneratorOption("password");
        if (password.empty()) return nullptr;

        std::cout << "Enter notes (optional): ";
        std::string notes;
        if (!std::getline(std::cin, notes)) return nullptr;

        return std::make_shared<Credential>(service, username, password, notes);
    }

    std::cout << "Invalid choice. Credential creation cancelled.\n";
    return nullptr;
}

/**
 * @brief Prompts for Credential Vault password and performs secure deletion of an item.
 * @param vault Reference to the active MasterVault.
 * @param index Zero-based index of the item to delete.
 * @return True if deleted successfully; false otherwise.
 */
bool handleDeleteCredential(MasterVault& vault, size_t index) {
    auto credential = vault.getCredential(index);
    if (!credential) {
        return false;
    }

    std::cout << "\nDelete " << getCredentialTypeBadge(credential) << " credential \""
              << credential->getService() << "\"?\n";
    std::cout << "  [1] Confirm Delete\n";
    std::cout << "  [2] Cancel\n";
    std::cout << "Enter choice: ";

    std::string choice;
    if (!std::getline(std::cin, choice) || choice != "1") {
        std::cout << "\nDeletion cancelled.\n";
        return false;
    }

    int attempts = 3;
    while (attempts > 0) {
        if (!std::cin.good()) {
            return false;
        }
        std::string password = TerminalUtils::readHiddenPassword("Enter credential vault password to confirm deletion: ");
        if (!std::cin.good()) {
            return false;
        }
        if (vault.verifyCredentialPassword(password)) {
            if (vault.deleteCredential(index)) {
                std::cout << "\nCredential deleted successfully.\n";
                return true;
            } else {
                std::cout << "\nError: Failed to delete credential from storage.\n";
                return false;
            }
        }

        attempts--;
        if (attempts > 0) {
            std::cout << "Invalid credential vault password. Attempts remaining: " << attempts << "\n";
        } else {
            std::cout << "\nMaximum attempts exceeded. Credential deletion denied.\n";
            return false;
        }
    }

    return false;
}

/**
 * @brief Provides a type-aware interactive editor modifying common and type-specific fields.
 * @param vault Reference to the active MasterVault.
 * @param index Zero-based index of the credential to edit.
 */
void handleEditCredential(MasterVault& vault, size_t index) {
    auto currentCredential = vault.getCredential(index);
    if (!currentCredential) {
        std::cout << "\nError: Credential not found.\n";
        return;
    }

    // Work on a deep clone so modifications only persist on Save
    std::shared_ptr<Credential> workingCredential(currentCredential->clone());

    while (true) {
        std::cout << "\n================ Edit Credential ================\n";
        std::cout << "Type       : " << workingCredential->getType() << " " << getCredentialTypeBadge(workingCredential) << "\n";
        std::cout << "Service    : " << workingCredential->getService() << "\n";
        std::cout << "Username   : " << workingCredential->getUsername() << "\n";
        std::cout << "Password   : " << workingCredential->getPassword() << "\n";
        std::cout << "Notes      : " << (workingCredential->getNotes().empty() ? "(none)" : workingCredential->getNotes()) << "\n";

        if (auto web = std::dynamic_pointer_cast<WebCredential>(workingCredential)) {
            std::cout << "URL        : " << web->getUrl() << "\n";
        } else if (auto wifi = std::dynamic_pointer_cast<WiFiCredential>(workingCredential)) {
            std::cout << "SSID       : " << wifi->getSsid() << "\n";
            std::cout << "Security   : " << wifi->getSecurityType() << "\n";
        } else if (auto ssh = std::dynamic_pointer_cast<SSHCredential>(workingCredential)) {
            std::cout << "Host       : " << ssh->getHost() << "\n";
            std::cout << "Port       : " << ssh->getPort() << "\n";
        }

        std::cout << "\nEdit Options:\n";
        std::cout << "  [1] Change Service / Label\n";
        std::cout << "  [2] Change Username\n";
        std::cout << "  [3] Change Password\n";
        std::cout << "  [4] Change Notes\n";

        if (workingCredential->getType() == "web") {
            std::cout << "  [5] Change Website URL\n";
        } else if (workingCredential->getType() == "wifi") {
            std::cout << "  [5] Change Network SSID\n";
            std::cout << "  [6] Change Security Protocol\n";
        } else if (workingCredential->getType() == "ssh") {
            std::cout << "  [5] Change Remote Host\n";
            std::cout << "  [6] Change Remote Port\n";
        }

        std::cout << "  [S] Save Changes\n";
        std::cout << "  [C] Cancel\n";
        std::cout << "Enter choice: ";

        std::string choice;
        if (!std::getline(std::cin, choice)) {
            std::cout << "\nChanges cancelled.\n";
            break;
        }

        if (choice == "1") {
            std::cout << "Enter new service / label: ";
            std::string newService;
            if (std::getline(std::cin, newService) && !newService.empty()) {
                workingCredential->setService(newService);
            }
        } else if (choice == "2") {
            std::cout << "Enter new username: ";
            std::string newUsername;
            if (std::getline(std::cin, newUsername)) {
                workingCredential->setUsername(newUsername);
            }
        } else if (choice == "3") {
            std::string newPassword = promptPasswordWithGeneratorOption("new password");
            if (!newPassword.empty()) {
                workingCredential->setPassword(newPassword);
            }
        } else if (choice == "4") {
            std::cout << "Enter new notes: ";
            std::string newNotes;
            if (std::getline(std::cin, newNotes)) {
                workingCredential->setNotes(newNotes);
            }
        } else if (choice == "5" && workingCredential->getType() == "web") {
            auto web = std::dynamic_pointer_cast<WebCredential>(workingCredential);
            std::cout << "Enter new URL: ";
            std::string newUrl;
            if (std::getline(std::cin, newUrl)) {
                web->setUrl(newUrl);
            }
        } else if (choice == "5" && workingCredential->getType() == "wifi") {
            auto wifi = std::dynamic_pointer_cast<WiFiCredential>(workingCredential);
            std::cout << "Enter new SSID: ";
            std::string newSsid;
            if (std::getline(std::cin, newSsid) && !newSsid.empty()) {
                wifi->setSsid(newSsid);
            }
        } else if (choice == "6" && workingCredential->getType() == "wifi") {
            auto wifi = std::dynamic_pointer_cast<WiFiCredential>(workingCredential);
            std::cout << "Enter new Security Protocol (WPA2, WPA3, WEP, Open): ";
            std::string newSec;
            if (std::getline(std::cin, newSec) && !newSec.empty()) {
                wifi->setSecurityType(newSec);
            }
        } else if (choice == "5" && workingCredential->getType() == "ssh") {
            auto ssh = std::dynamic_pointer_cast<SSHCredential>(workingCredential);
            std::cout << "Enter new Remote Host: ";
            std::string newHost;
            if (std::getline(std::cin, newHost) && !newHost.empty()) {
                ssh->setHost(newHost);
            }
        } else if (choice == "6" && workingCredential->getType() == "ssh") {
            auto ssh = std::dynamic_pointer_cast<SSHCredential>(workingCredential);
            std::cout << "Enter new Remote Port (default 22): ";
            std::string portInput;
            if (std::getline(std::cin, portInput) && !portInput.empty()) {
                try {
                    ssh->setPort(static_cast<uint16_t>(std::stoul(portInput)));
                } catch (...) {
                    std::cout << "Invalid port.\n";
                }
            }
        } else if (choice == "S" || choice == "s") {
            if (vault.updateCredential(index, workingCredential)) {
                std::cout << "\nCredential updated successfully.\n";
            } else {
                std::cout << "\nError: Failed to save updated credential.\n";
            }
            break;
        } else if (choice == "C" || choice == "c") {
            std::cout << "\nChanges cancelled.\n";
            break;
        } else {
            std::cout << "\nInvalid choice. Please try again.\n";
        }
    }
}

/**
 * @brief Displays detailed attributes of a credential with a password mask toggle.
 * @param vault Reference to the active MasterVault.
 * @param index Zero-based index of the credential to display.
 */
void viewCredentialDetails(MasterVault& vault, size_t index) {
    bool showPassword = false;

    while (true) {
        auto credential = vault.getCredential(index);
        if (!credential) {
            break;
        }

        std::cout << "\n================ Credential Details ================\n";
        std::cout << "Type       : " << credential->getType() << " " << getCredentialTypeBadge(credential) << "\n";
        std::cout << "Service    : " << credential->getService() << "\n";
        std::cout << "Username   : " << credential->getUsername() << "\n";
        if (showPassword) {
            std::cout << "Password   : " << credential->getPassword() << "\n";
        } else {
            std::cout << "Password   : ********\n";
        }
        std::cout << "Notes      : " << (credential->getNotes().empty() ? "(none)" : credential->getNotes()) << "\n";
        std::cout << "Created At : " << formatTimestamp(credential->getCreatedAt()) << "\n";

        // Display type-specific properties
        if (auto web = std::dynamic_pointer_cast<WebCredential>(credential)) {
            std::cout << "URL        : " << web->getUrl() << "\n";
        } else if (auto wifi = std::dynamic_pointer_cast<WiFiCredential>(credential)) {
            std::cout << "SSID       : " << wifi->getSsid() << "\n";
            std::cout << "Security   : " << wifi->getSecurityType() << "\n";
        } else if (auto ssh = std::dynamic_pointer_cast<SSHCredential>(credential)) {
            std::cout << "Host       : " << ssh->getHost() << "\n";
            std::cout << "Port       : " << ssh->getPort() << "\n";
        }
        std::cout << "----------------------------------------------------\n";

        std::cout << "  [1] " << (showPassword ? "Hide Password" : "Show Password") << "\n";
        std::cout << "  [2] Edit Credential\n";
        std::cout << "  [3] Delete Credential\n";
        std::cout << "  [4] Back\n";
        std::cout << "Enter choice (1-4): ";

        std::string choice;
        if (!std::getline(std::cin, choice)) {
            break;
        }

        if (choice == "1") {
            showPassword = !showPassword;
        } else if (choice == "2") {
            handleEditCredential(vault, index);
            showPassword = false;
        } else if (choice == "3") {
            if (handleDeleteCredential(vault, index)) {
                break;
            }
        } else if (choice == "4") {
            break;
        } else {
            std::cout << "Invalid choice. Please enter 1, 2, 3, or 4.\n";
        }
    }
}

/**
 * @brief Displays all stored credentials and allows selecting an item or adding new entries.
 * @param vault Reference to the active MasterVault.
 */
void handleManageCredentials(MasterVault& vault) {
    if (!ensureCredentialVaultUnlocked(vault)) {
        return;
    }

    while (true) {
        auto credentials = vault.getPolymorphicCredentials();

        std::cout << "\n================ Manage Credentials ================\n";
        if (credentials.empty()) {
            std::cout << "No credentials currently stored in vault.\n\n";
        } else {
            for (size_t i = 0; i < credentials.size(); ++i) {
                const auto& item = credentials[i];
                std::cout << "[" << std::setw(2) << (i + 1) << "] "
                          << getCredentialTypeBadge(item) << " "
                          << item->getService();
                if (!item->getUsername().empty()) {
                    std::cout << " (" << item->getUsername() << ")";
                }
                std::cout << "\n";
            }
            std::cout << "\n";
        }

        std::cout << "Options:\n";
        std::cout << "  [A] Add New Credential\n";
        if (!credentials.empty()) {
            std::cout << "  [1-" << credentials.size() << "] Select Credential for Details / Edit / Delete\n";
        }
        std::cout << "  [0] Back to Session Menu\n";
        std::cout << "Enter choice: ";

        std::string input;
        if (!std::getline(std::cin, input)) {
            break;
        }

        if (input == "0" || input == "b" || input == "B") {
            break;
        }

        if (input == "A" || input == "a") {
            auto newCredential = promptCreatePolymorphicCredential();
            if (newCredential) {
                if (vault.addCredential(newCredential)) {
                    std::cout << "\nCredential added successfully.\n";
                } else {
                    std::cout << "\nError: Failed to save credential to encrypted vault.\n";
                }
            }
            continue;
        }

        try {
            size_t selectedIndex = std::stoul(input);
            if (selectedIndex >= 1 && selectedIndex <= credentials.size()) {
                viewCredentialDetails(vault, selectedIndex - 1);
            } else {
                std::cout << "Invalid choice. Please select a valid number from the list.\n";
            }
        } catch (...) {
            std::cout << "Invalid input. Please enter a number or 'A'.\n";
        }
    }
}

/**
 * @brief Performs interactive keyword search across all fields of stored credentials.
 * @param vault Reference to the active MasterVault.
 */
void handleSearchCredentials(MasterVault& vault) {
    if (!ensureCredentialVaultUnlocked(vault)) {
        return;
    }

    std::cout << "\n================ Search Credentials ================\n";
    std::cout << "Enter search query: ";
    std::string query;
    if (!std::getline(std::cin, query) || query.empty()) {
        std::cout << "Search cancelled.\n";
        return;
    }

    auto searchResults = vault.search(query);
    if (searchResults.empty()) {
        std::cout << "\nNo credentials matched query \"" << query << "\".\n";
        return;
    }

    auto allCredentials = vault.getPolymorphicCredentials();

    while (true) {
        std::cout << "\n--- Search Results for \"" << query << "\" ("
                  << searchResults.size() << " found) ---\n";

        for (size_t i = 0; i < searchResults.size(); ++i) {
            const auto& item = searchResults[i];
            std::cout << "[" << (i + 1) << "] "
                      << getCredentialTypeBadge(item) << " "
                      << item->getService();
            if (!item->getUsername().empty()) {
                std::cout << " (" << item->getUsername() << ")";
            }
            std::cout << "\n";
        }

        std::cout << "\nEnter result number to view details (0 to go back): ";
        std::string selectionInput;
        if (!std::getline(std::cin, selectionInput) || selectionInput == "0") {
            break;
        }

        try {
            size_t resultIdx = std::stoul(selectionInput);
            if (resultIdx >= 1 && resultIdx <= searchResults.size()) {
                const auto& targetItem = searchResults[resultIdx - 1];

                // Map matched search pointer back to its canonical vault index
                size_t canonicalIndex = 0;
                bool found = false;
                for (size_t k = 0; k < allCredentials.size(); ++k) {
                    if (allCredentials[k] == targetItem || *allCredentials[k] == *targetItem) {
                        canonicalIndex = k;
                        found = true;
                        break;
                    }
                }

                if (found) {
                    viewCredentialDetails(vault, canonicalIndex);
                    // Refresh search results after potential edit or deletion
                    searchResults = vault.search(query);
                    allCredentials = vault.getPolymorphicCredentials();
                    if (searchResults.empty()) {
                        std::cout << "\nNo remaining credentials match query \"" << query << "\".\n";
                        break;
                    }
                } else {
                    std::cout << "Selected credential could not be located.\n";
                }
            } else {
                std::cout << "Invalid choice. Please select a number between 1 and "
                          << searchResults.size() << ".\n";
            }
        } catch (...) {
            std::cout << "Invalid input. Please enter a valid number.\n";
        }
    }
}

/**
 * @brief Provides standalone utilities for password generation and entropy evaluation.
 */
void handlePasswordTools() {
    while (true) {
        std::cout << "\n================ Password Tools ================\n";
        std::cout << "  [1] Generate Random Password\n";
        std::cout << "  [2] Evaluate Password Strength\n";
        std::cout << "  [3] Back to Session Menu\n";
        std::cout << "Enter choice (1-3): ";

        std::string choice;
        if (!std::getline(std::cin, choice) || choice == "3") {
            break;
        }

        if (choice == "1") {
            std::cout << "\n--- Random Password Generator ---\n";
            std::cout << "Enter length (8-128, default 16): ";
            std::string lengthInput;
            size_t length = 16;
            if (std::getline(std::cin, lengthInput) && !lengthInput.empty()) {
                try {
                    length = std::stoul(lengthInput);
                    if (length < 8) length = 8;
                    if (length > 128) length = 128;
                } catch (...) {
                    length = 16;
                }
            }

            auto askFlag = [](const std::string& promptLabel) -> bool {
                std::cout << promptLabel << " (Y/n, default Y): ";
                std::string input;
                if (!std::getline(std::cin, input) || input.empty()) {
                    return true;
                }
                return input[0] == 'Y' || input[0] == 'y';
            };

            PasswordOptions options;
            options.length = length;
            options.uppercase = askFlag("Include uppercase letters (A-Z)");
            options.lowercase = askFlag("Include lowercase letters (a-z)");
            options.digits = askFlag("Include digits (0-9)");
            options.symbols = askFlag("Include symbols (!@#$%...)");

            try {
                std::string generated = PasswordGenerator::generate(options);
                PasswordStrengthResult strength = PasswordStrength::analyze(generated);

                std::cout << "\nGenerated Password : " << generated << "\n";
                std::cout << "Strength Score     : " << strength.score << "/100\n";
                std::cout << "Entropy Bits       : " << std::fixed << std::setprecision(2)
                          << strength.entropy << " bits\n";
                std::cout << "Evaluation         : " << strength.feedback << "\n";
            } catch (const std::exception& exception) {
                std::cout << "Generation failed: " << exception.what() << "\n";
            }
        } else if (choice == "2") {
            std::cout << "\n--- Password Strength Evaluator ---\n";
            std::cout << "Enter password to evaluate: ";
            std::string password;
            if (std::getline(std::cin, password) && !password.empty()) {
                PasswordStrengthResult result = PasswordStrength::analyze(password);
                std::cout << "\nAnalysis Result:\n";
                std::cout << "  Strength Score : " << result.score << "/100\n";
                std::cout << "  Entropy Bits   : " << std::fixed << std::setprecision(2)
                          << result.entropy << " bits\n";

                std::string rating;
                if (result.score >= 80) rating = "Very Strong";
                else if (result.score >= 60) rating = "Strong";
                else if (result.score >= 40) rating = "Moderate";
                else rating = "Weak";

                std::cout << "  Rating         : " << rating << "\n";
                std::cout << "  Feedback       : " << result.feedback << "\n";
            } else {
                std::cout << "Password cannot be empty.\n";
            }
        } else {
            std::cout << "Invalid choice. Please enter 1, 2, or 3.\n";
        }
    }
}

/**
 * @brief Renders the security health dashboard with score bar, metrics, and audit warnings.
 * @param vault Reference to the active MasterVault.
 */
void handleSecurityDashboard(MasterVault& vault) {
    if (!ensureCredentialVaultUnlocked(vault)) {
        return;
    }

    auto credentials = vault.getPolymorphicCredentials();

    std::cout << "\n================ Security Health Dashboard ================\n";
    if (credentials.empty()) {
        std::cout << "Vault is currently empty. Add credentials to evaluate security health.\n";
        return;
    }

    SecurityScore auditScore = PasswordAnalyzer::analyze(credentials);

    // Compute detailed strength breakdown
    size_t strongCount = 0;
    size_t moderateCount = 0;
    size_t weakCount = 0;

    std::unordered_map<std::string, size_t> passwordFrequencyMap;
    for (const auto& credential : credentials) {
        if (!credential) continue;
        ++passwordFrequencyMap[credential->getPassword()];
        int score = PasswordStrength::score(credential->getPassword());
        if (score >= 80) {
            strongCount++;
        } else if (score >= 50) {
            moderateCount++;
        } else {
            weakCount++;
        }
    }

    // Visual score progress bar (20 characters wide)
    int clampedScore = std::max(0, std::min(100, auditScore.score));
    int filledBars = (clampedScore * 20) / 100;
    std::string progressBar;
    for (int i = 0; i < 20; ++i) {
        progressBar += (i < filledBars) ? "=" : "-";
    }

    std::string healthStatus;
    if (clampedScore >= 80) {
        healthStatus = "EXCELLENT";
    } else if (clampedScore >= 60) {
        healthStatus = "GOOD";
    } else if (clampedScore >= 40) {
        healthStatus = "MODERATE (Attention Needed)";
    } else {
        healthStatus = "CRITICAL (High Risk)";
    }

    std::cout << "Overall Vault Health Score : [" << progressBar << "] "
              << clampedScore << "/100 (" << healthStatus << ")\n\n";

    std::cout << "Statistics Summary:\n";
    std::cout << "  Total Credentials Stored : " << credentials.size() << "\n";
    std::cout << "  Strong Passwords         : " << strongCount << "\n";
    std::cout << "  Moderate Passwords       : " << moderateCount << "\n";
    std::cout << "  Weak Passwords           : " << weakCount << "\n";
    std::cout << "  Reused Passwords         : " << auditScore.reusedPasswords << "\n";
    std::cout << "  Old / Stale Passwords    : " << auditScore.oldPasswords << "\n\n";

    std::cout << "Security Audit Warnings:\n";
    bool warningFound = false;

    for (const auto& credential : credentials) {
        if (!credential) continue;

        int score = PasswordStrength::score(credential->getPassword());
        if (score < 50) {
            warningFound = true;
            std::cout << "  [WARNING] " << getCredentialTypeBadge(credential) << " \""
                      << credential->getService() << "\": Weak password (" << score
                      << "/100). Recommendation: "
                      << PasswordStrength::feedback(credential->getPassword()) << "\n";
        }

        if (passwordFrequencyMap[credential->getPassword()] > 1) {
            warningFound = true;
            std::cout << "  [WARNING] " << getCredentialTypeBadge(credential) << " \""
                      << credential->getService()
                      << "\": Password is reused across multiple accounts!\n";
        }
    }

    if (!warningFound) {
        std::cout << "  [OK] No critical vulnerabilities found. All passwords meet recommended security levels.\n";
    }
}

/**
 * @brief Coordinates the main interactive Master Session menu.
 * @param vault Reference to the authenticated MasterVault.
 * @return True to return to the initial user login menu; false to terminate completely.
 */
bool runMasterVaultSession(MasterVault& vault) {
    while (true) {
        std::cout << "\n--- Master Vault Session (User: " << vault.getUsername() << ") ---\n";
        std::cout << "  [1] Manage Credentials (Add, View, Edit, Delete, Details)\n";
        std::cout << "  [2] Search Credentials\n";
        std::cout << "  [3] Password Tools (Generate Password, Check Strength)\n";
        std::cout << "  [4] Security Health Dashboard (Overall Score & Security Audit)\n";
        std::cout << "  [5] Lock Vault / Switch User\n";
        std::cout << "  [6] Exit\n";
        std::cout << "Enter choice (1-6): ";

        std::string choice;
        if (!std::getline(std::cin, choice)) {
            vault.lock();
            std::cout << "\nVault locked. Application closed.\n";
            return false;
        }

        try {
            if (choice == "1") {
                handleManageCredentials(vault);
            } else if (choice == "2") {
                handleSearchCredentials(vault);
            } else if (choice == "3") {
                handlePasswordTools();
            } else if (choice == "4") {
                handleSecurityDashboard(vault);
            } else if (choice == "5") {
                vault.lock();
                std::cout << "\nVault locked.\n";
                return true; // Return to login menu
            } else if (choice == "6") {
                vault.lock();
                std::cout << "\nVault locked. Application closed.\n";
                return false; // Exit application
            } else {
                std::cout << "\nInvalid choice. Please enter 1, 2, 3, 4, 5, or 6.\n";
            }
        } catch (const UnauthorizedAccessException& exception) {
            std::cout << "\n[SECURITY ALERT] Unauthorized access: " << exception.what() << "\n";
        } catch (const WrongPasswordException& exception) {
            std::cout << "\n[AUTH ERROR] Authentication failed: " << exception.what() << "\n";
        } catch (const LockoutException& exception) {
            std::cout << "\n[LOCKOUT ALERT] Access is locked out: " << exception.what() << "\n";
        } catch (const CorruptedVaultException& exception) {
            std::cout << "\n[CORRUPTION ERROR] Vault data corrupted: " << exception.what() << "\n";
        } catch (const FileException& exception) {
            std::cout << "\n[I/O ERROR] File operation failed: " << exception.what() << "\n";
        } catch (const VaultException& exception) {
            std::cout << "\n[VAULT ERROR] Operation failed: " << exception.what() << "\n";
        } catch (const std::exception& exception) {
            std::cout << "\n[UNEXPECTED ERROR] An error occurred: " << exception.what() << "\n";
        }
    }
    vault.lock();
    return false;
}

/**
 * @brief Prompts for username and master password to initialize a new user vault.
 * @param vault Reference to the active MasterVault.
 */
void handleCreateMasterVault(MasterVault& vault) {
    std::cout << "\nEnter username: ";
    std::string username;
    if (!std::getline(std::cin, username) || username.empty()) {
        std::cout << "Error: Username cannot be empty.\n";
        return;
    }

    if (MasterVault::existsForUser(username)) {
        std::cout << "\nA Master Vault already exists for this username.\n";
        std::cout << "Please use Login to Master Vault.\n";
        return;
    }

    std::string masterPassword;
    while (true) {
        if (!std::cin.good()) {
            return;
        }
        masterPassword = TerminalUtils::readHiddenPassword("Create master password: ");
        if (!std::cin.good()) {
            return;
        }
        if (masterPassword.empty()) {
            std::cout << "Error: Master password cannot be empty.\n";
            continue;
        }

        std::string confirmPassword = TerminalUtils::readHiddenPassword("Confirm master password: ");
        if (!std::cin.good()) {
            return;
        }
        if (masterPassword != confirmPassword) {
            std::cout << "Error: Passwords do not match. Please try again.\n";
            continue;
        }
        break;
    }

    try {
        if (vault.create(username, masterPassword)) {
            std::cout << "\nMaster vault created successfully.\n";
            std::cout << "Master vault loaded.\n";
            runMasterVaultSession(vault);
        } else {
            std::cout << "\nError: Failed to create master vault.\n";
        }
    } catch (const VaultException& exception) {
        std::cout << "\n[VAULT ERROR] " << exception.what() << "\n";
    }
}

/**
 * @brief Authenticates a user into their Master Vault session.
 * @param vault Reference to the active MasterVault.
 * @return True to continue to main loop; false to exit.
 */
bool handleLoginMasterVault(MasterVault& vault) {
    std::cout << "\nEnter username: ";
    std::string username;
    if (!std::getline(std::cin, username) || username.empty()) {
        std::cout << "Error: Username cannot be empty.\n";
        return true;
    }

    if (!MasterVault::existsForUser(username)) {
        std::cout << "\nNo master vault found for this username.\n";
        return true;
    }

    int remainingSeconds = 0;
    if (MasterVault::isMasterLockedOut(username, remainingSeconds)) {
        std::cout << "\nMaster Vault login is temporarily locked.\n";
        std::cout << "Please try again in " << remainingSeconds << " seconds.\n";
        return true;
    }

    while (true) {
        if (MasterVault::isMasterLockedOut(username, remainingSeconds)) {
            std::cout << "\nMaster Vault login is temporarily locked.\n";
            std::cout << "Please try again in " << remainingSeconds << " seconds.\n";
            return true;
        }

        std::string masterPassword = TerminalUtils::readHiddenPassword("Enter master password: ");
        if (masterPassword.empty() && !std::cin.good()) {
            return true;
        }

        int attemptsRemaining = 0;
        try {
            if (vault.unlockMaster(username, masterPassword, attemptsRemaining)) {
                std::cout << "\nMaster vault loaded.\n";
                return runMasterVaultSession(vault);
            }
        } catch (const VaultException& exception) {
            std::cout << "\n[VAULT ERROR] " << exception.what() << "\n";
            return true;
        }

        if (attemptsRemaining > 0) {
            std::cout << "Invalid master password.\n";
            std::cout << "Attempts remaining: " << attemptsRemaining << "\n";
        } else {
            std::cout << "\nMaximum login attempts exceeded.\n";
            std::cout << "Master Vault login temporarily locked.\n";
            return true;
        }
    }
}

} // anonymous namespace

int main() {
    std::cout << "VaultSync - Secure Password Manager\n";

    MasterVault vault;

    while (true) {
        std::cout << "\n1. Create Master Vault\n";
        std::cout << "2. Login to Master Vault\n";
        std::cout << "3. Exit\n";
        std::cout << "Enter choice (1-3): ";

        std::string choice;
        if (!std::getline(std::cin, choice)) {
            std::cout << "\nApplication closed.\n";
            break;
        }

        try {
            if (choice == "1") {
                handleCreateMasterVault(vault);
            } else if (choice == "2") {
                bool shouldContinue = handleLoginMasterVault(vault);
                if (!shouldContinue) {
                    break;
                }
            } else if (choice == "3") {
                std::cout << "\nApplication closed.\n";
                break;
            } else {
                std::cout << "\nInvalid choice. Please enter 1, 2, or 3.\n";
            }
        } catch (const VaultException& exception) {
            std::cout << "\n[VAULT ERROR] " << exception.what() << "\n";
        } catch (const std::exception& exception) {
            std::cout << "\n[ERROR] " << exception.what() << "\n";
        }
    }

    return 0;
}
