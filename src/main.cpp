#include <iostream>
#include <vector>
#include <string>
#include "Credential.h"
#include "MasterVault.h"
#include "TerminalUtils.h"

namespace {

bool ensureCredentialVaultUnlocked(MasterVault& vault) {
    if (vault.isCredentialsUnlocked()) {
        return true;
    }

    // Delayed setup: configure credential vault password if not yet set
    if (!vault.hasCredentialPassword()) {
        std::cout << "\nNo credential vault password has been configured.\n";
        while (true) {
            std::string credPass = TerminalUtils::readHiddenPassword("Create credential vault password: ");
            if (credPass.empty()) {
                std::cout << "Error: Password cannot be empty.\n";
                continue;
            }

            std::string confirmPass = TerminalUtils::readHiddenPassword("Confirm credential vault password: ");
            if (credPass != confirmPass) {
                std::cout << "Error: Passwords do not match. Please try again.\n";
                continue;
            }

            if (!vault.setupCredentialPassword(credPass)) {
                std::cout << "Credential vault password must be different from the master password.\n";
                continue;
            }

            std::cout << "\nCredential vault password configured successfully.\n";
            return true;
        }
    }

    // Authenticate existing credential vault password (3 attempts)
    vault.resetCredentialsAttempts();
    while (true) {
        std::string credPass = TerminalUtils::readHiddenPassword("Enter credential vault password: ");
        int attemptsRemaining = 0;
        if (vault.unlockCredentials(credPass, attemptsRemaining)) {
            std::cout << "\nCredential vault unlocked.\n";
            return true;
        }

        std::cout << "Invalid credential vault password.\n";
        if (attemptsRemaining <= 0) {
            std::cout << "\nMaximum attempts exceeded.\n";
            std::cout << "Credential vault access denied.\n";
            return false;
        }
    }
}

void handleEditCredential(MasterVault& vault, size_t index) {
    if (index >= vault.getCredentialCount()) {
        return;
    }

    // Temporary copy: all modifications apply only to tempCred until Save Changes
    Credential tempCred = vault.getCredentials()[index];

    while (true) {
        std::cout << "\n================ Edit Credential ================\n\n";
        std::cout << "Service  : " << tempCred.getService() << "\n";
        std::cout << "Username : " << tempCred.getUsername() << "\n";
        std::cout << "Password : " << tempCred.getPassword() << "\n";
        std::cout << "Notes    : " << (tempCred.getNotes().empty() ? "(none)" : tempCred.getNotes()) << "\n\n";

        std::cout << "1. Change Service\n";
        std::cout << "2. Change Username\n";
        std::cout << "3. Change Password\n";
        std::cout << "4. Change Notes\n";
        std::cout << "5. Save Changes\n";
        std::cout << "6. Cancel\n";
        std::cout << "Enter choice: ";

        std::string choice;
        if (!std::getline(std::cin, choice)) {
            std::cout << "\nChanges cancelled.\n";
            break;
        }

        if (choice == "1") {
            std::cout << "\nEnter new service: ";
            std::string newService;
            if (!std::getline(std::cin, newService)) break;
            if (newService.empty()) {
                std::cout << "Error: Service cannot be empty.\n";
            } else {
                tempCred.setService(newService);
            }
        } else if (choice == "2") {
            std::cout << "\nEnter new username: ";
            std::string newUsername;
            if (!std::getline(std::cin, newUsername)) break;
            if (newUsername.empty()) {
                std::cout << "Error: Username cannot be empty.\n";
            } else {
                tempCred.setUsername(newUsername);
            }
        } else if (choice == "3") {
            std::string newPass = TerminalUtils::readHiddenPassword("\nEnter new password: ");
            if (newPass.empty()) {
                std::cout << "Error: Password cannot be empty.\n";
            } else {
                std::string confirmPass = TerminalUtils::readHiddenPassword("Confirm new password: ");
                if (newPass != confirmPass) {
                    std::cout << "\nError: Passwords do not match.\n";
                } else {
                    tempCred.setPassword(newPass);
                }
            }
        } else if (choice == "4") {
            std::cout << "\nEnter new notes: ";
            std::string newNotes;
            if (!std::getline(std::cin, newNotes)) break;
            tempCred.setNotes(newNotes);
        } else if (choice == "5") {
            if (vault.updateCredential(index, tempCred)) {
                std::cout << "\nCredential updated successfully.\n";
            } else {
                std::cout << "\nError: Failed to save changes.\n";
            }
            break;
        } else if (choice == "6") {
            std::cout << "\nChanges cancelled.\n";
            break;
        } else {
            std::cout << "\nInvalid choice. Please enter 1, 2, 3, 4, 5, or 6.\n";
        }
    }
}

bool handleDeleteCredential(MasterVault& vault, size_t index) {
    if (index >= vault.getCredentialCount()) {
        return false;
    }

    const Credential& cred = vault.getCredentials()[index];

    while (true) {
        std::cout << "\nDelete credential \"" << cred.getService() << "\"?\n\n";
        std::cout << "1. Confirm Delete\n";
        std::cout << "2. Cancel\n";
        std::cout << "Enter choice: ";

        std::string choice;
        if (!std::getline(std::cin, choice)) {
            std::cout << "\nDeletion cancelled.\n";
            return false;
        }

        if (choice == "2") {
            std::cout << "\nDeletion cancelled.\n";
            return false;
        } else if (choice == "1") {
            break;
        } else {
            std::cout << "\nInvalid choice. Please enter 1 or 2.\n";
        }
    }

    int attempts = 3;
    while (attempts > 0) {
        std::string password = TerminalUtils::readHiddenPassword("Enter credential vault password: ");
        if (vault.verifyCredentialPassword(password)) {
            if (vault.deleteCredential(index)) {
                std::cout << "\nCredential deleted successfully.\n";
                return true;
            } else {
                std::cout << "\nError: Failed to delete credential.\n";
                return false;
            }
        }

        attempts--;
        if (attempts > 0) {
            std::cout << "Invalid credential vault password.\n";
            std::cout << "Attempts remaining: " << attempts << "\n";
        } else {
            std::cout << "\nMaximum attempts exceeded.\n";
            std::cout << "Credential deletion denied.\n";
            return false;
        }
    }

    return false;
}

void viewCredentialDetails(MasterVault& vault, size_t index) {
    bool showPassword = false;

    while (true) {
        if (index >= vault.getCredentialCount()) {
            break;
        }
        const Credential& cred = vault.getCredentials()[index];

        std::cout << "\n================ Credential Details ================\n\n";
        std::cout << "Service  : " << cred.getService() << "\n";
        std::cout << "Username : " << cred.getUsername() << "\n";
        if (showPassword) {
            std::cout << "Password : " << cred.getPassword() << "\n";
        } else {
            std::cout << "Password : ********\n";
        }
        std::cout << "Notes    : " << (cred.getNotes().empty() ? "(none)" : cred.getNotes()) << "\n\n";

        std::cout << "1. Show Password\n";
        std::cout << "2. Hide Password\n";
        std::cout << "3. Edit Credential\n";
        std::cout << "4. Delete Credential\n";
        std::cout << "5. Back\n";
        std::cout << "Enter choice: ";

        std::string choice;
        if (!std::getline(std::cin, choice)) {
            break;
        }

        if (choice == "1") {
            showPassword = true;
        } else if (choice == "2") {
            showPassword = false;
        } else if (choice == "3") {
            handleEditCredential(vault, index);
            showPassword = false;
        } else if (choice == "4") {
            if (handleDeleteCredential(vault, index)) {
                break; // Return to Credential Vault credential list
            }
        } else if (choice == "5") {
            break; // Return to credential list
        } else {
            std::cout << "\nInvalid choice. Please enter 1, 2, 3, 4, or 5.\n";
        }
    }
}

void handleViewCredentials(MasterVault& vault) {
    if (!vault.hasCredentialPassword()) {
        std::cout << "\nNo credentials currently stored in the vault.\n";
        return;
    }

    if (!ensureCredentialVaultUnlocked(vault)) {
        return;
    }

    while (true) {
        const auto& credentials = vault.getCredentials();
        if (credentials.empty()) {
            std::cout << "\nNo credentials currently stored in the vault.\n";
            return;
        }

        std::cout << "\n================ Credential Vault ================\n\n";
        for (size_t i = 0; i < credentials.size(); ++i) {
            std::cout << "[" << (i + 1) << "] " << credentials[i].getService() << "\n";
        }
        std::cout << "\nSelect credential (0 to go back): ";

        std::string input;
        if (!std::getline(std::cin, input)) {
            break;
        }

        try {
            size_t idx = std::stoul(input);
            if (idx == 0) {
                break; // Return to Master Vault menu
            }
            if (idx >= 1 && idx <= credentials.size()) {
                viewCredentialDetails(vault, idx - 1);
            } else {
                std::cout << "\nInvalid choice. Please select a valid credential number.\n";
            }
        } catch (...) {
            std::cout << "\nInvalid input. Please enter a valid number.\n";
        }
    }
}

bool runMasterVaultSession(MasterVault& vault) {
    while (true) {
        std::cout << "\n1. Add Credential\n";
        std::cout << "2. View Credentials\n";
        std::cout << "3. Lock Vault\n";
        std::cout << "4. Exit\n";
        std::cout << "Enter choice (1-4): ";

        std::string choice;
        if (!std::getline(std::cin, choice)) {
            vault.lock();
            std::cout << "\nVault locked. Application closed.\n";
            return false;
        }

        if (choice == "1") {
            if (!ensureCredentialVaultUnlocked(vault)) {
                continue;
            }

            std::cout << "\nEnter service: ";
            std::string service;
            if (!std::getline(std::cin, service)) break;

            std::cout << "Enter username: ";
            std::string username;
            if (!std::getline(std::cin, username)) break;

            std::string password = TerminalUtils::readHiddenPassword("Enter password: ");

            std::cout << "Enter notes: ";
            std::string notes;
            if (!std::getline(std::cin, notes)) break;

            Credential cred(service, username, password, notes);
            if (vault.addCredential(cred)) {
                std::cout << "\nCredential added successfully.\n";
            } else {
                std::cout << "\nError: Failed to save credential.\n";
            }
        } else if (choice == "2") {
            handleViewCredentials(vault);
        } else if (choice == "3") {
            vault.lock();
            std::cout << "\nVault locked.\n";
            return true; // Return to initial menu
        } else if (choice == "4") {
            vault.lock();
            std::cout << "\nVault locked. Application closed.\n";
            return false; // Exit completely
        } else {
            std::cout << "\nInvalid choice. Please enter 1, 2, 3, or 4.\n";
        }
    }
    vault.lock();
    return false;
}

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
        masterPassword = TerminalUtils::readHiddenPassword("Create master password: ");
        if (masterPassword.empty()) {
            std::cout << "Error: Master password cannot be empty.\n";
            continue;
        }

        std::string confirmPassword = TerminalUtils::readHiddenPassword("Confirm master password: ");
        if (masterPassword != confirmPassword) {
            std::cout << "Error: Passwords do not match. Please try again.\n";
            continue;
        }
        break;
    }

    if (vault.create(username, masterPassword)) {
        std::cout << "\nMaster vault created successfully.\n";
        std::cout << "Master vault loaded.\n";
        // Automatically enter normal Master Vault menu
        runMasterVaultSession(vault);
    } else {
        std::cout << "\nError: Failed to create master vault.\n";
    }
}

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

    int attempts = 3;
    while (attempts > 0) {
        std::string masterPassword = TerminalUtils::readHiddenPassword("Enter master password: ");
        int attemptsRemaining = 0;
        if (vault.unlockMaster(username, masterPassword, attemptsRemaining)) {
            std::cout << "\nMaster vault loaded.\n";
            return runMasterVaultSession(vault);
        }

        attempts--;
        std::cout << "Invalid master password.\n";
        if (attempts <= 0) {
            std::cout << "\nMaximum login attempts exceeded.\n";
            std::cout << "Master Vault access denied.\n";
            return true;
        }
    }
    return true;
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
    }

    return 0;
}
