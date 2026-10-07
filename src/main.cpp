#include <iostream>
#include <vector>
#include <string>
#include "Credential.h"
#include "MasterVault.h"
#include "TerminalUtils.h"

namespace {

void displayCredentials(const std::vector<Credential>& credentials) {
    if (credentials.empty()) {
        std::cout << "\nNo credentials currently stored in the vault.\n";
        return;
    }

    std::cout << "\n================ Stored Credentials (" << credentials.size() << ") ================\n";
    for (size_t i = 0; i < credentials.size(); ++i) {
        std::cout << "[" << (i + 1) << "] Service  : " << credentials[i].getService() << "\n"
                  << "    Username : " << credentials[i].getUsername() << "\n"
                  << "    Password : ********\n"
                  << "    Notes    : " << (credentials[i].getNotes().empty() ? "(none)" : credentials[i].getNotes()) << "\n";
        if (i + 1 < credentials.size()) {
            std::cout << "----------------------------------------------------\n";
        }
    }
    std::cout << "====================================================\n";
}

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
            if (!vault.hasCredentialPassword()) {
                std::cout << "\nNo credentials currently stored in the vault.\n";
                continue;
            }

            if (!ensureCredentialVaultUnlocked(vault)) {
                continue;
            }

            if (vault.getCredentialCount() == 0) {
                std::cout << "\nNo credentials currently stored in the vault.\n";
            } else {
                std::cout << "\nLoaded " << vault.getCredentialCount() << " existing credentials.\n";
                displayCredentials(vault.getCredentials());
            }
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
