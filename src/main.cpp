#include <iostream>
#include <vector>
#include <string>
#include "Credential.h"
#include "FileStorage.h"

void displayCredentials(const std::vector<Credential>& credentials) {
    if (credentials.empty()) {
        std::cout << "\nNo credentials currently stored in the vault.\n";
        return;
    }

    std::cout << "\n================ Stored Credentials (" << credentials.size() << ") ================\n";
    for (size_t i = 0; i < credentials.size(); ++i) {
        std::cout << "[" << (i + 1) << "] Service  : " << credentials[i].getService() << "\n"
                  << "    Username : " << credentials[i].getUsername() << "\n"
                  << "    Password : " << credentials[i].getPassword() << "\n"
                  << "    Notes    : " << (credentials[i].getNotes().empty() ? "(none)" : credentials[i].getNotes()) << "\n";
        if (i + 1 < credentials.size()) {
            std::cout << "----------------------------------------------------\n";
        }
    }
    std::cout << "====================================================\n";
}

int main() {
    FileStorage storage("data/vault.bin");
    std::vector<Credential> credentials = storage.load();

    std::cout << "========================================\n";
    std::cout << "  VaultSync - Secure Password Manager   \n";
    std::cout << "  Binary Storage & Input Demonstration  \n";
    std::cout << "========================================\n";
    std::cout << "Loaded " << credentials.size() << " existing credential(s) from " << storage.getFilePath() << "\n";

    while (true) {
        std::cout << "\nMenu Options:\n";
        std::cout << "1. Add New Credential\n";
        std::cout << "2. View All Stored Credentials\n";
        std::cout << "3. Exit\n";
        std::cout << "Enter choice (1-3): ";

        std::string choice;
        if (!std::getline(std::cin, choice)) {
            std::cout << "\nExiting...\n";
            break;
        }

        if (choice == "1") {
            std::cout << "\n--- Add New Credential ---\n";

            std::cout << "Enter Service (e.g. GitHub): ";
            std::string service;
            if (!std::getline(std::cin, service)) break;

            std::cout << "Enter Username: ";
            std::string username;
            if (!std::getline(std::cin, username)) break;

            std::cout << "Enter Password [Press Enter for default: p@ssw0rd]: ";
            std::string password;
            if (!std::getline(std::cin, password)) break;
            if (password.empty()) {
                password = "p@ssw0rd";
            }

            std::cout << "Enter Notes (optional): ";
            std::string notes;
            if (!std::getline(std::cin, notes)) break;

            credentials.emplace_back(service, username, password, notes);

            if (storage.save(credentials)) {
                std::cout << "\n[Success] Credential saved to binary vault ('" << storage.getFilePath() << "')!\n";
            } else {
                std::cout << "\n[Error] Failed to save credential to file.\n";
            }
        } else if (choice == "2") {
            displayCredentials(credentials);
        } else if (choice == "3") {
            std::cout << "Exiting VaultSync. Goodbye!\n";
            break;
        } else {
            std::cout << "Invalid choice. Please enter 1, 2, or 3.\n";
        }
    }

    return 0;
}
