#include <iostream>
#include "Credential.h"

int main()
{
    std::cout << "VaultSync - Secure Password Manager\n";
    std::cout << "--- Milestone 1: Credential Model Demo ---\n\n";

    // Create a Credential instance
    Credential cred("GitHub", "palash-08", "SecretPass123!", "Personal development account");

    // Display fields using getters
    std::cout << "Service  : " << cred.getService() << "\n";
    std::cout << "Username : " << cred.getUsername() << "\n";
    std::cout << "Password : " << cred.getPassword() << "\n";
    std::cout << "Notes    : " << cred.getNotes() << "\n\n";

    // Demonstrate modifying password using setter
    std::cout << "Updating password...\n";
    cred.setPassword("UpdatedSecurePass456!");
    std::cout << "New Password : " << cred.getPassword() << "\n";

    return 0;
}
