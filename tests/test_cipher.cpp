#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <filesystem>
#include <iomanip>

#include "ICipher.h"
#include "XORCipher.h"
#include "FileStorage.h"
#include "Credential.h"
#include "CryptoUtils.h"
#include "MasterVault.h"

namespace fs = std::filesystem;

void testBasicXORRoundtrip() {
    std::cout << "[Test 1] Basic Plaintext -> Encrypt -> Decrypt -> Plaintext Roundtrip\n";

    // Polymorphism: instantiate concrete XORCipher through abstract ICipher interface
    std::unique_ptr<ICipher> cipher = std::make_unique<XORCipher>("MySecretKey99");

    std::string originalText = "TopSecretPassword!2026";
    std::vector<uint8_t> plaintext(originalText.begin(), originalText.end());

    std::vector<uint8_t> ciphertext = cipher->encrypt(plaintext);
    std::vector<uint8_t> decrypted = cipher->decrypt(ciphertext);
    std::string decryptedText(decrypted.begin(), decrypted.end());

    std::cout << "  Original  : \"" << originalText << "\"\n";
    std::cout << "  Ciphertext: [";
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ciphertext[i]);
        if (i + 1 < ciphertext.size()) std::cout << " ";
    }
    std::cout << std::dec << "]\n";
    std::cout << "  Decrypted : \"" << decryptedText << "\"\n";

    // Assertions
    assert(ciphertext != plaintext && "Ciphertext should differ from plaintext!");
    assert(decrypted == plaintext && "Decrypted data must match original plaintext!");
    assert(decryptedText == originalText && "Decrypted text must match original string!");

    std::cout << "  --> PASS: Plaintext matches decrypted data exactly.\n\n";
}

void testBinaryDataRoundtrip() {
    std::cout << "[Test 2] Arbitrary Binary Bytes Roundtrip\n";

    std::unique_ptr<ICipher> cipher = std::make_unique<XORCipher>("BinaryKey");

    // Include zero bytes, high bytes, boundary values
    std::vector<uint8_t> binaryData = {0x00, 0xFF, 0x7F, 0x80, 0xAA, 0x55, 0x01, 0xFE};

    std::vector<uint8_t> ciphertext = cipher->encrypt(binaryData);
    std::vector<uint8_t> decrypted = cipher->decrypt(ciphertext);

    assert(decrypted == binaryData && "Binary roundtrip failed!");
    std::cout << "  --> PASS: Arbitrary binary data encrypted and restored successfully.\n\n";
}

void testFileStorageEncryptionIntegration() {
    std::cout << "[Test 3] FileStorage Encrypted Persistence Integration\n";

    const std::string testFile = "data/test_vault.bin";
    if (fs::exists(testFile)) {
        fs::remove(testFile);
    }

    auto cipher = std::make_shared<XORCipher>("IntegrationKey123");
    FileStorage storage(testFile, cipher);

    std::vector<Credential> originalCreds = {
        Credential("GitHub", "octocat", "super_secret_token", "Personal token"),
        Credential("Email", "user@example.com", "mypassword456", "Work mail")
    };

    // Save with cipher
    bool saved = storage.save(originalCreds);
    assert(saved && "FileStorage::save failed!");

    // Inspect raw file bytes to ensure plaintext password is NOT stored as raw ASCII
    std::ifstream rawIn(testFile, std::ios::binary);
    std::string rawContents((std::istreambuf_iterator<char>(rawIn)),
                             std::istreambuf_iterator<char>());
    rawIn.close();

    assert(rawContents.find("super_secret_token") == std::string::npos &&
           "Plaintext password must NOT appear unencrypted in file!");
    std::cout << "  Verified: Plaintext password is NOT visible in raw encrypted storage file.\n";

    // Load with cipher
    std::vector<Credential> loadedCreds = storage.load();
    assert(loadedCreds.size() == originalCreds.size() && "Credential count mismatch!");
    for (size_t i = 0; i < originalCreds.size(); ++i) {
        assert(loadedCreds[i].getService() == originalCreds[i].getService());
        assert(loadedCreds[i].getUsername() == originalCreds[i].getUsername());
        assert(loadedCreds[i].getPassword() == originalCreds[i].getPassword());
        assert(loadedCreds[i].getNotes() == originalCreds[i].getNotes());
    }

    std::cout << "  Verified: All " << loadedCreds.size() << " credentials correctly decrypted and restored.\n";

    // Cleanup
    fs::remove(testFile);
    std::cout << "  --> PASS: FileStorage encryption integration test passed successfully.\n\n";
}

void testCryptoUtils() {
    std::cout << "[Test 4] CryptoUtils SHA-256 and Salted Hashing\n";

    // NIST standard test vector: SHA-256("abc")
    std::string hashAbc = CryptoUtils::sha256("abc");
    assert(hashAbc == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" &&
           "NIST SHA-256 test vector mismatch!");

    // Salt generation and salted password verification
    std::string salt = CryptoUtils::generateSalt(16);
    assert(salt.size() == 32 && "Salt length should be 32 hex characters!");

    std::string password = "MasterPassword#2026";
    std::string storedHash = CryptoUtils::hashPassword(password, salt);

    assert(CryptoUtils::verifyPassword(password, salt, storedHash) &&
           "Valid password verification failed!");
    assert(!CryptoUtils::verifyPassword("WrongPassword", salt, storedHash) &&
           "Invalid password should NOT verify!");

    std::cout << "  --> PASS: SHA-256 test vectors, salt generation, and verification passed.\n\n";
}

void testMasterVaultDualAuth() {
    std::cout << "[Test 5] MasterVault Username, Delayed Credential Setup & Dual Authentication\n";

    const std::string testUser = "testuser_auth";
    const std::string testVaultPath = MasterVault::getVaultPathForUser(testUser);
    if (fs::exists(testVaultPath)) {
        fs::remove(testVaultPath);
    }

    MasterVault vault;
    assert(!MasterVault::existsForUser(testUser) && "Vault should not exist prior to creation!");

    std::string masterPass = "MasterVaultSecret#1";
    std::string credPass = "CredentialVaultSecret#2";

    // 1. Create vault for user (credential vault password is NOT requested during creation)
    bool created = vault.create(testUser, masterPass);
    assert(created && "MasterVault creation failed!");
    assert(MasterVault::existsForUser(testUser) && "Vault file must exist after creation!");
    assert(!vault.hasCredentialPassword() && "Credential password must NOT be configured yet!");

    // 2. Prevent duplicate creation for same username
    bool duplicate = vault.create(testUser, "DifferentPass");
    assert(!duplicate && "Duplicate master vault creation for same username must be rejected!");

    // 3. Delayed credential password setup: reject identical password
    bool samePass = vault.setupCredentialPassword(masterPass);
    assert(!samePass && "Credential vault password must be different from master password!");

    // 4. Successful credential password setup
    bool setupOk = vault.setupCredentialPassword(credPass);
    assert(setupOk && "Credential vault password setup failed with distinct password!");
    assert(vault.hasCredentialPassword() && "Credential vault password must now be marked configured!");
    assert(vault.isCredentialsUnlocked() && "Credential vault should be unlocked after setup!");

    // 5. Add credential
    bool added = vault.addCredential(Credential("TestService", "testuser", "securepass777", "Notes"));
    assert(added && "Adding credential failed!");
    assert(vault.getCredentialCount() == 1 && "Credential count should be 1!");

    // 6. Lock vault
    vault.lock();
    assert(!vault.isMasterUnlocked() && "Master vault must be locked!");
    assert(!vault.isCredentialsUnlocked() && "Credential vault must be locked!");

    // 7. Master Vault login attempts
    int attempts = 0;
    bool wrongMaster = vault.unlockMaster(testUser, "WrongMaster", attempts);
    assert(!wrongMaster && "Wrong master password should fail!");
    assert(attempts == 2 && "Remaining attempts should be 2!");

    bool correctMaster = vault.unlockMaster(testUser, masterPass, attempts);
    assert(correctMaster && "Correct master password should succeed!");
    assert(vault.isMasterUnlocked() && "Master vault must be unlocked!");
    assert(!vault.isCredentialsUnlocked() && "Credential vault must remain locked!");

    // 8. Credential Vault login: Master password MUST be rejected
    int credAttempts = 0;
    bool masterUsedForCred = vault.unlockCredentials(masterPass, credAttempts);
    assert(!masterUsedForCred && "Master password must NEVER unlock Credential Vault!");
    assert(credAttempts == 2 && "Remaining credential attempts should be 2!");

    // 9. 3 failed credential password attempts
    vault.unlockCredentials("Wrong1", credAttempts);
    assert(credAttempts == 1 && "Remaining credential attempts should be 1!");
    vault.unlockCredentials("Wrong2", credAttempts);
    assert(credAttempts == 0 && "Remaining credential attempts should be 0!");

    // 10. Correct credential password unlocks
    vault.resetCredentialsAttempts();
    bool correctCred = vault.unlockCredentials(credPass, credAttempts);
    assert(correctCred && "Unlock with correct credential password failed!");
    assert(vault.isCredentialsUnlocked() && "Credential vault must be unlocked!");
    assert(vault.getCredentialCount() == 1 && "Credential count should be 1!");

    // 11. Verify plaintext password is NOT in vault file
    std::ifstream raw(testVaultPath, std::ios::binary);
    std::string rawData((std::istreambuf_iterator<char>(raw)),
                         std::istreambuf_iterator<char>());
    raw.close();
    assert(rawData.find("securepass777") == std::string::npos && "Plaintext password leaked in file!");
    assert(rawData.find(masterPass) == std::string::npos && "Master password leaked in file!");
    assert(rawData.find(credPass) == std::string::npos && "Credential password leaked in file!");

    // Cleanup
    fs::remove(testVaultPath);
    std::cout << "  --> PASS: Master Vault and Credential Vault dual authentication verified.\n\n";
}

void testMasterVaultEditCredential() {
    std::cout << "[Test 6] MasterVault Credential Edit & Encrypted Persistence Roundtrip\n";

    const std::string testUser = "testuser_edit";
    const std::string testVaultPath = MasterVault::getVaultPathForUser(testUser);
    if (fs::exists(testVaultPath)) {
        fs::remove(testVaultPath);
    }

    MasterVault vault;
    std::string masterPass = "MasterSecret#99";
    std::string credPass = "CredSecret#88";

    assert(vault.create(testUser, masterPass));
    assert(vault.setupCredentialPassword(credPass));

    // 1. Add initial credential
    Credential original("GitHub", "olduser", "oldpass123", "old notes");
    assert(vault.addCredential(original));
    assert(vault.getCredentialCount() == 1);

    // 2. Edit credential at index 0
    Credential updated("GitHub Enterprise", "newuser", "newpass456", "new notes");
    bool editOk = vault.updateCredential(0, updated);
    assert(editOk && "MasterVault::updateCredential failed!");

    // 3. Verify in-memory update
    const auto& creds = vault.getCredentials();
    assert(creds[0].getService() == "GitHub Enterprise");
    assert(creds[0].getUsername() == "newuser");
    assert(creds[0].getPassword() == "newpass456");
    assert(creds[0].getNotes() == "new notes");

    // 4. Out-of-bounds update returns false
    assert(!vault.updateCredential(5, updated) && "Out-of-bounds update should fail!");

    // 5. Lock vault and reload from disk to verify persistence
    vault.lock();

    MasterVault reloadedVault;
    int attempts = 0;
    assert(reloadedVault.unlockMaster(testUser, masterPass, attempts));
    assert(reloadedVault.unlockCredentials(credPass, attempts));

    assert(reloadedVault.getCredentialCount() == 1);
    const auto& reloadedCreds = reloadedVault.getCredentials();
    assert(reloadedCreds[0].getService() == "GitHub Enterprise");
    assert(reloadedCreds[0].getUsername() == "newuser");
    assert(reloadedCreds[0].getPassword() == "newpass456");
    assert(reloadedCreds[0].getNotes() == "new notes");

    // 6. Verify plaintext password is NOT in raw encrypted file
    std::ifstream raw(testVaultPath, std::ios::binary);
    std::string rawData((std::istreambuf_iterator<char>(raw)),
                         std::istreambuf_iterator<char>());
    raw.close();
    assert(rawData.find("newpass456") == std::string::npos && "Plaintext password leaked in file!");

    // Cleanup
    fs::remove(testVaultPath);
    std::cout << "  --> PASS: Credential edit, persistence, and encryption verified.\n\n";
}

void testMasterVaultDeleteCredential() {
    std::cout << "[Test 7] MasterVault Credential Secure Deletion & Encrypted Persistence Roundtrip\n";

    const std::string testUser = "testuser_delete";
    const std::string testVaultPath = MasterVault::getVaultPathForUser(testUser);
    if (fs::exists(testVaultPath)) {
        fs::remove(testVaultPath);
    }

    MasterVault vault;
    std::string masterPass = "MasterSecret#11";
    std::string credPass = "CredSecret#22";

    assert(vault.create(testUser, masterPass));
    assert(vault.setupCredentialPassword(credPass));

    // 1. Add two credentials
    Credential cred1("GitHub", "octocat", "supertoken999", "notes1");
    Credential cred2("AWS", "clouduser", "cloudsecret888", "notes2");
    assert(vault.addCredential(cred1));
    assert(vault.addCredential(cred2));
    assert(vault.getCredentialCount() == 2);

    // 2. verifyCredentialPassword checks
    assert(!vault.verifyCredentialPassword("WrongPassword") && "Wrong password should be rejected!");
    assert(!vault.verifyCredentialPassword(masterPass) && "Master password must NEVER authorize deletion!");
    assert(vault.verifyCredentialPassword(credPass) && "Correct credential password must authorize deletion!");

    // 3. Delete first credential ("GitHub")
    bool deleteOk = vault.deleteCredential(0);
    assert(deleteOk && "MasterVault::deleteCredential failed!");
    assert(vault.getCredentialCount() == 1);
    assert(vault.getCredentials()[0].getService() == "AWS");

    // 4. Out-of-bounds delete returns false
    assert(!vault.deleteCredential(5) && "Out-of-bounds delete should fail!");

    // 5. Lock vault and reload from disk to verify persistence
    vault.lock();

    MasterVault reloadedVault;
    int attempts = 0;
    assert(reloadedVault.unlockMaster(testUser, masterPass, attempts));
    assert(reloadedVault.unlockCredentials(credPass, attempts));

    assert(reloadedVault.getCredentialCount() == 1);
    assert(reloadedVault.getCredentials()[0].getService() == "AWS");

    // 6. Verify deleted plaintext password is completely gone from disk
    std::ifstream raw(testVaultPath, std::ios::binary);
    std::string rawData((std::istreambuf_iterator<char>(raw)),
                         std::istreambuf_iterator<char>());
    raw.close();
    assert(rawData.find("supertoken999") == std::string::npos && "Deleted password leaked in file!");

    // 7. Delete remaining credential to verify empty vault persistence
    assert(reloadedVault.deleteCredential(0));
    assert(reloadedVault.getCredentialCount() == 0);

    reloadedVault.lock();
    MasterVault emptyReloaded;
    assert(emptyReloaded.unlockMaster(testUser, masterPass, attempts));
    assert(emptyReloaded.unlockCredentials(credPass, attempts));
    assert(emptyReloaded.getCredentialCount() == 0);

    // Cleanup
    fs::remove(testVaultPath);
    std::cout << "  --> PASS: Secure credential deletion, persistence, and authorization verified.\n\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "  VaultSync: ICipher & XORCipher Tests  \n";
    std::cout << "========================================\n\n";

    testBasicXORRoundtrip();
    testBinaryDataRoundtrip();
    testFileStorageEncryptionIntegration();
    testCryptoUtils();
    testMasterVaultDualAuth();
    testMasterVaultEditCredential();
    testMasterVaultDeleteCredential();

    std::cout << "All cipher and vault tests passed successfully!\n";
    return 0;
}
