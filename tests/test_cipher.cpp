#ifdef NDEBUG
#undef NDEBUG
#endif
#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <sys/stat.h>
#include <chrono>
#include <thread>

#include "crypto/ICipher.h"
#include "crypto/XORCipher.h"
#include "storage/FileStorage.h"
#include "credentials/Credential.h"
#include "crypto/CryptoUtils.h"
#include "auth/MasterVault.h"
#include "credentials/WebCredential.h"
#include "credentials/WiFiCredential.h"
#include "credentials/SSHCredential.h"
#include "storage/Repository.h"
#include "storage/Vault.h"
#include "vault/VaultProxy.h"
#include "security/VaultExceptions.h"
#include "security/PasswordGenerator.h"
#include "security/PasswordStrength.h"
#include "security/PasswordAnalyzer.h"
#include "crypto/AESCipher.h"
#include "ui/TerminalUtils.h"
#include "storage/BackupConfig.h"
#include "storage/SftpSubprocessClient.h"

namespace fs = std::filesystem;

void testArchitectureComponents() {
    std::cout << "[Test 9] Polymorphic Credentials, Repository, Vault Proxy & Password Tools\n";

    std::vector<std::shared_ptr<Credential>> originalCredentials = {
        std::make_shared<WebCredential>("Web", "alice", "web-secret", "note", "https://example.test"),
        std::make_shared<WiFiCredential>("Home WiFi", "", "wifi-secret", "", "HomeNet", "WPA2"),
        std::make_shared<SSHCredential>("Server", "root", "ssh-secret", "", "host.test", 2222)
    };

    assert(originalCredentials[0]->clone()->getType() == "web");
    assert(*originalCredentials[0] == *originalCredentials[0]->clone());
    assert(originalCredentials[0]->matches("alice"));

    Repository<Credential> credentialRepository;
    for (const auto& credential : originalCredentials) {
        credentialRepository.add(credential);
    }

    assert(credentialRepository.size() == 3);
    assert(credentialRepository.get(1)->getType() == "wifi");
    assert(credentialRepository.find([](const Credential& credential) {
        return credential.matches("host.test");
    }).size() == 1);

    const std::string testVaultPath = "data/test_polymorphic_vault.bin";
    if (fs::exists(testVaultPath)) {
        fs::remove(testVaultPath);
    }

    FileStorage fileStorage(testVaultPath);
    bool savedPoly = fileStorage.save(originalCredentials);
    assert(savedPoly);

    auto restoredCredentials = fileStorage.loadPolymorphic();
    assert(restoredCredentials.size() == 3);
    assert(restoredCredentials[0]->getType() == "web");
    assert(restoredCredentials[1]->getType() == "wifi");
    assert(restoredCredentials[2]->getType() == "ssh");

    assert(static_cast<WebCredential&>(*restoredCredentials[0]).getUrl() == "https://example.test");
    assert(static_cast<WiFiCredential&>(*restoredCredentials[1]).getSsid() == "HomeNet");
    assert(static_cast<SSHCredential&>(*restoredCredentials[2]).getPort() == 2222);

    assert(*restoredCredentials[0] == *originalCredentials[0]);
    assert(*restoredCredentials[1] == *originalCredentials[1]);
    assert(*restoredCredentials[2] == *originalCredentials[2]);

    fs::remove(testVaultPath);

    Vault vault;
    VaultProxy unauthorizedProxy(vault);
    bool rejected = false;
    try {
        unauthorizedProxy.getCredentials();
    } catch (const UnauthorizedAccessException&) {
        rejected = true;
    }
    assert(rejected);

    vault.unlock();
    VaultProxy authorizedProxy(vault, true);
    authorizedProxy.addCredential(originalCredentials[0]);
    assert(authorizedProxy.search("alice").size() == 1);

    authorizedProxy.lock();
    rejected = false;
    try {
        authorizedProxy.getCredentials();
    } catch (const UnauthorizedAccessException&) {
        rejected = true;
    }
    assert(rejected);

    bool exceptionInheritanceVerified = false;
    try {
        throw CorruptedVaultException();
    } catch (const VaultException&) {
        exceptionInheritanceVerified = true;
    }
    assert(exceptionInheritanceVerified);

    std::string generatedPassword = PasswordGenerator::generate(24, true, true, true, true);
    assert(generatedPassword.size() == 24);

    PasswordStrengthResult strengthResult = PasswordStrength::analyze(generatedPassword);
    assert(strengthResult.score > 0 && strengthResult.entropy > 0);

    std::vector<std::shared_ptr<Credential>> reusedCredentials = {
        std::make_shared<Credential>("ServiceA", "userA", "sharedSecretPassword"),
        std::make_shared<Credential>("ServiceB", "userB", "sharedSecretPassword")
    };
    assert(PasswordAnalyzer::isReused("sharedSecretPassword", reusedCredentials));
    assert(PasswordAnalyzer::securityScore(reusedCredentials).reusedPasswords == 2);

    std::cout << "  --> PASS: Polymorphic credentials, access control proxy, and analyzer verified.\n\n";
}

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

    bool created = vault.create(testUser, masterPass);
    assert(created);
    bool setup = vault.setupCredentialPassword(credPass);
    assert(setup);

    // 1. Add initial credential
    Credential original("GitHub", "olduser", "oldpass123", "old notes");
    bool added = vault.addCredential(original);
    assert(added);
    assert(vault.getCredentialCount() == 1);

    // 2. Edit credential at index 0
    Credential updated("GitHub Enterprise", "newuser", "newpass456", "new notes");
    
    // Domain rule: changing secret password without credential password must be rejected!
    bool unauthEdit = vault.updateCredential(0, updated);
    assert(!unauthEdit && "Updating credential secret without password must be rejected!");

    // Domain rule: changing secret password with wrong credential password must be rejected!
    bool wrongPassEdit = vault.updateCredential(0, updated, "WrongPassword");
    assert(!wrongPassEdit && "Updating credential secret with wrong password must be rejected!");

    // Verify original password and metadata preserved after unauthorized attempts
    assert(vault.getCredentials()[0].getPassword() == "oldpass123");
    assert(vault.getCredentials()[0].getService() == "GitHub");

    // Domain rule: changing secret password with valid credential password succeeds!
    bool editOk = vault.updateCredential(0, updated, credPass);
    assert(editOk && "MasterVault::updateCredential with valid credPass failed!");

    // 3. Verify in-memory update
    const auto& creds = vault.getCredentials();
    assert(creds[0].getService() == "GitHub Enterprise");
    assert(creds[0].getUsername() == "newuser");
    assert(creds[0].getPassword() == "newpass456");
    assert(creds[0].getNotes() == "new notes");

    // Test non-sensitive metadata update (password unchanged): does not require re-authentication
    Credential metaUpdated("GitHub Enterprise Pro", "newuser", "newpass456", "updated notes");
    bool metaEditOk = vault.updateCredential(0, metaUpdated);
    assert(metaEditOk && "Updating non-sensitive metadata only should not require re-authentication!");
    assert(vault.getCredentials()[0].getService() == "GitHub Enterprise Pro");
    assert(vault.getCredentials()[0].getNotes() == "updated notes");

    // Test non-sensitive metadata update with empty/untouched password field:
    // Must succeed without credential password and must NOT erase stored password
    Credential emptyPassUpdated("GitHub Enterprise Suite", "suiteuser", "", "suite notes");
    bool emptyPassEditOk = vault.updateCredential(0, emptyPassUpdated);
    assert(emptyPassEditOk && "Updating metadata with empty password must succeed without credential password!");
    assert(vault.getCredentials()[0].getService() == "GitHub Enterprise Suite");
    assert(vault.getCredentials()[0].getUsername() == "suiteuser");
    assert(vault.getCredentials()[0].getPassword() == "newpass456" && "Empty password field must NOT erase existing stored password!");
    assert(vault.getCredentials()[0].getNotes() == "suite notes");

    // Test failed authorization preserving original password
    Credential unauthChange("GitHub ShouldFail", "failuser", "failed_secret", "fail notes");
    bool failedChange = vault.updateCredential(0, unauthChange, "WrongPass123");
    assert(!failedChange && "Unauthorized secret change must be rejected!");
    assert(vault.getCredentials()[0].getService() == "GitHub Enterprise Suite" && "Original service preserved on failure!");
    assert(vault.getCredentials()[0].getPassword() == "newpass456" && "Original password preserved on failure!");

    // 4. Out-of-bounds update returns false
    bool oobUpdate = vault.updateCredential(5, updated, credPass);
    assert(!oobUpdate && "Out-of-bounds update should fail!");

    // 5. Lock vault and reload from disk to verify persistence
    vault.lock();

    MasterVault reloadedVault;
    int attempts = 0;
    bool reloadedMaster = reloadedVault.unlockMaster(testUser, masterPass, attempts);
    assert(reloadedMaster);
    bool reloadedCred = reloadedVault.unlockCredentials(credPass, attempts);
    assert(reloadedCred);

    assert(reloadedVault.getCredentialCount() == 1);
    const auto& reloadedCreds = reloadedVault.getCredentials();
    assert(reloadedCreds[0].getService() == "GitHub Enterprise Suite");
    assert(reloadedCreds[0].getUsername() == "suiteuser");
    assert(reloadedCreds[0].getPassword() == "newpass456");
    assert(reloadedCreds[0].getNotes() == "suite notes");

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

    bool created = vault.create(testUser, masterPass);
    assert(created);
    bool setup = vault.setupCredentialPassword(credPass);
    assert(setup);

    // 1. Add two credentials
    Credential cred1("GitHub", "octocat", "supertoken999", "notes1");
    Credential cred2("AWS", "clouduser", "cloudsecret888", "notes2");
    bool added1 = vault.addCredential(cred1);
    assert(added1);
    bool added2 = vault.addCredential(cred2);
    assert(added2);
    assert(vault.getCredentialCount() == 2);

    // 2. verifyCredentialPassword checks
    assert(!vault.verifyCredentialPassword("WrongPassword") && "Wrong password should be rejected!");
    assert(!vault.verifyCredentialPassword(masterPass) && "Master password must NEVER authorize deletion!");
    assert(vault.verifyCredentialPassword(credPass) && "Correct credential password must authorize deletion!");

    // 3. Delete first credential ("GitHub")
    // Domain rule: calling deleteCredential without credential password must be rejected!
    bool unauthDelete = vault.deleteCredential(0);
    assert(!unauthDelete && "Deleting credential without password must fail!");

    // Domain rule: calling deleteCredential with wrong password must be rejected!
    bool wrongPassDelete = vault.deleteCredential(0, "WrongPassword");
    assert(!wrongPassDelete && "Deleting credential with wrong password must fail!");

    // Domain rule: calling deleteCredential without explicit confirmation must fail!
    bool unconfirmedDelete = vault.deleteCredential(0, credPass, false);
    assert(!unconfirmedDelete && "Deleting credential without explicit confirmation must fail!");

    // Domain rule: calling deleteCredential with valid credential password and confirmation succeeds!
    bool deleteOk = vault.deleteCredential(0, credPass, true);
    assert(deleteOk && "MasterVault::deleteCredential failed!");
    assert(vault.getCredentialCount() == 1);
    assert(vault.getCredentials()[0].getService() == "AWS");

    // 4. Out-of-bounds delete returns false
    bool oobDelete = vault.deleteCredential(5, credPass);
    assert(!oobDelete && "Out-of-bounds delete should fail!");

    // 5. Lock vault and reload from disk to verify persistence
    vault.lock();

    MasterVault reloadedVault;
    int attempts = 0;
    bool reloadedMaster = reloadedVault.unlockMaster(testUser, masterPass, attempts);
    assert(reloadedMaster);
    bool reloadedCred = reloadedVault.unlockCredentials(credPass, attempts);
    assert(reloadedCred);

    assert(reloadedVault.getCredentialCount() == 1);
    assert(reloadedVault.getCredentials()[0].getService() == "AWS");

    // 6. Verify deleted plaintext password is completely gone from disk
    std::ifstream raw(testVaultPath, std::ios::binary);
    std::string rawData((std::istreambuf_iterator<char>(raw)),
                         std::istreambuf_iterator<char>());
    raw.close();
    assert(rawData.find("supertoken999") == std::string::npos && "Deleted password leaked in file!");

    // 7. Delete remaining credential to verify empty vault persistence
    bool unauthRemDelete = reloadedVault.deleteCredential(0);
    assert(!unauthRemDelete && "Deleting remaining credential without password must fail!");
    bool deletedRem = reloadedVault.deleteCredential(0, credPass);
    assert(deletedRem);
    assert(reloadedVault.getCredentialCount() == 0);

    reloadedVault.lock();
    MasterVault emptyReloaded;
    bool emptyMaster = emptyReloaded.unlockMaster(testUser, masterPass, attempts);
    assert(emptyMaster);
    bool emptyCred = emptyReloaded.unlockCredentials(credPass, attempts);
    assert(emptyCred);
    assert(emptyReloaded.getCredentialCount() == 0);

    // Cleanup
    fs::remove(testVaultPath);
    std::cout << "  --> PASS: Secure credential deletion, persistence, and authorization verified.\n\n";
}

void testMasterVaultLoginAttemptsAndLockout() {
    std::cout << "[Test 8] MasterVault 3-Attempt Failed Login and Temporary Lockout\n";

    const std::string testUser = "testuser_lockout";
    const std::string otherUser = "testuser_other";
    const std::string testVaultPath = MasterVault::getVaultPathForUser(testUser);
    if (fs::exists(testVaultPath)) {
        fs::remove(testVaultPath);
    }

    MasterVault vault;
    std::string masterPass = "MasterSecret#99";
    std::string credPass = "CredSecret#88";

    bool created = vault.create(testUser, masterPass);
    assert(created);
    bool setup = vault.setupCredentialPassword(credPass);
    assert(setup);
    bool added = vault.addCredential(Credential("TestService", "lockout_user", "sample_pass", "notes"));
    assert(added);
    vault.lock();

    // 1. Enter wrong Master Password once: 2 attempts remaining
    int attempts = 0;
    bool attempt1 = vault.unlockMaster(testUser, "WrongPass1", attempts);
    assert(!attempt1 && "Wrong password must fail!");
    assert(attempts == 2 && "Remaining attempts must be 2!");

    // 2. Enter wrong Master Password twice: 1 attempt remaining
    bool attempt2 = vault.unlockMaster(testUser, "WrongPass2", attempts);
    assert(!attempt2 && "Wrong password must fail!");
    assert(attempts == 1 && "Remaining attempts must be 1!");

    // 3. Enter wrong Master Password three times: lockout triggered
    bool attempt3 = vault.unlockMaster(testUser, "WrongPass3", attempts);
    assert(!attempt3 && "Wrong password must fail!");
    assert(attempts == 0 && "Remaining attempts must be 0!");

    // 4. Verify temporary lockout active and reports remaining duration
    int remainingSec = 0;
    assert(MasterVault::isMasterLockedOut(testUser, remainingSec) && "User must be locked out after 3 failures!");
    assert(remainingSec >= 28 && remainingSec <= 30 && "Remaining lockout seconds must be within 30s window!");

    // 5. Verify lockout is scoped to this user only (other user not blocked)
    int otherRemaining = 0;
    assert(!MasterVault::isMasterLockedOut(otherUser, otherRemaining) && "Unrelated user must NOT be locked out!");

    // 6. Attempting login during lockout must remain blocked
    bool blockedAttempt = vault.unlockMaster(testUser, masterPass, attempts);
    assert(!blockedAttempt && "Login must be blocked during temporary lockout!");
    assert(attempts == 0);

    // 7. Reset lockout (simulates 30s expiration)
    MasterVault::resetMasterLockout(testUser);
    assert(!MasterVault::isMasterLockedOut(testUser, remainingSec) && "Lockout must be cleared!");

    // 8. Successful login resets failed attempts
    bool correctLogin = vault.unlockMaster(testUser, masterPass, attempts);
    assert(correctLogin && "Login must succeed with correct password after lockout!");
    assert(attempts == 3 && "Attempts must be reset to 3 upon successful login!");

    // 9. Verify partial failure followed by success resets counter
    vault.lock();
    bool wrongOnce = vault.unlockMaster(testUser, "WrongOnce", attempts);
    assert(!wrongOnce);
    assert(attempts == 2);
    bool resetSuccess = vault.unlockMaster(testUser, masterPass, attempts); // Success resets counter
    assert(resetSuccess);
    vault.lock();
    bool wrongAgain = vault.unlockMaster(testUser, "WrongAgain", attempts);
    assert(!wrongAgain);
    assert(attempts == 2 && "Next session must start with full 3 attempts!");

    // 10. Verify no credential data was lost or modified
    vault.resetMasterLockout(testUser);
    bool finalMaster = vault.unlockMaster(testUser, masterPass, attempts);
    assert(finalMaster);
    bool finalCred = vault.unlockCredentials(credPass, attempts);
    assert(finalCred);
    assert(vault.getCredentialCount() == 1);
    assert(vault.getCredentials()[0].getService() == "TestService");
    assert(vault.getCredentials()[0].getPassword() == "sample_pass");

    // Cleanup
    fs::remove(testVaultPath);
    std::cout << "  --> PASS: 3-attempt lockout, user-scoping, and reset behavior verified.\n\n";
}

void testAESCipherRoundtripAndRandomization() {
    std::cout << "[Test 10] AES-256-GCM Roundtrip and Nonce Randomization\n";

    std::string keyString = "VaultSyncAES256ProductionKey2026";
    std::unique_ptr<ICipher> cipher = std::make_unique<AESCipher>(keyString);

    // 1. Text roundtrip
    std::string originalText = "TopSecretAESGCMPlaintext!2026";
    std::vector<uint8_t> plaintext(originalText.begin(), originalText.end());

    std::vector<uint8_t> ciphertext1 = cipher->encrypt(plaintext);
    assert(ciphertext1 != plaintext && "Ciphertext must not match plaintext!");
    assert(ciphertext1.size() == AESCipher::OVERHEAD_SIZE + plaintext.size() &&
           "Ciphertext payload size must equal overhead (12 IV + 16 Tag) + plaintext length!");

    std::vector<uint8_t> decrypted1 = cipher->decrypt(ciphertext1);
    std::string decryptedText1(decrypted1.begin(), decrypted1.end());
    assert(decrypted1 == plaintext && "Decrypted bytes must match original plaintext!");
    assert(decryptedText1 == originalText && "Decrypted string must match original text!");

    // 2. Randomization across runs for identical plaintext (due to unique IVs)
    std::vector<uint8_t> ciphertext2 = cipher->encrypt(plaintext);
    assert(ciphertext1 != ciphertext2 &&
           "Ciphertext must be randomized across runs for identical plaintext due to unique IVs!");
    assert(ciphertext1.size() == ciphertext2.size());

    // Verify IVs differ
    bool ivsDiffer = !std::equal(ciphertext1.begin(), ciphertext1.begin() + AESCipher::IV_SIZE, ciphertext2.begin());
    assert(ivsDiffer && "Distinct encryptions must use distinct random IVs!");

    std::vector<uint8_t> decrypted2 = cipher->decrypt(ciphertext2);
    assert(decrypted2 == plaintext && "Both randomized ciphertexts must decrypt to the original plaintext!");

    // 3. Binary data roundtrip (including null and boundary bytes)
    std::vector<uint8_t> binaryData = {0x00, 0xFF, 0x7F, 0x80, 0xAA, 0x55, 0x01, 0xFE, 0x00, 0x42};
    std::vector<uint8_t> binaryCiphertext = cipher->encrypt(binaryData);
    std::vector<uint8_t> binaryDecrypted = cipher->decrypt(binaryCiphertext);
    assert(binaryDecrypted == binaryData && "Binary payload must roundtrip cleanly through AES-256-GCM!");

    // 4. Non-32-byte key handling (SHA-256 derivation)
    AESCipher shortKeyCipher("ShortKey");
    assert(shortKeyCipher.getKey().size() == 32 && "Key must be normalized/derived to 32 bytes!");
    std::vector<uint8_t> shortKeyCiphertext = shortKeyCipher.encrypt(plaintext);
    std::vector<uint8_t> shortKeyDecrypted = shortKeyCipher.decrypt(shortKeyCiphertext);
    assert(shortKeyDecrypted == plaintext && "Derived 32-byte key must successfully encrypt and decrypt!");

    std::cout << "  --> PASS: AES-256-GCM roundtrip and IV randomization verified.\n\n";
}

void testAESCipherAuthenticationAndTamperDetection() {
    std::cout << "[Test 11] AES-256-GCM Authentication, Wrong Key & Tamper Detection\n";

    AESCipher cipherA("MasterKeyA_123456789012345678901");
    AESCipher cipherB("DifferentKeyB_098765432109876543");

    std::string originalText = "SensitiveInformationToProtectFromTampering";
    std::vector<uint8_t> plaintext(originalText.begin(), originalText.end());
    std::vector<uint8_t> validCiphertext = cipherA.encrypt(plaintext);

    // 1. Wrong key decryption fails and throws CorruptedVaultException
    bool wrongKeyCaught = false;
    try {
        cipherB.decrypt(validCiphertext);
    } catch (const CorruptedVaultException&) {
        wrongKeyCaught = true;
    }
    assert(wrongKeyCaught && "Decryption with incorrect key must throw CorruptedVaultException!");

    // 2. Tampered ciphertext portion fails authentication
    std::vector<uint8_t> tamperedCiphertext = validCiphertext;
    tamperedCiphertext[AESCipher::OVERHEAD_SIZE] ^= 0x01; // flip 1 bit in ciphertext
    bool ciphertextTamperCaught = false;
    try {
        cipherA.decrypt(tamperedCiphertext);
    } catch (const CorruptedVaultException&) {
        ciphertextTamperCaught = true;
    }
    assert(ciphertextTamperCaught && "Flipping a bit in ciphertext must fail authentication and throw CorruptedVaultException!");

    // 3. Tampered GCM authentication tag fails authentication
    std::vector<uint8_t> tamperedTag = validCiphertext;
    tamperedTag[AESCipher::IV_SIZE + 4] ^= 0x01; // flip 1 bit in GCM tag
    bool tagTamperCaught = false;
    try {
        cipherA.decrypt(tamperedTag);
    } catch (const CorruptedVaultException&) {
        tagTamperCaught = true;
    }
    assert(tagTamperCaught && "Flipping a bit in authentication tag must fail authentication and throw CorruptedVaultException!");

    // 4. Tampered IV fails authentication
    std::vector<uint8_t> tamperedIV = validCiphertext;
    tamperedIV[0] ^= 0x01; // flip 1 bit in IV
    bool ivTamperCaught = false;
    try {
        cipherA.decrypt(tamperedIV);
    } catch (const CorruptedVaultException&) {
        ivTamperCaught = true;
    }
    assert(ivTamperCaught && "Flipping a bit in IV must fail authentication and throw CorruptedVaultException!");

    // 5. Truncated payload (< 28 bytes) throws CorruptedVaultException
    std::vector<uint8_t> truncatedPayload(validCiphertext.begin(), validCiphertext.begin() + 20);
    bool truncationCaught = false;
    try {
        cipherA.decrypt(truncatedPayload);
    } catch (const CorruptedVaultException&) {
        truncationCaught = true;
    }
    assert(truncationCaught && "Truncated payload (< 28 bytes) must throw CorruptedVaultException!");

    // 6. Integration with FileStorage
    const std::string testVaultPath = "data/test_aes_storage.bin";
    if (fs::exists(testVaultPath)) {
        fs::remove(testVaultPath);
    }

    auto aesCipher = std::make_shared<AESCipher>("FileStorageAESProductionKey");
    FileStorage storage(testVaultPath, aesCipher);

    std::vector<std::shared_ptr<Credential>> credentials = {
        std::make_shared<WebCredential>("GitHub", "alice", "super_secret_github_pass", "token", "https://github.com"),
        std::make_shared<WiFiCredential>("OfficeNet", "wpa", "office_wpa3_key", "guest", "OfficeNet", "WPA3")
    };

    bool storageSaved = storage.save(credentials);
    assert(storageSaved && "FileStorage must successfully save credentials using AESCipher!");

    // Verify plaintext password is NOT in raw file
    std::ifstream rawFile(testVaultPath, std::ios::binary);
    std::string fileBytes((std::istreambuf_iterator<char>(rawFile)), std::istreambuf_iterator<char>());
    rawFile.close();

    assert(fileBytes.find("super_secret_github_pass") == std::string::npos &&
           "Plaintext password must NOT appear in raw AES-encrypted storage file!");
    assert(fileBytes.find("office_wpa3_key") == std::string::npos &&
           "Plaintext WiFi password must NOT appear in raw AES-encrypted storage file!");

    // Load and verify credentials decrypted accurately
    auto restored = storage.loadPolymorphic();
    assert(restored.size() == 2);
    assert(restored[0]->getService() == "GitHub");
    assert(restored[0]->getPassword() == "super_secret_github_pass");
    assert(restored[1]->getService() == "OfficeNet");
    assert(restored[1]->getPassword() == "office_wpa3_key");

    fs::remove(testVaultPath);
    std::cout << "  --> PASS: Authentication, wrong key rejection, tamper detection, and FileStorage integration verified.\n\n";
}

void testMasterVaultAESAndProxyIntegration() {
    std::cout << "[Test 12] MasterVault AES-256-GCM & VaultProxy Integration\n";

    const std::string testUser = "testuser_phase3";
    const std::string testVaultPath = MasterVault::getVaultPathForUser(testUser);
    if (fs::exists(testVaultPath)) {
        fs::remove(testVaultPath);
    }

    MasterVault vault;
    std::string masterPass = "MasterPhase3Secret#2026";
    std::string credPass = "CredPhase3Secret#2026";

    // 1. Create vault
    bool created = vault.create(testUser, masterPass);
    assert(created);
    assert(MasterVault::existsForUser(testUser));

    // 2. VaultProxy should reject access when vault is locked
    bool unauthorizedCaught = false;
    try {
        vault.getProxy().getCredentials();
    } catch (const UnauthorizedAccessException&) {
        unauthorizedCaught = true;
    }
    assert(unauthorizedCaught && "Accessing credentials via VaultProxy before unlock must throw UnauthorizedAccessException!");

    // 3. Setup credential password (switches to AESCipher)
    bool setup = vault.setupCredentialPassword(credPass);
    assert(setup);
    assert(vault.isCredentialsUnlocked());

    // 4. Add polymorphic credentials
    auto webCred = std::make_shared<WebCredential>("GitHub", "alice", "gh_token_xyz999", "api token", "https://github.com");
    auto wifiCred = std::make_shared<WiFiCredential>("HomeWiFi", "", "wpa3_super_pass", "living room", "HomeNet_5G", "WPA3");
    auto sshCred = std::make_shared<SSHCredential>("ProdServer", "ubuntu", "id_ed25519_pass", "bastion", "prod.example.com", 2222);

    bool addedWeb = vault.addCredential(webCred);
    assert(addedWeb);
    bool addedWifi = vault.addCredential(wifiCred);
    assert(addedWifi);
    bool addedSsh = vault.addCredential(sshCred);
    assert(addedSsh);
    assert(vault.getCredentialCount() == 3);

    // 5. Search credentials across different polymorphic fields
    auto searchUrl = vault.search("github.com");
    assert(searchUrl.size() == 1);
    assert(searchUrl[0]->getService() == "GitHub");

    auto searchSsid = vault.search("HomeNet_5G");
    assert(searchSsid.size() == 1);
    assert(searchSsid[0]->getService() == "HomeWiFi");

    auto searchHost = vault.search("prod.example.com");
    assert(searchHost.size() == 1);
    assert(searchHost[0]->getService() == "ProdServer");

    // 6. Direct VaultProxy operations when authenticated
    auto proxyCreds = vault.getProxy().getCredentials();
    assert(proxyCreds.size() == 3);

    // 7. Verify file on disk is encrypted with AES-256-GCM and contains no plaintext
    std::ifstream raw(testVaultPath, std::ios::binary);
    std::string rawBytes((std::istreambuf_iterator<char>(raw)), std::istreambuf_iterator<char>());
    raw.close();

    assert(rawBytes.find("gh_token_xyz999") == std::string::npos && "Plaintext web password must NOT appear in AES file!");
    assert(rawBytes.find("wpa3_super_pass") == std::string::npos && "Plaintext wifi password must NOT appear in AES file!");
    assert(rawBytes.find("id_ed25519_pass") == std::string::npos && "Plaintext ssh password must NOT appear in AES file!");
    assert(rawBytes.find("https://github.com") == std::string::npos && "Plaintext URL must NOT appear in AES file!");

#if defined(__unix__) || defined(__APPLE__)
    struct stat st{};
    int statRes = ::stat(testVaultPath.c_str(), &st);
    assert(statRes == 0 && "Vault file must exist for stat check!");
    assert((st.st_mode & 0777) == 0600 && "Vault file must have strict 0600 POSIX permissions!");
#endif

    // 8. Lock vault and verify in-memory cleanup
    vault.lock();
    assert(!vault.isMasterUnlocked());
    assert(!vault.isCredentialsUnlocked());
    assert(vault.getCredentialCount() == 0);

    bool lockedProxyAccessBlocked = false;
    try {
        vault.getProxy().getCredentials();
    } catch (const UnauthorizedAccessException&) {
        lockedProxyAccessBlocked = true;
    }
    assert(lockedProxyAccessBlocked && "VaultProxy must throw UnauthorizedAccessException after lock()!");

    // 9. Reload vault from disk with new MasterVault instance
    MasterVault reloadedVault;
    int attempts = 0;
    bool reloadedMaster = reloadedVault.unlockMaster(testUser, masterPass, attempts);
    assert(reloadedMaster);
    bool reloadedCred = reloadedVault.unlockCredentials(credPass, attempts);
    assert(reloadedCred);
    assert(reloadedVault.isCredentialsUnlocked());
    assert(reloadedVault.getCredentialCount() == 3);

    // 10. Verify polymorphic downcasting and restored attributes
    auto restoredCreds = reloadedVault.getPolymorphicCredentials();
    assert(restoredCreds.size() == 3);

    auto restoredWeb = std::dynamic_pointer_cast<WebCredential>(restoredCreds[0]);
    assert(restoredWeb != nullptr);
    assert(restoredWeb->getType() == "web");
    assert(restoredWeb->getUrl() == "https://github.com");
    assert(restoredWeb->getPassword() == "gh_token_xyz999");

    auto restoredWiFi = std::dynamic_pointer_cast<WiFiCredential>(restoredCreds[1]);
    assert(restoredWiFi != nullptr);
    assert(restoredWiFi->getType() == "wifi");
    assert(restoredWiFi->getSsid() == "HomeNet_5G");
    assert(restoredWiFi->getSecurityType() == "WPA3");

    auto restoredSSH = std::dynamic_pointer_cast<SSHCredential>(restoredCreds[2]);
    assert(restoredSSH != nullptr);
    assert(restoredSSH->getType() == "ssh");
    assert(restoredSSH->getHost() == "prod.example.com");
    assert(restoredSSH->getPort() == 2222);

    // 11. Cleanup test file
    fs::remove(testVaultPath);
    std::cout << "  --> PASS: MasterVault AES-256-GCM encryption, VaultProxy access control, and polymorphic persistence verified.\n\n";
}

void testPhase2And3AuthorizationAndFlow() {
    std::cout << "[Test 13] Phase 2 & 3: Authorization Refactor, Revised Flow, and Session Security\n";

    const std::string testUser = "testuser_phase23";
    const std::string testVaultPath = MasterVault::getVaultPathForUser(testUser);
    if (fs::exists(testVaultPath)) {
        fs::remove(testVaultPath);
    }

    MasterVault vault;
    std::string masterPass = "MasterSecure#2026";
    std::string credPass = "CredSecure#2026";

    // 1. Initial State: Locked
    assert(vault.getSessionState() == MasterVault::SessionState::Locked);
    assert(!vault.isMasterUnlocked());
    assert(!vault.isCredentialsUnlocked());

    // 2. Setup vault and credential password
    bool created = vault.create(testUser, masterPass);
    assert(created);
    bool setup = vault.setupCredentialPassword(credPass);
    assert(setup);

    // Add credentials for testing
    auto webCred = std::make_shared<WebCredential>("GitHub", "alice", "gh_secret_key_123", "personal token", "https://github.com");
    auto wifiCred = std::make_shared<WiFiCredential>("OfficeWiFi", "", "wifi_wpa3_pass", "hq", "OfficeNet_Secure", "WPA3");
    assert(vault.addCredential(webCred));
    assert(vault.addCredential(wifiCred));
    assert(vault.getCredentialCount() == 2);

    // 3. Lock vault completely (simulating fresh application launch)
    vault.lock();
    assert(vault.getSessionState() == MasterVault::SessionState::Locked);
    assert(!vault.isMasterUnlocked());
    assert(!vault.isCredentialsUnlocked());

    // 4. Phase 3 Revised Login Flow:
    // User enters Master Password -> opens dashboard immediately in MasterAuthenticated state WITHOUT credential password prompt
    int masterAttempts = 0;
    bool masterOk = vault.unlockMaster(testUser, masterPass, masterAttempts);
    assert(masterOk && "Master authentication must succeed with valid master password!");
    assert(vault.isMasterUnlocked() && "Master vault must be unlocked!");
    assert(!vault.isCredentialsUnlocked() && "Credential vault must NOT be unlocked yet (2-tier isolation)!");
    assert(vault.getSessionState() == MasterVault::SessionState::MasterAuthenticated);

    // 5. Low-risk tools must work immediately in MasterAuthenticated state
    std::string generatedPass = PasswordGenerator::generate(20, true, true, true, true);
    assert(generatedPass.length() == 20 && "PasswordGenerator must work in MasterAuthenticated state!");
    PasswordStrengthResult strength = PasswordStrength::analyze(generatedPass);
    assert(strength.score >= 80);

    // 6. Credential data is protected and not leaked prior to unlock
    assert(vault.getCredentialCount() == 0 && "Credentials count must be 0 before unlock!");
    assert(vault.getCredentials().empty() && "getCredentials() must be empty before unlock!");
    assert(vault.getPolymorphicCredentials().empty() && "getPolymorphicCredentials() must be empty before unlock!");
    assert(vault.search("GitHub").empty() && "search() must return empty results before unlock!");
    assert(vault.getCredential(0) == nullptr && "getCredential() must return nullptr before unlock!");

    // Direct proxy calls must throw UnauthorizedAccessException
    bool proxyBlocked = false;
    try {
        vault.getProxy().getCredentials();
    } catch (const UnauthorizedAccessException&) {
        proxyBlocked = true;
    }
    assert(proxyBlocked && "Direct VaultProxy access must throw UnauthorizedAccessException before unlock!");

    // Direct reveal/copy attempts before unlock must throw UnauthorizedAccessException
    bool revealBlocked = false;
    try {
        vault.revealPassword(0, credPass);
    } catch (const UnauthorizedAccessException&) {
        revealBlocked = true;
    }
    assert(revealBlocked && "revealPassword before credentials unlock must throw UnauthorizedAccessException!");

    bool copyBlocked = false;
    try {
        vault.copyPassword(0, credPass);
    } catch (const UnauthorizedAccessException&) {
        copyBlocked = true;
    }
    assert(copyBlocked && "copyPassword before credentials unlock must throw UnauthorizedAccessException!");

    // 7. Credential Vault Unlock:
    // Failed credential attempts: verify 3-attempt temporary lockout
    int credAttempts = 0;
    assert(!vault.unlockCredentials("WrongCred1", credAttempts));
    assert(credAttempts == 2);
    assert(!vault.unlockCredentials("WrongCred2", credAttempts));
    assert(credAttempts == 1);
    assert(!vault.unlockCredentials("WrongCred3", credAttempts));
    assert(credAttempts == 0);

    int lockoutRemaining = 0;
    assert(vault.isCredentialsLockedOut(lockoutRemaining) && "Credential vault must be locked out after 3 failures!");
    assert(lockoutRemaining > 0 && lockoutRemaining <= 30);

    // While locked out, credential unlock is refused
    assert(!vault.unlockCredentials(credPass, credAttempts) && "Unlock must be refused during lockout!");

    // Reset lockout
    vault.resetCredentialsAttempts();
    assert(!vault.isCredentialsLockedOut(lockoutRemaining));

    // Successful credential vault unlock transitions state to CredentialsUnlocked
    bool credOk = vault.unlockCredentials(credPass, credAttempts);
    assert(credOk && "Unlock with valid credential password must succeed!");
    assert(vault.isCredentialsUnlocked());
    assert(vault.getSessionState() == MasterVault::SessionState::CredentialsUnlocked);
    assert(vault.getCredentialCount() == 2);

    // 8. Domain authorization on sensitive operations:
    // 8a. Password reveal
    bool revealWrongPassBlocked = false;
    try {
        vault.revealPassword(0, "InvalidPassword");
    } catch (const UnauthorizedAccessException&) {
        revealWrongPassBlocked = true;
    }
    assert(revealWrongPassBlocked && "revealPassword with wrong password must throw UnauthorizedAccessException!");
    std::string revealed = vault.revealPassword(0, credPass);
    assert(revealed == "gh_secret_key_123" && "revealPassword with valid password must return plaintext secret!");

    // 8b. Password copy
    bool copyWrongPassBlocked = false;
    try {
        vault.copyPassword(0, "InvalidPassword");
    } catch (const UnauthorizedAccessException&) {
        copyWrongPassBlocked = true;
    }
    assert(copyWrongPassBlocked && "copyPassword with wrong password must throw UnauthorizedAccessException!");
    std::string copied = vault.copyPassword(0, credPass);
    assert(copied == "gh_secret_key_123" && "copyPassword with valid password must return plaintext secret!");

    // 8c. Modifying stored secret requires credential password
    auto editedWeb = std::make_shared<WebCredential>("GitHub Enterprise", "alice", "new_super_secret_gh", "updated notes", "https://github.com");
    // Without password
    assert(!vault.updateCredential(0, editedWeb) && "Updating secret without password must fail!");
    // With wrong password
    assert(!vault.updateCredential(0, editedWeb, "WrongPass") && "Updating secret with wrong password must fail!");
    // With correct password
    assert(vault.updateCredential(0, editedWeb, credPass) && "Updating secret with correct credPass must succeed!");
    assert(vault.revealPassword(0, credPass) == "new_super_secret_gh");

    // 8d. Modifying non-sensitive metadata only (password unchanged) does NOT require re-authentication
    auto editedMetaOnly = std::make_shared<WebCredential>("GitHub Enterprise v2", "alice_new", "new_super_secret_gh", "notes v2", "https://github.com");
    assert(vault.updateCredential(0, editedMetaOnly) && "Updating non-secret metadata must succeed without credential password!");
    assert(vault.getCredential(0)->getService() == "GitHub Enterprise v2");
    assert(vault.getCredential(0)->getUsername() == "alice_new");

    // 8d-2. Modifying metadata with empty password field preserves existing secret without requiring re-auth
    auto editedEmptyPass = std::make_shared<WebCredential>("GitHub Enterprise v3", "alice_v3", "", "notes v3", "https://github.com");
    assert(vault.updateCredential(0, editedEmptyPass) && "Updating with empty password must succeed as metadata-only edit!");
    assert(vault.getCredential(0)->getService() == "GitHub Enterprise v3");
    assert(vault.getCredential(0)->getUsername() == "alice_v3");
    assert(vault.revealPassword(0, credPass) == "new_super_secret_gh" && "Existing secret must NOT be overwritten by empty password!");

    // 8d-3. Direct proxy updateCredential tests:
    // Proxy update with empty password preserves existing secret
    auto proxyMetaOnly = std::make_shared<WebCredential>("GitHub Enterprise v4", "alice_v4", "", "notes v4", "https://github.com");
    assert(vault.getProxy().updateCredential(0, proxyMetaOnly) && "Proxy update with empty password must succeed as metadata-only edit!");
    assert(vault.getProxy().revealPassword(0, credPass) == "new_super_secret_gh" && "Proxy update must preserve existing secret!");

    // Proxy update with new secret password without password throws UnauthorizedAccessException
    auto proxyNewPass = std::make_shared<WebCredential>("GitHub Enterprise v4", "alice_v4", "infiltrated_secret", "notes v4", "https://github.com");
    bool proxyNoPassBlocked = false;
    try {
        vault.getProxy().updateCredential(0, proxyNewPass);
    } catch (const UnauthorizedAccessException&) {
        proxyNoPassBlocked = true;
    }
    assert(proxyNoPassBlocked && "Proxy updateCredential changing secret without password must throw UnauthorizedAccessException!");

    // Proxy update with new secret password and wrong password throws UnauthorizedAccessException
    bool proxyWrongPassBlocked = false;
    try {
        vault.getProxy().updateCredential(0, proxyNewPass, "WrongPassword");
    } catch (const UnauthorizedAccessException&) {
        proxyWrongPassBlocked = true;
    }
    assert(proxyWrongPassBlocked && "Proxy updateCredential changing secret with wrong password must throw UnauthorizedAccessException!");
    assert(vault.getProxy().revealPassword(0, credPass) == "new_super_secret_gh" && "Secret must be preserved after rejected proxy update!");

    // 8e. Deleting credential requires credential password verification and explicit confirmation
    assert(!vault.deleteCredential(0) && "Direct deleteCredential without password must fail!");
    assert(!vault.deleteCredential(0, "WrongPass") && "deleteCredential with wrong password must fail!");
    assert(!vault.deleteCredential(0, credPass, false) && "deleteCredential without explicit confirmation must fail!");
    assert(vault.getCredentialCount() == 2); // Cancellation preserved, no deletion occurred

    // Direct proxy deletion access control checks
    bool proxyDeleteUnconfirmedBlocked = false;
    try {
        vault.getProxy().deleteCredential(0, credPass, false);
    } catch (const UnauthorizedAccessException&) {
        proxyDeleteUnconfirmedBlocked = true;
    }
    assert(proxyDeleteUnconfirmedBlocked && "Proxy deleteCredential without confirmation must throw UnauthorizedAccessException!");

    bool proxyDeleteWrongPassBlocked = false;
    try {
        vault.getProxy().deleteCredential(0, "WrongPass", true);
    } catch (const UnauthorizedAccessException&) {
        proxyDeleteWrongPassBlocked = true;
    }
    assert(proxyDeleteWrongPassBlocked && "Proxy deleteCredential with wrong password must throw UnauthorizedAccessException!");

    bool proxyDeleteNoPassBlocked = false;
    try {
        vault.getProxy().deleteCredential(0);
    } catch (const UnauthorizedAccessException&) {
        proxyDeleteNoPassBlocked = true;
    }
    assert(proxyDeleteNoPassBlocked && "Proxy deleteCredential without password must throw UnauthorizedAccessException!");

    assert(vault.deleteCredential(0, credPass, true) && "deleteCredential with valid credPass must succeed!");
    assert(vault.getCredentialCount() == 1);

    // 9. Inactivity timeout testing
    vault.setInactivityTimeout(300);
    assert(vault.getInactivityTimeout() == 300);
    // Directly simulate timeout check with 1-second threshold
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    bool timedOut = vault.checkInactivityTimeout(1);
    assert(timedOut && "Session should time out after simulated inactivity!");
    assert(!vault.isCredentialsUnlocked() && "Credentials access must be revoked after timeout!");
    assert(vault.getSessionState() == MasterVault::SessionState::MasterAuthenticated);
    assert(vault.getCredentialCount() == 0 && "In-memory credential cache must be purged on timeout!");

    // Re-unlocking after inactivity timeout
    assert(vault.unlockCredentials(credPass, credAttempts));
    assert(vault.getSessionState() == MasterVault::SessionState::CredentialsUnlocked);
    assert(vault.getCredentialCount() == 1);

    // 10. Explicit Lock and Logout
    vault.lock();
    assert(vault.getSessionState() == MasterVault::SessionState::Locked);
    assert(!vault.isMasterUnlocked());
    assert(!vault.isCredentialsUnlocked());
    assert(vault.getCredentialCount() == 0);

    // Cleanup
    fs::remove(testVaultPath);
    std::cout << "  --> PASS: Phase 2 & 3 authorization refactor, session states, and security policies verified.\n\n";
}

void testClipboardAndGeneratorWorkflow() {
    std::cout << "[Test 14] Password Generator, Copy Action & Clipboard Utilities\n";

    // 1. TerminalUtils::copyToClipboard empty string check
    assert(!TerminalUtils::copyToClipboard("") && "Copying empty string must fail and return false!");

    // 2. Simulated clipboard hook success
    std::string captured;
    TerminalUtils::setClipboardHookForTesting([&](const std::string& text) {
        captured = text;
        return true;
    });

    std::string testSecret = "SuperGeneratedPass#2026";
    bool copyOk = TerminalUtils::copyToClipboard(testSecret);
    assert(copyOk && "copyToClipboard must succeed when clipboard transport succeeds!");
    assert(captured == testSecret && "Captured clipboard text must match input secret!");

    // 3. Simulated clipboard failure handling (must not report success on failure)
    TerminalUtils::setClipboardHookForTesting([](const std::string&) {
        return false; // simulate failure
    });
    bool copyFailed = TerminalUtils::copyToClipboard(testSecret);
    assert(!copyFailed && "copyToClipboard must return false when transport fails!");

    // Reset hook
    TerminalUtils::setClipboardHookForTesting(nullptr);

    // 4. Actual Clipboard Integration Test (distinguishing live integration from simulated unit test)
    std::string livePayload = "VaultSync_Live_Clipboard_Pass#998877";
    bool actualCopySuccess = TerminalUtils::copyToClipboard(livePayload);
    if (actualCopySuccess) {
        // Verify roundtrip readback from the actual system clipboard
        std::string actualReadBack = TerminalUtils::getClipboardText();
        assert(actualReadBack == livePayload && "Actual system clipboard readback must match payload exactly!");
        std::cout << "  --> Verified LIVE system clipboard roundtrip via native desktop utility.\n";
    } else {
        std::cout << "  --> Notice: Headless environment without native clipboard utility correctly returned false.\n";
    }

    // 5. Password Generator works independently without unlocking Credential Vault
    MasterVault lockedVault;
    assert(!lockedVault.isCredentialsUnlocked());

    PasswordOptions opts;
    opts.length = 24;
    opts.uppercase = true;
    opts.lowercase = true;
    opts.digits = true;
    opts.symbols = true;

    std::string gen1 = PasswordGenerator::generate(opts);
    assert(gen1.length() == 24);
    assert(gen1.find_first_of("0123456789") != std::string::npos);
    assert(gen1.find_first_of("!@#$%^&*()-_=+[]{}|;:,.<>?") != std::string::npos);

    // 6. Generated password can be copied without credential vault unlock
    TerminalUtils::setClipboardHookForTesting([&](const std::string& text) {
        captured = text;
        return true;
    });
    bool genCopyOk = TerminalUtils::copyToClipboard(gen1);
    assert(genCopyOk && "Generated password must be copyable without credential unlock!");
    assert(captured == gen1);
    TerminalUtils::setClipboardHookForTesting(nullptr);

    // 7. Password generator length bounds
    PasswordOptions shortOpts;
    shortOpts.length = 8;
    std::string shortGen = PasswordGenerator::generate(shortOpts);
    assert(shortGen.length() == 8);

    PasswordOptions longOpts;
    longOpts.length = 128;
    std::string longGen = PasswordGenerator::generate(longOpts);
    assert(longGen.length() == 128);

    std::cout << "  --> PASS: Password generator, clipboard integration, and error handling verified.\n\n";
}

void testOffsiteBackupConfigAndSubprocess() {
    std::cout << "[Test 15] Off-Site Backup Configuration & OpenSSH SFTP Subprocess Client\n";

    // 1. Verify BackupConfig defaults
    BackupConfig defaultConfig;
    assert(!defaultConfig.isValid() && "Default config with empty host must be invalid!");
    assert(defaultConfig.port == 22 && "Default port must be 22!");
    assert(defaultConfig.remoteDir == "backups/vaultsync" && "Default remoteDir must be 'backups/vaultsync'!");
    assert(defaultConfig.connectTimeout == 5 && "Default timeout must be 5s!");
    assert(defaultConfig.authMethod == BackupConfig::AuthMethod::Key && "Default authMethod must be Key!");
    assert(defaultConfig.getAuthMethodString() == "key" && "Default authMethod string must be 'key'!");

    // 2. Verify Config save and load with strict 0600 POSIX permissions
    const std::string testConfPath = "data/test_backup.conf";
    if (fs::exists(testConfPath)) {
        fs::remove(testConfPath);
    }

    BackupConfig configToSave;
    configToSave.host = "backup-box.tailnet-xyz.ts.net";
    configToSave.port = 2222;
    configToSave.user = "tailscale_user";
    configToSave.remoteDir = "remote/vault_backups";
    configToSave.identityFile = "~/.ssh/test_id_ed25519";
    configToSave.authMethod = BackupConfig::AuthMethod::Key;
    configToSave.connectTimeout = 3;

    assert(configToSave.isValid() && "Populated config must be valid!");
    assert(configToSave.saveToFile(testConfPath) && "Config saveToFile must return true!");
    assert(fs::exists(testConfPath) && "Config file must exist on disk!");

#if defined(__unix__) || defined(__APPLE__)
    struct stat confSt{};
    int confStatRes = ::stat(testConfPath.c_str(), &confSt);
    assert(confStatRes == 0 && "Stat must succeed on test config file!");
    assert((confSt.st_mode & 0777) == 0600 && "backup.conf must have strict 0600 POSIX permissions!");
#endif

    BackupConfig loadedConfig = BackupConfig::loadFromFile(testConfPath);
    assert(loadedConfig.isValid());
    assert(loadedConfig.host == "backup-box.tailnet-xyz.ts.net");
    assert(loadedConfig.port == 2222);
    assert(loadedConfig.user == "tailscale_user");
    assert(loadedConfig.remoteDir == "remote/vault_backups");
    assert(loadedConfig.identityFile == "~/.ssh/test_id_ed25519");
    assert(loadedConfig.authMethod == BackupConfig::AuthMethod::Key);
    assert(loadedConfig.getAuthMethodString() == "key");
    assert(loadedConfig.connectTimeout == 3);

    // Verify path expansion for home directory
    std::string expanded = BackupConfig::expandPath("~/.ssh/test_id_ed25519");
    assert(expanded.find('~') == std::string::npos && "expandPath must replace leading tilde with home directory!");

    fs::remove(testConfPath);

    // 2b. Verify Password-based Auth Config save & load roundtrip
    BackupConfig pwConfigToSave;
    pwConfigToSave.host = "remote-sftp.box";
    pwConfigToSave.port = 2022;
    pwConfigToSave.user = "backup_admin";
    pwConfigToSave.remoteDir = "vault_sync_backups";
    pwConfigToSave.authMethod = BackupConfig::AuthMethod::Password;
    pwConfigToSave.password = "SuperSecretSFTPPass!2026";
    pwConfigToSave.connectTimeout = 4;

    assert(pwConfigToSave.isValid());
    assert(pwConfigToSave.saveToFile(testConfPath));

    BackupConfig loadedPwConfig = BackupConfig::loadFromFile(testConfPath);
    assert(loadedPwConfig.isValid());
    assert(loadedPwConfig.host == "remote-sftp.box");
    assert(loadedPwConfig.port == 2022);
    assert(loadedPwConfig.user == "backup_admin");
    assert(loadedPwConfig.authMethod == BackupConfig::AuthMethod::Password);
    assert(loadedPwConfig.getAuthMethodString() == "password");
    assert(loadedPwConfig.password == "SuperSecretSFTPPass!2026");
    assert(loadedPwConfig.connectTimeout == 4);

    fs::remove(testConfPath);

    // 3. Verify SFTP Batch Script formatting & atomic operations
    std::string batch = SftpSubprocessClient::generateBatchScript("/local/path/vault_alice.bin", "backups/vault", "vault_alice", "20261024_120000");
    assert(batch.find("-mkdir \"backups/vault\"") != std::string::npos && "Batch must contain -mkdir!");
    assert(batch.find("cd \"backups/vault\"") != std::string::npos && "Batch must contain cd to remote directory!");
    assert(batch.find("put \"/local/path/vault_alice.bin\" \"vault_alice.bin.tmp\"") != std::string::npos && "Batch must upload to .tmp atomic staging file!");
    assert(batch.find("rename \"vault_alice.bin.tmp\" \"vault_alice_20261024_120000.bin\"") != std::string::npos && "Batch must atomically rename .tmp to timestamped .bin!");
    assert(batch.find("-symlink \"vault_alice_20261024_120000.bin\" \"vault_alice_latest.bin\"") != std::string::npos && "Batch must update latest symlink!");
    assert(batch.find("quit") != std::string::npos && "Batch must conclude with quit!");

    // 4. Verify parameter validation in executeBackup
    BackupConfig invalidConfig;
    auto resInvalid = SftpSubprocessClient::executeBackup("/non/existent/file.bin", invalidConfig);
    assert(!resInvalid.success && "executeBackup on nonexistent file must fail!");

    const std::string dummyVaultFile = "data/test_dummy_vault.bin";
    std::ofstream dummyOut(dummyVaultFile, std::ios::binary);
    dummyOut << "TEST_VAULT_PAYLOAD_CIPHERTEXT";
    dummyOut.close();

    BackupConfig emptyPwConfig;
    emptyPwConfig.host = "backup.server.internal";
    emptyPwConfig.authMethod = BackupConfig::AuthMethod::Password;
    emptyPwConfig.password = "";
    auto resEmptyPw = SftpSubprocessClient::executeBackup(dummyVaultFile, emptyPwConfig);
    assert(!resEmptyPw.success && "executeBackup with password auth but empty password must fail!");
    assert(resEmptyPw.message.find("password is required") != std::string::npos);

    // 5. Verify MasterVault integration checks
    MasterVault vault;
    auto lockedBkp = vault.performOffsiteBackup(configToSave);
    assert(!lockedBkp.success && "performOffsiteBackup on locked MasterVault must fail!");
    assert(lockedBkp.message.find("locked") != std::string::npos && "Error message must state Master Vault is locked!");

    // 6. Verify subprocess execution against closed port on localhost (terminates cleanly without hang)
    BackupConfig unreachableConfig;
    unreachableConfig.host = "127.0.0.1";
    unreachableConfig.port = 65534; // Closed port
    unreachableConfig.connectTimeout = 1;

    auto resUnreachable = SftpSubprocessClient::executeBackup(dummyVaultFile, unreachableConfig);
    assert(!resUnreachable.success && "Subprocess connection to closed port must report failure!");
    assert(resUnreachable.exitCode != 0 && "Exit code must be non-zero!");

    fs::remove(dummyVaultFile);

    std::cout << "  --> PASS: BackupConfig persistence (0600), batch generation, and SFTP subprocess execution verified.\n\n";
}

int main() {
    std::cout << "=====================================================\n";
    std::cout << "  VaultSync: Cryptographic Tests (XOR & AES-256-GCM)  \n";
    std::cout << "=====================================================\n\n";

    testBasicXORRoundtrip();
    testBinaryDataRoundtrip();
    testFileStorageEncryptionIntegration();
    testCryptoUtils();
    testMasterVaultDualAuth();
    testMasterVaultEditCredential();
    testMasterVaultDeleteCredential();
    testMasterVaultLoginAttemptsAndLockout();
    testArchitectureComponents();
    testAESCipherRoundtripAndRandomization();
    testAESCipherAuthenticationAndTamperDetection();
    testMasterVaultAESAndProxyIntegration();
    testPhase2And3AuthorizationAndFlow();
    testClipboardAndGeneratorWorkflow();
    testOffsiteBackupConfigAndSubprocess();

    std::cout << "All cipher and vault tests passed successfully!\n";
    return 0;
}

