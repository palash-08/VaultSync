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
    bool editOk = vault.updateCredential(0, updated);
    assert(editOk && "MasterVault::updateCredential failed!");

    // 3. Verify in-memory update
    const auto& creds = vault.getCredentials();
    assert(creds[0].getService() == "GitHub Enterprise");
    assert(creds[0].getUsername() == "newuser");
    assert(creds[0].getPassword() == "newpass456");
    assert(creds[0].getNotes() == "new notes");

    // 4. Out-of-bounds update returns false
    bool oobUpdate = vault.updateCredential(5, updated);
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
    bool deleteOk = vault.deleteCredential(0);
    assert(deleteOk && "MasterVault::deleteCredential failed!");
    assert(vault.getCredentialCount() == 1);
    assert(vault.getCredentials()[0].getService() == "AWS");

    // 4. Out-of-bounds delete returns false
    bool oobDelete = vault.deleteCredential(5);
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
    bool deletedRem = reloadedVault.deleteCredential(0);
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

    std::cout << "All cipher and vault tests passed successfully!\n";
    return 0;
}

