#include "auth/MasterVault.h"
#include "crypto/AESCipher.h"
#include "crypto/CryptoUtils.h"
#include "security/VaultExceptions.h"

#include <chrono>
#include <filesystem>
#include <unordered_map>

namespace fs = std::filesystem;

namespace {

/**
 * @brief Thread-safe or session-wide record tracking failed master login attempts and lockout timers.
 */
struct LockoutRecord {
    int failedAttempts = 0;
    std::chrono::steady_clock::time_point lockoutEnd{};
};

// Global map tracking temporary lockouts across different usernames
std::unordered_map<std::string, LockoutRecord> g_userLockouts;

} // anonymous namespace

MasterVault::MasterVault(const std::string& path)
    : vaultPath(path),
      masterUnlocked(false),
      masterFailedAttempts(0),
      masterLockedOut(false),
      credUnlocked(false),
      credFailedAttempts(0),
      credLockedOut(false),
      cipher(nullptr),
      storage(nullptr),
      vault(std::make_unique<Vault>()),
      proxy(std::make_unique<VaultProxy>(*vault, false))
{
    // If a custom path was provided upon construction, initialize file storage
    if (!path.empty()) {
        storage = std::make_unique<FileStorage>(path, nullptr);
    }
}

MasterVault::~MasterVault() {
    // Secure cleanup: wipe decrypted credentials and cipher keys from memory when destroyed
    lock();
}

std::string MasterVault::getVaultPathForUser(const std::string& username) {
    return "data/vault_" + username + ".bin";
}

bool MasterVault::existsForUser(const std::string& username) {
    std::string path = getVaultPathForUser(username);
    return exists(path);
}

bool MasterVault::exists(const std::string& path) {
    if (fs::exists(path)) {
        return true;
    }
    // Also check parent directory in case binary runs from build/ directory
    if (fs::exists("../" + path)) {
        return true;
    }
    return false;
}

bool MasterVault::create(const std::string& user, const std::string& masterPassword) {
    // Step 1: Validate inputs
    if (user.empty() || masterPassword.empty()) {
        return false;
    }

    // Step 2: Prevent duplicate creation if a vault already exists for this username
    if (existsForUser(user)) {
        return false;
    }

    username = user;
    vaultPath = getVaultPathForUser(username);

    // Step 3: Generate a random 16-byte salt and hash the master password with SHA-256
    masterSalt = CryptoUtils::generateSalt(16);
    masterPasswordHash = CryptoUtils::hashPassword(masterPassword, masterSalt);

    // Step 4: Credential vault password is NOT set at creation time (delayed setup)
    credSalt.clear();
    credPasswordHash.clear();

    // Step 5: Clear any existing in-memory credentials
    vault->clear();
    syncLegacyCache();

    // Step 6: Initialize file storage and write vault metadata (credentials start empty)
    storage = std::make_unique<FileStorage>(vaultPath, nullptr);
    storage->setUsername(username);
    storage->setMasterSalt(masterSalt);
    storage->setMasterPasswordHash(masterPasswordHash);
    storage->setCredSalt("");
    storage->setCredPasswordHash("");

    // Persist empty vault header (version 5 format)
    bool saved = storage->save(vault->getCredentials());
    if (saved) {
        masterUnlocked = true;
        masterFailedAttempts = 0;
        masterLockedOut = false;
        credUnlocked = false;
        credFailedAttempts = 0;
        credLockedOut = false;
        proxy->setAuthenticated(false);
    }
    return saved;
}

bool MasterVault::unlockMaster(const std::string& user, const std::string& masterPassword, int& attemptsRemaining) {
    // Step 1: Validate input parameters
    if (user.empty() || masterPassword.empty()) {
        attemptsRemaining = 0;
        return false;
    }

    // Step 2: Check if this user is currently locked out from too many failed attempts
    int remainingSeconds = 0;
    if (isMasterLockedOut(user, remainingSeconds)) {
        attemptsRemaining = 0;
        return false;
    }

    // Step 3: Ensure vault file exists
    if (!existsForUser(user)) {
        attemptsRemaining = 0;
        return false;
    }

    // Step 4: Read file header from disk
    username = user;
    vaultPath = getVaultPathForUser(username);
    storage = std::make_unique<FileStorage>(vaultPath, nullptr);

    std::string storedUser, salt1, hash1, salt2, hash2;
    uint32_t version = 0;
    if (!storage->readHeader(storedUser, salt1, hash1, salt2, hash2, version)) {
        attemptsRemaining = 0;
        return false;
    }

    masterSalt = salt1;
    masterPasswordHash = hash1;
    credSalt = salt2;
    credPasswordHash = hash2;

    // Step 5: Verify master password against the stored salted hash
    if (CryptoUtils::verifyPassword(masterPassword, masterSalt, masterPasswordHash)) {
        masterUnlocked = true;
        masterFailedAttempts = 0;
        masterLockedOut = false;
        credUnlocked = false;
        credFailedAttempts = 0;
        credLockedOut = false;
        attemptsRemaining = 3;

        // Reset lockout tracking on successful login
        g_userLockouts[user].failedAttempts = 0;
        g_userLockouts[user].lockoutEnd = std::chrono::steady_clock::time_point{};
        return true;
    }

    // Step 6: On failed login, increment attempt counter and apply temporary lockout if >= 3
    auto& record = g_userLockouts[user];
    record.failedAttempts++;
    masterFailedAttempts = record.failedAttempts;

    if (record.failedAttempts >= 3) {
        record.lockoutEnd = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        masterLockedOut = true;
        attemptsRemaining = 0;
    } else {
        attemptsRemaining = 3 - record.failedAttempts;
    }
    return false;
}

bool MasterVault::isMasterLockedOut(const std::string& username, int& remainingSeconds) {
    auto it = g_userLockouts.find(username);
    if (it == g_userLockouts.end()) {
        remainingSeconds = 0;
        return false;
    }

    auto now = std::chrono::steady_clock::now();
    if (it->second.lockoutEnd > now) {
        auto diffMs = std::chrono::duration_cast<std::chrono::milliseconds>(it->second.lockoutEnd - now).count();
        remainingSeconds = static_cast<int>((diffMs + 999) / 1000);
        if (remainingSeconds <= 0) {
            remainingSeconds = 1;
        }
        return true;
    }

    // Lockout has expired: reset counter
    if (it->second.failedAttempts >= 3) {
        it->second.failedAttempts = 0;
        it->second.lockoutEnd = std::chrono::steady_clock::time_point{};
    }
    remainingSeconds = 0;
    return false;
}

void MasterVault::resetMasterLockout(const std::string& username) {
    auto it = g_userLockouts.find(username);
    if (it != g_userLockouts.end()) {
        it->second.failedAttempts = 0;
        it->second.lockoutEnd = std::chrono::steady_clock::time_point{};
    }
}

bool MasterVault::isMasterUnlocked() const {
    return masterUnlocked;
}

bool MasterVault::hasCredentialPassword() const {
    return !credPasswordHash.empty();
}

bool MasterVault::setupCredentialPassword(const std::string& credPassword) {
    // Step 1: Ensure user is logged into the Master Vault
    if (!masterUnlocked || credPassword.empty()) {
        return false;
    }

    // Step 2: Enforce security rule: Credential Vault password cannot match Master Vault password
    if (CryptoUtils::verifyPassword(credPassword, masterSalt, masterPasswordHash)) {
        return false;
    }

    // Step 3: Generate a unique 16-byte salt and hash the credential password
    credSalt = CryptoUtils::generateSalt(16);
    credPasswordHash = CryptoUtils::hashPassword(credPassword, credSalt);

    // Step 4: Derive a 256-bit encryption key and initialize the AES-256-GCM cipher
    std::string encryptionKey = CryptoUtils::deriveKey(credPassword, credSalt);
    cipher = std::make_shared<AESCipher>(encryptionKey);

    // Step 5: Configure storage with the AES cipher and header credentials
    storage->setCipher(cipher);
    storage->setUsername(username);
    storage->setMasterSalt(masterSalt);
    storage->setMasterPasswordHash(masterPasswordHash);
    storage->setCredSalt(credSalt);
    storage->setCredPasswordHash(credPasswordHash);

    // Step 6: Unlock the inner vault and authorize VaultProxy for access
    vault->unlock();
    proxy->setAuthenticated(true);
    credUnlocked = true;
    credFailedAttempts = 0;
    credLockedOut = false;

    // Step 7: Persist encrypted initial vault file to disk
    return saveToDisk();
}

bool MasterVault::unlockCredentials(const std::string& credPassword, int& attemptsRemaining) {
    // Step 1: Verify prerequisites
    if (!masterUnlocked || credLockedOut || credPassword.empty() || credPasswordHash.empty()) {
        attemptsRemaining = 0;
        return false;
    }

    // Step 2: Verify password against the stored salted hash
    if (CryptoUtils::verifyPassword(credPassword, credSalt, credPasswordHash)) {
        credUnlocked = true;
        credFailedAttempts = 0;
        credLockedOut = false;
        attemptsRemaining = 3;

        // Step 3: Derive 256-bit encryption key and initialize AES-256-GCM cipher
        std::string encryptionKey = CryptoUtils::deriveKey(credPassword, credSalt);
        cipher = std::make_shared<AESCipher>(encryptionKey);

        storage->setCipher(cipher);
        storage->setUsername(username);
        storage->setMasterSalt(masterSalt);
        storage->setMasterPasswordHash(masterPasswordHash);
        storage->setCredSalt(credSalt);
        storage->setCredPasswordHash(credPasswordHash);

        // Step 4: Unlock inner vault and authorize VaultProxy
        vault->unlock();
        proxy->setAuthenticated(true);

        // Step 5: Decrypt and load credentials from disk into the repository
        try {
            vault->clear();
            auto loaded = storage->loadPolymorphic();
            for (const auto& item : loaded) {
                vault->addCredential(item);
            }
            syncLegacyCache();
        } catch (const VaultException&) {
            // Decryption failure, tamper detection, or corrupt payload
            lock();
            attemptsRemaining = 0;
            return false;
        }

        return true;
    }

    // Step 6: Handle failed credential vault login attempt
    credFailedAttempts++;
    attemptsRemaining = 3 - credFailedAttempts;
    if (attemptsRemaining <= 0) {
        credLockedOut = true;
        attemptsRemaining = 0;
    }
    return false;
}

bool MasterVault::isCredentialsUnlocked() const {
    return credUnlocked;
}

void MasterVault::resetCredentialsAttempts() {
    credFailedAttempts = 0;
    credLockedOut = false;
}

void MasterVault::lock() {
    // Step 1: Revoke VaultProxy authorization and lock inner vault
    if (proxy) {
        proxy->lock();
    }
    if (vault) {
        vault->clear();
        vault->lock();
    }

    // Step 2: Clear in-memory caches and session flags
    masterUnlocked = false;
    credUnlocked = false;
    credFailedAttempts = 0;
    credLockedOut = false;
    cachedCredentials.clear();

    // Step 3: Zero out and purge AES cipher from memory
    cipher.reset();
    if (storage) {
        storage->setCipher(nullptr);
    }

    // Step 4: Clear user identity and cached salts/hashes from RAM
    username.clear();
    vaultPath.clear();
    masterSalt.clear();
    masterPasswordHash.clear();
    credSalt.clear();
    credPasswordHash.clear();
}

bool MasterVault::addCredential(std::shared_ptr<Credential> credential) {
    if (!masterUnlocked || !credUnlocked || !credential) {
        return false;
    }

    // Route through VaultProxy (enforcing authorization check)
    try {
        proxy->addCredential(std::move(credential));
        syncLegacyCache();
        return saveToDisk();
    } catch (const UnauthorizedAccessException&) {
        return false;
    }
}

bool MasterVault::addCredential(const Credential& credential) {
    // Wrap value-type Credential in shared_ptr and forward to polymorphic method
    return addCredential(std::make_shared<Credential>(credential));
}

bool MasterVault::updateCredential(size_t index, std::shared_ptr<Credential> updated) {
    if (!masterUnlocked || !credUnlocked || !updated) {
        return false;
    }

    // Route through VaultProxy (enforcing authorization check)
    try {
        if (!proxy->updateCredential(index, std::move(updated))) {
            return false;
        }
        syncLegacyCache();
        return saveToDisk();
    } catch (const UnauthorizedAccessException&) {
        return false;
    }
}

bool MasterVault::updateCredential(size_t index, const Credential& updated) {
    return updateCredential(index, std::make_shared<Credential>(updated));
}

bool MasterVault::deleteCredential(size_t index) {
    if (!masterUnlocked || !credUnlocked) {
        return false;
    }

    // Route through VaultProxy (enforcing authorization check)
    try {
        if (!proxy->deleteCredential(index)) {
            return false;
        }
        syncLegacyCache();
        return saveToDisk();
    } catch (const UnauthorizedAccessException&) {
        return false;
    }
}

std::shared_ptr<Credential> MasterVault::getCredential(size_t index) const {
    if (!masterUnlocked || !credUnlocked) {
        return nullptr;
    }
    try {
        auto all = proxy->getCredentials();
        if (index >= all.size()) {
            return nullptr;
        }
        return all[index];
    } catch (const UnauthorizedAccessException&) {
        return nullptr;
    }
}

std::vector<std::shared_ptr<Credential>> MasterVault::getPolymorphicCredentials() const {
    if (!masterUnlocked || !credUnlocked) {
        return {};
    }
    try {
        return proxy->getCredentials();
    } catch (const UnauthorizedAccessException&) {
        return {};
    }
}

std::vector<std::shared_ptr<Credential>> MasterVault::search(const std::string& query) const {
    if (!masterUnlocked || !credUnlocked) {
        return {};
    }
    try {
        return proxy->search(query);
    } catch (const UnauthorizedAccessException&) {
        return {};
    }
}

const std::vector<Credential>& MasterVault::getCredentials() const {
    syncLegacyCache();
    return cachedCredentials;
}

size_t MasterVault::getCredentialCount() const {
    if (!masterUnlocked || !credUnlocked) {
        return 0;
    }
    try {
        return proxy->getCredentials().size();
    } catch (const UnauthorizedAccessException&) {
        return 0;
    }
}

bool MasterVault::verifyCredentialPassword(const std::string& credPassword) const {
    if (credPassword.empty() || credPasswordHash.empty() || credSalt.empty()) {
        return false;
    }
    // Security check: Master password must NEVER authorize credential vault operations
    if (CryptoUtils::verifyPassword(credPassword, masterSalt, masterPasswordHash)) {
        return false;
    }
    return CryptoUtils::verifyPassword(credPassword, credSalt, credPasswordHash);
}

VaultProxy& MasterVault::getProxy() {
    return *proxy;
}

const VaultProxy& MasterVault::getProxy() const {
    return *proxy;
}

bool MasterVault::save() {
    return saveToDisk();
}

const std::string& MasterVault::getUsername() const {
    return username;
}

void MasterVault::syncLegacyCache() const {
    cachedCredentials.clear();
    if (!masterUnlocked || !credUnlocked || !proxy) {
        return;
    }
    try {
        auto items = proxy->getCredentials();
        cachedCredentials.reserve(items.size());
        for (const auto& item : items) {
            if (item) {
                cachedCredentials.push_back(*item);
            }
        }
    } catch (const UnauthorizedAccessException&) {
        cachedCredentials.clear();
    }
}

bool MasterVault::saveToDisk() {
    if (!storage || !cipher || !proxy) {
        return false;
    }
    storage->setUsername(username);
    storage->setMasterSalt(masterSalt);
    storage->setMasterPasswordHash(masterPasswordHash);
    storage->setCredSalt(credSalt);
    storage->setCredPasswordHash(credPasswordHash);
    storage->setCipher(cipher);

    try {
        auto items = proxy->getCredentials();
        return storage->save(items);
    } catch (const UnauthorizedAccessException&) {
        return false;
    }
}
