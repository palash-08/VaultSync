#include "MasterVault.h"
#include "CryptoUtils.h"
#include "XORCipher.h"
#include <filesystem>
#include <chrono>
#include <unordered_map>

namespace fs = std::filesystem;

namespace {

struct LockoutRecord {
    int failedAttempts = 0;
    std::chrono::steady_clock::time_point lockoutEnd{};
};

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
      storage(nullptr)
{
    if (!path.empty()) {
        storage = std::make_unique<FileStorage>(path, nullptr);
    }
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
    if (fs::exists("../" + path)) {
        return true;
    }
    return false;
}

bool MasterVault::create(const std::string& user, const std::string& masterPassword) {
    if (user.empty() || masterPassword.empty()) {
        return false;
    }

    if (existsForUser(user)) {
        return false; // Prevent duplicate creation
    }

    username = user;
    vaultPath = getVaultPathForUser(username);

    // Generate salt and compute salted master password hash
    masterSalt = CryptoUtils::generateSalt(16);
    masterPasswordHash = CryptoUtils::hashPassword(masterPassword, masterSalt);

    // Credential vault password is NOT configured at creation time
    credSalt.clear();
    credPasswordHash.clear();
    credentials.clear();

    storage = std::make_unique<FileStorage>(vaultPath, nullptr);
    storage->setUsername(username);
    storage->setMasterSalt(masterSalt);
    storage->setMasterPasswordHash(masterPasswordHash);
    storage->setCredSalt("");
    storage->setCredPasswordHash("");

    bool saved = storage->save(credentials);
    if (saved) {
        masterUnlocked = true;
        masterFailedAttempts = 0;
        masterLockedOut = false;
        credUnlocked = false;
        credFailedAttempts = 0;
        credLockedOut = false;
    }
    return saved;
}

bool MasterVault::unlockMaster(const std::string& user, const std::string& masterPassword, int& attemptsRemaining) {
    if (user.empty() || masterPassword.empty()) {
        attemptsRemaining = 0;
        return false;
    }

    int remainingSeconds = 0;
    if (isMasterLockedOut(user, remainingSeconds)) {
        attemptsRemaining = 0;
        return false;
    }

    if (!existsForUser(user)) {
        attemptsRemaining = 0;
        return false;
    }

    username = user;
    vaultPath = getVaultPathForUser(username);
    storage = std::make_unique<FileStorage>(vaultPath, nullptr);

    std::string u, s1, h1, s2, h2;
    uint32_t version = 0;
    if (!storage->readHeader(u, s1, h1, s2, h2, version)) {
        attemptsRemaining = 0;
        return false;
    }

    masterSalt = s1;
    masterPasswordHash = h1;
    credSalt = s2;
    credPasswordHash = h2;

    if (CryptoUtils::verifyPassword(masterPassword, masterSalt, masterPasswordHash)) {
        masterUnlocked = true;
        masterFailedAttempts = 0;
        masterLockedOut = false;
        credUnlocked = false;
        credFailedAttempts = 0;
        credLockedOut = false;
        attemptsRemaining = 3;

        // Reset user failed attempts & lockout state on successful login
        g_userLockouts[user].failedAttempts = 0;
        g_userLockouts[user].lockoutEnd = std::chrono::steady_clock::time_point{};
        return true;
    }

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

    // Lockout expired: reset failed attempts counter
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
    if (!masterUnlocked || credPassword.empty()) {
        return false;
    }

    // Verify Credential Vault password differs from Master Vault password
    if (CryptoUtils::verifyPassword(credPassword, masterSalt, masterPasswordHash)) {
        return false;
    }

    credSalt = CryptoUtils::generateSalt(16);
    credPasswordHash = CryptoUtils::hashPassword(credPassword, credSalt);

    // Derive encryption key solely from credential password
    std::string encryptionKey = CryptoUtils::deriveKey(credPassword, credSalt);
    cipher = std::make_shared<XORCipher>(encryptionKey);

    storage->setCipher(cipher);
    storage->setUsername(username);
    storage->setMasterSalt(masterSalt);
    storage->setMasterPasswordHash(masterPasswordHash);
    storage->setCredSalt(credSalt);
    storage->setCredPasswordHash(credPasswordHash);

    credUnlocked = true;
    credFailedAttempts = 0;
    credLockedOut = false;

    return storage->save(credentials);
}

bool MasterVault::unlockCredentials(const std::string& credPassword, int& attemptsRemaining) {
    if (!masterUnlocked || credLockedOut || credPassword.empty()) {
        attemptsRemaining = 0;
        return false;
    }

    if (credPasswordHash.empty()) {
        attemptsRemaining = 0;
        return false;
    }

    if (CryptoUtils::verifyPassword(credPassword, credSalt, credPasswordHash)) {
        credUnlocked = true;
        credFailedAttempts = 0;
        credLockedOut = false;
        attemptsRemaining = 3;

        std::string encryptionKey = CryptoUtils::deriveKey(credPassword, credSalt);
        cipher = std::make_shared<XORCipher>(encryptionKey);
        storage->setCipher(cipher);
        storage->setUsername(username);
        storage->setMasterSalt(masterSalt);
        storage->setMasterPasswordHash(masterPasswordHash);
        storage->setCredSalt(credSalt);
        storage->setCredPasswordHash(credPasswordHash);

        credentials = storage->load();
        return true;
    }

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
    masterUnlocked = false;
    credUnlocked = false;
    credentials.clear();
    cipher.reset();
    if (storage) {
        storage->setCipher(nullptr);
    }
}

bool MasterVault::addCredential(const Credential& credential) {
    if (!masterUnlocked || !credUnlocked || !storage || !cipher) {
        return false;
    }

    credentials.push_back(credential);
    return storage->save(credentials);
}

bool MasterVault::updateCredential(size_t index, const Credential& updated) {
    if (!masterUnlocked || !credUnlocked || !storage || !cipher) {
        return false;
    }
    if (index >= credentials.size()) {
        return false;
    }

    Credential original = credentials[index];
    credentials[index] = updated;
    if (!storage->save(credentials)) {
        credentials[index] = original;
        return false;
    }
    return true;
}

bool MasterVault::verifyCredentialPassword(const std::string& credPassword) const {
    if (credPassword.empty() || credPasswordHash.empty() || credSalt.empty()) {
        return false;
    }
    // Master password must never be accepted to authorize credential operations
    if (CryptoUtils::verifyPassword(credPassword, masterSalt, masterPasswordHash)) {
        return false;
    }
    return CryptoUtils::verifyPassword(credPassword, credSalt, credPasswordHash);
}

bool MasterVault::deleteCredential(size_t index) {
    if (!masterUnlocked || !credUnlocked || !storage || !cipher) {
        return false;
    }
    if (index >= credentials.size()) {
        return false;
    }

    Credential removed = credentials[index];
    credentials.erase(credentials.begin() + index);
    if (!storage->save(credentials)) {
        credentials.insert(credentials.begin() + index, removed);
        return false;
    }
    return true;
}

const std::vector<Credential>& MasterVault::getCredentials() const {
    static const std::vector<Credential> empty;
    if (!masterUnlocked || !credUnlocked) {
        return empty;
    }
    return credentials;
}

size_t MasterVault::getCredentialCount() const {
    if (!masterUnlocked || !credUnlocked) {
        return 0;
    }
    return credentials.size();
}

const std::string& MasterVault::getUsername() const {
    return username;
}
