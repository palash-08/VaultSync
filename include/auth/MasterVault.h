#ifndef MASTER_VAULT_H
#define MASTER_VAULT_H

#include <string>
#include <vector>
#include <memory>

#include "credentials/Credential.h"
#include "storage/FileStorage.h"
#include "crypto/ICipher.h"
#include "storage/Vault.h"
#include "vault/VaultProxy.h"

/**
 * @brief MasterVault coordinates two-tier authentication, user identification, and access control.
 *
 * Architecture Overview:
 * 1. Two-Tier Authentication:
 *    - Master Vault Password: Logs the user in and establishes the active session.
 *    - Credential Vault Password: Configured on first use, derives a 256-bit encryption key
 *      used by AES-256-GCM to decrypt the stored credentials.
 *
 * 2. Design Patterns Applied:
 *    - Repository Pattern: Manages credentials in memory using Repository<Credential>.
 *    - Proxy Pattern: VaultProxy guards access to the underlying Vault and enforces authorization.
 *    - Strategy Pattern: Cryptography uses ICipher interface, defaulting to AESCipher (AES-256-GCM).
 *
 * 3. Polymorphism:
 *    - Stores and serializes polymorphic credentials (WebCredential, WiFiCredential, SSHCredential, etc.).
 *    - Retains full backward compatibility with legacy value-based Credential objects.
 */
class MasterVault {
private:
    std::string vaultPath;
    std::string username;

    // Master Vault authentication state (Login tier)
    std::string masterSalt;
    std::string masterPasswordHash;
    bool masterUnlocked;
    int masterFailedAttempts;
    bool masterLockedOut;

    // Credential Vault authentication & encryption state (Data tier)
    std::string credSalt;
    std::string credPasswordHash;
    bool credUnlocked;
    int credFailedAttempts;
    bool credLockedOut;

    // Cryptography and persistence
    std::shared_ptr<ICipher> cipher;
    std::unique_ptr<FileStorage> storage;

    // In-memory credential repository and access-control proxy
    std::unique_ptr<Vault> vault;
    std::unique_ptr<VaultProxy> proxy;

    // Cached credentials for backward-compatible value access
    mutable std::vector<Credential> cachedCredentials;

    /**
     * @brief Helper that synchronizes the legacy cachedCredentials vector from the proxy.
     */
    void syncLegacyCache() const;

    /**
     * @brief Saves the current in-memory credentials to encrypted disk storage.
     * @return True if save succeeded; false otherwise.
     */
    bool saveToDisk();

public:
    /**
     * @brief Constructs a MasterVault instance.
     * @param path Optional custom file path to the vault file.
     */
    explicit MasterVault(const std::string& path = "");

    /**
     * @brief Destructor that securely locks and wipes decrypted credentials from RAM.
     */
    ~MasterVault();

    // Prevent accidental copying (holds unique_ptrs to vault and proxy)
    MasterVault(const MasterVault&) = delete;
    MasterVault& operator=(const MasterVault&) = delete;

    // Allow moving
    MasterVault(MasterVault&&) noexcept = default;
    MasterVault& operator=(MasterVault&&) noexcept = default;

    /**
     * @brief Computes standard vault storage path for a given username (e.g. "data/vault_alice.bin").
     * @param username The owner's username identifier.
     * @return Standard file system path for the user's vault.
     */
    static std::string getVaultPathForUser(const std::string& username);

    /**
     * @brief Checks if a master vault exists for the given username.
     * @param username The owner's username identifier.
     * @return True if the vault file exists on disk; false otherwise.
     */
    static bool existsForUser(const std::string& username);

    /**
     * @brief Checks if a master vault file exists at the specified path.
     * @param path File system path to check.
     * @return True if the file exists; false otherwise.
     */
    static bool exists(const std::string& path = "data/vault.bin");

    /**
     * @brief Creates a new Master Vault for the specified username with a master password.
     *
     * Note: The Credential Vault password is NOT requested here; it is configured
     * on first credential use via setupCredentialPassword().
     *
     * @param username Vault owner identifier.
     * @param masterPassword Plaintext master vault password.
     * @return True if vault was created and persisted, false if duplicate or invalid.
     */
    bool create(const std::string& username, const std::string& masterPassword);

    /**
     * @brief Authenticates the user to the Master Vault session.
     * @param username Vault owner identifier.
     * @param masterPassword Master password attempt.
     * @param attemptsRemaining Output parameter reporting remaining login attempts.
     * @return True if master password verified, false otherwise.
     */
    bool unlockMaster(const std::string& username, const std::string& masterPassword, int& attemptsRemaining);

    /**
     * @brief Checks if Master Vault login is currently temporarily locked out for the given user.
     * @param username Vault owner identifier.
     * @param remainingSeconds Output parameter reporting remaining lockout time in seconds.
     * @return True if locked out, false otherwise.
     */
    static bool isMasterLockedOut(const std::string& username, int& remainingSeconds);

    /**
     * @brief Resets failed login attempts and lockout state for the specified user.
     * @param username Vault owner identifier.
     */
    static void resetMasterLockout(const std::string& username);

    /**
     * @brief Checks if the Master Vault session is currently unlocked.
     * @return True if Master Vault is unlocked; false otherwise.
     */
    bool isMasterUnlocked() const;

    /**
     * @brief Checks if a Credential Vault Password has been configured for this vault.
     * @return True if configured; false if delayed setup is pending.
     */
    bool hasCredentialPassword() const;

    /**
     * @brief Configures the Credential Vault Password on first credential use.
     *
     * Rejects passwords that are identical to the Master Vault Password.
     * Derives a 256-bit AES key and switches FileStorage to AES-256-GCM encryption.
     *
     * @param credPassword Plaintext credential vault password.
     * @return True if configured successfully; false if identical to master or invalid.
     */
    bool setupCredentialPassword(const std::string& credPassword);

    /**
     * @brief Authenticates access to the Credential Vault and decrypts stored credentials.
     * @param credPassword Credential vault password attempt.
     * @param attemptsRemaining Output parameter reporting remaining attempts.
     * @return True if password verified and credentials decrypted; false otherwise.
     */
    bool unlockCredentials(const std::string& credPassword, int& attemptsRemaining);

    /**
     * @brief Checks if the Credential Vault is currently unlocked and decrypted.
     * @return True if unlocked; false otherwise.
     */
    bool isCredentialsUnlocked() const;

    /**
     * @brief Resets the Credential Vault failed attempts counter.
     */
    void resetCredentialsAttempts();

    /**
     * @brief Locks the entire vault, purging decrypted credentials and AES keys from memory.
     */
    void lock();

    /**
     * @brief Adds a polymorphic credential and persists the encrypted vault to disk.
     * @param credential Shared pointer to the credential to add.
     * @return True if added and saved successfully; false otherwise.
     */
    bool addCredential(std::shared_ptr<Credential> credential);

    /**
     * @brief Updates an existing polymorphic credential at the specified index and saves to disk.
     * @param index Zero-based index of the credential to update.
     * @param updated Replacement credential object.
     * @return True if updated and saved successfully; false otherwise.
     */
    bool updateCredential(size_t index, std::shared_ptr<Credential> updated);

    /**
     * @brief Retrieves a specific polymorphic credential by index.
     * @param index Zero-based index of the credential.
     * @return Shared pointer to the credential, or nullptr if locked or index out of bounds.
     */
    std::shared_ptr<Credential> getCredential(size_t index) const;

    /**
     * @brief Returns all credentials as polymorphic shared pointers.
     * @return Vector of shared pointers to stored credentials.
     */
    std::vector<std::shared_ptr<Credential>> getPolymorphicCredentials() const;

    /**
     * @brief Searches credentials matching a query string across all fields.
     * @param query Search query to match (service, username, URL, SSID, host, notes).
     * @return Vector of matching credentials.
     */
    std::vector<std::shared_ptr<Credential>> search(const std::string& query) const;

    /**
     * @brief Adds a legacy value-based credential and persists the encrypted vault to disk.
     * @param credential Credential value object to add.
     * @return True if added and saved successfully; false otherwise.
     */
    bool addCredential(const Credential& credential);

    /**
     * @brief Updates an existing credential at the specified index and persists to disk.
     * @param index Zero-based index of the credential.
     * @param updated Updated credential object.
     * @return True if updated and saved successfully; false otherwise.
     */
    bool updateCredential(size_t index, const Credential& updated);

    /**
     * @brief Verifies whether the provided password matches the Credential Vault Password.
     * @param credPassword Plaintext credential vault password to verify.
     * @return True if password matches the stored salted hash; false otherwise.
     */
    bool verifyCredentialPassword(const std::string& credPassword) const;

    /**
     * @brief Removes a credential at the specified index and persists the encrypted vault to disk.
     * @param index Zero-based index of the credential to remove.
     * @return True if removed and saved successfully; false otherwise.
     */
    bool deleteCredential(size_t index);

    /**
     * @brief Returns a reference to the collection of stored credentials if unlocked.
     * @return Const reference to vector of Credential objects.
     */
    const std::vector<Credential>& getCredentials() const;

    /**
     * @brief Returns the total count of credentials currently stored in the vault.
     * @return Number of stored credentials, or 0 if locked.
     */
    size_t getCredentialCount() const;

    /**
     * @brief Exposes the underlying VaultProxy for proxy-pattern access control operations.
     * @return Reference to the internal VaultProxy instance.
     */
    VaultProxy& getProxy();

    /**
     * @brief Exposes the underlying const VaultProxy for proxy-pattern access control operations.
     * @return Const reference to the internal VaultProxy instance.
     */
    const VaultProxy& getProxy() const;

    /**
     * @brief Manually triggers persisting the in-memory vault to disk.
     * @return True if save succeeded; false otherwise.
     */
    bool save();

    /**
     * @brief Returns the vault username identifier.
     * @return Const reference to the username string.
     */
    const std::string& getUsername() const;
};

#endif // MASTER_VAULT_H
