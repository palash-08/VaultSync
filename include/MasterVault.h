#ifndef MASTER_VAULT_H
#define MASTER_VAULT_H

#include <string>
#include <vector>
#include <memory>
#include "Credential.h"
#include "FileStorage.h"
#include "ICipher.h"

/**
 * @brief MasterVault coordinates authentication, user identification, and controlled access.
 *
 * Implements two independent authentication mechanisms:
 * 1. Master Vault Password: Authenticates access to the Master Vault session.
 * 2. Credential Vault Password: Configured on first use, decrypts and accesses stored credentials.
 */
class MasterVault {
private:
    std::string vaultPath;
    std::string username;

    // Master Vault authentication state
    std::string masterSalt;
    std::string masterPasswordHash;
    bool masterUnlocked;
    int masterFailedAttempts;
    bool masterLockedOut;

    // Credential Vault authentication & encryption state
    std::string credSalt;
    std::string credPasswordHash;
    bool credUnlocked;
    int credFailedAttempts;
    bool credLockedOut;

    std::shared_ptr<ICipher> cipher;
    std::unique_ptr<FileStorage> storage;
    std::vector<Credential> credentials;

public:
    explicit MasterVault(const std::string& path = "");

    /**
     * @brief Computes standard vault storage path for a given username.
     */
    static std::string getVaultPathForUser(const std::string& username);

    /**
     * @brief Checks if a master vault exists for the given username.
     */
    static bool existsForUser(const std::string& username);

    /**
     * @brief Checks if a master vault file exists at the specified path.
     */
    static bool exists(const std::string& path = "data/vault.bin");

    /**
     * @brief Creates a new Master Vault for the specified username with a master password.
     * Note: Credential vault password is NOT requested here; it is configured on first credential use.
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
     * @brief Checks if the Master Vault is currently unlocked.
     */
    bool isMasterUnlocked() const;

    /**
     * @brief Checks if a Credential Vault Password has been configured for this vault.
     */
    bool hasCredentialPassword() const;

    /**
     * @brief Configures the Credential Vault Password on first credential use.
     * Rejects passwords identical to the Master Vault Password.
     * @param credPassword Plaintext credential vault password.
     * @return True if configured successfully, false if identical to master or invalid.
     */
    bool setupCredentialPassword(const std::string& credPassword);

    /**
     * @brief Authenticates access to the Credential Vault, initializing decryption.
     * @param credPassword Credential vault password attempt.
     * @param attemptsRemaining Output parameter reporting remaining attempts.
     * @return True if credential vault password verified and credentials decrypted, false otherwise.
     */
    bool unlockCredentials(const std::string& credPassword, int& attemptsRemaining);

    /**
     * @brief Checks if the Credential Vault is currently unlocked.
     */
    bool isCredentialsUnlocked() const;

    /**
     * @brief Resets the Credential Vault failed attempts counter.
     */
    void resetCredentialsAttempts();

    /**
     * @brief Locks the entire vault, purging decrypted credentials and cipher keys from memory.
     */
    void lock();

    /**
     * @brief Adds a new credential and persists the encrypted vault to disk.
     * @param credential Credential to add.
     * @return True if added and saved successfully, false otherwise.
     */
    bool addCredential(const Credential& credential);

    /**
     * @brief Updates an existing credential at the specified index and persists to disk.
     * @param index Zero-based index of the credential.
     * @param updated Updated credential object.
     * @return True if updated and saved successfully, false otherwise.
     */
    bool updateCredential(size_t index, const Credential& updated);

    /**
     * @brief Verifies whether the provided password matches the Credential Vault Password.
     * @param credPassword Plaintext credential vault password to verify.
     * @return True if password matches the stored salted hash, false otherwise.
     */
    bool verifyCredentialPassword(const std::string& credPassword) const;

    /**
     * @brief Removes a credential at the specified index and persists the encrypted vault to disk.
     * @param index Zero-based index of the credential to remove.
     * @return True if removed and saved successfully, false otherwise.
     */
    bool deleteCredential(size_t index);

    /**
     * @brief Returns the collection of stored credentials if Credential Vault is unlocked.
     */
    const std::vector<Credential>& getCredentials() const;

    /**
     * @brief Returns the count of credentials currently stored in the vault.
     */
    size_t getCredentialCount() const;

    /**
     * @brief Returns the vault username identifier.
     */
    const std::string& getUsername() const;
};

#endif // MASTER_VAULT_H
