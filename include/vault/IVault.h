#ifndef I_VAULT_H
#define I_VAULT_H

#include "credentials/Credential.h"

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Interface defining core vault operations for managing credentials.
 *
 * Provides an abstract contract for adding, updating, deleting, searching,
 * and securing credentials, adhered to by concrete vaults and security proxies.
 */
class IVault {
public:
    /**
     * @brief Virtual destructor for polymorphic interface cleanup.
     */
    virtual ~IVault() = default;

    /**
     * @brief Adds a new credential to the vault.
     * @param credential Shared pointer to the credential to add.
     */
    virtual void addCredential(std::shared_ptr<Credential> credential) = 0;

    /**
     * @brief Updates an existing credential at the specified index.
     * @param index The zero-based index of the credential to update.
     * @param credential The new credential to place at the specified index.
     * @return True if the credential was successfully updated; false otherwise.
     */
    virtual bool updateCredential(size_t index, std::shared_ptr<Credential> credential) = 0;

    /**
     * @brief Updates a credential at the specified index, validating credential password if secrets are modified.
     * @param index The zero-based index of the credential to update.
     * @param credential The new credential to place at the specified index.
     * @param credPassword Plaintext credential password used to authorize secret changes.
     * @return True if the credential was successfully updated; false otherwise.
     */
    virtual bool updateCredential(size_t index, std::shared_ptr<Credential> credential, const std::string& credPassword) {
        (void)credPassword;
        return updateCredential(index, std::move(credential));
    }

    /**
     * @brief Deletes a credential at the specified index.
     * @param index The zero-based index of the credential to delete.
     * @return True if the credential was successfully deleted; false otherwise.
     */
    virtual bool deleteCredential(size_t index) = 0;

    /**
     * @brief Deletes a credential at the specified index, authorized by credential password and confirmation.
     * @param index The zero-based index of the credential to delete.
     * @param credPassword Plaintext credential password used to authorize deletion.
     * @param confirmed Explicit deletion confirmation flag (defaults to true).
     * @return True if the credential was successfully deleted; false otherwise.
     */
    virtual bool deleteCredential(size_t index, const std::string& credPassword, bool confirmed = true) {
        if (!confirmed) return false;
        (void)credPassword;
        return deleteCredential(index);
    }

    /**
     * @brief Reveals the plaintext secret password for a credential after password verification.
     * @param index The zero-based index of the credential.
     * @param credPassword Plaintext credential password used to authorize reveal.
     * @return The plaintext password string.
     */
    virtual std::string revealPassword(size_t index, const std::string& credPassword) const {
        (void)index;
        (void)credPassword;
        return "";
    }

    /**
     * @brief Retrieves all credentials stored in the vault.
     * @return A vector of shared pointers to all credentials.
     */
    virtual std::vector<std::shared_ptr<Credential>> getCredentials() const = 0;

    /**
     * @brief Searches for credentials matching the specified search query.
     * @param query The search query string to match against credentials.
     * @return A vector of shared pointers to matching credentials.
     */
    virtual std::vector<std::shared_ptr<Credential>> search(const std::string& query) const = 0;

    /**
     * @brief Locks the vault, restricting access to stored credentials.
     */
    virtual void lock() = 0;

    /**
     * @brief Checks whether the vault is currently locked.
     * @return True if the vault is locked; false if unlocked.
     */
    virtual bool isLocked() const = 0;
};

#endif // I_VAULT_H
