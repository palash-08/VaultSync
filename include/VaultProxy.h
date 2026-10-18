#ifndef VAULT_PROXY_H
#define VAULT_PROXY_H

#include "IVault.h"
#include "Vault.h"

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Proxy protecting access to a Vault instance by enforcing authentication checks.
 *
 * Implements the Proxy design pattern. Any attempted access to the underlying vault
 * throws an UnauthorizedAccessException unless authenticated is true and the vault is unlocked.
 */
class VaultProxy : public IVault {
private:
    Vault& vault;
    bool authenticated;

    /**
     * @brief Validates authentication and vault state, throwing an exception if unauthorized.
     * @throws UnauthorizedAccessException If not authenticated or vault is locked.
     */
    void authorize() const;

public:
    /**
     * @brief Constructs a VaultProxy wrapping the given Vault instance.
     * @param vault Reference to the underlying Vault to protect.
     * @param authenticated Initial authentication state (default: false).
     */
    explicit VaultProxy(Vault& vault, bool authenticated = false);

    /**
     * @brief Sets the authentication status of the proxy.
     * @param isAuthenticated True if authenticated; false otherwise.
     */
    void setAuthenticated(bool isAuthenticated);

    /**
     * @brief Adds a credential to the underlying vault after authorization check.
     * @param credential The credential to add.
     * @throws UnauthorizedAccessException If authorization check fails.
     */
    void addCredential(std::shared_ptr<Credential> credential) override;

    /**
     * @brief Updates a credential at the specified index after authorization check.
     * @param index The zero-based index of the credential to update.
     * @param credential The replacement credential.
     * @return True if update succeeded; false otherwise.
     * @throws UnauthorizedAccessException If authorization check fails.
     */
    bool updateCredential(size_t index, std::shared_ptr<Credential> credential) override;

    /**
     * @brief Deletes a credential at the specified index after authorization check.
     * @param index The zero-based index of the credential to delete.
     * @return True if deletion succeeded; false otherwise.
     * @throws UnauthorizedAccessException If authorization check fails.
     */
    bool deleteCredential(size_t index) override;

    /**
     * @brief Retrieves all credentials after authorization check.
     * @return Vector of credentials from the underlying vault.
     * @throws UnauthorizedAccessException If authorization check fails.
     */
    std::vector<std::shared_ptr<Credential>> getCredentials() const override;

    /**
     * @brief Searches credentials matching query string after authorization check.
     * @param query Search query to match.
     * @return Vector of matching credentials.
     * @throws UnauthorizedAccessException If authorization check fails.
     */
    std::vector<std::shared_ptr<Credential>> search(const std::string& query) const override;

    /**
     * @brief Locks the underlying vault and revokes authentication on this proxy.
     */
    void lock() override;

    /**
     * @brief Checks if access is locked or unauthenticated.
     * @return True if not authenticated or underlying vault is locked.
     */
    bool isLocked() const override;
};

#endif // VAULT_PROXY_H
