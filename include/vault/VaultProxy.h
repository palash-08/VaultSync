#ifndef VAULT_PROXY_H
#define VAULT_PROXY_H

#include "vault/IVault.h"
#include "storage/Vault.h"

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Proxy protecting access to a Vault instance by enforcing authentication checks.
 *
 * Implements the Proxy design pattern. Any attempted access to the underlying vault
 * throws an UnauthorizedAccessException unless authenticated is true and the vault is unlocked.
 * Sensitive operations (revealing secret passwords, modifying secrets, and deleting credentials)
 * additionally enforce credential-password authorization via the configured password verifier.
 */
class VaultProxy : public IVault {
private:
    Vault& vault;
    bool authenticated;
    std::function<bool(const std::string&)> passwordVerifier;

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
     * @param verifier Optional callback function for credential password verification.
     */
    explicit VaultProxy(Vault& vault, bool authenticated = false,
                        std::function<bool(const std::string&)> verifier = nullptr);

    /**
     * @brief Sets or updates the password verification callback.
     * @param verifier Callback function returning true if the credential password is valid.
     */
    void setPasswordVerifier(std::function<bool(const std::string&)> verifier);

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
     * @throws UnauthorizedAccessException If authorization check fails or secret change is unverified.
     */
    bool updateCredential(size_t index, std::shared_ptr<Credential> credential) override;

    /**
     * @brief Updates a credential at the specified index, authorizing secret changes with password.
     * @param index The zero-based index of the credential to update.
     * @param credential The replacement credential.
     * @param credPassword Plaintext credential password used if secret was altered.
     * @return True if update succeeded; false otherwise.
     * @throws UnauthorizedAccessException If authorization check fails or credential password invalid.
     */
    bool updateCredential(size_t index, std::shared_ptr<Credential> credential,
                          const std::string& credPassword) override;

    /**
     * @brief Deletes a credential at the specified index after authorization check.
     * @note When a password verifier is configured, this overload requires password authorization.
     * @param index The zero-based index of the credential to delete.
     * @return True if deletion succeeded; false otherwise.
     * @throws UnauthorizedAccessException If authorization check fails or password is missing.
     */
    bool deleteCredential(size_t index) override;

    /**
     * @brief Deletes a credential at the specified index with explicit credential password authorization and confirmation.
     * @param index The zero-based index of the credential to delete.
     * @param credPassword Plaintext credential password authorizing the deletion.
     * @param confirmed Explicit deletion confirmation flag (defaults to true).
     * @return True if deletion succeeded; false otherwise.
     * @throws UnauthorizedAccessException If authorization check fails, confirmation is false, or password invalid.
     */
    bool deleteCredential(size_t index, const std::string& credPassword, bool confirmed = true) override;

    /**
     * @brief Reveals the plaintext secret password after verifying credential password.
     * @param index The zero-based index of the credential.
     * @param credPassword Plaintext credential password authorizing reveal.
     * @return Stored plaintext password string.
     * @throws UnauthorizedAccessException If authorization check fails or credential password invalid.
     */
    std::string revealPassword(size_t index, const std::string& credPassword) const override;

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
