#ifndef VAULT_H
#define VAULT_H

#include "IVault.h"
#include "Repository.h"

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Concrete implementation of IVault storing credentials in an in-memory repository.
 */
class Vault : public IVault {
private:
    Repository<Credential> credentials;
    bool locked = false;

public:
    /**
     * @brief Default constructor creating an unlocked, empty Vault.
     */
    Vault() = default;

    /**
     * @brief Adds a credential to the vault if unlocked.
     * @param credential The credential to add.
     */
    void addCredential(std::shared_ptr<Credential> credential) override;

    /**
     * @brief Updates the credential at the specified index if unlocked.
     * @param index The zero-based index of the credential to update.
     * @param credential The replacement credential.
     * @return True if updated; false if locked or index is out of bounds.
     */
    bool updateCredential(size_t index, std::shared_ptr<Credential> credential) override;

    /**
     * @brief Deletes the credential at the specified index if unlocked.
     * @param index The zero-based index of the credential to delete.
     * @return True if deleted; false if locked or index is out of bounds.
     */
    bool deleteCredential(size_t index) override;

    /**
     * @brief Retrieves all credentials if unlocked.
     * @return Vector of credentials, or an empty vector if locked.
     */
    std::vector<std::shared_ptr<Credential>> getCredentials() const override;

    /**
     * @brief Searches credentials matching a query string if unlocked.
     * @param query Search query to match.
     * @return Vector of matching credentials, or empty vector if locked.
     */
    std::vector<std::shared_ptr<Credential>> search(const std::string& query) const override;

    /**
     * @brief Locks the vault, preventing access and modifications.
     */
    void lock() override;

    /**
     * @brief Checks if the vault is currently locked.
     * @return True if locked; false otherwise.
     */
    bool isLocked() const override;

    /**
     * @brief Unlocks the vault, enabling access to stored credentials.
     */
    void unlock();
};

#endif // VAULT_H
