#include "vault/VaultProxy.h"
#include "security/VaultExceptions.h"

VaultProxy::VaultProxy(Vault& vault, bool authenticated,
                       std::function<bool(const std::string&)> verifier)
    : vault(vault),
      authenticated(authenticated),
      passwordVerifier(std::move(verifier)) {
}

void VaultProxy::authorize() const {
    if (!authenticated || vault.isLocked()) {
        throw UnauthorizedAccessException("VaultProxy: Access denied. Vault is locked.");
    }
}

void VaultProxy::setPasswordVerifier(std::function<bool(const std::string&)> verifier) {
    passwordVerifier = std::move(verifier);
}

void VaultProxy::setAuthenticated(bool isAuthenticated) {
    authenticated = isAuthenticated;
}

void VaultProxy::addCredential(std::shared_ptr<Credential> credential) {
    authorize();
    vault.addCredential(std::move(credential));
}

bool VaultProxy::updateCredential(size_t index, std::shared_ptr<Credential> credential) {
    return updateCredential(index, std::move(credential), "");
}

bool VaultProxy::updateCredential(size_t index, std::shared_ptr<Credential> credential,
                                  const std::string& credPassword) {
    authorize();
    if (!credential) {
        return false;
    }

    auto all = vault.getCredentials();
    if (index >= all.size() || !all[index]) {
        return false;
    }

    std::string existingPass = all[index]->getPassword();

    // Preserve existing password if updated password is empty or untouched
    if (credential->getPassword().empty()) {
        credential->setPassword(existingPass);
    }

    // Modifying stored secret requires credential password authorization
    if (existingPass != credential->getPassword()) {
        if (passwordVerifier && !passwordVerifier(credPassword)) {
            throw UnauthorizedAccessException("VaultProxy: Invalid credential password to modify secret.");
        }
    }

    return vault.updateCredential(index, std::move(credential));
}

bool VaultProxy::deleteCredential(size_t index) {
    authorize();
    if (passwordVerifier) {
        throw UnauthorizedAccessException("VaultProxy: Credential password authorization required to delete credential.");
    }
    return vault.deleteCredential(index);
}

bool VaultProxy::deleteCredential(size_t index, const std::string& credPassword, bool confirmed) {
    authorize();
    if (!confirmed) {
        throw UnauthorizedAccessException("VaultProxy: Explicit confirmation required to delete credential.");
    }
    if (passwordVerifier && !passwordVerifier(credPassword)) {
        throw UnauthorizedAccessException("VaultProxy: Invalid credential password for deletion.");
    }
    return vault.deleteCredential(index);
}

std::string VaultProxy::revealPassword(size_t index, const std::string& credPassword) const {
    authorize();
    if (passwordVerifier && !passwordVerifier(credPassword)) {
        throw UnauthorizedAccessException("VaultProxy: Invalid credential password to reveal secret.");
    }
    auto all = vault.getCredentials();
    if (index >= all.size() || !all[index]) {
        throw std::out_of_range("VaultProxy: Index out of bounds.");
    }
    return all[index]->getPassword();
}

std::vector<std::shared_ptr<Credential>> VaultProxy::getCredentials() const {
    authorize();
    return vault.getCredentials();
}

std::vector<std::shared_ptr<Credential>> VaultProxy::search(const std::string& query) const {
    authorize();
    return vault.search(query);
}

void VaultProxy::lock() {
    if (authenticated) {
        vault.lock();
    }
    authenticated = false;
}

bool VaultProxy::isLocked() const {
    return !authenticated || vault.isLocked();
}
