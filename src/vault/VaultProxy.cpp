#include "vault/VaultProxy.h"
#include "security/VaultExceptions.h"

VaultProxy::VaultProxy(Vault& vault, bool authenticated)
    : vault(vault),
      authenticated(authenticated) {
}

void VaultProxy::authorize() const {
    if (!authenticated || vault.isLocked()) {
        throw UnauthorizedAccessException();
    }
}

void VaultProxy::setAuthenticated(bool isAuthenticated) {
    authenticated = isAuthenticated;
}

void VaultProxy::addCredential(std::shared_ptr<Credential> credential) {
    authorize();
    vault.addCredential(std::move(credential));
}

bool VaultProxy::updateCredential(size_t index, std::shared_ptr<Credential> credential) {
    authorize();
    return vault.updateCredential(index, std::move(credential));
}

bool VaultProxy::deleteCredential(size_t index) {
    authorize();
    return vault.deleteCredential(index);
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
