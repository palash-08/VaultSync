#include "Vault.h"

void Vault::addCredential(std::shared_ptr<Credential> credential) {
    if (!locked) {
        credentials.add(std::move(credential));
    }
}

bool Vault::updateCredential(size_t index, std::shared_ptr<Credential> credential) {
    if (locked) {
        return false;
    }
    return credentials.replace(index, std::move(credential));
}

bool Vault::deleteCredential(size_t index) {
    if (locked) {
        return false;
    }
    return credentials.remove(index);
}

std::vector<std::shared_ptr<Credential>> Vault::getCredentials() const {
    if (locked) {
        return {};
    }
    return credentials.getAll();
}

std::vector<std::shared_ptr<Credential>> Vault::search(const std::string& query) const {
    if (locked) {
        return {};
    }
    return credentials.find([&query](const Credential& credential) {
        return credential.matches(query);
    });
}

void Vault::lock() {
    locked = true;
}

bool Vault::isLocked() const {
    return locked;
}

void Vault::unlock() {
    locked = false;
}

void Vault::clear() {
    // Wipes all credential pointers from the in-memory repository
    credentials.clear();
}

size_t Vault::size() const {
    if (locked) {
        return 0;
    }
    return credentials.size();
}
