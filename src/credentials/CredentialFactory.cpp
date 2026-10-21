#include "credentials/CredentialFactory.h"
#include "credentials/WebCredential.h"
#include "credentials/WiFiCredential.h"
#include "credentials/SSHCredential.h"
#include "security/VaultExceptions.h"

#include <istream>

std::shared_ptr<Credential> CredentialFactory::create(const std::string& type) {
    if (type == "generic") {
        return std::make_shared<Credential>();
    }
    if (type == "web") {
        return std::make_shared<WebCredential>();
    }
    if (type == "wifi") {
        return std::make_shared<WiFiCredential>();
    }
    if (type == "ssh") {
        return std::make_shared<SSHCredential>();
    }
    throw CorruptedVaultException("Unknown credential type: " + type);
}

std::shared_ptr<Credential> CredentialFactory::deserialize(const std::string& type, std::istream& stream) {
    std::shared_ptr<Credential> credential = create(type);
    credential->deserialize(stream);
    if (!stream) {
        throw CorruptedVaultException("Invalid credential data");
    }
    return credential;
}
