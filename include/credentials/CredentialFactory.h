#ifndef CREDENTIAL_FACTORY_H
#define CREDENTIAL_FACTORY_H

#include "credentials/Credential.h"
#include <iosfwd>
#include <memory>
#include <string>

/**
 * @brief Factory for instantiating and deserializing polymorphic Credential objects.
 *
 * Supports creating concrete credential instances such as generic Credential,
 * WebCredential, WiFiCredential, and SSHCredential based on type strings.
 */
class CredentialFactory {
public:
    /**
     * @brief Creates a new default instance of the specified credential type.
     * @param type String identifier for the credential type ("generic", "web", "wifi", "ssh").
     * @return Shared pointer to the newly created Credential instance.
     * @throws CorruptedVaultException If the type identifier is unknown.
     */
    static std::shared_ptr<Credential> create(const std::string& type);

    /**
     * @brief Creates and deserializes a credential instance from an input stream.
     * @param type String identifier for the credential type.
     * @param stream Input stream containing serialized binary data.
     * @return Shared pointer to the deserialized Credential instance.
     * @throws CorruptedVaultException If the type is unknown or deserialization fails.
     */
    static std::shared_ptr<Credential> deserialize(const std::string& type, std::istream& stream);
};

#endif // CREDENTIAL_FACTORY_H
