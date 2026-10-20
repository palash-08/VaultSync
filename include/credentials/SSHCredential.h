#ifndef SSH_CREDENTIAL_H
#define SSH_CREDENTIAL_H

#include "credentials/Credential.h"

#include <cstdint>
#include <iosfwd>
#include <string>

/**
 * @brief Represents an SSH server credential including remote host and port information.
 */
class SSHCredential : public Credential {
private:
    std::string host;
    uint16_t port;

public:
    /**
     * @brief Constructs an SSHCredential with service, credentials, host, and port.
     * @param service Service or server identifier.
     * @param username Login username.
     * @param password Login password or passphrase.
     * @param notes Additional comments or metadata.
     * @param host Remote SSH host name or IP address.
     * @param port Remote SSH port number (default: 22).
     */
    SSHCredential(const std::string& service = {},
                  const std::string& username = {},
                  const std::string& password = {},
                  const std::string& notes = {},
                  const std::string& host = {},
                  uint16_t port = 22);

    /**
     * @brief Gets the credential type identifier ("ssh").
     * @return String literal "ssh".
     */
    std::string getType() const override;

    /**
     * @brief Gets the remote SSH host.
     * @return Const reference to host string.
     */
    const std::string& getHost() const;

    /**
     * @brief Gets the remote SSH port number.
     * @return Port number.
     */
    uint16_t getPort() const;

    /**
     * @brief Sets the remote SSH host.
     * @param host Remote host string.
     */
    void setHost(const std::string& host);

    /**
     * @brief Sets the remote SSH port number.
     * @param port Port number.
     */
    void setPort(uint16_t port);

    /**
     * @brief Displays SSH credential details to standard output.
     * @param showPassword Whether to print the plaintext password.
     */
    void display(bool showPassword) const override;

    /**
     * @brief Creates a polymorphic deep copy of this SSHCredential.
     * @return Raw pointer to newly allocated SSHCredential copy.
     */
    Credential* clone() const override;

    /**
     * @brief Serializes the SSH credential to a binary output stream.
     * @param stream The output stream to write binary data into.
     */
    void serialize(std::ostream& stream) const override;

    /**
     * @brief Deserializes the SSH credential from a binary input stream.
     * @param stream The input stream to read binary data from.
     */
    void deserialize(std::istream& stream) override;

    /**
     * @brief Checks if the credential matches a given search query (including host).
     * @param query Search string to test against fields.
     * @return True if query matches service, username, notes, or host.
     */
    bool matches(const std::string& query) const override;
};

#endif // SSH_CREDENTIAL_H
