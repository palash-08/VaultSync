#ifndef CREDENTIAL_H
#define CREDENTIAL_H

#include <cstdint>
#include <iosfwd>
#include <string>

/**
 * @brief Base model representing a stored credential entry.
 *
 * Encapsulates core credential fields including service name, username,
 * password, notes, and a timestamp indicating creation or modification time.
 * Serves as the polymorphic base class for specialized credential types.
 */
class Credential {
protected:
    std::string service;
    std::string username;
    std::string password;
    std::string notes;
    int64_t createdAt;

public:
    /**
     * @brief Constructs a new Credential instance.
     * @param service The name of the service or domain (e.g., "Google", "GitHub").
     * @param username The username, login ID, or email address.
     * @param password The secret password or token.
     * @param notes Optional notes or extra details.
     * @param createdAt Epoch timestamp in seconds when the credential was created (-1 for current time).
     */
    Credential(const std::string& service = {},
               const std::string& username = {},
               const std::string& password = {},
               const std::string& notes = {},
               int64_t createdAt = -1);

    /**
     * @brief Virtual destructor to support safe polymorphic deletion.
     */
    virtual ~Credential() = default;

    /**
     * @brief Retrieves the string identifier for this credential type.
     * @return String representing credential type (e.g., "generic").
     */
    virtual std::string getType() const;

    /**
     * @brief Displays the credential fields to standard output.
     * @param showPassword Whether to print the plaintext password or mask it.
     */
    virtual void display(bool showPassword) const;

    /**
     * @brief Creates a polymorphic deep copy of this credential.
     * @return Raw pointer to a newly allocated cloned Credential instance.
     */
    virtual Credential* clone() const;

    /**
     * @brief Serializes the credential object to a binary output stream.
     * @param stream The output stream to write binary data into.
     */
    virtual void serialize(std::ostream& stream) const;

    /**
     * @brief Deserializes the credential object from a binary input stream.
     * @param stream The input stream to read binary data from.
     */
    virtual void deserialize(std::istream& stream);

    /**
     * @brief Checks whether the credential matches a given case-insensitive search query.
     * @param query The search text to match against service, username, or notes.
     * @return True if the query substring is found; false otherwise.
     */
    virtual bool matches(const std::string& query) const;

    /**
     * @brief Gets the service name.
     * @return Const reference to the service name string.
     */
    const std::string& getService() const;

    /**
     * @brief Gets the username.
     * @return Const reference to the username string.
     */
    const std::string& getUsername() const;

    /**
     * @brief Gets the password.
     * @return Const reference to the password string.
     */
    const std::string& getPassword() const;

    /**
     * @brief Gets the notes.
     * @return Const reference to the notes string.
     */
    const std::string& getNotes() const;

    /**
     * @brief Gets the creation timestamp in epoch seconds.
     * @return Epoch timestamp as a 64-bit signed integer.
     */
    int64_t getCreatedAt() const;

    /**
     * @brief Sets the service name.
     * @param service New service name.
     */
    void setService(const std::string& service);

    /**
     * @brief Sets the username.
     * @param username New username.
     */
    void setUsername(const std::string& username);

    /**
     * @brief Sets the password.
     * @param password New password.
     */
    void setPassword(const std::string& password);

    /**
     * @brief Sets the notes.
     * @param notes New notes content.
     */
    void setNotes(const std::string& notes);

    /**
     * @brief Equality comparison operator.
     * @param other Another credential instance to compare against.
     * @return True if all corresponding fields and types match; false otherwise.
     */
    bool operator==(const Credential& other) const;

    /**
     * @brief Inequality comparison operator.
     * @param other Another credential instance to compare against.
     * @return True if any field or type differs; false otherwise.
     */
    bool operator!=(const Credential& other) const;

    /**
     * @brief Stream insertion operator for formatted output of credential summary.
     * @param stream The output stream.
     * @param credential The credential instance to output.
     * @return Reference to the output stream.
     */
    friend std::ostream& operator<<(std::ostream& stream, const Credential& credential);
};

#endif // CREDENTIAL_H
