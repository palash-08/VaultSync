#ifndef WEB_CREDENTIAL_H
#define WEB_CREDENTIAL_H

#include "credentials/Credential.h"

#include <iosfwd>
#include <string>

/**
 * @brief Represents a website or web-service credential including URL information.
 */
class WebCredential : public Credential {
private:
    std::string url;

public:
    /**
     * @brief Constructs a WebCredential with service, username, password, notes, and URL.
     * @param service Service or website name.
     * @param username Login username or email.
     * @param password Login password.
     * @param notes Additional comments or metadata.
     * @param url Associated website URL address.
     */
    WebCredential(const std::string& service = {},
                  const std::string& username = {},
                  const std::string& password = {},
                  const std::string& notes = {},
                  const std::string& url = {});

    /**
     * @brief Gets the credential type identifier ("web").
     * @return String literal "web".
     */
    std::string getType() const override;

    /**
     * @brief Gets the website URL.
     * @return Const reference to URL string.
     */
    const std::string& getUrl() const;

    /**
     * @brief Alias for getUrl(), returning the website URL.
     * @return Const reference to URL string.
     */
    const std::string& getWebsite() const;

    /**
     * @brief Sets the website URL.
     * @param url The new URL string.
     */
    void setUrl(const std::string& url);

    /**
     * @brief Displays the web credential details to standard output.
     * @param showPassword Whether to print the plaintext password.
     */
    void display(bool showPassword) const override;

    /**
     * @brief Creates a polymorphic deep copy of this WebCredential.
     * @return Raw pointer to newly allocated WebCredential copy.
     */
    Credential* clone() const override;

    /**
     * @brief Serializes the web credential to a binary output stream.
     * @param stream The output stream to write binary data into.
     */
    void serialize(std::ostream& stream) const override;

    /**
     * @brief Deserializes the web credential from a binary input stream.
     * @param stream The input stream to read binary data from.
     */
    void deserialize(std::istream& stream) override;

    /**
     * @brief Checks if the credential matches a given search query (including URL).
     * @param query Search string to test against fields.
     * @return True if query matches service, username, notes, or URL.
     */
    bool matches(const std::string& query) const override;
};

#endif // WEB_CREDENTIAL_H
