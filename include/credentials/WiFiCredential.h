#ifndef WIFI_CREDENTIAL_H
#define WIFI_CREDENTIAL_H

#include "credentials/Credential.h"

#include <iosfwd>
#include <string>

/**
 * @brief Represents a wireless network credential including SSID and security protocol.
 */
class WiFiCredential : public Credential {
private:
    std::string ssid;
    std::string securityType;

public:
    /**
     * @brief Constructs a WiFiCredential with network details.
     * @param service Service name or network label.
     * @param username Network username or identity (if applicable).
     * @param password Wi-Fi network password or pre-shared key.
     * @param notes Additional comments or metadata.
     * @param ssid Service Set Identifier (network name).
     * @param securityType Wi-Fi security protocol (e.g., "WPA2", "WPA3", "WEP").
     */
    WiFiCredential(const std::string& service = {},
                   const std::string& username = {},
                   const std::string& password = {},
                   const std::string& notes = {},
                   const std::string& ssid = {},
                   const std::string& securityType = {});

    /**
     * @brief Gets the credential type identifier ("wifi").
     * @return String literal "wifi".
     */
    std::string getType() const override;

    /**
     * @brief Gets the wireless network SSID.
     * @return Const reference to SSID string.
     */
    const std::string& getSsid() const;

    /**
     * @brief Gets the Wi-Fi security protocol type.
     * @return Const reference to security type string.
     */
    const std::string& getSecurityType() const;

    /**
     * @brief Sets the wireless network SSID.
     * @param ssid The SSID name string.
     */
    void setSsid(const std::string& ssid);

    /**
     * @brief Sets the Wi-Fi security protocol type.
     * @param securityType Security protocol string (e.g., "WPA2", "WPA3").
     */
    void setSecurityType(const std::string& securityType);

    /**
     * @brief Displays Wi-Fi credential details to standard output.
     * @param showPassword Whether to print the plaintext password.
     */
    void display(bool showPassword) const override;

    /**
     * @brief Creates a polymorphic deep copy of this WiFiCredential.
     * @return Raw pointer to newly allocated WiFiCredential copy.
     */
    Credential* clone() const override;

    /**
     * @brief Serializes the Wi-Fi credential to a binary output stream.
     * @param stream The output stream to write binary data into.
     */
    void serialize(std::ostream& stream) const override;

    /**
     * @brief Deserializes the Wi-Fi credential from a binary input stream.
     * @param stream The input stream to read binary data from.
     */
    void deserialize(std::istream& stream) override;

    /**
     * @brief Checks if the credential matches a given search query (including SSID).
     * @param query Search string to test against fields.
     * @return True if query matches service, username, notes, or SSID.
     */
    bool matches(const std::string& query) const override;
};

#endif // WIFI_CREDENTIAL_H
