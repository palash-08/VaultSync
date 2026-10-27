#ifndef NATIVE_HOST_H
#define NATIVE_HOST_H

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "auth/MasterVault.h"
#include "credentials/Credential.h"
#include "credentials/WebCredential.h"

/**
 * @brief Handles Chromium Native Messaging protocol communication, binary framing,
 *        and JSON action dispatching for the VaultSync extension companion.
 */
class NativeHost {
public:
    static constexpr uint32_t MAX_MESSAGE_SIZE = 1024 * 1024; // 1 MB Chromium limit

private:
    MasterVault vault;
    std::string activeUser;
    std::string cachedCredPassword;

    /**
     * @brief Securely zeroes sensitive string memory using OPENSSL_cleanse.
     * @param str String whose buffer will be wiped.
     */
    static void cleanseString(std::string& str);

public:
    /**
     * @brief Constructs a NativeHost instance.
     * @param vaultPath Optional custom vault file path.
     */
    explicit NativeHost(const std::string& vaultPath = "");

    /**
     * @brief Destructor that wipes cached credentials and locks the vault.
     */
    ~NativeHost();

    NativeHost(const NativeHost&) = delete;
    NativeHost& operator=(const NativeHost&) = delete;
    NativeHost(NativeHost&&) noexcept = default;
    NativeHost& operator=(NativeHost&&) noexcept = default;

    /**
     * @brief Reads a 4-byte length-prefixed message from a binary stream.
     * @param in Input stream (e.g. std::cin).
     * @param outJson String to receive the JSON payload.
     * @return True if read succeeded; false on EOF, error, or size > 1MB.
     */
    static bool readMessage(std::istream& in, std::string& outJson);

    /**
     * @brief Writes a 4-byte length-prefixed message to a binary stream.
     * @param out Output stream (e.g. std::cout).
     * @param json JSON payload to send.
     * @return True if write and flush succeeded; false otherwise.
     */
    static bool writeMessage(std::ostream& out, const std::string& json);

    /**
     * @brief Extracts canonical domain name from URL (e.g. "https://github.com/login" -> "github.com").
     * @param url Full or partial URL.
     * @return Lowercase canonical host/domain.
     */
    static std::string extractDomain(const std::string& url);

    /**
     * @brief Extracts lowercase scheme from URL (e.g. "https://github.com" -> "https").
     * @param url Full or partial URL.
     * @return Lowercase scheme or empty string if no scheme present.
     */
    static std::string extractScheme(const std::string& url);

    /**
     * @brief Extracts explicit port string from URL (e.g. "http://localhost:8080" -> "8080").
     * @param url Full or partial URL.
     * @return Port string or empty string if no explicit port present.
     */
    static std::string extractPort(const std::string& url);

    /**
     * @brief Dispatches a JSON request string to the corresponding VaultSync action.
     * @param requestJson Raw JSON string received from Chromium.
     * @return Formatted JSON response string.
     */
    std::string handleMessage(const std::string& requestJson);

    /**
     * @brief Executes the message loop on the provided streams until EOF.
     * @param in Input stream.
     * @param out Output stream.
     */
    void run(std::istream& in, std::ostream& out);

    /**
     * @brief Returns reference to underlying MasterVault instance (used in unit tests).
     */
    MasterVault& getVault();

    /**
     * @brief Returns active session username.
     */
    const std::string& getActiveUser() const;
};

#endif // NATIVE_HOST_H
