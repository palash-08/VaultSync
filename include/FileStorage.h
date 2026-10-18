#ifndef FILE_STORAGE_H
#define FILE_STORAGE_H

#include "Credential.h"
#include "ICipher.h"

#include <cstdint>
#include <iosfwd>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Manages encrypted and authenticated binary persistence for vault data.
 *
 * Handles file I/O, format versioning, headers (salts, password hashes, usernames),
 * and binary serialization of credentials with optional symmetric encryption via ICipher.
 */
class FileStorage {
private:
    std::string filePath;
    std::shared_ptr<ICipher> cipher;
    std::string username;
    std::string masterSalt;
    std::string masterPasswordHash;
    std::string credSalt;
    std::string credPasswordHash;

    static std::string resolvePath(const std::string& path);
    static void writeString(std::ostream& stream, const std::string& str);
    static std::string readString(std::istream& stream);

    static void serializeCredentials(std::ostream& stream, const std::vector<Credential>& credentials);
    static std::vector<Credential> deserializeCredentials(std::istream& stream);
    static void serializePolymorphic(std::ostream& stream,
                                     const std::vector<std::shared_ptr<Credential>>& credentials);
    static std::vector<std::shared_ptr<Credential>> deserializePolymorphic(std::istream& stream);

public:
    /**
     * @brief Constructs a FileStorage instance.
     * @param path File system path to the binary vault file.
     * @param cipher Optional cipher implementation for encrypting stored credentials.
     */
    explicit FileStorage(const std::string& path = "data/vault.bin",
                         std::shared_ptr<ICipher> cipher = nullptr);

    /**
     * @brief Saves a list of value-type credentials to the vault file.
     * @param credentials Vector of Credential objects to persist.
     * @return True if save succeeded; false otherwise.
     */
    bool save(const std::vector<Credential>& credentials) const;

    /**
     * @brief Saves a collection of polymorphic credentials to the vault file (version 5).
     * @param credentials Vector of shared pointers to Credential instances.
     * @return True if save succeeded; false otherwise.
     */
    bool save(const std::vector<std::shared_ptr<Credential>>& credentials) const;

    /**
     * @brief Loads value-type credentials from the vault file.
     * @return Vector of restored Credential objects.
     */
    std::vector<Credential> load();

    /**
     * @brief Loads polymorphic credentials from the vault file.
     * @return Vector of shared pointers to restored Credential objects.
     */
    std::vector<std::shared_ptr<Credential>> loadPolymorphic();

    /**
     * @brief Reads the vault file header including username, salts, hashes, and version.
     * @param outUsername Output parameter receiving the stored username.
     * @param outMasterSalt Output parameter receiving the master salt.
     * @param outMasterHash Output parameter receiving the master password hash.
     * @param outCredSalt Output parameter receiving the credential salt.
     * @param outCredHash Output parameter receiving the credential password hash.
     * @param outVersion Output parameter receiving the file format version.
     * @return True if header was read successfully; false otherwise.
     */
    bool readHeader(std::string& outUsername,
                    std::string& outMasterSalt,
                    std::string& outMasterHash,
                    std::string& outCredSalt,
                    std::string& outCredHash,
                    uint32_t& outVersion) const;

    /**
     * @brief Backward-compatibility header reader without username.
     * @param outMasterSalt Output parameter receiving the master salt.
     * @param outMasterHash Output parameter receiving the master password hash.
     * @param outCredSalt Output parameter receiving the credential salt.
     * @param outCredHash Output parameter receiving the credential password hash.
     * @param outVersion Output parameter receiving the file format version.
     * @return True if header was read successfully; false otherwise.
     */
    bool readHeader(std::string& outMasterSalt,
                    std::string& outMasterHash,
                    std::string& outCredSalt,
                    std::string& outCredHash,
                    uint32_t& outVersion) const;

    /**
     * @brief Backward-compatibility header reader for single-hash formats.
     * @param outSalt Output parameter receiving the salt.
     * @param outHash Output parameter receiving the hash.
     * @param outVersion Output parameter receiving the version.
     * @return True if header was read successfully; false otherwise.
     */
    bool readHeader(std::string& outSalt,
                    std::string& outHash,
                    uint32_t& outVersion) const;

    /**
     * @brief Gets the configured vault file path.
     * @return Const reference to file path string.
     */
    const std::string& getFilePath() const;

    /**
     * @brief Sets the vault file path.
     * @param path New file system path.
     */
    void setFilePath(const std::string& path);

    /**
     * @brief Gets the active cipher.
     * @return Shared pointer to ICipher instance, or nullptr if disabled.
     */
    std::shared_ptr<ICipher> getCipher() const;

    /**
     * @brief Sets the active cipher for encryption and decryption.
     * @param cipher Shared pointer to ICipher implementation.
     */
    void setCipher(std::shared_ptr<ICipher> cipher);

    /**
     * @brief Gets the configured username.
     * @return Const reference to username string.
     */
    const std::string& getUsername() const;

    /**
     * @brief Sets the username to be persisted in the file header.
     * @param user Username string.
     */
    void setUsername(const std::string& user);

    /**
     * @brief Gets the master password salt.
     * @return Const reference to salt string.
     */
    const std::string& getMasterSalt() const;

    /**
     * @brief Sets the master password salt.
     * @param salt Salt string.
     */
    void setMasterSalt(const std::string& salt);

    /**
     * @brief Gets the master password hash.
     * @return Const reference to hash string.
     */
    const std::string& getMasterPasswordHash() const;

    /**
     * @brief Sets the master password hash.
     * @param hash Hash string.
     */
    void setMasterPasswordHash(const std::string& hash);

    /**
     * @brief Gets the credential password salt.
     * @return Const reference to salt string.
     */
    const std::string& getCredSalt() const;

    /**
     * @brief Sets the credential password salt.
     * @param salt Salt string.
     */
    void setCredSalt(const std::string& salt);

    /**
     * @brief Gets the credential password hash.
     * @return Const reference to hash string.
     */
    const std::string& getCredPasswordHash() const;

    /**
     * @brief Sets the credential password hash.
     * @param hash Hash string.
     */
    void setCredPasswordHash(const std::string& hash);
};

#endif // FILE_STORAGE_H
