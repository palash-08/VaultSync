#ifndef FILE_STORAGE_H
#define FILE_STORAGE_H

#include <string>
#include <vector>
#include <memory>
#include <iosfwd>
#include <cstdint>
#include "Credential.h"
#include "ICipher.h"

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
    static void writeString(std::ostream& os, const std::string& str);
    static std::string readString(std::istream& is);

    static void serializeCredentials(std::ostream& os, const std::vector<Credential>& credentials);
    static std::vector<Credential> deserializeCredentials(std::istream& is);

public:
    explicit FileStorage(const std::string& path = "data/vault.bin",
                         std::shared_ptr<ICipher> cipher = nullptr);

    bool save(const std::vector<Credential>& credentials) const;
    std::vector<Credential> load();

    bool readHeader(std::string& outUsername,
                    std::string& outMasterSalt, std::string& outMasterHash,
                    std::string& outCredSalt, std::string& outCredHash,
                    uint32_t& outVersion) const;

    // Backward-compatibility overload without username
    bool readHeader(std::string& outMasterSalt, std::string& outMasterHash,
                    std::string& outCredSalt, std::string& outCredHash,
                    uint32_t& outVersion) const;

    bool readHeader(std::string& outSalt, std::string& outHash, uint32_t& outVersion) const;

    const std::string& getFilePath() const;
    void setFilePath(const std::string& path);

    std::shared_ptr<ICipher> getCipher() const;
    void setCipher(std::shared_ptr<ICipher> cipher);

    const std::string& getUsername() const;
    void setUsername(const std::string& user);

    const std::string& getMasterSalt() const;
    void setMasterSalt(const std::string& salt);

    const std::string& getMasterPasswordHash() const;
    void setMasterPasswordHash(const std::string& hash);

    const std::string& getCredSalt() const;
    void setCredSalt(const std::string& salt);

    const std::string& getCredPasswordHash() const;
    void setCredPasswordHash(const std::string& hash);
};

#endif // FILE_STORAGE_H
