#include "FileStorage.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <cstdint>

namespace fs = std::filesystem;

FileStorage::FileStorage(const std::string& path, std::shared_ptr<ICipher> cipher)
    : filePath(path),
      cipher(std::move(cipher))
{
}

std::string FileStorage::resolvePath(const std::string& path) {
    if (fs::exists(path)) {
        return path;
    }
    if (fs::exists("../" + path)) {
        return "../" + path;
    }
    fs::path p(path);
    if (p.has_parent_path()) {
        fs::create_directories(p.parent_path());
    }
    return path;
}

void FileStorage::writeString(std::ostream& os, const std::string& str) {
    uint32_t len = static_cast<uint32_t>(str.size());
    os.write(reinterpret_cast<const char*>(&len), sizeof(len));
    if (len > 0) {
        os.write(str.data(), len);
    }
}

std::string FileStorage::readString(std::istream& is) {
    uint32_t len = 0;
    is.read(reinterpret_cast<char*>(&len), sizeof(len));
    if (!is || len == 0) {
        return "";
    }
    std::string str(len, '\0');
    is.read(&str[0], len);
    return str;
}

void FileStorage::serializeCredentials(std::ostream& os, const std::vector<Credential>& credentials) {
    uint32_t count = static_cast<uint32_t>(credentials.size());
    os.write(reinterpret_cast<const char*>(&count), sizeof(count));

    for (const auto& cred : credentials) {
        writeString(os, cred.getService());
        writeString(os, cred.getUsername());
        writeString(os, cred.getPassword());
        writeString(os, cred.getNotes());
    }
}

std::vector<Credential> FileStorage::deserializeCredentials(std::istream& is) {
    std::vector<Credential> result;
    uint32_t count = 0;
    is.read(reinterpret_cast<char*>(&count), sizeof(count));
    if (!is) {
        return result;
    }

    result.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        std::string service = readString(is);
        std::string user = readString(is);
        std::string password = readString(is);
        std::string notes = readString(is);

        if (!is) {
            std::cerr << "[FileStorage] Warning: Unexpected end of file while reading credentials.\n";
            break;
        }
        result.emplace_back(service, user, password, notes);
    }

    return result;
}

bool FileStorage::readHeader(std::string& outUsername,
                            std::string& outMasterSalt, std::string& outMasterHash,
                            std::string& outCredSalt, std::string& outCredHash,
                            uint32_t& outVersion) const {
    std::string actualPath = resolvePath(filePath);
    std::ifstream in(actualPath, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }

    char magic[4] = {0};
    in.read(magic, sizeof(magic));
    if (magic[0] != 'V' || magic[1] != 'S' || magic[2] != 'Y' || magic[3] != 'N') {
        return false;
    }

    uint32_t version = 0;
    in.read(reinterpret_cast<char*>(&version), sizeof(version));
    outVersion = version;

    if (version == 4) {
        outUsername = readString(in);
        outMasterSalt = readString(in);
        outMasterHash = readString(in);
        outCredSalt = readString(in);
        outCredHash = readString(in);
        return true;
    } else if (version == 3) {
        outUsername = "";
        outMasterSalt = readString(in);
        outMasterHash = readString(in);
        outCredSalt = readString(in);
        outCredHash = readString(in);
        return true;
    } else if (version == 2) {
        outUsername = "";
        outMasterSalt = readString(in);
        outMasterHash = readString(in);
        outCredSalt = "";
        outCredHash = "";
        return true;
    } else if (version == 1) {
        outUsername = "";
        outMasterSalt = "";
        outMasterHash = "";
        outCredSalt = "";
        outCredHash = "";
        return true;
    }

    return false;
}

bool FileStorage::readHeader(std::string& outMasterSalt, std::string& outMasterHash,
                            std::string& outCredSalt, std::string& outCredHash,
                            uint32_t& outVersion) const {
    std::string dummyUser;
    return readHeader(dummyUser, outMasterSalt, outMasterHash, outCredSalt, outCredHash, outVersion);
}

bool FileStorage::readHeader(std::string& outSalt, std::string& outHash, uint32_t& outVersion) const {
    std::string dummyUser, dummyCredSalt, dummyCredHash;
    return readHeader(dummyUser, outSalt, outHash, dummyCredSalt, dummyCredHash, outVersion);
}

bool FileStorage::save(const std::vector<Credential>& credentials) const {
    std::string actualPath = resolvePath(filePath);
    std::ofstream out(actualPath, std::ios::binary);
    if (!out.is_open()) {
        return false;
    }

    // Write 4-byte magic identifier 'VSYN' (VaultSync)
    const char magic[4] = {'V', 'S', 'Y', 'N'};
    out.write(magic, sizeof(magic));

    if (!username.empty() || !masterSalt.empty() || !credSalt.empty()) {
        // Version 4: Supports username identifier + dual authentication metadata
        uint32_t version = 4;
        out.write(reinterpret_cast<const char*>(&version), sizeof(version));
        writeString(out, username);
        writeString(out, masterSalt);
        writeString(out, masterPasswordHash);
        writeString(out, credSalt);
        writeString(out, credPasswordHash);
    } else {
        // Version 1: Raw cipher test mode
        uint32_t version = 1;
        out.write(reinterpret_cast<const char*>(&version), sizeof(version));
    }

    // Serialize credential records into byte buffer
    std::ostringstream buffer(std::ios::binary);
    serializeCredentials(buffer, credentials);
    std::string serializedStr = buffer.str();
    std::vector<uint8_t> payload(serializedStr.begin(), serializedStr.end());

    // If an ICipher is attached, encrypt payload before writing to disk
    if (cipher) {
        payload = cipher->encrypt(payload);
    }

    if (!payload.empty()) {
        out.write(reinterpret_cast<const char*>(payload.data()), payload.size());
    }

    return out.good();
}

std::vector<Credential> FileStorage::load() {
    std::vector<Credential> result;
    std::string actualPath = resolvePath(filePath);
    std::ifstream in(actualPath, std::ios::binary);
    if (!in.is_open()) {
        return result;
    }

    // Verify 4-byte magic identifier
    char magic[4] = {0};
    in.read(magic, sizeof(magic));
    if (magic[0] != 'V' || magic[1] != 'S' || magic[2] != 'Y' || magic[3] != 'N') {
        std::cerr << "[FileStorage] Warning: Invalid or corrupted vault file header.\n";
        return result;
    }

    // Verify format version
    uint32_t version = 0;
    in.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version == 4) {
        username = readString(in);
        masterSalt = readString(in);
        masterPasswordHash = readString(in);
        credSalt = readString(in);
        credPasswordHash = readString(in);
    } else if (version == 3) {
        masterSalt = readString(in);
        masterPasswordHash = readString(in);
        credSalt = readString(in);
        credPasswordHash = readString(in);
    } else if (version == 2) {
        masterSalt = readString(in);
        masterPasswordHash = readString(in);
    } else if (version != 1) {
        std::cerr << "[FileStorage] Warning: Unsupported vault file version: " << version << "\n";
        return result;
    }

    // Read remaining payload from file
    std::vector<uint8_t> payload((std::istreambuf_iterator<char>(in)),
                                  std::istreambuf_iterator<char>());

    if (payload.empty()) {
        return result;
    }

    // If an ICipher is attached, decrypt payload before deserializing
    if (cipher) {
        payload = cipher->decrypt(payload);
    }

    std::string decryptedStr(payload.begin(), payload.end());
    std::istringstream buffer(decryptedStr, std::ios::binary);
    return deserializeCredentials(buffer);
}

const std::string& FileStorage::getFilePath() const {
    return filePath;
}

void FileStorage::setFilePath(const std::string& path) {
    this->filePath = path;
}

std::shared_ptr<ICipher> FileStorage::getCipher() const {
    return cipher;
}

void FileStorage::setCipher(std::shared_ptr<ICipher> cipher) {
    this->cipher = std::move(cipher);
}

const std::string& FileStorage::getUsername() const {
    return username;
}

void FileStorage::setUsername(const std::string& user) {
    this->username = user;
}

const std::string& FileStorage::getMasterSalt() const {
    return masterSalt;
}

void FileStorage::setMasterSalt(const std::string& salt) {
    this->masterSalt = salt;
}

const std::string& FileStorage::getMasterPasswordHash() const {
    return masterPasswordHash;
}

void FileStorage::setMasterPasswordHash(const std::string& hash) {
    this->masterPasswordHash = hash;
}

const std::string& FileStorage::getCredSalt() const {
    return credSalt;
}

void FileStorage::setCredSalt(const std::string& salt) {
    this->credSalt = salt;
}

const std::string& FileStorage::getCredPasswordHash() const {
    return credPasswordHash;
}

void FileStorage::setCredPasswordHash(const std::string& hash) {
    this->credPasswordHash = hash;
}
