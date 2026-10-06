#include "FileStorage.h"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <cstdint>

namespace fs = std::filesystem;

FileStorage::FileStorage(const std::string& path)
    : filePath(path)
{
}

std::string FileStorage::resolvePath(const std::string& path) {
    if (fs::exists(path)) {
        return path;
    }
    if (fs::exists("../" + path)) {
        return "../" + path;
    }
    // Ensure parent directory exists if creating for the first time
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

bool FileStorage::save(const std::vector<Credential>& credentials) const {
    std::string actualPath = resolvePath(filePath);
    std::ofstream out(actualPath, std::ios::binary);
    if (!out.is_open()) {
        return false;
    }

    // Write 4-byte magic identifier 'VSYN' (VaultSync)
    const char magic[4] = {'V', 'S', 'Y', 'N'};
    out.write(magic, sizeof(magic));

    // Write format version (1)
    uint32_t version = 1;
    out.write(reinterpret_cast<const char*>(&version), sizeof(version));

    // Write number of credentials
    uint32_t count = static_cast<uint32_t>(credentials.size());
    out.write(reinterpret_cast<const char*>(&count), sizeof(count));

    // Write each credential's fields
    for (const auto& cred : credentials) {
        writeString(out, cred.getService());
        writeString(out, cred.getUsername());
        writeString(out, cred.getPassword());
        writeString(out, cred.getNotes());
    }

    return out.good();
}

std::vector<Credential> FileStorage::load() const {
    std::vector<Credential> result;
    std::string actualPath = resolvePath(filePath);
    std::ifstream in(actualPath, std::ios::binary);
    if (!in.is_open()) {
        // File does not exist yet (normal on first launch)
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
    if (version != 1) {
        std::cerr << "[FileStorage] Warning: Unsupported vault file version: " << version << "\n";
        return result;
    }

    // Read credential count
    uint32_t count = 0;
    in.read(reinterpret_cast<char*>(&count), sizeof(count));
    if (!in) {
        return result;
    }

    result.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        std::string service = readString(in);
        std::string username = readString(in);
        std::string password = readString(in);
        std::string notes = readString(in);

        if (!in) {
            std::cerr << "[FileStorage] Warning: Unexpected end of file while reading credentials.\n";
            break;
        }
        result.emplace_back(service, username, password, notes);
    }

    return result;
}

const std::string& FileStorage::getFilePath() const {
    return filePath;
}

void FileStorage::setFilePath(const std::string& path) {
    this->filePath = path;
}
