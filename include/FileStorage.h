#ifndef FILE_STORAGE_H
#define FILE_STORAGE_H

#include <string>
#include <vector>
#include "Credential.h"

class FileStorage {
private:
    std::string filePath;

    static std::string resolvePath(const std::string& path);
    static void writeString(std::ostream& os, const std::string& str);
    static std::string readString(std::istream& is);

public:
    explicit FileStorage(const std::string& path = "data/vault.bin");

    bool save(const std::vector<Credential>& credentials) const;
    std::vector<Credential> load() const;

    const std::string& getFilePath() const;
    void setFilePath(const std::string& path);
};

#endif // FILE_STORAGE_H
