#include "storage/BackupConfig.h"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <sys/stat.h>

namespace fs = std::filesystem;

namespace {

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return s;
}

} // anonymous namespace

bool BackupConfig::isValid() const {
    return !host.empty() && port > 0 && port <= 65535 && connectTimeout > 0;
}

std::string BackupConfig::getAuthMethodString() const {
    return (authMethod == AuthMethod::Password) ? "password" : "key";
}

void BackupConfig::setAuthMethodFromString(const std::string& method) {
    std::string m = toLower(trim(method));
    if (m == "password") {
        authMethod = AuthMethod::Password;
    } else {
        authMethod = AuthMethod::Key;
    }
}

std::string BackupConfig::expandPath(const std::string& path) {
    if (path.rfind("~/", 0) == 0) {
        const char* home = std::getenv("HOME");
        if (home != nullptr) {
            return std::string(home) + path.substr(1);
        }
    }
    return path;
}

std::string BackupConfig::getDefaultConfigPath() {
    const char* xdgConfig = std::getenv("XDG_CONFIG_HOME");
    if (xdgConfig != nullptr && xdgConfig[0] != '\0') {
        return std::string(xdgConfig) + "/vaultsync/backup.conf";
    }

    const char* home = std::getenv("HOME");
    if (home != nullptr && home[0] != '\0') {
        return std::string(home) + "/.config/vaultsync/backup.conf";
    }

    return "data/backup.conf";
}

BackupConfig BackupConfig::loadFromFile(const std::string& configPath) {
    BackupConfig config;
    std::string path = configPath.empty() ? getDefaultConfigPath() : configPath;

    std::ifstream file(path);
    if (!file.is_open()) {
        return config;
    }

    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';' || line[0] == '[') {
            continue;
        }

        size_t eqPos = line.find('=');
        if (eqPos == std::string::npos) {
            continue;
        }

        std::string key = toLower(trim(line.substr(0, eqPos)));
        std::string val = trim(line.substr(eqPos + 1));

        if (key == "host") {
            config.host = val;
        } else if (key == "port") {
            try { config.port = std::stoi(val); } catch (...) {}
        } else if (key == "user") {
            config.user = val;
        } else if (key == "remote_dir" || key == "remotedir") {
            config.remoteDir = val;
        } else if (key == "auth_method" || key == "authmethod") {
            config.setAuthMethodFromString(val);
        } else if (key == "identity_file" || key == "identityfile") {
            config.identityFile = val;
        } else if (key == "password") {
            config.password = val;
        } else if (key == "connect_timeout" || key == "connecttimeout") {
            try { config.connectTimeout = std::stoi(val); } catch (...) {}
        }
    }

    return config;
}

bool BackupConfig::saveToFile(const std::string& configPath) const {
    std::string path = configPath.empty() ? getDefaultConfigPath() : configPath;

    try {
        fs::path parent = fs::path(path).parent_path();
        if (!parent.empty()) {
            fs::create_directories(parent);
            ::chmod(parent.c_str(), S_IRWXU); // 0700
        }

        std::ofstream file(path, std::ios::trunc);
        if (!file.is_open()) {
            return false;
        }

        file << "# VaultSync Off-Site Backup Configuration\n";
        file << "# Encrypted off-site sync target via Tailscale tailnet & SFTP\n";
        file << "[remote]\n";
        file << "host = " << host << "\n";
        file << "port = " << port << "\n";
        file << "user = " << user << "\n";
        file << "remote_dir = " << remoteDir << "\n";
        file << "auth_method = " << getAuthMethodString() << "\n";
        file << "identity_file = " << identityFile << "\n";
        if (authMethod == AuthMethod::Password && !password.empty()) {
            file << "password = " << password << "\n";
        }
        file << "connect_timeout = " << connectTimeout << "\n";
        file.close();

        ::chmod(path.c_str(), S_IRUSR | S_IWUSR); // 0600
        return true;
    } catch (...) {
        return false;
    }
}
