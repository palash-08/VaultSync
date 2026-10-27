#ifndef BACKUP_CONFIG_H
#define BACKUP_CONFIG_H

#include <string>

/**
 * @brief Configuration parameters for off-site SFTP backup over Tailscale.
 *
 * Config file is stored at $XDG_CONFIG_HOME/vaultsync/backup.conf
 * (defaulting to ~/.config/vaultsync/backup.conf) with restrictive 0600 POSIX permissions.
 */
struct BackupConfig {
    enum class AuthMethod {
        Key,
        Password
    };

    std::string host;               ///< Remote host (Tailscale MagicDNS name e.g., "backup-node" or 100.x.y.z)
    int port = 22;                  ///< SSH/SFTP port (default: 22)
    std::string user;               ///< Remote SSH username (default: current local user if empty)
    std::string remoteDir = "backups/vaultsync"; ///< Remote directory path (default: "backups/vaultsync")
    AuthMethod authMethod = AuthMethod::Key;     ///< Authentication mode: Key (default) or Password
    std::string identityFile;       ///< Private key path (e.g., "~/.ssh/id_ed25519")
    std::string password;           ///< Remote SFTP password (for password-based authentication)
    int connectTimeout = 5;         ///< Connection timeout in seconds (default: 5)

    /**
     * @brief Returns string representation of auth method ("key" or "password").
     */
    std::string getAuthMethodString() const;

    /**
     * @brief Sets auth method from string ("key" or "password").
     */
    void setAuthMethodFromString(const std::string& method);

    /**
     * @brief Checks if the configuration is populated with minimum necessary fields (host not empty).
     */
    bool isValid() const;

    /**
     * @brief Resolves default configuration path: $XDG_CONFIG_HOME/vaultsync/backup.conf.
     */
    static std::string getDefaultConfigPath();

    /**
     * @brief Loads configuration from file. If file does not exist, returns defaults.
     * @param configPath Path to config file (empty string uses getDefaultConfigPath()).
     */
    static BackupConfig loadFromFile(const std::string& configPath = "");

    /**
     * @brief Saves configuration to file with 0600 POSIX permissions.
     * @param configPath Path to config file (empty string uses getDefaultConfigPath()).
     * @return true if successfully written and permissions applied; false otherwise.
     */
    bool saveToFile(const std::string& configPath = "") const;

    /**
     * @brief Expands leading '~' to the user's home directory if present.
     */
    static std::string expandPath(const std::string& path);
};

#endif // BACKUP_CONFIG_H
