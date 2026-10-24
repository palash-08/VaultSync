#ifndef SFTP_SUBPROCESS_CLIENT_H
#define SFTP_SUBPROCESS_CLIENT_H

#include "storage/BackupConfig.h"
#include <string>

/**
 * @brief Subprocess-based SFTP client for executing headless off-site backups via OpenSSH (/usr/bin/sftp).
 *
 * Implements atomic two-phase commit over SFTP without invoking /bin/sh shell interpreters.
 */
class SftpSubprocessClient {
public:
    struct BackupResult {
        bool success = false;
        int exitCode = -1;
        std::string message;
        std::string destination;
        std::string remoteFile;
    };

    /**
     * @brief Executes an atomic SFTP backup of the specified local vault file using /usr/bin/sftp.
     * 
     * Uses POSIX pipe, fork, and execvp without invoking any shell interpreter (/bin/sh).
     * 
     * @param localVaultPath Path to local encrypted vault (e.g. ~/.local/state/vaultsync/vault_alice.bin)
     * @param config Backup connection and target settings
     * @return BackupResult containing exit code, status, and descriptive message
     */
    static BackupResult executeBackup(const std::string& localVaultPath, const BackupConfig& config);

    /**
     * @brief Generates the atomic batch script commands for SFTP stdin.
     */
    static std::string generateBatchScript(const std::string& localVaultPath,
                                           const std::string& remoteDir,
                                           const std::string& baseStem,
                                           const std::string& timestamp);

    /**
     * @brief Generates an ISO-style compact timestamp string (YYYYMMDD_HHMMSS).
     */
    static std::string getCurrentTimestamp();
};

#endif // SFTP_SUBPROCESS_CLIENT_H
