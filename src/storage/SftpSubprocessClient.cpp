#include "storage/SftpSubprocessClient.h"

#include <unistd.h>
#include <sys/wait.h>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <sstream>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;

namespace {

std::string escapeSftpPath(const std::string& path) {
    std::string escaped;
    for (char c : path) {
        if (c == '"' || c == '\\') {
            escaped.push_back('\\');
        }
        escaped.push_back(c);
    }
    return escaped;
}

std::string trimLines(const std::string& text) {
    std::string result;
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        size_t first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        size_t last = line.find_last_not_of(" \t\r\n");
        std::string cleaned = line.substr(first, (last - first + 1));
        if (!cleaned.empty()) {
            if (!result.empty()) result += " | ";
            result += cleaned;
        }
    }
    return result;
}

} // anonymous namespace

std::string SftpSubprocessClient::getCurrentTimestamp() {
    std::time_t now = std::time(nullptr);
    std::tm t{};
    ::localtime_r(&now, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &t);
    return std::string(buf);
}

std::string SftpSubprocessClient::generateBatchScript(const std::string& localVaultPath,
                                                     const std::string& remoteDir,
                                                     const std::string& baseStem,
                                                     const std::string& timestamp) {
    std::ostringstream script;
    std::string localEscaped = escapeSftpPath(localVaultPath);
    std::string tmpName = escapeSftpPath(baseStem + ".bin.tmp");
    std::string stampName = escapeSftpPath(baseStem + "_" + timestamp + ".bin");
    std::string latestName = escapeSftpPath(baseStem + "_latest.bin");

    if (!remoteDir.empty() && remoteDir != ".") {
        std::string dirEscaped = escapeSftpPath(remoteDir);
        // '-' prefix informs sftp not to terminate if mkdir fails (e.g. dir exists)
        script << "-mkdir \"" << dirEscaped << "\"\n";
        script << "cd \"" << dirEscaped << "\"\n";
    }

    // Atomic two-phase commit: upload to .tmp then rename
    script << "put \"" << localEscaped << "\" \"" << tmpName << "\"\n";
    script << "rename \"" << tmpName << "\" \"" << stampName << "\"\n";
    script << "-symlink \"" << stampName << "\" \"" << latestName << "\"\n";
    script << "quit\n";

    return script.str();
}

SftpSubprocessClient::BackupResult SftpSubprocessClient::executeBackup(const std::string& localVaultPath,
                                                                       const BackupConfig& config) {
    BackupResult result;

    if (!fs::exists(localVaultPath)) {
        result.success = false;
        result.exitCode = -1;
        result.message = "Local vault file does not exist: " + localVaultPath;
        return result;
    }

    if (!config.isValid()) {
        result.success = false;
        result.exitCode = -1;
        result.message = "Remote backup host is not configured. Please set host in backup settings.";
        return result;
    }

    std::string target = config.user.empty() ? config.host : (config.user + "@" + config.host);
    result.destination = target;

    std::string stem = fs::path(localVaultPath).stem().string();
    std::string timestamp = getCurrentTimestamp();
    std::string timestampedFile = stem + "_" + timestamp + ".bin";
    result.remoteFile = timestampedFile;

    std::string batchScript = generateBatchScript(localVaultPath, config.remoteDir, stem, timestamp);

    int stdinPipe[2];
    int outPipe[2];

    if (::pipe(stdinPipe) < 0) {
        result.success = false;
        result.exitCode = -1;
        result.message = "Failed to create stdin pipe for subprocess.";
        return result;
    }

    if (::pipe(outPipe) < 0) {
        ::close(stdinPipe[0]);
        ::close(stdinPipe[1]);
        result.success = false;
        result.exitCode = -1;
        result.message = "Failed to create stdout pipe for subprocess.";
        return result;
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(stdinPipe[0]);
        ::close(stdinPipe[1]);
        ::close(outPipe[0]);
        ::close(outPipe[1]);
        result.success = false;
        result.exitCode = -1;
        result.message = "Failed to fork subprocess.";
        return result;
    }

    if (pid == 0) {
        // Child Process
        ::dup2(stdinPipe[0], STDIN_FILENO);
        ::dup2(outPipe[1], STDOUT_FILENO);
        ::dup2(outPipe[1], STDERR_FILENO);

        ::close(stdinPipe[0]);
        ::close(stdinPipe[1]);
        ::close(outPipe[0]);
        ::close(outPipe[1]);

        std::vector<std::string> argStrings;
        argStrings.push_back("sftp");
        argStrings.push_back("-b");
        argStrings.push_back("-"); // Read commands from stdin stream
        argStrings.push_back("-P");
        argStrings.push_back(std::to_string(config.port));
        argStrings.push_back("-o");
        argStrings.push_back("BatchMode=yes");
        argStrings.push_back("-o");
        argStrings.push_back("ConnectTimeout=" + std::to_string(config.connectTimeout));
        argStrings.push_back("-o");
        argStrings.push_back("StrictHostKeyChecking=accept-new");

        if (!config.identityFile.empty()) {
            argStrings.push_back("-i");
            argStrings.push_back(BackupConfig::expandPath(config.identityFile));
        }

        argStrings.push_back(target);

        std::vector<char*> cArgs;
        for (auto& s : argStrings) {
            cArgs.push_back(s.data());
        }
        cArgs.push_back(nullptr);

        ::execvp("sftp", cArgs.data());

        // Reached only if execvp failed
        const char* err = "execvp(sftp) failed: check if sftp is installed in PATH\n";
        ::write(STDERR_FILENO, err, std::strlen(err));
        ::_exit(127);
    }

    // Parent Process
    ::close(stdinPipe[0]);
    ::close(outPipe[1]);

    // Send batch script to child stdin
    size_t totalWritten = 0;
    while (totalWritten < batchScript.size()) {
        ssize_t w = ::write(stdinPipe[1], batchScript.data() + totalWritten, batchScript.size() - totalWritten);
        if (w <= 0) break;
        totalWritten += static_cast<size_t>(w);
    }
    ::close(stdinPipe[1]); // Close write end to signal EOF to sftp

    // Read captured stdout/stderr from child
    std::string capturedOutput;
    char buffer[1024];
    ssize_t bytesRead = 0;
    while ((bytesRead = ::read(outPipe[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytesRead] = '\0';
        capturedOutput.append(buffer, bytesRead);
    }
    ::close(outPipe[0]);

    int status = 0;
    ::waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
        result.exitCode = WEXITSTATUS(status);
        if (result.exitCode == 0) {
            result.success = true;
            result.message = "Vault successfully backed up to " + target + ":" + config.remoteDir + "/" + timestampedFile;
        } else if (result.exitCode == 127) {
            result.success = false;
            result.message = "OpenSSH sftp executable not found in PATH.";
        } else if (result.exitCode == 255) {
            result.success = false;
            std::string errStr = trimLines(capturedOutput);
            if (errStr.empty()) errStr = "Host unreachable or connection timed out.";
            result.message = "SFTP connection error: " + errStr;
        } else {
            result.success = false;
            std::string errStr = trimLines(capturedOutput);
            result.message = "SFTP failed (code " + std::to_string(result.exitCode) + "): " + errStr;
        }
    } else if (WIFSIGNALED(status)) {
        result.exitCode = 128 + WTERMSIG(status);
        result.success = false;
        result.message = "SFTP subprocess killed by signal " + std::to_string(WTERMSIG(status));
    }

    return result;
}
