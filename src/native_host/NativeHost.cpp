#include "native_host/NativeHost.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>

NativeHost::NativeHost(const std::string& vaultPath)
    : vault(vaultPath) {
}

NativeHost::~NativeHost() {
    cleanseString(cachedCredPassword);
    vault.lock();
    activeUser.clear();
}

void NativeHost::cleanseString(std::string& str) {
    if (!str.empty()) {
        OPENSSL_cleanse(&str[0], str.size());
        str.clear();
    }
}

bool NativeHost::readMessage(std::istream& in, std::string& outJson) {
    outJson.clear();
    uint32_t length = 0;
    in.read(reinterpret_cast<char*>(&length), sizeof(uint32_t));
    if (!in || static_cast<size_t>(in.gcount()) != sizeof(uint32_t)) {
        return false;
    }

    if (length == 0) {
        return true;
    }

    if (length > MAX_MESSAGE_SIZE) {
        return false;
    }

    outJson.resize(length);
    in.read(&outJson[0], length);
    if (!in || static_cast<uint32_t>(in.gcount()) != length) {
        outJson.clear();
        return false;
    }

    return true;
}

bool NativeHost::writeMessage(std::ostream& out, const std::string& json) {
    uint32_t length = static_cast<uint32_t>(json.size());
    out.write(reinterpret_cast<const char*>(&length), sizeof(uint32_t));
    if (!out) {
        return false;
    }

    if (length > 0) {
        out.write(json.data(), length);
        if (!out) {
            return false;
        }
    }

    out.flush();
    return out.good();
}

std::string NativeHost::extractDomain(const std::string& url) {
    if (url.empty()) {
        return "";
    }

    std::string s = url;
    size_t protoPos = s.find("://");
    if (protoPos != std::string::npos) {
        s = s.substr(protoPos + 3);
    }

    // Strip basic auth credentials (user:pass@) if present
    size_t atPos = s.find('@');
    if (atPos != std::string::npos) {
        s = s.substr(atPos + 1);
    }

    size_t slashPos = s.find('/');
    if (slashPos != std::string::npos) {
        s = s.substr(0, slashPos);
    }
    size_t qPos = s.find('?');
    if (qPos != std::string::npos) {
        s = s.substr(0, qPos);
    }

    size_t portPos = s.find(':');
    if (portPos != std::string::npos) {
        s = s.substr(0, portPos);
    }

    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    if (s.rfind("www.", 0) == 0) {
        s = s.substr(4);
    }

    return s;
}

std::string NativeHost::extractScheme(const std::string& url) {
    size_t protoPos = url.find("://");
    if (protoPos == std::string::npos) {
        return "";
    }
    std::string scheme = url.substr(0, protoPos);
    std::transform(scheme.begin(), scheme.end(), scheme.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return scheme;
}

std::string NativeHost::extractPort(const std::string& url) {
    if (url.empty()) {
        return "";
    }
    std::string s = url;
    size_t protoPos = s.find("://");
    if (protoPos != std::string::npos) {
        s = s.substr(protoPos + 3);
    }
    size_t atPos = s.find('@');
    if (atPos != std::string::npos) {
        s = s.substr(atPos + 1);
    }
    size_t slashPos = s.find('/');
    if (slashPos != std::string::npos) {
        s = s.substr(0, slashPos);
    }
    size_t qPos = s.find('?');
    if (qPos != std::string::npos) {
        s = s.substr(0, qPos);
    }
    size_t portPos = s.find(':');
    if (portPos != std::string::npos) {
        return s.substr(portPos + 1);
    }
    return "";
}

std::string NativeHost::handleMessage(const std::string& requestJson) {
    nlohmann::json req;
    try {
        req = nlohmann::json::parse(requestJson);
    } catch (const std::exception& e) {
        nlohmann::json err = {
            {"success", false},
            {"error", std::string("JSON parse error: ") + e.what()}
        };
        return err.dump();
    }

    std::string action = req.value("action", "");

    // Enforce inactivity timeout: auto-lock and purge secrets if idle threshold exceeded
    if (vault.checkInactivityTimeout()) {
        cleanseString(cachedCredPassword);
        activeUser.clear();
    }

    if (action == "status") {
        std::string user = req.value("user", activeUser);
        if (user.empty()) {
            user = activeUser;
        }

        bool vaultExists = !user.empty() && MasterVault::existsForUser(user);
        std::string stateStr;
        switch (vault.getSessionState()) {
            case MasterVault::SessionState::Locked:
                stateStr = "Locked";
                break;
            case MasterVault::SessionState::MasterAuthenticated:
                stateStr = "MasterAuthenticated";
                break;
            case MasterVault::SessionState::CredentialsUnlocked:
                stateStr = "CredentialsUnlocked";
                break;
        }

        nlohmann::json resp = {
            {"success", true},
            {"action", "status"},
            {"state", stateStr},
            {"user", user},
            {"vault_exists", vaultExists},
            {"has_credential_password", vault.hasCredentialPassword()},
            {"inactivity_timeout_seconds", vault.getInactivityTimeout()}
        };
        return resp.dump();
    }

    if (action == "set_timeout") {
        int timeoutSeconds = req.value("timeout_seconds", req.value("timeout", 300));
        vault.setInactivityTimeout(timeoutSeconds);
        nlohmann::json resp = {
            {"success", true},
            {"action", "set_timeout"},
            {"timeout_seconds", timeoutSeconds}
        };
        return resp.dump();
    }

    if (action == "unlock") {
        std::string user = req.value("user", req.value("username", activeUser));
        std::string masterPassword = req.value("master_password", req.value("masterPassword", ""));
        std::string credPassword = req.value("cred_password", req.value("credPassword", ""));

        if (user.empty()) {
            nlohmann::json err = {
                {"success", false},
                {"action", "unlock"},
                {"error", "Username is required"}
            };
            return err.dump();
        }

        int remainingLockoutSec = 0;
        if (MasterVault::isMasterLockedOut(user, remainingLockoutSec)) {
            nlohmann::json err = {
                {"success", false},
                {"action", "unlock"},
                {"error", "Master vault is locked out. Try again in " + std::to_string(remainingLockoutSec) + "s."}
            };
            return err.dump();
        }

        int attemptsRemaining = 0;
        bool masterOk = vault.unlockMaster(user, masterPassword, attemptsRemaining);
        cleanseString(masterPassword);

        if (!masterOk) {
            nlohmann::json err = {
                {"success", false},
                {"action", "unlock"},
                {"error", "Invalid master password"},
                {"attempts_remaining", attemptsRemaining}
            };
            cleanseString(credPassword);
            return err.dump();
        }

        activeUser = user;

        if (!credPassword.empty()) {
            if (!vault.hasCredentialPassword()) {
                if (!vault.setupCredentialPassword(credPassword)) {
                    nlohmann::json err = {
                        {"success", false},
                        {"action", "unlock"},
                        {"error", "Failed to setup credential password (must differ from master)"}
                    };
                    cleanseString(credPassword);
                    return err.dump();
                }
            } else {
                int credAttempts = 0;
                bool credOk = vault.unlockCredentials(credPassword, credAttempts);
                if (!credOk) {
                    nlohmann::json err = {
                        {"success", false},
                        {"action", "unlock"},
                        {"error", "Invalid credential password"},
                        {"attempts_remaining", credAttempts}
                    };
                    cleanseString(credPassword);
                    return err.dump();
                }
            }
            cachedCredPassword = credPassword;
            cleanseString(credPassword);
        }

        vault.recordActivity();

        std::string stateStr = (vault.getSessionState() == MasterVault::SessionState::CredentialsUnlocked)
            ? "CredentialsUnlocked"
            : "MasterAuthenticated";

        nlohmann::json resp = {
            {"success", true},
            {"action", "unlock"},
            {"state", stateStr},
            {"message", "Vault authenticated successfully"}
        };
        return resp.dump();
    }

    if (action == "get_credentials") {
        if (vault.getSessionState() != MasterVault::SessionState::CredentialsUnlocked) {
            nlohmann::json err = {
                {"success", false},
                {"action", "get_credentials"},
                {"error", "Vault is locked. Unlock credential vault first."}
            };
            return err.dump();
        }

        vault.recordActivity();

        std::string rawUrl = req.value("url", "");
        if (rawUrl.empty()) {
            rawUrl = req.value("domain", "");
        }
        std::string targetDomain = extractDomain(rawUrl);

        // If target domain is empty, return an empty list, never all credentials
        if (targetDomain.empty()) {
            nlohmann::json resp = {
                {"success", true},
                {"action", "get_credentials"},
                {"domain", ""},
                {"count", 0},
                {"credentials", nlohmann::json::array()}
            };
            return resp.dump();
        }

        std::string reqScheme = extractScheme(rawUrl);
        std::string reqPort = extractPort(rawUrl);

        auto allCreds = vault.getPolymorphicCredentials();
        nlohmann::json credList = nlohmann::json::array();

        for (size_t idx = 0; idx < allCreds.size(); ++idx) {
            const auto& cred = allCreds[idx];
            if (!cred) continue;

            auto webCred = std::dynamic_pointer_cast<WebCredential>(cred);
            if (!webCred) {
                continue; // Only WebCredential entries can be matched for autofill
            }

            std::string credUrl = webCred->getUrl();
            std::string credDomain = extractDomain(credUrl);
            if (credDomain.empty()) {
                continue;
            }

            // Match only when hosts are equal, or when request host is a true subdomain
            bool match = false;
            if (targetDomain == credDomain) {
                match = true;
            } else if (targetDomain.size() > credDomain.size() + 1 &&
                       targetDomain.compare(targetDomain.size() - credDomain.size() - 1,
                                            credDomain.size() + 1,
                                            "." + credDomain) == 0) {
                match = true;
            }

            if (!match) {
                continue;
            }

            // Scheme validation:
            // A saved URL with no scheme is treated as https only.
            // Allow http only when the saved credential itself is explicitly http.
            std::string credScheme = extractScheme(credUrl);
            std::string effectiveCredScheme = credScheme.empty() ? "https" : credScheme;

            if (reqScheme == "http" && effectiveCredScheme != "http") {
                continue; // An http page must not receive an https/schemeless credential
            }

            // Port validation: If the saved URL has an explicit port, the request port must match
            std::string credPort = extractPort(credUrl);
            if (!credPort.empty() && reqPort != credPort) {
                continue;
            }

            std::string secret = cred->getPassword();
            nlohmann::json entry = {
                {"service", cred->getService()},
                {"username", cred->getUsername()},
                {"password", secret},
                {"url", credUrl},
                {"type", cred->getType()}
            };
            cleanseString(secret);
            credList.push_back(entry);
        }

        nlohmann::json resp = {
            {"success", true},
            {"action", "get_credentials"},
            {"domain", targetDomain},
            {"count", credList.size()},
            {"credentials", credList}
        };
        return resp.dump();
    }

    if (action == "lock") {
        cleanseString(cachedCredPassword);
        vault.lock();
        activeUser.clear();

        nlohmann::json resp = {
            {"success", true},
            {"action", "lock"},
            {"state", "Locked"},
            {"message", "Vault securely locked and session purged"}
        };
        return resp.dump();
    }

    nlohmann::json err = {
        {"success", false},
        {"error", "Unknown action: " + action}
    };
    return err.dump();
}

/**
 * @brief Executes the message loop on the provided streams until EOF.
 *
 * NOTE: The host execution loop is strictly single-threaded and processes
 * requests sequentially in order. The Chromium extension background service
 * worker FIFO response matching only holds if the host answers requests
 * strictly in order.
 */
void NativeHost::run(std::istream& in, std::ostream& out) {
    std::string msg;
    while (readMessage(in, msg)) {
        if (msg.empty()) {
            continue;
        }
        std::string response = handleMessage(msg);
        if (!writeMessage(out, response)) {
            break;
        }
    }
}

MasterVault& NativeHost::getVault() {
    return vault;
}

const std::string& NativeHost::getActiveUser() const {
    return activeUser;
}
