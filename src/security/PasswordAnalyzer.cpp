#include "security/PasswordAnalyzer.h"
#include "security/PasswordStrength.h"

#include <chrono>
#include <unordered_map>

bool PasswordAnalyzer::isReused(const std::string& password,
                                const std::vector<std::shared_ptr<Credential>>& credentials) {
    for (const auto& credential : credentials) {
        if (credential && credential->getPassword() == password) {
            return true;
        }
    }
    return false;
}

SecurityScore PasswordAnalyzer::securityScore(const std::vector<std::shared_ptr<Credential>>& credentials,
                                              int maxAgeDays) {
    SecurityScore result;
    if (credentials.empty()) {
        return result;
    }

    std::unordered_map<std::string, size_t> passwordCounts;
    for (const auto& credential : credentials) {
        if (credential) {
            ++passwordCounts[credential->getPassword()];
        }
    }

    const auto currentTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    long totalScorePoints = 0;

    for (const auto& credential : credentials) {
        if (!credential) {
            continue;
        }

        totalScorePoints += PasswordStrength::score(credential->getPassword());

        if (passwordCounts[credential->getPassword()] > 1) {
            ++result.reusedPasswords;
        }

        if (credential->getCreatedAt() > 0 &&
            (currentTime - credential->getCreatedAt()) > static_cast<int64_t>(maxAgeDays) * 86400) {
            ++result.oldPasswords;
        }
    }

    long penalty = static_cast<long>(result.reusedPasswords) * 10 +
                   static_cast<long>(result.oldPasswords) * 5;

    result.score = static_cast<int>(totalScorePoints / credentials.size()) - static_cast<int>(penalty);
    if (result.score < 0) {
        result.score = 0;
    }

    return result;
}
