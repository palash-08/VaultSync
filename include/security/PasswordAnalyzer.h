#ifndef PASSWORD_ANALYZER_H
#define PASSWORD_ANALYZER_H

#include "credentials/Credential.h"

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Represents security score assessment results for credentials in a vault.
 */
struct SecurityScore {
    int score = 100;            /**< Overall security score between 0 and 100. */
    size_t reusedPasswords = 0; /**< Number of credentials with duplicated passwords. */
    size_t oldPasswords = 0;    /**< Number of credentials exceeding maximum age threshold. */
};

/**
 * @brief Provides analysis utilities for credential collections such as reuse detection and security scoring.
 */
class PasswordAnalyzer {
public:
    /**
     * @brief Checks if a given password is reused across any of the provided credentials.
     * @param password The password string to search for.
     * @param credentials The collection of credentials to check against.
     * @return True if any credential uses the given password; false otherwise.
     */
    static bool isReused(const std::string& password,
                         const std::vector<std::shared_ptr<Credential>>& credentials);

    /**
     * @brief Calculates an aggregate security score and health metrics for a collection of credentials.
     * @param credentials The collection of credentials to analyze.
     * @param maxAgeDays Maximum permitted password age in days before flagging as old (default: 365).
     * @return A SecurityScore structure containing score, reused count, and old count.
     */
    static SecurityScore securityScore(const std::vector<std::shared_ptr<Credential>>& credentials,
                                       int maxAgeDays = 365);

    /**
     * @brief Alias for securityScore(), performing full health analysis on credential collection.
     * @param credentials The collection of credentials to analyze.
     * @param maxAgeDays Maximum permitted password age in days before flagging as old (default: 365).
     * @return A SecurityScore structure containing score, reused count, and old count.
     */
    static SecurityScore analyze(const std::vector<std::shared_ptr<Credential>>& credentials,
                                 int maxAgeDays = 365) {
        return securityScore(credentials, maxAgeDays);
    }
};


#endif // PASSWORD_ANALYZER_H
