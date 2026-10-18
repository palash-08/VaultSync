#ifndef PASSWORD_GENERATOR_H
#define PASSWORD_GENERATOR_H

#include <cstddef>
#include <string>

/**
 * @brief Configuration options for password generation.
 */
struct PasswordOptions {
    size_t length = 16;     /**< Total character length of the generated password. */
    bool uppercase = true;  /**< Whether to include uppercase letters (A-Z). */
    bool lowercase = true;  /**< Whether to include lowercase letters (a-z). */
    bool digits = true;     /**< Whether to include numeric digits (0-9). */
    bool symbols = true;    /**< Whether to include special symbols. */
};

/**
 * @brief Utility for securely generating random passwords adhering to customizable criteria.
 */
class PasswordGenerator {
public:
    /**
     * @brief Generates a random password using the specified configuration options.
     * @param options Structure defining length and character set requirements.
     * @return Generated password string.
     * @throws std::invalid_argument If options specify no characters or length cannot satisfy requirements.
     */
    static std::string generate(const PasswordOptions& options);

    /**
     * @brief Generates a random password with explicit parameters.
     * @param length Desired character length of the password.
     * @param uppercase Whether to include uppercase characters (default: true).
     * @param lowercase Whether to include lowercase characters (default: true).
     * @param digits Whether to include numeric digits (default: true).
     * @param symbols Whether to include special symbols (default: true).
     * @return Generated password string.
     * @throws std::invalid_argument If options specify no characters or length cannot satisfy requirements.
     */
    static std::string generate(size_t length,
                                bool uppercase = true,
                                bool lowercase = true,
                                bool digits = true,
                                bool symbols = true);
};

#endif // PASSWORD_GENERATOR_H
