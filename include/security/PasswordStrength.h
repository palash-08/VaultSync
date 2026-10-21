#ifndef PASSWORD_STRENGTH_H
#define PASSWORD_STRENGTH_H

#include <string>

/**
 * @brief Analysis result of password strength and entropy evaluation.
 */
struct PasswordStrengthResult {
    int score = 0;          /**< Score from 0 to 100 representing password robustness. */
    double entropy = 0.0;   /**< Information entropy in bits. */
    std::string feedback;   /**< Qualitative feedback or recommendations. */
};

/**
 * @brief Utility for evaluating password strength, information entropy, and user feedback.
 */
class PasswordStrength {
public:
    /**
     * @brief Performs full analysis of the given password, computing score, entropy, and feedback.
     * @param password The password string to evaluate.
     * @return PasswordStrengthResult structure containing detailed metrics.
     */
    static PasswordStrengthResult analyze(const std::string& password);

    /**
     * @brief Computes a numerical strength score for the password on a 0-100 scale.
     * @param password The password string to evaluate.
     * @return Integer score from 0 (very weak) to 100 (very strong).
     */
    static int score(const std::string& password);

    /**
     * @brief Computes Shannon information entropy of the password in bits.
     * @param password The password string to evaluate.
     * @return Entropy value in bits.
     */
    static double entropy(const std::string& password);

    /**
     * @brief Provides human-readable feedback describing password strength and improvement advice.
     * @param password The password string to evaluate.
     * @return Feedback message string.
     */
    static std::string feedback(const std::string& password);
};

#endif // PASSWORD_STRENGTH_H
