#include "PasswordStrength.h"

#include <algorithm>
#include <cctype>
#include <cmath>

PasswordStrengthResult PasswordStrength::analyze(const std::string& password) {
    int poolSize = 0;
    bool hasUppercase = false;
    bool hasLowercase = false;
    bool hasDigits = false;
    bool hasSymbols = false;

    for (unsigned char character : password) {
        hasUppercase |= static_cast<bool>(std::isupper(character));
        hasLowercase |= static_cast<bool>(std::islower(character));
        hasDigits |= static_cast<bool>(std::isdigit(character));
        hasSymbols |= !static_cast<bool>(std::isalnum(character));
    }

    poolSize = (hasUppercase ? 26 : 0) +
               (hasLowercase ? 26 : 0) +
               (hasDigits ? 10 : 0) +
               (hasSymbols ? 33 : 0);

    double calculatedEntropy = (password.empty() || poolSize == 0)
                                   ? 0.0
                                   : static_cast<double>(password.size()) * std::log2(poolSize);

    int calculatedScore = static_cast<int>(calculatedEntropy);
    if (calculatedScore > 100) {
        calculatedScore = 100;
    }
    if (password.size() < 8) {
        calculatedScore = std::min(calculatedScore, 25);
    }

    std::string feedbackMessage;
    if (calculatedScore >= 80) {
        feedbackMessage = "Strong";
    } else if (calculatedScore >= 50) {
        feedbackMessage = "Moderate";
    } else {
        feedbackMessage = "Weak; use a longer, less predictable password";
    }

    return PasswordStrengthResult{calculatedScore, calculatedEntropy, feedbackMessage};
}

int PasswordStrength::score(const std::string& password) {
    return analyze(password).score;
}

double PasswordStrength::entropy(const std::string& password) {
    return analyze(password).entropy;
}

std::string PasswordStrength::feedback(const std::string& password) {
    return analyze(password).feedback;
}
