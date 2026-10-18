#pragma once
#include <string>
struct PasswordStrengthResult{int score=0;double entropy=0;std::string feedback;};
class PasswordStrength{public:static PasswordStrengthResult analyze(const std::string&);static int score(const std::string&);static double entropy(const std::string&);static std::string feedback(const std::string&);};
