#pragma once
#include "Credential.h"
#include <memory>
#include <vector>
struct SecurityScore{int score=100;size_t reusedPasswords=0,oldPasswords=0;};
class PasswordAnalyzer{public:static bool isReused(const std::string&,const std::vector<std::shared_ptr<Credential>>&);static SecurityScore securityScore(const std::vector<std::shared_ptr<Credential>>&,int maxAgeDays=365);};
