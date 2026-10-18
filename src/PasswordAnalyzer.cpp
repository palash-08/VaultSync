#include "PasswordAnalyzer.h"
#include "PasswordStrength.h"
#include <chrono>
#include <unordered_map>
bool PasswordAnalyzer::isReused(const std::string&p,const std::vector<std::shared_ptr<Credential>>&cs){for(auto&c:cs)if(c&&c->getPassword()==p)return true;return false;}
SecurityScore PasswordAnalyzer::securityScore(const std::vector<std::shared_ptr<Credential>>&cs,int maxAge){SecurityScore r;std::unordered_map<std::string,size_t>counts;for(auto&c:cs)if(c)++counts[c->getPassword()];auto now=std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());if(cs.empty())return r;long points=0;for(auto&c:cs){if(!c)continue;points+=PasswordStrength::score(c->getPassword());if(counts[c->getPassword()]>1)++r.reusedPasswords;if(c->getCreatedAt()>0&&now-c->getCreatedAt()>static_cast<int64_t>(maxAge)*86400)++r.oldPasswords;}long penalty=static_cast<long>(r.reusedPasswords)*10+static_cast<long>(r.oldPasswords)*5;r.score=static_cast<int>(points/cs.size())-static_cast<int>(penalty);if(r.score<0)r.score=0;return r;}
