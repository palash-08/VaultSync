#pragma once
#include <string>
struct PasswordOptions{size_t length=16;bool uppercase=true,lowercase=true,digits=true,symbols=true;};
class PasswordGenerator{public:static std::string generate(const PasswordOptions&);static std::string generate(size_t length,bool uppercase=true,bool lowercase=true,bool digits=true,bool symbols=true);};
