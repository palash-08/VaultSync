#pragma once
#include "Credential.h"
#include <memory>
#include <string>
class CredentialFactory {
public:
    static std::shared_ptr<Credential> create(const std::string& type);
    static std::shared_ptr<Credential> deserialize(const std::string& type, std::istream& input);
};
