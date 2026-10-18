#pragma once
#include "Credential.h"
class SSHCredential : public Credential {
    std::string host; uint16_t port;
public:
    SSHCredential(const std::string& service={},const std::string& username={},const std::string& password={},const std::string& notes={},const std::string& host={},uint16_t port=22);
    std::string getType() const override; const std::string& getHost() const; uint16_t getPort() const;
    void display(bool) const override; Credential* clone() const override; void serialize(std::ostream&) const override; void deserialize(std::istream&) override; bool matches(const std::string&) const override;
};
