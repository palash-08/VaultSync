#pragma once
#include "Credential.h"
class WiFiCredential : public Credential {
    std::string ssid, securityType;
public:
    WiFiCredential(const std::string& service={},const std::string& username={},const std::string& password={},const std::string& notes={},const std::string& ssid={},const std::string& securityType={});
    std::string getType() const override; const std::string& getSsid() const; const std::string& getSecurityType() const;
    void display(bool) const override; Credential* clone() const override; void serialize(std::ostream&) const override; void deserialize(std::istream&) override; bool matches(const std::string&) const override;
};
