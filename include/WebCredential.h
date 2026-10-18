#pragma once
#include "Credential.h"
class WebCredential : public Credential {
    std::string url;
public:
    WebCredential(const std::string& service={},const std::string& username={},const std::string& password={},const std::string& notes={},const std::string& url={});
    std::string getType() const override; const std::string& getUrl() const; const std::string& getWebsite() const;
    void setUrl(const std::string&); void display(bool) const override; Credential* clone() const override;
    void serialize(std::ostream&) const override; void deserialize(std::istream&) override; bool matches(const std::string&) const override;
};
