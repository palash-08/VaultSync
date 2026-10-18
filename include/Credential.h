#ifndef CREDENTIAL_H
#define CREDENTIAL_H

#include <cstdint>
#include <iosfwd>
#include <string>

class Credential {
protected:
    std::string service, username, password, notes;
    int64_t createdAt;
public:
    Credential(const std::string& service = {}, const std::string& username = {},
               const std::string& password = {}, const std::string& notes = {}, int64_t createdAt = -1);
    virtual ~Credential() = default;
    virtual std::string getType() const;
    virtual void display(bool showPassword) const;
    virtual Credential* clone() const;
    virtual void serialize(std::ostream& os) const;
    virtual void deserialize(std::istream& is);
    virtual bool matches(const std::string& query) const;
    const std::string& getService() const; const std::string& getUsername() const;
    const std::string& getPassword() const; const std::string& getNotes() const;
    int64_t getCreatedAt() const;
    void setService(const std::string&); void setUsername(const std::string&);
    void setPassword(const std::string&); void setNotes(const std::string&);
    bool operator==(const Credential&) const; bool operator!=(const Credential&) const;
    friend std::ostream& operator<<(std::ostream&, const Credential&);
};
#endif
