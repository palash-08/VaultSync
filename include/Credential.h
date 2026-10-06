#ifndef CREDENTIAL_H
#define CREDENTIAL_H

#include <string>

class Credential {
private:
    std::string service;
    std::string username;
    std::string password;
    std::string notes;

public:
    // Constructor
    Credential(const std::string& service,
               const std::string& username,
               const std::string& password,
               const std::string& notes = "");

    // Getters
    const std::string& getService() const;
    const std::string& getUsername() const;
    const std::string& getPassword() const;
    const std::string& getNotes() const;

    // Setters
    void setService(const std::string& service);
    void setUsername(const std::string& username);
    void setPassword(const std::string& password);
    void setNotes(const std::string& notes);
};

#endif // CREDENTIAL_H
