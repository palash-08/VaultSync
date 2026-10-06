#include "Credential.h"

Credential::Credential(const std::string& service,
                       const std::string& username,
                       const std::string& password,
                       const std::string& notes)
    : service(service),
      username(username),
      password(password),
      notes(notes)
{
}

const std::string& Credential::getService() const {
    return service;
}

const std::string& Credential::getUsername() const {
    return username;
}

const std::string& Credential::getPassword() const {
    return password;
}

const std::string& Credential::getNotes() const {
    return notes;
}

void Credential::setService(const std::string& service) {
    this->service = service;
}

void Credential::setUsername(const std::string& username) {
    this->username = username;
}

void Credential::setPassword(const std::string& password) {
    this->password = password;
}

void Credential::setNotes(const std::string& notes) {
    this->notes = notes;
}
