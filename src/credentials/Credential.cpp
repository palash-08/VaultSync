#include "credentials/Credential.h"
#include "credentials/WebCredential.h"
#include "credentials/WiFiCredential.h"
#include "credentials/SSHCredential.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <iostream>
#include <limits>

namespace {

void writeBinaryString(std::ostream& stream, const std::string& str) {
    uint32_t length = static_cast<uint32_t>(str.size());
    stream.write(reinterpret_cast<const char*>(&length), sizeof(length));
    if (length > 0) {
        stream.write(str.data(), length);
    }
}

std::string readBinaryString(std::istream& stream) {
    uint32_t length = 0;
    stream.read(reinterpret_cast<char*>(&length), sizeof(length));
    if (!stream || length > 16 * 1024 * 1024) {
        stream.setstate(std::ios::failbit);
        return {};
    }
    std::string str(length, '\0');
    if (length > 0) {
        stream.read(&str[0], length);
    }
    return str;
}

std::string toLowerCase(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return text;
}

} // namespace

Credential::Credential(const std::string& service,
                       const std::string& username,
                       const std::string& password,
                       const std::string& notes,
                       int64_t createdAt)
    : service(service),
      username(username),
      password(password),
      notes(notes),
      createdAt(createdAt < 0 ? std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) : createdAt) {
}

std::string Credential::getType() const {
    return "generic";
}

void Credential::display(bool showPassword) const {
    std::cout << "Service: " << service << "\n";
    std::cout << "Username: " << username << "\n";
    std::cout << "Password: " << (showPassword ? password : "********") << "\n";
    std::cout << "Notes: " << notes << "\n";
}

Credential* Credential::clone() const {
    return new Credential(*this);
}

void Credential::serialize(std::ostream& stream) const {
    writeBinaryString(stream, service);
    writeBinaryString(stream, username);
    writeBinaryString(stream, password);
    writeBinaryString(stream, notes);
    stream.write(reinterpret_cast<const char*>(&createdAt), sizeof(createdAt));
}

void Credential::deserialize(std::istream& stream) {
    service = readBinaryString(stream);
    username = readBinaryString(stream);
    password = readBinaryString(stream);
    notes = readBinaryString(stream);
    stream.read(reinterpret_cast<char*>(&createdAt), sizeof(createdAt));
}

bool Credential::matches(const std::string& query) const {
    const std::string lowerQuery = toLowerCase(query);
    return toLowerCase(service).find(lowerQuery) != std::string::npos ||
           toLowerCase(username).find(lowerQuery) != std::string::npos ||
           toLowerCase(notes).find(lowerQuery) != std::string::npos;
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

int64_t Credential::getCreatedAt() const {
    return createdAt;
}

void Credential::setService(const std::string& newService) {
    service = newService;
}

void Credential::setUsername(const std::string& newUsername) {
    username = newUsername;
}

void Credential::setPassword(const std::string& newPassword) {
    password = newPassword;
}

void Credential::setNotes(const std::string& newNotes) {
    notes = newNotes;
}

bool Credential::operator==(const Credential& other) const {
    if (getType() != other.getType() ||
        service != other.service ||
        username != other.username ||
        password != other.password ||
        notes != other.notes ||
        createdAt != other.createdAt) {
        return false;
    }

    if (const auto* webThis = dynamic_cast<const WebCredential*>(this)) {
        const auto* webOther = dynamic_cast<const WebCredential*>(&other);
        return webOther != nullptr && webThis->getUrl() == webOther->getUrl();
    }

    if (const auto* wifiThis = dynamic_cast<const WiFiCredential*>(this)) {
        const auto* wifiOther = dynamic_cast<const WiFiCredential*>(&other);
        return wifiOther != nullptr &&
               wifiThis->getSsid() == wifiOther->getSsid() &&
               wifiThis->getSecurityType() == wifiOther->getSecurityType();
    }

    if (const auto* sshThis = dynamic_cast<const SSHCredential*>(this)) {
        const auto* sshOther = dynamic_cast<const SSHCredential*>(&other);
        return sshOther != nullptr &&
               sshThis->getHost() == sshOther->getHost() &&
               sshThis->getPort() == sshOther->getPort();
    }

    return true;
}

bool Credential::operator!=(const Credential& other) const {
    return !(*this == other);
}

std::ostream& operator<<(std::ostream& stream, const Credential& credential) {
    stream << "Credential(" << credential.getType() << ", "
           << credential.service << ", "
           << credential.username << ")";
    return stream;
}
