#include "credentials/SSHCredential.h"

#include <iostream>

SSHCredential::SSHCredential(const std::string& service,
                             const std::string& username,
                             const std::string& password,
                             const std::string& notes,
                             const std::string& host,
                             uint16_t port)
    : Credential(service, username, password, notes),
      host(host),
      port(port) {
}

std::string SSHCredential::getType() const {
    return "ssh";
}

const std::string& SSHCredential::getHost() const {
    return host;
}

uint16_t SSHCredential::getPort() const {
    return port;
}

void SSHCredential::setHost(const std::string& newHost) {
    host = newHost;
}

void SSHCredential::setPort(uint16_t newPort) {
    port = newPort;
}

void SSHCredential::display(bool showPassword) const {
    Credential::display(showPassword);
    std::cout << "Host: " << host << "\n";
    std::cout << "Port: " << port << "\n";
}

Credential* SSHCredential::clone() const {
    return new SSHCredential(*this);
}

void SSHCredential::serialize(std::ostream& stream) const {
    Credential::serialize(stream);
    uint32_t length = static_cast<uint32_t>(host.size());
    stream.write(reinterpret_cast<const char*>(&length), sizeof(length));
    if (length > 0) {
        stream.write(host.data(), length);
    }
    stream.write(reinterpret_cast<const char*>(&port), sizeof(port));
}

void SSHCredential::deserialize(std::istream& stream) {
    Credential::deserialize(stream);
    uint32_t length = 0;
    stream.read(reinterpret_cast<char*>(&length), sizeof(length));
    if (length > 16 * 1024 * 1024) {
        stream.setstate(std::ios::failbit);
        return;
    }
    host.assign(length, '\0');
    if (length > 0) {
        stream.read(&host[0], length);
    }
    stream.read(reinterpret_cast<char*>(&port), sizeof(port));
}

bool SSHCredential::matches(const std::string& query) const {
    return Credential::matches(query) || host.find(query) != std::string::npos;
}
