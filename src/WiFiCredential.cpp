#include "WiFiCredential.h"

#include <iostream>

namespace {

void writeBinaryString(std::ostream& stream, const std::string& value) {
    uint32_t length = static_cast<uint32_t>(value.size());
    stream.write(reinterpret_cast<const char*>(&length), sizeof(length));
    if (length > 0) {
        stream.write(value.data(), length);
    }
}

std::string readBinaryString(std::istream& stream) {
    uint32_t length = 0;
    stream.read(reinterpret_cast<char*>(&length), sizeof(length));
    if (!stream || length > 16 * 1024 * 1024) {
        stream.setstate(std::ios::failbit);
        return {};
    }
    std::string value(length, '\0');
    if (length > 0) {
        stream.read(&value[0], length);
    }
    return value;
}

} // namespace

WiFiCredential::WiFiCredential(const std::string& service,
                               const std::string& username,
                               const std::string& password,
                               const std::string& notes,
                               const std::string& ssid,
                               const std::string& securityType)
    : Credential(service, username, password, notes),
      ssid(ssid),
      securityType(securityType) {
}

std::string WiFiCredential::getType() const {
    return "wifi";
}

const std::string& WiFiCredential::getSsid() const {
    return ssid;
}

const std::string& WiFiCredential::getSecurityType() const {
    return securityType;
}

void WiFiCredential::setSsid(const std::string& newSsid) {
    ssid = newSsid;
}

void WiFiCredential::setSecurityType(const std::string& newSecurityType) {
    securityType = newSecurityType;
}

void WiFiCredential::display(bool showPassword) const {
    Credential::display(showPassword);
    std::cout << "SSID: " << ssid << "\n";
    std::cout << "Security: " << securityType << "\n";
}

Credential* WiFiCredential::clone() const {
    return new WiFiCredential(*this);
}

void WiFiCredential::serialize(std::ostream& stream) const {
    Credential::serialize(stream);
    writeBinaryString(stream, ssid);
    writeBinaryString(stream, securityType);
}

void WiFiCredential::deserialize(std::istream& stream) {
    Credential::deserialize(stream);
    ssid = readBinaryString(stream);
    securityType = readBinaryString(stream);
}

bool WiFiCredential::matches(const std::string& query) const {
    return Credential::matches(query) || ssid.find(query) != std::string::npos;
}
