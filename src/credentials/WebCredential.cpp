#include "credentials/WebCredential.h"

#include <iostream>

WebCredential::WebCredential(const std::string& service,
                             const std::string& username,
                             const std::string& password,
                             const std::string& notes,
                             const std::string& url)
    : Credential(service, username, password, notes),
      url(url) {
}

std::string WebCredential::getType() const {
    return "web";
}

const std::string& WebCredential::getUrl() const {
    return url;
}

const std::string& WebCredential::getWebsite() const {
    return url;
}

void WebCredential::setUrl(const std::string& newUrl) {
    url = newUrl;
}

void WebCredential::display(bool showPassword) const {
    Credential::display(showPassword);
    std::cout << "URL: " << url << "\n";
}

Credential* WebCredential::clone() const {
    return new WebCredential(*this);
}

void WebCredential::serialize(std::ostream& stream) const {
    Credential::serialize(stream);
    uint32_t length = static_cast<uint32_t>(url.size());
    stream.write(reinterpret_cast<const char*>(&length), sizeof(length));
    if (length > 0) {
        stream.write(url.data(), length);
    }
}

void WebCredential::deserialize(std::istream& stream) {
    Credential::deserialize(stream);
    uint32_t length = 0;
    stream.read(reinterpret_cast<char*>(&length), sizeof(length));
    if (length > 16 * 1024 * 1024) {
        stream.setstate(std::ios::failbit);
        return;
    }
    url.assign(length, '\0');
    if (length > 0) {
        stream.read(&url[0], length);
    }
}

bool WebCredential::matches(const std::string& query) const {
    return Credential::matches(query) || url.find(query) != std::string::npos;
}
