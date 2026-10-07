#include "XORCipher.h"

namespace {
    const std::string DEFAULT_KEY = "VaultSyncDemoKey";
}

XORCipher::XORCipher(const std::string& keyStr) {
    setKey(keyStr);
}

XORCipher::XORCipher(const std::vector<uint8_t>& keyBytes) {
    setKey(keyBytes);
}

void XORCipher::setKey(const std::string& keyStr) {
    if (keyStr.empty()) {
        key.assign(DEFAULT_KEY.begin(), DEFAULT_KEY.end());
    } else {
        key.assign(keyStr.begin(), keyStr.end());
    }
}

void XORCipher::setKey(const std::vector<uint8_t>& keyBytes) {
    if (keyBytes.empty()) {
        key.assign(DEFAULT_KEY.begin(), DEFAULT_KEY.end());
    } else {
        key = keyBytes;
    }
}

const std::vector<uint8_t>& XORCipher::getKey() const {
    return key;
}

std::vector<uint8_t> XORCipher::encrypt(const std::vector<uint8_t>& plaintext) const {
    if (key.empty() || plaintext.empty()) {
        return plaintext;
    }

    std::vector<uint8_t> result(plaintext.size());
    const size_t keyLen = key.size();
    for (size_t i = 0; i < plaintext.size(); ++i) {
        result[i] = plaintext[i] ^ key[i % keyLen];
    }
    return result;
}

std::vector<uint8_t> XORCipher::decrypt(const std::vector<uint8_t>& ciphertext) const {
    // XOR encryption is symmetric and self-inverse:
    // (A ^ B) ^ B = A
    // Decrypting is identical to encrypting with the same key.
    return encrypt(ciphertext);
}
