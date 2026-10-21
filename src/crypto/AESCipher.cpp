#include "crypto/AESCipher.h"
#include "crypto/CryptoUtils.h"
#include "security/VaultExceptions.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <stdexcept>

namespace {

bool isHexString(const std::string& str) {
    if (str.empty()) {
        return false;
    }
    return std::all_of(str.begin(), str.end(), [](unsigned char c) {
        return std::isxdigit(c);
    });
}

uint8_t hexCharToByte(char hexChar) {
    if (hexChar >= '0' && hexChar <= '9') {
        return static_cast<uint8_t>(hexChar - '0');
    }
    if (hexChar >= 'a' && hexChar <= 'f') {
        return static_cast<uint8_t>(hexChar - 'a' + 10);
    }
    if (hexChar >= 'A' && hexChar <= 'F') {
        return static_cast<uint8_t>(hexChar - 'A' + 10);
    }
    return 0;
}

std::vector<uint8_t> hexToBytes(const std::string& hexString) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hexString.size() / 2);
    for (size_t i = 0; i + 1 < hexString.size(); i += 2) {
        uint8_t high = hexCharToByte(hexString[i]);
        uint8_t low = hexCharToByte(hexString[i + 1]);
        bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return bytes;
}

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const noexcept {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};

using ScopedEvpCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

} // namespace

std::vector<uint8_t> AESCipher::normalizeKey(const std::string& keyString) {
    if (keyString.size() == KEY_SIZE) {
        return std::vector<uint8_t>(keyString.begin(), keyString.end());
    }
    if (keyString.size() == 64 && isHexString(keyString)) {
        return hexToBytes(keyString);
    }
    std::string hashHex = CryptoUtils::sha256(keyString);
    return hexToBytes(hashHex);
}

std::vector<uint8_t> AESCipher::normalizeKey(const std::vector<uint8_t>& keyBytes) {
    if (keyBytes.size() == KEY_SIZE) {
        return keyBytes;
    }
    std::string hashHex = CryptoUtils::sha256(keyBytes);
    return hexToBytes(hashHex);
}

AESCipher::AESCipher(const std::string& keyString)
    : key(normalizeKey(keyString)) {
}

AESCipher::AESCipher(const std::vector<uint8_t>& keyBytes)
    : key(normalizeKey(keyBytes)) {
}

std::vector<uint8_t> AESCipher::encrypt(const std::vector<uint8_t>& plaintext) const {
    std::vector<uint8_t> iv(IV_SIZE);
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        throw VaultException("Failed to generate cryptographically secure random IV");
    }

    ScopedEvpCipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw VaultException("Failed to allocate EVP_CIPHER_CTX for AES-GCM encryption");
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw VaultException("Failed to initialize AES-256-GCM cipher");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
        throw VaultException("Failed to configure AES-256-GCM IV length");
    }

    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw VaultException("Failed to set AES-256-GCM key and IV");
    }

    std::vector<uint8_t> ciphertext(plaintext.size());
    int outLength = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outLength,
                              plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            throw VaultException("Failed during AES-256-GCM EncryptUpdate");
        }
    }

    int finalLength = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outLength, &finalLength) != 1) {
        throw VaultException("Failed during AES-256-GCM EncryptFinal");
    }
    ciphertext.resize(static_cast<size_t>(outLength + finalLength));

    std::vector<uint8_t> tag(TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        throw VaultException("Failed to retrieve AES-256-GCM authentication tag");
    }

    std::vector<uint8_t> payload;
    payload.reserve(iv.size() + tag.size() + ciphertext.size());
    payload.insert(payload.end(), iv.begin(), iv.end());
    payload.insert(payload.end(), tag.begin(), tag.end());
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());

    return payload;
}

std::vector<uint8_t> AESCipher::decrypt(const std::vector<uint8_t>& ciphertext) const {
    if (ciphertext.size() < OVERHEAD_SIZE) {
        throw CorruptedVaultException("Encrypted payload too short for AES-GCM IV and authentication tag");
    }

    std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + IV_SIZE);
    std::vector<uint8_t> tag(ciphertext.begin() + IV_SIZE, ciphertext.begin() + OVERHEAD_SIZE);

    const uint8_t* rawCiphertext = ciphertext.data() + OVERHEAD_SIZE;
    size_t rawCiphertextSize = ciphertext.size() - OVERHEAD_SIZE;

    ScopedEvpCipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw VaultException("Failed to allocate EVP_CIPHER_CTX for AES-GCM decryption");
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw VaultException("Failed to initialize AES-256-GCM cipher for decryption");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
        throw VaultException("Failed to configure AES-256-GCM IV length for decryption");
    }

    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw VaultException("Failed to set AES-256-GCM key and IV for decryption");
    }

    std::vector<uint8_t> plaintext(rawCiphertextSize);
    int outLength = 0;
    if (rawCiphertextSize > 0) {
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outLength,
                              rawCiphertext, static_cast<int>(rawCiphertextSize)) != 1) {
            throw CorruptedVaultException("AES-256-GCM decryption failed during update");
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                            const_cast<uint8_t*>(tag.data())) != 1) {
        throw CorruptedVaultException("Failed to configure expected AES-256-GCM authentication tag");
    }

    int finalLength = 0;
    int verificationResult = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outLength, &finalLength);
    if (verificationResult <= 0) {
        throw CorruptedVaultException("AES-256-GCM authentication verification failed (tampered data or wrong key)");
    }

    plaintext.resize(static_cast<size_t>(outLength + finalLength));
    return plaintext;
}

const std::vector<uint8_t>& AESCipher::getKey() const {
    return key;
}

void AESCipher::setKey(const std::string& keyString) {
    key = normalizeKey(keyString);
}

void AESCipher::setKey(const std::vector<uint8_t>& keyBytes) {
    key = normalizeKey(keyBytes);
}
