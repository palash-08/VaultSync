#ifndef XOR_CIPHER_H
#define XOR_CIPHER_H

#include "ICipher.h"
#include <string>
#include <vector>
#include <cstdint>

/**
 * @brief Repeating-key XOR Cipher implementation of ICipher.
 *
 * WARNING: XORCipher is intended strictly for EDUCATIONAL and DEMONSTRATION purposes.
 * It is NOT cryptographically secure and must NOT be used for production data protection.
 * In production or real-world vault storage, an authenticated cipher such as AES-256-GCM
 * should be used.
 *
 * In XOR cipher:
 *   ciphertext[i] = plaintext[i] ^ key[i % key_length]
 * Since XOR is self-inverse:
 *   plaintext[i]  = ciphertext[i] ^ key[i % key_length]
 */
class XORCipher : public ICipher {
private:
    std::vector<uint8_t> key;

public:
    explicit XORCipher(const std::string& keyStr = "VaultSyncDemoKey");
    explicit XORCipher(const std::vector<uint8_t>& keyBytes);

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) const override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) const override;

    const std::vector<uint8_t>& getKey() const;
    void setKey(const std::string& keyStr);
    void setKey(const std::vector<uint8_t>& keyBytes);
};

#endif // XOR_CIPHER_H
