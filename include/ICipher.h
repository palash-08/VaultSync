#ifndef ICIPHER_H
#define ICIPHER_H

#include <vector>
#include <cstdint>
#include <string>

/**
 * @brief Abstract interface defining cryptographic cipher operations.
 *
 * Provides a common contract for encrypting and decrypting arbitrary
 * binary data (std::vector<uint8_t>). Derived classes implement specific
 * cryptographic algorithms (e.g., XORCipher for educational/demo purposes,
 * AESCipher for production).
 */
class ICipher {
public:
    virtual ~ICipher() = default;

    /**
     * @brief Encrypts binary plaintext into binary ciphertext.
     * @param plaintext Raw binary data to encrypt.
     * @return Encrypted binary data.
     */
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) const = 0;

    /**
     * @brief Decrypts binary ciphertext back to original binary plaintext.
     * @param ciphertext Encrypted binary data to decrypt.
     * @return Decrypted binary data.
     */
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) const = 0;
};

#endif // ICIPHER_H
