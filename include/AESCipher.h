#ifndef AES_CIPHER_H
#define AES_CIPHER_H

#include "ICipher.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief Production-grade authenticated symmetric cipher using AES-256-GCM.
 *
 * Implements the ICipher interface using OpenSSL's EVP API to provide
 * authenticated encryption with associated data (AEAD) via Galois/Counter Mode (GCM).
 *
 * Features:
 * - 256-bit (32-byte) symmetric encryption key.
 * - 96-bit (12-byte) cryptographically secure random Initialization Vector (IV)
 *   generated per encryption using OpenSSL's RAND_bytes.
 * - 128-bit (16-byte) GCM authentication tag for tamper detection and data integrity.
 * - Serialized payload layout: [12 bytes IV] + [16 bytes GCM Tag] + [Ciphertext].
 */
class AESCipher : public ICipher {
public:
    /// Length of AES-256 key in bytes (32 bytes = 256 bits).
    static constexpr size_t KEY_SIZE = 32;

    /// Standard recommended length of GCM Initialization Vector in bytes (12 bytes = 96 bits).
    static constexpr size_t IV_SIZE = 12;

    /// Length of GCM authentication tag in bytes (16 bytes = 128 bits).
    static constexpr size_t TAG_SIZE = 16;

    /// Total header overhead (IV + Tag) preceding the ciphertext payload.
    static constexpr size_t OVERHEAD_SIZE = IV_SIZE + TAG_SIZE;

private:
    std::vector<uint8_t> key;

    static std::vector<uint8_t> normalizeKey(const std::string& keyString);
    static std::vector<uint8_t> normalizeKey(const std::vector<uint8_t>& keyBytes);

public:
    /**
     * @brief Constructs an AESCipher with a string key.
     * @param keyString The encryption key. If not 32 bytes, derived using SHA-256.
     */
    explicit AESCipher(const std::string& keyString);

    /**
     * @brief Constructs an AESCipher with raw byte key.
     * @param keyBytes The encryption key bytes. If not 32 bytes, derived using SHA-256.
     */
    explicit AESCipher(const std::vector<uint8_t>& keyBytes);

    /**
     * @brief Encrypts binary plaintext using AES-256-GCM with a fresh random IV.
     * @param plaintext Raw binary data to encrypt.
     * @return Serialized payload containing [12 bytes IV] + [16 bytes Tag] + [Ciphertext].
     * @throws VaultException If IV generation or encryption context initialization fails.
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) const override;

    /**
     * @brief Decrypts and authenticates an AES-256-GCM serialized payload.
     * @param ciphertext Serialized payload containing [IV] + [Tag] + [Ciphertext].
     * @return Decrypted binary plaintext.
     * @throws CorruptedVaultException If payload is malformed, truncated, or fails authentication.
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) const override;

    /**
     * @brief Retrieves the normalized 32-byte encryption key.
     * @return Const reference to key byte vector.
     */
    const std::vector<uint8_t>& getKey() const;

    /**
     * @brief Updates the encryption key from a string.
     * @param keyString New key string. If not 32 bytes, derived using SHA-256.
     */
    void setKey(const std::string& keyString);

    /**
     * @brief Updates the encryption key from raw bytes.
     * @param keyBytes New key bytes. If not 32 bytes, derived using SHA-256.
     */
    void setKey(const std::vector<uint8_t>& keyBytes);
};

#endif // AES_CIPHER_H
