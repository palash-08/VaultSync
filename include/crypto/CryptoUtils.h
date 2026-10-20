#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <vector>
#include <cstdint>

/**
 * @brief Cryptographic utilities for password hashing, salting, and key derivation.
 *
 * Implements FIPS 180-4 compliant SHA-256, secure random salt generation,
 * iterative salted password hashing (PBKDF-style stretching), constant-time
 * hash verification, and key derivation for the ICipher encryption layer.
 */
namespace CryptoUtils {

    /**
     * @brief Computes the SHA-256 hash of a string.
     * @param input Input string to hash.
     * @return 64-character lowercase hexadecimal hash.
     */
    std::string sha256(const std::string& input);

    /**
     * @brief Computes the SHA-256 hash of raw byte data.
     * @param data Binary vector to hash.
     * @return 64-character lowercase hexadecimal hash.
     */
    std::string sha256(const std::vector<uint8_t>& data);

    /**
     * @brief Generates a cryptographically random hexadecimal salt.
     * @param numBytes Number of random bytes to generate (default: 16 bytes = 32 hex chars).
     * @return Random hexadecimal string.
     */
    std::string generateSalt(size_t numBytes = 16);

    /**
     * @brief Computes an iterated, salted hash of a password for secure storage.
     * @param password Plaintext master password.
     * @param salt Random salt string.
     * @param iterations Number of hash stretch iterations (default: 5000).
     * @return Stretched hexadecimal password hash.
     */
    std::string hashPassword(const std::string& password, const std::string& salt, size_t iterations = 5000);

    /**
     * @brief Verifies a password against a stored salt and hash in constant time.
     * @param password Password attempt.
     * @param salt Stored salt string.
     * @param expectedHash Stored hash string.
     * @return True if password matches, false otherwise.
     */
    bool verifyPassword(const std::string& password, const std::string& salt, const std::string& expectedHash);

    /**
     * @brief Derives a deterministic cryptographic encryption key from the master password and salt.
     * @param masterPassword Plaintext master password.
     * @param salt Vault salt string.
     * @return Derived key string suitable for configuring an ICipher implementation.
     */
    std::string deriveKey(const std::string& masterPassword, const std::string& salt);

}

#endif // CRYPTO_UTILS_H
