#ifndef VAULT_EXCEPTIONS_H
#define VAULT_EXCEPTIONS_H

#include <stdexcept>
#include <string>

/**
 * @brief Base exception class for all VaultSync domain-specific errors.
 */
class VaultException : public std::runtime_error {
public:
    /**
     * @brief Constructs a VaultException with an explanatory message.
     * @param message Explanatory error message string.
     */
    explicit VaultException(const std::string& message)
        : std::runtime_error(message) {
    }
};

/**
 * @brief Exception thrown when an incorrect password is provided during authentication.
 */
class WrongPasswordException : public VaultException {
public:
    /**
     * @brief Constructs a WrongPasswordException with an explanatory message.
     * @param message Explanatory error message string (default: "Wrong password").
     */
    explicit WrongPasswordException(const std::string& message = "Wrong password")
        : VaultException(message) {
    }
};

/**
 * @brief Exception thrown when an operation is attempted without valid authorization.
 */
class UnauthorizedAccessException : public VaultException {
public:
    /**
     * @brief Constructs an UnauthorizedAccessException with an explanatory message.
     * @param message Explanatory error message string (default: "Vault access is not authorized").
     */
    explicit UnauthorizedAccessException(const std::string& message = "Vault access is not authorized")
        : VaultException(message) {
    }
};

/**
 * @brief Exception thrown when vault data on disk or in a stream is corrupted or invalid.
 */
class CorruptedVaultException : public VaultException {
public:
    /**
     * @brief Constructs a CorruptedVaultException with an explanatory message.
     * @param message Explanatory error message string (default: "Vault data is corrupted").
     */
    explicit CorruptedVaultException(const std::string& message = "Vault data is corrupted")
        : VaultException(message) {
    }
};

/**
 * @brief Exception thrown when an I/O operation on the vault file fails.
 */
class FileException : public VaultException {
public:
    /**
     * @brief Constructs a FileException with an explanatory message.
     * @param message Explanatory error message string (default: "Vault file operation failed").
     */
    explicit FileException(const std::string& message = "Vault file operation failed")
        : VaultException(message) {
    }
};

/**
 * @brief Exception thrown when access is temporarily barred due to excessive failed attempts.
 */
class LockoutException : public VaultException {
public:
    /**
     * @brief Constructs a LockoutException with an explanatory message.
     * @param message Explanatory error message string (default: "Access is locked out").
     */
    explicit LockoutException(const std::string& message = "Access is locked out")
        : VaultException(message) {
    }
};

#endif // VAULT_EXCEPTIONS_H
