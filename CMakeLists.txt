cmake_minimum_required(VERSION 3.16)

project(VaultSync
    VERSION 1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(VaultSync
    src/main.cpp
    src/Credential.cpp
    src/WebCredential.cpp
    src/WiFiCredential.cpp
    src/SSHCredential.cpp
    src/CredentialFactory.cpp
    src/Vault.cpp
    src/VaultProxy.cpp
    src/PasswordGenerator.cpp
    src/PasswordStrength.cpp
    src/PasswordAnalyzer.cpp
    src/FileStorage.cpp
    src/XORCipher.cpp
    src/AESCipher.cpp
    src/CryptoUtils.cpp
    src/MasterVault.cpp
    src/TerminalUtils.cpp
)

target_include_directories(VaultSync PRIVATE include)
target_link_libraries(VaultSync PRIVATE OpenSSL::Crypto)

# Cipher and cryptographic test binary
add_executable(test_cipher
    tests/test_cipher.cpp
    src/Credential.cpp
    src/WebCredential.cpp
    src/WiFiCredential.cpp
    src/SSHCredential.cpp
    src/CredentialFactory.cpp
    src/Vault.cpp
    src/VaultProxy.cpp
    src/PasswordGenerator.cpp
    src/PasswordStrength.cpp
    src/PasswordAnalyzer.cpp
    src/FileStorage.cpp
    src/XORCipher.cpp
    src/AESCipher.cpp
    src/CryptoUtils.cpp
    src/MasterVault.cpp
    src/TerminalUtils.cpp
)

target_include_directories(test_cipher PRIVATE include)
target_link_libraries(test_cipher PRIVATE OpenSSL::Crypto)

enable_testing()
add_test(NAME test_cipher COMMAND test_cipher)
