cmake_minimum_required(VERSION 3.16)

project(VaultSync
    VERSION 1.0.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(vaultsync
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

target_include_directories(vaultsync PRIVATE include)
target_link_libraries(vaultsync PRIVATE OpenSSL::Crypto)

# Alias target to VaultSync for backward-compatible CMake target references
add_executable(VaultSync ALIAS vaultsync)

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

# -----------------------------------------------------------------------------
# Installation Rules
# -----------------------------------------------------------------------------
install(TARGETS vaultsync
    RUNTIME DESTINATION bin
)

install(FILES README.md architecture.md
    DESTINATION share/doc/vaultsync
)

# -----------------------------------------------------------------------------
# CPack Debian (.deb) Packaging Configuration
# -----------------------------------------------------------------------------
set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME "vaultsync")
set(CPACK_PACKAGE_VENDOR "Palash Patel")
set(CPACK_PACKAGE_CONTACT "packages@palash.pro")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Secure terminal vault manager for personal credentials")
set(CPACK_PACKAGE_DESCRIPTION "VaultSync is an encrypted terminal-based password and credential manager written in C++17 utilizing AES-256-GCM and PBKDF2-HMAC-SHA256.")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Palash Patel <packages@palash.pro>")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/palash-08/VaultSync")
set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
set(CPACK_DEBIAN_PACKAGE_RELEASE "1")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_COMPRESSION_TYPE "gzip")
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)

include(CPack)
