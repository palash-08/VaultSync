cmake_minimum_required(VERSION 3.16)

project(VaultSync
    VERSION 1.0.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

include(FetchContent)
FetchContent_Declare(ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
    GIT_TAG v5.0.0
)
FetchContent_MakeAvailable(ftxui)

add_executable(vaultsync
    src/main.cpp
    src/credentials/Credential.cpp
    src/credentials/WebCredential.cpp
    src/credentials/WiFiCredential.cpp
    src/credentials/SSHCredential.cpp
    src/credentials/CredentialFactory.cpp
    src/storage/Vault.cpp
    src/vault/VaultProxy.cpp
    src/security/PasswordGenerator.cpp
    src/security/PasswordStrength.cpp
    src/security/PasswordAnalyzer.cpp
    src/storage/FileStorage.cpp
    src/crypto/XORCipher.cpp
    src/crypto/AESCipher.cpp
    src/crypto/CryptoUtils.cpp
    src/auth/MasterVault.cpp
    src/ui/TerminalUtils.cpp
)

target_include_directories(vaultsync PRIVATE
    include
    include/crypto
    include/auth
    include/credentials
    include/storage
    include/security
    include/vault
    include/ui
)

target_link_libraries(vaultsync PRIVATE
    OpenSSL::Crypto
    ftxui::screen
    ftxui::dom
    ftxui::component
)

# Alias target to VaultSync for backward-compatible CMake target references
add_executable(VaultSync ALIAS vaultsync)

# Ensure VaultSync binary matches vaultsync build output
add_custom_command(TARGET vaultsync POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:vaultsync> ${CMAKE_CURRENT_BINARY_DIR}/VaultSync
)

# Cipher and cryptographic test binary
add_executable(test_cipher
    tests/test_cipher.cpp
    src/credentials/Credential.cpp
    src/credentials/WebCredential.cpp
    src/credentials/WiFiCredential.cpp
    src/credentials/SSHCredential.cpp
    src/credentials/CredentialFactory.cpp
    src/storage/Vault.cpp
    src/vault/VaultProxy.cpp
    src/security/PasswordGenerator.cpp
    src/security/PasswordStrength.cpp
    src/security/PasswordAnalyzer.cpp
    src/storage/FileStorage.cpp
    src/crypto/XORCipher.cpp
    src/crypto/AESCipher.cpp
    src/crypto/CryptoUtils.cpp
    src/auth/MasterVault.cpp
    src/ui/TerminalUtils.cpp
)

target_include_directories(test_cipher PRIVATE
    include
    include/crypto
    include/auth
    include/credentials
    include/storage
    include/security
    include/vault
    include/ui
)
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
