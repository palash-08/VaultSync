cmake_minimum_required(VERSION 3.16)

project(VaultSync
    VERSION 1.0.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

include(FetchContent)
include(GNUInstallDirs)

find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    FetchContent_Declare(nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

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
    src/storage/BackupConfig.cpp
    src/storage/SftpSubprocessClient.cpp
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
    src/storage/BackupConfig.cpp
    src/storage/SftpSubprocessClient.cpp
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
# C++ Native Messaging Host (vaultsync-host)
# -----------------------------------------------------------------------------
add_executable(vaultsync-host
    src/native_host/main.cpp
    src/native_host/NativeHost.cpp
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
    src/storage/BackupConfig.cpp
    src/storage/SftpSubprocessClient.cpp
    src/auth/MasterVault.cpp
    src/ui/TerminalUtils.cpp
)

target_include_directories(vaultsync-host PRIVATE
    include
    include/crypto
    include/auth
    include/credentials
    include/storage
    include/security
    include/vault
    include/ui
    include/native_host
)

target_link_libraries(vaultsync-host PRIVATE
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# -----------------------------------------------------------------------------
# Native Messaging Host Unit Tests
# -----------------------------------------------------------------------------
add_executable(test_native_host
    tests/test_native_host.cpp
    src/native_host/NativeHost.cpp
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
    src/storage/BackupConfig.cpp
    src/storage/SftpSubprocessClient.cpp
    src/auth/MasterVault.cpp
    src/ui/TerminalUtils.cpp
)

target_include_directories(test_native_host PRIVATE
    include
    include/crypto
    include/auth
    include/credentials
    include/storage
    include/security
    include/vault
    include/ui
    include/native_host
)

target_link_libraries(test_native_host PRIVATE
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

add_test(NAME test_native_host COMMAND test_native_host)

# -----------------------------------------------------------------------------
# Native Messaging Host Manifest Configuration
# -----------------------------------------------------------------------------
set(NATIVE_HOST_NAME "com.vaultsync.native")
set(NATIVE_HOST_EXTENSION_ID "fhmcpggbfoaaglijeknjdnpnehbpdajb")

# Configure manifest for prefix installation
set(NATIVE_HOST_PATH "${CMAKE_INSTALL_FULL_BINDIR}/vaultsync-host")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/com.vaultsync.native.json.in"
    "${CMAKE_CURRENT_BINARY_DIR}/com.vaultsync.native.json"
    @ONLY
)

# Configure development manifest pointing to local build directory
set(NATIVE_HOST_PATH "${CMAKE_CURRENT_BINARY_DIR}/vaultsync-host")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/com.vaultsync.native.json.in"
    "${CMAKE_CURRENT_BINARY_DIR}/com.vaultsync.native.dev.json"
    @ONLY
)

# -----------------------------------------------------------------------------
# Installation Rules
# -----------------------------------------------------------------------------
install(TARGETS vaultsync vaultsync-host
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install relocatable manifest to share/vaultsync/
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/com.vaultsync.native.json"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/vaultsync"
)

# Install user registration helper scripts
install(PROGRAMS
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/register_host.sh"
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/unregister_host.sh"
    DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

# Explicit option for system-wide manifest installation into /etc/ (requires root/sudo)
option(INSTALL_SYSTEM_NATIVE_HOST_MANIFEST
    "Install native messaging host manifest into system /etc directories for Chromium and Chrome"
    OFF
)

if(INSTALL_SYSTEM_NATIVE_HOST_MANIFEST)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/com.vaultsync.native.json"
        DESTINATION /etc/chromium/native-messaging-hosts
    )
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/com.vaultsync.native.json"
        DESTINATION /etc/opt/chrome/native-messaging-hosts
    )
endif()
install(FILES README.md architecture.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
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
