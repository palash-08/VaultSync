cmake_minimum_required(VERSION 3.16)

project(VaultSync
    VERSION 1.0
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

add_executable(VaultSync
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

target_include_directories(VaultSync PRIVATE 
    include
    include/crypto
    include/auth
    include/credentials
    include/storage
    include/security
    include/vault
    include/ui
)
target_link_libraries(VaultSync PRIVATE
    OpenSSL::Crypto
    ftxui::screen
    ftxui::dom
    ftxui::component
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
