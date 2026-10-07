cmake_minimum_required(VERSION 3.16)

project(VaultSync
    VERSION 1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(VaultSync
    src/main.cpp
    src/Credential.cpp
    src/FileStorage.cpp
    src/XORCipher.cpp
    src/CryptoUtils.cpp
    src/MasterVault.cpp
    src/TerminalUtils.cpp
)

target_include_directories(VaultSync PRIVATE include)

# Cipher and cryptographic test binary
add_executable(test_cipher
    tests/test_cipher.cpp
    src/Credential.cpp
    src/FileStorage.cpp
    src/XORCipher.cpp
    src/CryptoUtils.cpp
    src/MasterVault.cpp
    src/TerminalUtils.cpp
)

target_include_directories(test_cipher PRIVATE include)
