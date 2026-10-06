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
)

target_include_directories(VaultSync PRIVATE include)
