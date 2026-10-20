# VaultSync

<p align="center">
  <strong>Encrypted terminal-based password and credential manager written in modern C++17.</strong><br>
  Built with OpenSSL AES-256-GCM authenticated encryption, PBKDF2-HMAC-SHA256 key derivation, and XDG-compliant storage.
</p>

---

> [!NOTE]
> **APT Repository In Progress**: The official signed Debian/Ubuntu package repository at [`apt.palash.pro`](https://apt.palash.pro) is currently being set up. In the meantime, the project can be built from source using CMake and installed using the ".deb" package generated with CPack as shown below.

---

## Overview

**VaultSync** is a lightweight, terminal-native credential manager designed for personal workstation security. It stores credentials locally in encrypted binary vaults using authenticated AES-256-GCM symmetric encryption, memory-hard PBKDF2 key derivation (600,000 iterations), and zero-knowledge dual authentication (separating login authentication from credential vault encryption). Vault files are strictly isolated in `$XDG_STATE_HOME/vaultsync` (defaulting to `~/.local/state/vaultsync`) with POSIX `0700` directory and `0600` file permissions.

---

## Installation & Build

### Prerequisites

- **C++ Compiler**: GCC 9+ or Clang 10+ (supporting C++17)
- **Build System**: CMake 3.16+
- **Cryptographic Library**: OpenSSL 3.0+ (`libssl-dev`)
- **Package Utilities** (optional, for `.deb` creation): `dpkg-dev`

```bash
# Debian / Ubuntu dependencies
sudo apt-get update && sudo apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    dpkg-dev
```

### Build from Source

```bash
# 1. Clone the repository
git clone https://github.com/palash-08/VaultSync.git
cd VaultSync

# 2. Configure and build in Release mode
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel

# 3. Run the automated test suite
ctest --test-dir build --output-on-failure

# 4. Install binary and documentation to your system
sudo cmake --install build
```

This installs the `vaultsync` executable to `/usr/local/bin` (or `CMAKE_INSTALL_PREFIX/bin`) and documentation to `/usr/local/share/doc/vaultsync`.

---

## Generating the Debian Package (.deb)

VaultSync includes native CPack Debian packaging integration:

```bash
# Build release binary and package with CPack
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build
cpack --config build/CPackConfig.cmake -G DEB -B build/packages

# Inspect the generated package
dpkg-deb --info build/packages/vaultsync_1.0.0-1_amd64.deb
dpkg-deb --contents build/packages/vaultsync_1.0.0-1_amd64.deb

# Install on Debian/Ubuntu systems
sudo dpkg -i build/packages/vaultsync_1.0.0-1_amd64.deb
```

---

## Quick Start Guide

Launch the terminal manager:

```bash
vaultsync
```

### 1. Initialize a Master Vault
1. Select `[1] Create Master Vault`.
2. Enter your username (e.g. `developer`).
3. Set your **Master Account Password** (authenticates user login and protects against brute-force lockouts).
4. Set your **Credential Vault Password** (serves as the primary key material for AES-256-GCM encryption).

### 2. Login to Master Vault
1. Select `[2] Login to Master Vault`.
2. Enter your username and master password (passwords are masked in the terminal).
3. Access the authenticated management session.

---

## Supported Credential Types

VaultSync handles credentials polymorphically, providing tailored attributes for different services:

| Type | Badge | Specific Attributes | Example Target |
| :--- | :---: | :--- | :--- |
| **Web** | `[WEB]` | URL, Username, Password | Cloud consoles, web dashboards |
| **WiFi** | `[WIFI]` | SSID, Password, Encryption Type (`WPA2`, `WPA3`, etc.) | Network configurations |
| **SSH** | `[SSH]` | Host / IP, Port (default: 22), Username, Key/Passphrase | Servers, jump hosts, VPS nodes |
| **Generic** | `[GEN]` | Title, Username, Password | Desktop apps, database logins |

---

## Password Tools & Health Dashboard

Inside an authenticated vault session, you can run security diagnostics:

- **Password Generation**: Generate cryptographically secure passwords with customizable length and symbol sets.
- **Shannon Entropy Check**: Real-time evaluation of password complexity, length, and character space.
- **Duplicate & Reuse Audit**: Scan the vault to detect identical passwords reused across multiple accounts.
- **Vault Health Score**: View an aggregate 0–100 score evaluating the overall security posture of your stored credentials.

---

## Running the Test Suite

VaultSync ships with a comprehensive regression test suite (`test_cipher`) registered with CTest:

```bash
# Configure in Debug mode
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target test_cipher

# Run all 12 test suites
ctest --test-dir build --verbose
```

The test suite validates:
- AES-256-GCM encryption, decryption, and authentication tag verification.
- Tamper detection on modified ciphertext and initialization vectors.
- 600,000-iteration PBKDF2-HMAC-SHA256 key derivation.
- XDG storage relocation and POSIX `0700`/`0600` permissions.
- Polymorphic binary serialization and deserialization.
- Brute-force lockout rate limiting and dual authentication logic.

---

## Project Layout

```
VaultSync/
├── CMakeLists.txt          # Build system and CPack Debian packaging rules
├── README.md               # Project documentation
├── architecture.md         # 23-section architecture specification
├── include/                # Public C++ header files
│   ├── AESCipher.h         # OpenSSL AES-256-GCM authenticated cipher
│   ├── Credential.h        # Base polymorphic credential abstraction
│   ├── CredentialFactory.h # Factory for instantiating polymorphic credentials
│   ├── CryptoUtils.h       # PBKDF2 key derivation & cryptographic utilities
│   ├── FileStorage.h       # Tagged binary persistence with atomic writes
│   ├── ICipher.h           # Abstract cipher interface
│   ├── IVault.h            # Abstract vault interface
│   ├── MasterVault.h       # Dual-auth coordinator and lockout protection
│   ├── PasswordAnalyzer.h  # Vault-wide security scoring and duplicate check
│   ├── PasswordGenerator.h # Cryptographically secure password generator
│   ├── PasswordStrength.h  # Entropy scoring and pattern evaluation
│   ├── Repository.h        # Generic template repository with predicate search
│   ├── SSHCredential.h     # SSH credential specialization
│   ├── TerminalUtils.h     # Terminal input masking & formatting
│   ├── Vault.h             # Concrete vault storage engine
│   ├── VaultExceptions.h   # Custom exception hierarchy
│   ├── VaultProxy.h        # Access control proxy wrapper
│   ├── WebCredential.h     # Web credential specialization
│   ├── WiFiCredential.h    # WiFi credential specialization
│   └── XORCipher.h         # Fallback test cipher
├── src/                    # C++ implementation files
├── tests/                  # Automated test suite
│   └── test_cipher.cpp     # CTest test suites (12 modules)
└── docs/                   # Engineering logs and reference documentation
```

---

## License

This project is licensed under the [MIT License](LICENSE).
