# VaultSync

**A Secure Password Manager for Linux, written in C++17.**

VaultSync is a local-first password manager that securely stores your credentials in an encrypted vault on your Linux machine. It provides a terminal-based interface, browser autofill through a Chrome/Chromium extension, password security analysis, and encrypted off-site backups.

---

## 1. Features

- **Individual User Vaults:** Each user has a separate encrypted vault protected by two passwords:
  - **Master Password:** Authenticates the user and grants access to the application.
  - **Credential Password:** Unlocks and decrypts the stored credentials.

- **Multiple Credential Types:** Supports website, Wi-Fi, SSH, and general-purpose credentials.

- **Credential Management:** Add, view, edit, delete, search, and copy saved credentials.

- **Password Security Tools:**
  - Secure password generator.
  - Password strength checker.
  - Security audit that identifies weak, reused, and old passwords.
  - Overall vault security score out of 100.

- **Automatic Lockout:** Three consecutive incorrect password attempts lock the corresponding authentication step for 30 seconds.

- **Inactivity Lock:** Automatically locks the vault after a period of inactivity.

- **Browser Autofill:** A Chrome/Chromium extension detects login forms and allows users to fill saved credentials directly into websites.

- **Encrypted Off-site Backup:** Transfers a copy of the encrypted vault to another machine over a Tailscale network using SFTP.

---

## 2. Supported Credential Types

VaultSync uses object-oriented polymorphism to support different credential categories, each with its own specialized attributes.

| Credential Type | Badge | Specific Attributes | Example Use |
|---|---|---|---|
| Web | `[WEB]` | URL, Username, Password | Websites, cloud consoles, dashboards |
| Wi-Fi | `[WIFI]` | SSID, Password, Encryption Type | Wireless network configurations |
| SSH | `[SSH]` | Host/IP, Port, Username, Key/Passphrase | Servers, VPS, jump hosts |
| Generic | `[GEN]` | Title, Username, Password | Desktop applications, database logins |

---

## 3. Security Architecture

VaultSync uses multiple security mechanisms to protect stored credentials.

### 3.1 Password Protection

- Passwords are never stored in plaintext.
- Salted password hashes are used for password verification.
- The master password and credential password serve separate purposes.

### 3.2 Encryption

- **Algorithm:** AES-256-GCM.
- **Library:** OpenSSL.
- **Key Derivation:** PBKDF2-HMAC-SHA256.
- **Initialization Vector:** A fresh 12-byte random IV for each encryption operation.
- **Authentication Tag:** A 16-byte GCM authentication tag to detect tampering.

The encryption key is derived from the credential password and is never stored directly on disk.

### 3.3 File Integrity

VaultSync validates its encrypted vault data before accepting it. Invalid, corrupted, or tampered encrypted data is rejected rather than loaded as valid credentials.

### 3.4 File Permissions and Storage

- Vault files are stored in `~/.local/state/vaultsync`.
- Access is restricted to the owning user account through filesystem permissions.

---

## 4. Requirements

### System Requirements

- Linux (tested on Debian/Ubuntu).
- C++17-compatible compiler (GCC or Clang).
- CMake 3.16 or newer.
- OpenSSL development libraries (`libssl-dev`).

### Optional Dependencies

- Google Chrome or Chromium for browser autofill.
- Tailscale and SFTP for off-site backups.

### Install Dependencies

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev
```

FTXUI (terminal UI library) and the JSON library are downloaded automatically by CMake during the build process.

---

## 5. Installation

### 5.1 Install Using the APT Repository

The recommended installation method for Debian/Ubuntu (amd64).

**Step 1: Download and trust the repository's public GPG key.**

```bash
sudo mkdir -p /etc/apt/keyrings

sudo curl -fsSL https://apt.palash.pro/keyring.gpg \
  -o /etc/apt/keyrings/vaultsync.asc
```

**Step 2: Add the APT repository.**

```bash
echo "deb [signed-by=/etc/apt/keyrings/vaultsync.asc] https://apt.palash.pro stable main" \
  | sudo tee /etc/apt/sources.list.d/vaultsync.list
```

**Step 3: Update package lists and install VaultSync.**

```bash
sudo apt update
sudo apt install vaultsync
```

Future updates can be installed using:

```bash
sudo apt upgrade
```

### 5.2 Build from Source

Clone the repository:

```bash
git clone https://github.com/palash-08/VaultSync.git
cd VaultSync
```

Configure and build:

```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Run the automated tests:

```bash
ctest --test-dir build --output-on-failure
```

Launch VaultSync:

```bash
./build/vaultsync
```

### 5.3 Install System-wide

```bash
sudo cmake --install build
```

### 5.4 Build a Debian Package (.deb)

Configure the build with system-wide native messaging host registration:

```bash
cmake -B build -S . \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DINSTALL_SYSTEM_NATIVE_HOST_MANIFEST=ON
```

Build and package:

```bash
cmake --build build

cpack --config build/CPackConfig.cmake \
  -G DEB -B build/packages
```

Install the package:

```bash
sudo dpkg -i build/packages/vaultsync_*.deb
```

The package installs:

- `vaultsync`
- `vaultsync-host`
- Browser registration helper scripts.
- Native messaging host configuration for Chrome and Chromium (when the corresponding CMake option is enabled).

**Note:** If you install with `INSTALL_SYSTEM_NATIVE_HOST_MANIFEST=ON`, you do not need to run `register_host.sh` manually. You only need to load the browser extension.

If you build without this option, run the registration script after installation.

---

## 6. Getting Started

1. Launch the application:

   ```bash
   vaultsync
   ```

2. Select **Create Master Vault**.

3. Choose a username and configure:
   - Master password.
   - Credential password.

4. Log in using your username and master password.

5. Enter your credential password to unlock the credential vault.

6. Start managing your credentials using the application tabs:
   - Add and manage credentials.
   - Search saved entries.
   - Generate secure passwords.
   - Check password strength.
   - Run security audits.

---

## 7. Browser Autofill Architecture

VaultSync integrates with Chrome/Chromium through a browser extension and a native messaging host.

The extension never directly accesses the encrypted vault file. Instead, it communicates with `vaultsync-host`, a helper executable that uses the same underlying C++ code as the terminal application.

### 7.1 Architecture Overview

```text
       WEB PAGE
    ┌──────────────┐
    │  content.js  │
    │              │
    │ Detects login│
    │ forms & fills│
    └──────┬───────┘
           │
           ▼
    ┌──────────────────┐
    │  background.js   │
    │                  │
    │ Routes requests  │
    └────────┬─────────┘
             │
             ▼
    ┌──────────────────────┐
    │   vaultsync-host     │
    │                      │
    │ Native Messaging     │
    │ Helper (C++)         │
    └──────────┬───────────┘
               │
               ▼
    ┌──────────────────────┐
    │   Encrypted Vault    │
    │                      │
    │   Local Storage      │
    └──────────────────────┘

       BROWSER POPUP
    ┌──────────────────────┐
    │    popup.html/js     │
    │                      │
    │ Unlock / Lock Vault  │
    │ Select Saved Login   │
    └──────────┬───────────┘
               │
               └──── Requests through
                     background.js
```

### 7.2 Component Responsibilities

| Component | Responsibility |
|---|---|
| `content.js` | Detects login forms, adds the VaultSync icon to password fields, and fills credentials. |
| `popup.html` / `popup.js` | Provides the browser popup for unlocking, locking, and selecting credentials. |
| `background.js` | Acts as the communication layer between the popup, content scripts, and native helper. |
| `vaultsync-host` | Handles native messaging requests, accesses the vault using the shared C++ implementation, and returns matching credentials. |

### 7.3 Communication

Chrome communicates with `vaultsync-host` using the Native Messaging API over standard input and output (stdin/stdout).

- No network port is opened for browser communication.
- The native messaging host manifest specifies which extension is allowed to connect.
- The helper returns credentials matching the requested website rather than exposing the entire vault to the extension.

---

## 8. Browser Autofill Setup

### Step 1: Build the Project

Ensure that the native helper executable exists:

```bash
cmake --build build
```

The helper should be available at:

```text
build/vaultsync-host
```

### Step 2: Register the Native Messaging Host

Skip this step if VaultSync was installed using the APT repository or a `.deb` package with system-wide native host registration enabled.

For a source build:

```bash
./scripts/register_host.sh --binary ./build/vaultsync-host
```

### Step 3: Load the Browser Extension

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select the project's `extension/` directory.

### Step 4: Use Autofill

1. Click the VaultSync toolbar icon.
2. Unlock the vault using your master and credential passwords.
3. Open a website for which you have saved credentials.
4. Click the VaultSync icon displayed in the password field.
5. Select or fill the matching login.

### Unregister the Native Messaging Host

To remove browser registration:

```bash
./scripts/unregister_host.sh
```

---

## 9. Off-site Backup

VaultSync supports encrypted off-site backups using SFTP over a Tailscale network.

### 9.1 Requirements

- Tailscale installed and running on both machines.
- SSH access configured on the backup machine.
- An SSH key available for authentication.
- A destination directory on the backup machine.

### 9.2 Configuration

Open the **Backup** tab in VaultSync and provide:

- Backup machine hostname or Tailscale IP.
- SSH username.
- Destination folder.
- SSH private key file.

The configuration is saved in:

```text
~/.config/vaultsync/backup.conf
```

### 9.3 Backup Process

1. Start a backup from the application.
2. VaultSync locates the encrypted vault file.
3. It transfers a copy using SFTP.
4. The backup is saved on the remote machine with a timestamp in its filename.

**Security:** The backup machine receives the already-encrypted vault file, not the decrypted credentials or passwords.

---

## 10. CI/CD Pipeline

VaultSync uses GitHub Actions to automate testing, building, and release publishing.

Two workflows are configured:

| Workflow | Trigger | Responsibilities |
|---|---|---|
| `ci.yml` | Pushes to `main` or `feature/**`, and pull requests targeting `main` | Configures the CMake build, compiles the project, and runs automated tests. |
| `release.yml` | Version tags such as `v1.0.0`, or manual execution | Builds and tests the application, creates a `.deb` package, publishes a GitHub Release, and updates the APT repository. |

### Release Distribution

Released packages are published through the signed APT repository:

```text
https://apt.palash.pro
```

This allows users to install and update VaultSync using standard Debian/Ubuntu package management tools.

---

## 11. Project Structure

```text
VaultSync/
│
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
│
├── include/                 # Header files
│
├── src/                     # Application source code
│   ├── auth/                # Authentication, sessions, lockout
│   ├── credentials/         # Web, Wi-Fi, SSH, Generic credentials
│   ├── crypto/              # Encryption and password hashing
│   ├── vault/               # Credential storage and searching
│   ├── storage/             # File operations and backups
│   ├── security/            # Password generator, strength, audit
│   ├── native_host/         # Browser native messaging helper
│   └── ui/                  # Terminal user interface
│
├── extension/               # Chrome/Chromium extension
│
├── scripts/                 # Host registration/unregistration
│
├── tests/                   # Automated tests
│
├── docs/                    # Additional documentation
│
├── CMakeLists.txt           # Build and installation configuration
├── .gitignore
└── README.md
```

---

## 12. Future Improvements

Potential areas for further development include:

- More comprehensive automated security testing.
- Improved cross-platform support.
- Additional browser integration.
- Stronger backup and recovery workflows.
- Enhanced credential security auditing.

---

## 13. License

See the repository's license file for licensing and usage information.
