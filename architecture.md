# VaultSync — Architecture

## 1. Overview

The Secure Password Manager is a C++ TUI (Terminal User Interface) application for storing and managing user credentials inside a protected local vault.

The implementation is centered around:

- Credential management
- Master-password authentication
- Encrypted vault storage
- Multiple credential types
- Controlled vault access
- Password-related utilities
- File handling and serialization
- Exception handling

The exact set of optional features and the final class structure may change during development.

---

# 2. High-Level Architecture

```text
                         Application
                              │
                              ▼
                       Authentication
                              │
                              ▼
                         VaultProxy
                              │
                              ▼
                            Vault
                         /         \
                        /           \
                       ▼             ▼
              Credential System   Encryption
                                      │
                                      ▼
                                   Storage
```

The application is divided into several logical components rather than making the main program responsible for all operations.

---

# 3. TUI Layer

The application uses a Terminal User Interface (TUI) rather than a traditional command-line prompt-based interface.

The TUI is responsible for:

- Rendering screens
- Menus and navigation
- Forms and input fields
- Credential lists and tables
- Password visibility controls
- Status and error messages
- Keyboard input

The TUI should communicate with the application/backend components without directly manipulating vault data or storage.

General flow:

```text
User
 │
 ▼
TUI
 │
 ▼
Application / Backend
 │
 ▼
Result
 │
 ▼
TUI
 │
 ▼
User
```

## TUI Screens

The exact screen structure may change during development. The expected structure is:

```text
Login
  │
  ▼
Main Menu
  │
  ├── Vault
  │    ├── View Credentials
  │    ├── Add Credential
  │    ├── Edit Credential
  │    ├── Delete Credential
  │    └── Search
  │
  ├── Password Tools
  │    ├── Generate Password
  │    └── Password Strength
  │
  ├── Security
  │    └── Security Score
  │
  ├── Backup / Restore
  │
  └── Lock / Logout
```

## Credential View

Credentials may be presented as a table/list within the TUI.

Sensitive fields such as passwords should be hidden by default.

A credential detail view can provide actions such as:

```text
Show / Hide Password
Edit
Delete
Back
```

## Application Layer

The application layer connects the TUI with the backend components.

It handles:

- Selecting the requested operation
- Passing requests to the appropriate component
- Receiving results
- Passing results or errors back to the TUI

The application layer should not directly manipulate the stored vault data.

General flow:

```text
User
 │
 ▼
TUI
 │
 ▼
Application
 │
 ▼
Required component
 │
 ▼
Result
 │
 ▼
Application
 │
 ▼
TUI
 │
 ▼
User
```

---

# 4. Credential System

The credential system represents the different types of information that can be stored in the vault.

A common base `Credential` abstraction is used for shared information and operations.

```text
                    Credential
                    /    |    \
                   /     |     \
                  ▼      ▼      ▼
                Web     WiFi    SSH
```

## Credential

Contains information common to credentials, such as:

- Username
- Password
- Notes

It acts as the base type for the different credential categories.

Common operations include:

```text
Display
Get data
Modify data
```

The exact fields may be adjusted as the credential types are implemented.

---

## Web Credential

Represents credentials associated with websites or web services.

Possible information:

```text
Website
Username
Password
Notes
```

---

## WiFi Credential

Represents wireless network credentials.

Possible information:

```text
SSID
Password
Notes
```

---

## SSH Credential

Represents SSH connection credentials.

Possible information:

```text
Host
Port
Username
Password
Notes
```

---

# 5. Vault

The `Vault` represents the main collection of stored credentials.

It is responsible for operations such as:

```text
Add credential
View credentials
Edit credential
Delete credential
Search credentials
```

The Vault also acts as the central point for loading and saving credential data.

Conceptually:

```text
                    Vault
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
        Add         Search       Edit
          │           │           │
          └───────────┼───────────┘
                      ▼
                    Delete
```

The Vault should not be responsible for user-interface operations.

---

# 6. Authentication

Authentication controls access to the vault using a master password.

The master password itself should not be stored directly.

The authentication system is expected to maintain information such as:

```text
Salt
Password hash
```

Authentication flow:

```text
User enters master password
           │
           ▼
      Process password
           │
           ▼
       Generate hash
           │
           ▼
   Compare with stored hash
           │
       ┌───┴───┐
       ▼       ▼
    Success   Failure
       │       │
       ▼       ▼
    Access   Reject
```

Additional login protection may be added later.

---

# 7. Vault Access Control

A `VaultProxy` may be used between the application and the Vault.

```text
Application
     │
     ▼
VaultProxy
     │
     │ authentication check
     ▼
   Vault
```

The proxy acts as an access-control layer.

For example:

```text
Authenticated
     │
     ▼
Vault operation allowed
```

and:

```text
Not authenticated
     │
     ▼
Vault operation rejected
```

This keeps authentication checks separate from the core Vault implementation.

---

# 8. Encryption Architecture

Encryption is separated from the Vault through an abstract cipher interface.

```text
                     ICipher
                    /       \
                   /         \
                  ▼           ▼
             XORCipher     AESCipher
```

## ICipher

`ICipher` defines the common operations required from an encryption implementation.

Conceptually:

```text
encrypt()
decrypt()
```

The rest of the application can interact with the cipher through this interface without depending on a particular encryption algorithm.

---

## XORCipher

`XORCipher` is a concrete implementation of `ICipher`.

It provides:

```text
Encrypt data
Decrypt data
```

The initial implementation can use XOR-based encryption to keep the encryption layer simple and understandable.

---

## AESCipher

An AES implementation may be added later.

If implemented, it would follow the same `ICipher` interface:

```text
ICipher
   │
   ├── XORCipher
   │
   └── AESCipher
```

The final decision regarding AES and any external cryptographic library will be made during implementation.

---

# 9. Vault Data Flow

When saving the vault:

```text
Credential Objects
       │
       ▼
 Serialization
       │
       ▼
 Encryption
       │
       ▼
 Binary Storage
```

When loading:

```text
Binary Storage
       │
       ▼
 Decryption
       │
       ▼
 Deserialization
       │
       ▼
Credential Objects
```

This separates the in-memory representation of the credentials from their stored representation.

---

# 10. File Storage

The application will use local files for persistent storage.

The primary vault storage is expected to be a binary file containing encrypted vault data.

Conceptually:

```text
Vault
 │
 ▼
Serialize
 │
 ▼
Encrypt
 │
 ▼
Binary File
```

Authentication-related information may be stored separately from the vault.

The exact filenames and binary format will be finalized during implementation.

---

# 11. Serialization

Serialization converts the in-memory credential data into a form that can be written to a file.

```text
Credential
     │
     ▼
Serialize
     │
     ▼
Stored representation
```

Deserialization performs the reverse operation:

```text
Stored representation
     │
     ▼
Deserialize
     │
     ▼
Credential
```

Serialization will be designed to support the different credential types.

---

# 12. Repository

A generic `Repository<T>` may be used as an abstraction for storing and managing collections of objects.

Conceptually:

```text
Repository<T>
     │
     ├── Add
     ├── Remove
     ├── Get
     └── Search/iterate
```

For example:

```text
Repository<Credential>
```

or an appropriate polymorphic representation of credentials.

The final repository design will depend on the chosen credential storage implementation.

---

# 13. Password Tools

The password-management utilities form a separate part of the application.

Potential components include:

### Password Generator

Generates passwords according to user-selected requirements.

Possible options:

```text
Length
Uppercase
Lowercase
Numbers
Symbols
```

### Password Strength Analyzer

Evaluates characteristics such as:

```text
Length
Character variety
Numbers
Symbols
```

### Password Reuse Detection

Checks whether a password is already used by another stored credential.

### Password Age

Tracks when a password was created or last changed.

These features may be combined into a password/security utility component depending on the final implementation.

---

# 14. Security Score

The application may provide an overall security score based on the state of the stored credentials.

Potential factors include:

```text
Weak passwords
Reused passwords
Old passwords
Password strength
```

Example:

```text
Security Score: 82/100
```

The scoring system will be defined once the password-analysis features are implemented.

---

# 15. Login Protection

Additional protection may be implemented for repeated failed login attempts.

Possible flow:

```text
Failed Login
     │
     ▼
Increase Attempt Count
     │
     ▼
Apply Delay
     │
     ▼
Allow Next Attempt
```

The delay may increase with consecutive failures.

The exact limits and timing will be finalized during implementation.

---

# 16. Automatic Vault Locking

The application may automatically lock the vault after a period of inactivity.

```text
User Activity
     │
     ▼
Update activity time
     │
     ▼
Inactivity detected
     │
     ▼
Lock vault
     │
     ▼
Require authentication
```

This functionality will be integrated with the authentication/access-control layer.

---

# 17. Backup and Restore

The application may support encrypted backup and restoration of the vault.

### Backup

```text
Vault
 │
 ▼
Serialize
 │
 ▼
Encrypt
 │
 ▼
Backup File
```

### Restore

```text
Backup File
 │
 ▼
Decrypt
 │
 ▼
Deserialize
 │
 ▼
Vault
```

The backup should preserve the same protection applied to the primary vault data.

---

# 18. Audit Logging

An audit component may record important application events.

Potential events include:

```text
Successful login
Failed login
Credential added
Credential edited
Credential deleted
Vault locked
Logout
Backup
Restore
```

Conceptually:

```text
Application Event
       │
       ▼
 Audit Logger
       │
       ▼
   Audit Log
```

---

# 19. Tamper-Evident Audit Log

The selected advanced feature may be a hash-chained audit log.

The entries form a chain:

```text
Entry 1
   │
   ▼
Entry 2
   │
   ▼
Entry 3
   │
   ▼
Entry 4
```

Each entry is associated with information from the previous entry.

During verification:

```text
Audit Log
    │
    ▼
Verify chain
    │
 ┌──┴──┐
 ▼     ▼
Valid  Invalid
```

If an earlier entry is modified, subsequent verification can detect the inconsistency.

---

# 20. Exception Handling

The application will use exceptions for error conditions rather than handling every failure directly inside the main program.

Potential custom exceptions include:

```text
WrongPasswordException
UnauthorizedAccessException
CorruptedVaultException
FileException
```

Possible error sources:

```text
Authentication failure
Unauthorized vault access
Invalid vault data
File read/write failure
Invalid operations
```

General flow:

```text
Operation
   │
   ▼
Exception occurs
   │
   ▼
throw
   │
   ▼
catch
   │
   ▼
Display/handle error
```

---

# 21. C++ Architecture

The implementation is intended to demonstrate the following C++ concepts through the project:

```text
Classes
Encapsulation
Constructors
Destructors
this pointer

Inheritance
Function overriding
Virtual functions
Pure virtual functions
Abstract classes
Dynamic binding

Operator overloading
Friend functions
Static members

Templates
STL containers
Algorithms
Smart pointers

File handling
Binary I/O
Serialization

Exception handling
try / throw / catch
```

The exact usage of each concept will be determined by the final implementation rather than forcing every concept into a separate component.

---

# 22. Overall Component Relationship

```text
                           Application
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
              ▼                 ▼                 ▼
       Authentication      Password Tools     Audit Logger
              │
              ▼
         VaultProxy
              │
              ▼
            Vault
              │
       ┌──────┴──────┐
       ▼             ▼
 Credential       Repository
    System           │
       │             │
       ├── Web       │
       ├── WiFi      │
       └── SSH       │
                     │
                     ▼
                  Storage
                     │
                     ▼
                  ICipher
                 /       \
                ▼         ▼
           XORCipher   AESCipher*
```

`*` Optional / subject to final implementation.

---

# 23. Implementation Status

The architecture is intentionally not considered final.

Features and components may be:

- Added
- Removed
- Combined
- Renamed
- Simplified

as implementation progresses.

The final architecture should be updated here once the actual implementation is stable.
