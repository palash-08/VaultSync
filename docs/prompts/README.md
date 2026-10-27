# VaultSync — Prompts & Execution History

This document chronicles the prompt interactions, architectural directives, and engineering results throughout the development of **VaultSync** (a secure C++ Terminal User Interface password manager).

---

## Executive Summary & Prompt Matrix

| Prompt | Phase / Topic | Harness & Model | Key Actions & Results | Commit / Artifacts |
| :--- | :--- | :--- | :--- | :--- |
| **Prompt 1** | Architectural Specification & System Ingestion | Orchestrator (Internal) | Ingested 23-section architecture specification; validated GCC 16.2.1, CMake 4.4.3, ncurses 6.6. | `architecture.md` |
| **Prompt 2** | Role Definition & Read-Only Exploration | Orchestrator (Internal) | Mapped AO daemon (PID 7761, port 3001) & session `vaultsync-2`; cataloged flat codebase; verified baseline tests. | Test suite 1–8 |
| **Prompt 3** | Worker Session 1: Polymorphic Core Implementation | Codex / `gpt-6-luna` (medium effort) | Spawned worker `vaultsync-3`; implemented polymorphic credential hierarchy, access control, repository, and password tools across 27 files. | Commit `35125ae` (27 files) |
| **Prompt 4 & 5** | Readability Analysis & Sandbox Daemon Diagnosis | Orchestrator (Internal) | Diagnosed GPT-6 Luna token-minimization formatting; resolved daemon liveness false alarm (PID namespace isolation). | Technical RCA report |
| **Prompt 6** | Worker Session 2: Readability & Doxygen Refactor | Agy / `claude-opus-4-6` | Updated harness configuration; merged `35125ae`; spawned worker `vaultsync-4` to refactor 27 files with 4-space indents and Doxygen docs. | 27 refactored files (+2055 / -184) |
| **Prompt 7** | Verification, Build & Test Suite Execution | Orchestrator (Internal) | Verified `vaultsync-4` artifacts; built with CMake; executed all 9 test suites with 100% pass; merged to `main`. | Commit `6735cca`, `test_cipher` |
| **Prompt 8** | Remote Git Synchronization & Functional Roadmap | Orchestrator (Internal) | Pushed commits `35125ae` & `6735cca` to `origin/main`; planned UI integration, VaultProxy wiring, and OpenSSL 3.6.4 AES cipher. | `origin/main`, roadmap report |
| **Prompt 9** | Production Security with AES-256-GCM Cipher | Agy / `claude-opus-4-6` (`vaultsync-4`) | Delegated OpenSSL EVP AES-256-GCM authenticated cipher implementation, CMake linking, and unit tests to `rectify-code-readability` agent. | `AESCipher.h`, `AESCipher.cpp`, `test_cipher.cpp` |
| **Prompt 10** | Phase 3: Wire MasterVault to VaultProxy, Repository, & AESCipher | Orchestrator (Internal) | Wired `MasterVault` to `VaultProxy` and `Repository<Credential>`, switched default cipher to production `AESCipher` (AES-256-GCM), implemented polymorphic credential persistence with backward compatibility, added Test 12. | `MasterVault.h`, `MasterVault.cpp`, `Vault.h`, `Vault.cpp`, `FileStorage.cpp`, `test_cipher.cpp` |
| **Prompt 11** | Phase 4: Main Menu & Interactive TUI Overhaul | Agy / `claude-opus-4-6` (`vaultsync-4`) | Delegated interactive overhaul of `src/main.cpp` to expose polymorphic credentials, search, password tools, and security score. | `src/main.cpp`, `TerminalUtils` |
| **Prompt 12** | Debian APT Packaging & Custom Repository Feasibility | Codex (`vaultsync-6`) | Architectural feasibility analysis for packaging `.deb` via CPack/dpkg-deb and self-hosting an APT repo on `palash.pro` via Nginx. | Packaging spec, Nginx & GPG configs |
| **Prompt 13** | Phase 1: Core Code & Test Suite Rectification | Orchestrator (Internal) | Eliminated assert side-effects, upgraded KDF to 600k PBKDF2 iterations, migrated storage to XDG State with 0700/0600 permissions, achieved 100% CTest pass. | `CryptoUtils`, `FileStorage`, `MasterVault`, `test_cipher` |
| **Prompt 14** | Phase 2: CMake & CPack Configuration | Orchestrator (Internal) | Refactored target to lowercase `vaultsync`, added install rules for binary and docs, and configured CPack DEB generator with `CPACK_DEBIAN_PACKAGE_SHLIBDEPS`. | `CMakeLists.txt` |
| **Prompt 15** | Phase 3: CI/CD Readiness Assessment | Orchestrator (Internal) | Evaluated repository baseline for GitHub Actions; validated local CPack/CTest prerequisites and established CI/CD decoupling strategy. | `CMakeLists.txt`, `.github/workflows/` |
| **Prompt 16** | Modern TUI Architecture & FTXUI Plan (Collab) | Supreet (`feature/ftxui-integration`) | Formulated FTXUI embedding roadmap, evaluated TUI design tooling, and designed component tree. | Implementation roadmap |
| **Prompt 17** | FTXUI Architecture Review & OpenCode Alignment | Supreet (`feature/ftxui-integration`) | Reviewed TUI boundaries, verified FTXUI v5 APIs, proposed student-defensible incremental plan. | `Theme.h`, `src/main.cpp` |
| **Prompt 18** | Full FTXUI TUI Implementation | Supreet (`feature/ftxui-integration`) | Implemented full OpenCode-inspired TUI, integrated FTXUI v5 via CMake, created Theme.h, verified 100% tests. | `Theme.h`, `src/main.cpp` |
| **Prompt 19** | UI Hover Jitter Elimination & Tab Isolation | Supreet (`feature/ftxui-integration`) | Eliminated hover jitter feedback loops in buttons, isolated tab components, and hardened session security on vault lock. | `Theme.h`, `MasterVault.cpp` |
| **Prompt 20** | Off-Site Backup Feasibility & Tailscale/SFTP Architecture | Orchestrator (Internal) | Evaluated Tailscale VPN & SFTP feasibility; architected triple-layer defense, backup manager, and in-app TUI trigger. | `tailscale_sftp_offsite_backup_plan.md` |
| **Prompt 21** | Browser Extension Integration & Native Messaging Architecture | Orchestrator (Internal) | Formulated browser IPC feasibility matrix; established Native Messaging over TCP; defined dual-tier locking lifecycle. | `browser_extension_daemon_and_ipc_plan.md` |
| **Prompt 22** | Off-Site Backups via OpenSSH Subprocess & Tailscale | Orchestrator (`feature/off-site_backups`) | Implemented zero-overhead backup via OpenSSH subprocess (`pipe`/`execvp`), batch mode (`-b -`), atomic commit, FTXUI Tab 4, and Test 13. | `BackupConfig`, `SftpSubprocessClient`, `src/main.cpp` |
| **Prompt 23** | Chromium Extension Workflow & Implementation Roadmap | Orchestrator (Internal) | Formulated 5-phase roadmap for Chromium MV3 autofill extension and C++ native host with deterministic RSA identity. | `chromium_extension_native_messaging_plan.md` |
| **Prompt 24** | Chromium Extension Phase 1 & 2 Technical Deep Dive | Orchestrator (Internal) | Detailed mechanics of Phase 1 (OpenSSL RSA key derivation, extension ID mapping) and Phase 2 (4-byte binary framing, JSON protocol, MasterVault wiring). | Technical explanation & prompt log |
| **Prompt 25** | Phase 1 & 2 Implementation: Deterministic Identity & Native Host | Orchestrator (`feature/off-site_backups`) | Implemented deterministic RSA extension key pair, manifest V3 with fixed ID, C++ `vaultsync-host` binary framing, JSON protocol, and test suite. | `NativeHost.h/.cpp`, `main.cpp`, `test_native_host.cpp` |
| **Prompt 26** | CI/CD Standby Agent Provisioning & Orchestrator Execution | Orchestrator (`feature/off-site_backups`) | Spawned CI/CD standby subagent with full VPS reprepro context; continued Phase 1 & 2 implementation in parent orchestrator. | Subagent `CI/CD Standby Specialist` |
| **Prompt 27** | Phase 4: Extension Frontend & DOM Autofill Implementation | Orchestrator (`feature/off-site_backups`) | Implemented MV3 background message routing, content script form detection, inline badge rendering, synthetic bubbling autofill, and popup UI. | `background.js`, `content.js/.css`, `popup.html/.js` |
| **Prompt 28** | Phase 5: End-to-End Verification & Security Hardening | Orchestrator (`feature/off-site_backups`) | Implemented inactivity auto-lock, basic-auth URL normalization, POSIX subprocess binary IPC test, and interactive HTML test bench. | `test_native_host.cpp`, `NativeHost.cpp`, `test_login_page.html`, `TerminalUtils.cpp` |
| **Prompt 29** | Off-Site Backup SFTP Password & Key Auth Selection | Orchestrator (`feature/off-site_backups`) | Implemented password/key authentication selection for SFTP backups with OpenSSH SSH_ASKPASS support and FTXUI Tab 4 UI. | `BackupConfig.h/.cpp`, `SftpSubprocessClient.cpp`, `src/main.cpp`, `test_cipher.cpp` |

---

## Prompt 1: Initial Architecture Specification & System Ingestion

### Summary of User Prompt
The user provided the comprehensive 23-section **"Secure Password Manager — Architecture"** specification for VaultSync and instructed the orchestrator to ingest and internalize the architecture into context.

### Key Architecture / Design Objectives
- Ingest 23-section architecture: polymorphic credentials, access control proxy, repository, ciphers (XOR/AES), and binary persistence.
- Establish security baseline: brute-force lockout, password analytics, and custom exception hierarchy.

### Orchestrator Actions & Results
- Internalized complete system architecture, component dependencies, and design patterns.
- Verified build environment and toolchain readiness (GCC, CMake, ncurses).

### Artifacts and Files Involved
- [architecture.md](file:///home/supreet/VaultSync/architecture.md)

---

## Prompt 2: Orchestrator Role & Read-Only Exploration

### Summary of User Prompt
The user established the orchestrator role for managing the session and instructed the orchestrator to get familiar with the environment and inspect the existing codebase without making any code changes.

### Key Architecture / Design Objectives
- Catalog existing source code and identify gaps against the target 23-section architecture.
- Verify existing build pipelines and test suites in a strictly read-only manner.

### Orchestrator Actions & Results
- Cataloged baseline components (`Credential`, `FileStorage`, `XORCipher`, `CryptoUtils`, `MasterVault`).
- Verified tests 1–8 in [tests/test_cipher.cpp](file:///home/supreet/VaultSync/tests/test_cipher.cpp) with 100% pass rate.
- Documented missing polymorphic subclasses, `VaultProxy`, `Repository<T>`, and format v5 storage.

### Artifacts and Files Involved
- [include/Credential.h](file:///home/supreet/VaultSync/include/Credential.h)
- [include/FileStorage.h](file:///home/supreet/VaultSync/include/FileStorage.h)
- [include/ICipher.h](file:///home/supreet/VaultSync/include/ICipher.h)
- [include/XORCipher.h](file:///home/supreet/VaultSync/include/XORCipher.h)
- [include/CryptoUtils.h](file:///home/supreet/VaultSync/include/CryptoUtils.h)
- [include/MasterVault.h](file:///home/supreet/VaultSync/include/MasterVault.h)
- [tests/test_cipher.cpp](file:///home/supreet/VaultSync/tests/test_cipher.cpp)

---

## Prompt 3: Spawning Worker for Polymorphic Credentials & Access Control

### Summary of User Prompt
The user directed the orchestrator to configure a worker session using the `codex` harness with `gpt-6-luna` (medium effort) and spawn it to implement polymorphic credentials, access control, and other relevant components from the architecture.

### Key Architecture / Design Objectives
- Implement polymorphic credential hierarchy (`Credential`, `WebCredential`, `WiFiCredential`, `SSHCredential`, `CredentialFactory`).
- Implement `IVault`, `Vault`, `VaultProxy`, generic `Repository<T>`, and tagged binary storage (v5).
- Add password utilities (`PasswordGenerator`, `PasswordStrength`, `PasswordAnalyzer`) and custom exceptions.

### Orchestrator Actions & Results
- Spawned worker `vaultsync-3` using `gpt-6-luna` to implement components across 27 files.
- Added Test 9 in `tests/test_cipher.cpp` validating all new architectural components.

### Artifacts and Files Involved
- 27 project files created/modified in worker branch (commit `35125ae`).
- Test suite [Test 9] in [tests/test_cipher.cpp](file:///home/supreet/VaultSync/tests/test_cipher.cpp).

---

## Prompt 4 & 5: Code Readability Issue & Daemon Liveness False Alarm

### Summary of User Prompts
- **Prompt 4**: The user inspected the code generated by `gpt-6-luna` and observed that it lacked indentation, packed multiple statements into single lines, and was unreadable.
- **Prompt 5**: The user observed that the Codex worker reported the AO daemon was "stopped" during execution and requested an explanation.

### Key Architecture / Design Objectives
- Diagnose root cause of compressed formatting in model output.
- Investigate daemon status and formulate a refactoring plan to restore clean code formatting.

### Orchestrator Actions & Results
- Traced unreadable formatting to aggressive token-saving heuristics in `gpt-6-luna`.
- Determined daemon was alive on host port 3001; sandbox PID namespace isolation caused the false "stopped" report.

### Artifacts and Files Involved
- Technical RCA report presented to user.

---

## Prompt 6: Switching Harness to Agy + Claude Opus 4.6 for Readability Refactoring

### Summary of User Prompt
The user instructed the orchestrator to change the worker harness configuration to `agy` with model `claude-opus-4-6`, commit the existing changes, spawn a new worker session, and completely rectify the code readability and formatting across the codebase.

### Key Architecture / Design Objectives
- Reconfigure harness to `agy` with `claude-opus-4-6`.
- Refactor all 27 files to standard 4-space indentation, clean multi-line layout, and full Doxygen comments.

### Orchestrator Actions & Results
- Committed functional baseline as `35125ae`.
- Spawned worker `vaultsync-4` to systematically reformat and document all 27 files (+2055 / -184 lines).

### Artifacts and Files Involved
- Commit `35125ae`
- 27 refactored C++ header and source files

---

## Prompt 7: State and Progress Check

### Summary of User Prompt
The user submitted a concise verification request (`"check"`) to assess progress, inspect the refactoring quality, verify build validity, and confirm test suite health.

### Key Architecture / Design Objectives
- Verify that refactored files maintained 100% functional equivalence.
- Build cleanly with CMake and execute all unit test suites.

### Orchestrator Actions & Results
- Verified clean code structure and Doxygen blocks across all refactored files.
- Compiled cleanly with GCC and passed all 9 test suites in `tests/test_cipher.cpp`.
- Committed polished codebase as `6735cca` and merged to `main`.

### Artifacts and Files Involved
- Commit `6735cca`
- [tests/test_cipher.cpp](file:///home/supreet/VaultSync/tests/test_cipher.cpp)

---

## Prompt 8: Remote Push & Functional Roadmap Planning

### Summary of User Prompt
The user directed the orchestrator to push the local commits to the remote repository, inquired what technical steps remain to make the application fully functional, mentioned plans to transition to the AES cipher soon, and instructed not to make further code changes yet.

### Key Architecture / Design Objectives
- Synchronize local branches with remote GitHub repository.
- Formulate functional roadmap (TUI integration, `VaultProxy` wiring, OpenSSL AES-256-GCM cipher).

### Orchestrator Actions & Results
- Pushed commits `35125ae` and `6735cca` to `origin/main`.
- Verified OpenSSL availability and drafted integration roadmap for UI and AES-256-GCM.

### Artifacts and Files Involved
- Remote branch: `origin/main`
- Functional roadmap specification

---

## Prompt 9: Transition to Production Security with AES-256 Cipher

### Summary of User Prompt
The user directed the completion of Phase 2 by implementing `AESCipher` using OpenSSL to enhance security and transition VaultSync from educational/trial mode (`XORCipher`) to production-grade authenticated encryption. The user instructed to delegate the implementation to the `rectify-code-readability` worker agent.

### Key Architecture / Design Objectives
- Implement `AESCipher` implementing `ICipher` using OpenSSL EVP (`EVP_aes_256_gcm()`): 256-bit key, 12-byte random IV, 16-byte authentication tag.
- Link `OpenSSL::Crypto` in CMake and add test coverage for roundtrip, wrong key, and tamper detection.

### Orchestrator Actions & Results
- Delegated `AESCipher.h` and `AESCipher.cpp` implementation to worker `vaultsync-4`.
- Configured CMake linking and added unit tests covering encryption, decryption, and authentication tag verification.

### Artifacts and Files Involved
- [include/AESCipher.h](file:///home/supreet/VaultSync/include/AESCipher.h)
- [src/AESCipher.cpp](file:///home/supreet/VaultSync/src/AESCipher.cpp)
- [CMakeLists.txt](file:///home/supreet/VaultSync/CMakeLists.txt)
- [tests/test_cipher.cpp](file:///home/supreet/VaultSync/tests/test_cipher.cpp)

---

## Prompt 10: Phase 3 — Wire MasterVault to VaultProxy, Repository, & AESCipher

### Summary of User Prompt
The user directed the implementation of Phase 3: wiring `MasterVault` to `VaultProxy`, `Repository`, and `AESCipher`.

### Key Architecture / Design Objectives
- Wire `MasterVault` to `VaultProxy` and `Repository<Credential>`, replacing raw vector storage.
- Switch persistence to `AESCipher` (AES-256-GCM) with 256-bit keys derived from credential vault passwords.
- Maintain backward compatibility for v4/v5 binary storage and add integration Test 12.

### Orchestrator Actions & Results
- Integrated `Vault` and `VaultProxy` into `MasterVault`, routing all credential operations through access control.
- Updated `FileStorage` for polymorphic v4/v5 interoperability and added memory cleanup in `MasterVault::lock()`.
- Added Test 12 in `tests/test_cipher.cpp`; verified 100% pass across all 12 test suites.

### Artifacts and Files Involved
- [include/MasterVault.h](file:///home/supreet/VaultSync/include/MasterVault.h)
- [src/MasterVault.cpp](file:///home/supreet/VaultSync/src/MasterVault.cpp)
- [include/Vault.h](file:///home/supreet/VaultSync/include/Vault.h)
- [src/Vault.cpp](file:///home/supreet/VaultSync/src/Vault.cpp)
- [src/FileStorage.cpp](file:///home/supreet/VaultSync/src/FileStorage.cpp)
- [tests/test_cipher.cpp](file:///home/supreet/VaultSync/tests/test_cipher.cpp)

---

## Prompt 11: Phase 4 — Main Menu & Full Interactive TUI Overhaul

### Summary of User Prompt
The user directed the complete interactive overhaul of `src/main.cpp` to expose all implemented library components through the terminal user interface, creating a unified interactive workflow.

### Key Architecture / Design Objectives
- Build unified interactive menu in `src/main.cpp` for credentials, search, password tools, and security score.
- Enable creation and display of polymorphic types (`WebCredential`, `WiFiCredential`, `SSHCredential`).

### Orchestrator Actions & Results
- Replaced placeholder console flows with a multi-screen stateful loop wired to `MasterVault` and `VaultProxy`.
- Integrated password generator modal, entropy calculator, and exception handling.

### Artifacts and Files Involved
- [src/main.cpp](file:///home/supreet/VaultSync/src/main.cpp)
- [include/TerminalUtils.h](file:///home/supreet/VaultSync/include/TerminalUtils.h)

---

## Prompt 12: Debian APT Packaging & Self-Hosted Domain Repository Feasibility

### Summary of User Prompt
The user requested an architectural guide and comprehensive feasibility analysis for packaging VaultSync as a Debian (`.deb`) binary package and establishing a self-hosted custom APT repository hosted on domain `palash.pro` served via Nginx.

### Key Architecture / Design Objectives
- Design `.deb` package generation using CMake CPack and `dpkg-deb`.
- Architect GPG signing, Nginx virtual host, and repository metadata generation (`reprepro`).

### Orchestrator Actions & Results
- Spawned worker `vaultsync-6` to evaluate repository architecture and deployment requirements.
- Authored complete Debian deployment and APT repository guide.

### Artifacts and Files Involved
- [docs/DEBIAN_APT_DEPLOYMENT_GUIDE.md](file:///home/supreet/VaultSync/docs/DEBIAN_APT_DEPLOYMENT_GUIDE.md)

---

## Prompt 13: Phase 1 — Core Code & Test Suite Rectification

### Summary of User Prompt
The user instructed the implementation of Phase 1 remediation to prepare VaultSync for Debian packaging: eliminating `assert` side-effects in tests, upgrading key derivation to 600,000-iteration PBKDF2-HMAC-SHA256, and relocating vault storage to the XDG State Directory with strict POSIX permissions.

### Key Architecture / Design Objectives
- **Test Integrity**: Extracted stateful expressions from `assert(...)` into assigned variables in `tests/test_cipher.cpp` to prevent `NDEBUG` from disabling tests.
- **Hardened KDF**: Implemented OpenSSL `PKCS5_PBKDF2_HMAC` (600,000 iterations) for AES-256 key derivation in `CryptoUtils.cpp`.
- **XDG Storage & Path Sanitization**: Relocated default storage to `$XDG_STATE_HOME/vaultsync` (fallback `$HOME/.local/state/vaultsync`), sanitized/hashed usernames to eliminate path traversal, and enforced POSIX 0700 (directory) and 0600 (file) permissions.
- **Atomic File Safety**: Removed legacy relative path fallback in `FileStorage::resolvePath()` and implemented atomic write via temporary file replacement.

### Orchestrator Actions & Results
1. **Core Rectification**: Applied changes across `include/CryptoUtils.h`, `src/CryptoUtils.cpp`, `src/MasterVault.cpp`, `src/FileStorage.cpp`, and `tests/test_cipher.cpp`.
2. **Build & Test Validation**: Achieved 100% CTest pass rate across both Debug and Release build configurations.

### Artifacts and Files Involved
- [include/CryptoUtils.h](file:///home/palash/.ao/data/worktrees/vaultsync/vaultsync-5/include/CryptoUtils.h)
- [src/CryptoUtils.cpp](file:///home/palash/.ao/data/worktrees/vaultsync/vaultsync-5/src/CryptoUtils.cpp)
- [src/MasterVault.cpp](file:///home/palash/.ao/data/worktrees/vaultsync/vaultsync-5/src/MasterVault.cpp)
- [src/FileStorage.cpp](file:///home/palash/.ao/data/worktrees/vaultsync/vaultsync-5/src/FileStorage.cpp)
- [tests/test_cipher.cpp](file:///home/palash/.ao/data/worktrees/vaultsync/vaultsync-5/tests/test_cipher.cpp)

---

## Prompt 14: Phase 2 — CMake & CPack Configuration

### Summary of User Prompt
implement phase 2 with CMakeLists refactoring

### Key Architecture / Design Objectives
- **Target Standardization**: Renamed executable target to lowercase `vaultsync` and maintained `VaultSync` as an ALIAS target.
- **FHS Installation Rules**: Added `install(TARGETS vaultsync RUNTIME DESTINATION bin)` and installed documentation (`README.md`, `architecture.md`) to `share/doc/vaultsync`.
- **CPack DEB Metadata**: Configured CPack for Debian binary packaging with `CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON`, package vendor, maintainer, release `1`, and strict permissions.

### Orchestrator Actions & Results
1. **CMake Refactoring**: Updated `CMakeLists.txt` with target renaming, alias, install rules, and complete CPack configuration block.
2. **Installation Verification**: Verified staging via `cmake --install` to a temporary prefix, confirming `bin/vaultsync` and `share/doc/vaultsync/` layout.
3. **Build & Test Validation**: 100% CTest pass rate maintained across builds.

### Artifacts and Files Involved
- [CMakeLists.txt](file:///home/palash/.ao/data/worktrees/vaultsync/orchestrator/vaultsync-orchestrator/CMakeLists.txt)

---

## Prompt 15: Phase 3 CI/CD Readiness Assessment & Pre-Flight Verification

### Summary of User Prompt
The user inquired whether the repository is ready to begin constructing GitHub Actions CI/CD workflows using YAML configuration files after pushing the current local repository.

### Key Architecture / Design Objectives
- **Readiness Assessment**: Confirm whether the repository baseline (Phase 1 core rectification and Phase 2 CMake/CPack packaging) satisfies all prerequisites for automated CI/CD workflows.
- **Local Tree Evaluation**: Verify that Phase 1 is committed and pushed (`cb0a23c`) and that Phase 2 changes (`CMakeLists.txt` with lowercase target, FHS install rules, and CPack DEB configuration) pass local verification before upstream synchronization.
- **Workflow Decoupling**: Separate Continuous Integration (`ci.yml`, self-contained on Ubuntu runners with zero secrets) from Continuous Deployment (`release.yml`, requiring server-side GPG and reprepro configuration on `apt.palash.pro`).

### Orchestrator Actions & Results
1. **Verification**: Validated local CMake build, CTest suite (100% pass rate), and CPack Debian package generation targets.
2. **Readiness Confirmation**: Confirmed that committing and pushing the verified Phase 2 configuration provides a clean, fully qualified baseline to proceed with `.github/workflows/ci.yml`.

### Artifacts and Files Involved
- [CMakeLists.txt](file:///home/palash/.ao/data/worktrees/vaultsync/vaultsync-5/CMakeLists.txt)
- `.github/workflows/ci.yml` (upcoming)
- `.github/workflows/release.yml` (upcoming)

---

## Prompt 16: Modern TUI Architecture & FTXUI Implementation Planning

### Summary of User Prompt
The user directed the formulation of an implementation plan for embedding FTXUI (modern C++ functional terminal library) into VaultSync, requested an assessment of whether npx skills/tools are required for terminal UI design, and instructed to document the prompt.

### Key Architecture / Design Objectives
- Formulate an end-to-end embedding strategy for FTXUI via CMake FetchContent (`ftxui::screen`, `ftxui::dom`, `ftxui::component`).
- Assess Node/npx ecosystem tooling for TUI design and confirm native C++ FTXUI styling autonomy.
- Design a modular, reactive component tree separating UI views from `MasterVault` backend logic.

### Orchestrator Actions & Results
- Designed 4-phase implementation plan: CMake dependency integration, reactive component architecture, screen implementations, and verification.
- Evaluated terminal UI design tools: confirmed no npx packages are required for FTXUI; identified aesthetic palettes (Catppuccin, Nord) and ASCII header generators for optional design flair.
- Documented prompt interaction in prompt history.

### Artifacts and Files Involved
- [CMakeLists.txt](file:///home/supreet/VaultSync/CMakeLists.txt)
- [src/main.cpp](file:///home/supreet/VaultSync/src/main.cpp)
- [docs/prompts/README.md](file:///home/supreet/VaultSync/docs/prompts/README.md)

---

## Prompt 17: FTXUI Architecture Review & OpenCode Design Alignment

### Summary of User Prompt
The user directed a critical review of the proposed FTXUI implementation plan prior to code modifications: inspect existing TUI and boundaries, confirm FTXUI integration status, identify minimal changes for an OpenCode-inspired aesthetic, verify FTXUI APIs, separate essential from optional features, propose an incremental student-defensible plan, and document the prompt.

### Key Architecture / Design Objectives
- Validate existing codebase boundaries and confirm FTXUI is not yet integrated.
- Formulate a beginner-readable, procedural FTXUI design defendable in an academic viva without over-engineered asynchronous state machines.
- Specify minimal styling changes to achieve an OpenCode-inspired visual language (subtle borders, dark themes, accent badges).

### Orchestrator Actions & Results
- Inspected codebase: confirmed FTXUI is absent and needs integration via CMake FetchContent.
- Audited proposed APIs against FTXUI v5.0.0; replaced complex async state machine with synchronous per-screen components.
- Established phased incremental roadmap starting with theme helpers and the authentication home screen.
- Updated prompt documentation in compliance with format standards.

### Artifacts and Files Involved
- [CMakeLists.txt](file:///home/supreet/VaultSync/CMakeLists.txt)
- [src/main.cpp](file:///home/supreet/VaultSync/src/main.cpp)
- [docs/prompts/README.md](file:///home/supreet/VaultSync/docs/prompts/README.md)

---

## Prompt 18: Full FTXUI TUI Implementation & OpenCode Redesign

### Summary of User Prompt
The user directed the complete FTXUI redesign of VaultSync in one cohesive pass on branch `feature/ftxui-integration`: integrate FTXUI via CMake, create reusable styling helpers, implement centered auth screens, split-pane dashboard, polymorphic dialogs, password tools, and security health gauge, preserve all security/cryptography/lockout logic, and verify builds and unit tests without creating Git commits.

### Key Architecture / Design Objectives
- Integrate FTXUI v5.0.0 via CMake FetchContent while preserving headless `test_cipher` isolation.
- Establish OpenCode styling architecture in `include/Theme.h` (rounded borders, custom palette, type badges).
- Redesign `src/main.cpp` with centered auth, split-pane credential manager, modal forms, password generator, and audit gauge.

### Orchestrator Actions & Results
- Integrated `ftxui::screen`, `ftxui::dom`, and `ftxui::component` via CMake `FetchContent`.
- Created `include/Theme.h` defining OpenCode colors, badge decorators, and component styling options.
- Overhauled `src/main.cpp` implementing all screens connected to `MasterVault` without mocking.
- Compiled with GCC 16 and verified 100% pass across all 12 test suites in `test_cipher`.
- Confirmed full terminal launch and rendering via PTY test harness.

### Artifacts and Files Involved
- [CMakeLists.txt](file:///home/supreet/VaultSync/CMakeLists.txt)
- [include/Theme.h](file:///home/supreet/VaultSync/include/Theme.h)
- [src/main.cpp](file:///home/supreet/VaultSync/src/main.cpp)
- [docs/prompts/README.md](file:///home/supreet/VaultSync/docs/prompts/README.md)

---

## Prompt 19: UI Hover Jitter Elimination, Component Tab Isolation, & Vault Workflow Hardening

### Summary of User Prompt
Investigation and remediation of UI interaction defects (including mouse hover button jitter caused by dimension feedback loops) and workflow bugs across Master Vault authentication, credential creation/editing modal navigation, and dashboard state management.

### Key Architecture / Design Objectives
- Eliminate button hover jitter by maintaining strict dimension invariance across states in `Theme::buttonOption`.
- Isolate tab components using `ftxui::Container::Tab` to prevent background tabs from intercepting focus and clicks.
- Harden session security by purging in-memory credentials, salts, hashes, and lockout counters on vault lock.

### Orchestrator Actions & Results
- Updated `include/Theme.h` button and input placeholder transforms to prevent dimension oscillations.
- Replaced flat containers in `src/main.cpp` with `Container::Tab` for main navigation and modal inputs.
- Hardened `MasterVault::lock()` to wipe RAM caches and verified all 12 test suites in `test_cipher`.

### Artifacts and Files Involved
- [include/Theme.h](file:///home/supreet/VaultSync/include/Theme.h)
- [src/MasterVault.cpp](file:///home/supreet/VaultSync/src/MasterVault.cpp)
- [src/main.cpp](file:///home/supreet/VaultSync/src/main.cpp)
- [docs/prompts/README.md](file:///home/supreet/VaultSync/docs/prompts/README.md)

---

## Prompt 20: Off-Site Vault Backups via Tailscale & SFTP Architecture

### Summary of User Prompt
The user directed an architectural feasibility study and technical implementation plan for off-site backups over a private Tailscale tailnet using SFTP, investigated whether SFTP is suitable, designed an in-app "Trigger Off-Site Backup" option on the authenticated Master Vault screen, and instructed to document the prompt without modifying code.

### Key Architecture / Design Objectives
- Evaluate Tailscale mesh VPN and SFTP protocol suitability compared to Taildrop and cloud object storage.
- Design triple-layer defense-in-depth: AES-256-GCM vault encryption, SSH/SFTP transport security, and WireGuard isolation.
- Architect modular `IBackupClient` interface, XDG configuration, atomic uploads, and in-app FTXUI trigger.

### Orchestrator Actions & Results
- Completed feasibility study confirming Tailscale + SFTP as an optimal zero-public-attack-surface architecture.
- Authored comprehensive technical design artifact `tailscale_sftp_offsite_backup_plan.md`.
- Documented prompt interaction in prompt execution history.

### Artifacts and Files Involved
- [tailscale_sftp_offsite_backup_plan.md](file:///home/palash/.gemini/antigravity-cli/brain/a7b6fd37-e0f7-4c91-8ca2-7809e6bba520/tailscale_sftp_offsite_backup_plan.md)
- [docs/prompts/README.md](file:///home/palash/.ao/data/worktrees/vaultsync/orchestrator/vaultsync-orchestrator/docs/prompts/README.md)

---

## Prompt 21: Browser Extension Integration, Daemonization Strategy & Native Messaging Architecture

### Summary of User Prompt
The user requested an architectural implementation plan for integrating a browser extension (autofill feature), evaluated daemonization options (fully vs. partially vs. zero-daemon), assessed the security risks of localhost TCP socket connections vs. Native Messaging, designed the dual-tier Master Vault and Credential Vault locking lifecycle, requested a feasibility matrix, and instructed to document the prompt.

### Key Architecture / Design Objectives
- Evaluate IPC options (Native Messaging vs. Unix Domain Sockets vs. TCP) across security and resource usage.
- Formulate zero-daemon on-demand native host model, eliminating open network ports and attack surfaces.
- Define dual-tier locking lifecycle (Master Vault vs. Credential Vault) with memory scrubbing via `OPENSSL_cleanse()`.

### Orchestrator Actions & Results
- Authored IPC feasibility matrix proving Native Messaging (`stdin`/`stdout`) superior to localhost TCP.
- Generated technical design artifact `browser_extension_daemon_and_ipc_plan.md` detailing architecture and lifecycles.
- Documented prompt interaction in prompt execution history.

### Artifacts and Files Involved
- [browser_extension_daemon_and_ipc_plan.md](file:///home/palash/.gemini/antigravity-cli/brain/a7b6fd37-e0f7-4c91-8ca2-7809e6bba520/browser_extension_daemon_and_ipc_plan.md)
- [docs/prompts/README.md](file:///home/palash/.ao/data/worktrees/vaultsync/orchestrator/vaultsync-orchestrator/docs/prompts/README.md)

---

## Prompt 22: Off-Site Backups via OpenSSH Subprocess (`sftp`) over Tailscale

### Summary of User Prompt
The user directed the implementation of Option B (Subprocess Execution via OpenSSH `sftp` / `scp`) on a newly created local branch `feature/off-site_backups`. The requirement specified using Linux subprocesses to minimize C++ overhead (rejecting heavy third-party SSH libraries), with full documentation of the prompt.

### Key Architecture / Design Objectives
- Utilize standard POSIX primitives (`pipe`, `fork`, `execvp`) with `/usr/bin/sftp` to eliminate third-party SSH C++ libraries.
- Ensure shell injection immunity by avoiding `/bin/sh` or `popen()`, executing direct `argv` arrays with headless `-b -` batch streaming.
- Implement atomic two-phase staging (`.tmp` to timestamped `.bin`), XDG configuration (`0600`), and non-blocking FTXUI background worker.

### Orchestrator Actions & Results
- Implemented `BackupConfig` (`~/.config/vaultsync/backup.conf`) and `SftpSubprocessClient` using POSIX pipe/execvp streaming.
- Integrated `performOffsiteBackup()` into `MasterVault` and added dedicated Off-Site Backup tab (Tab 4) in `src/main.cpp`.
- Added unit test suite `testOffsiteBackupConfigAndSubprocess()` (Test 13) in `tests/test_cipher.cpp` with 100% pass rate.

### Artifacts and Files Involved
- [include/storage/BackupConfig.h](file:///home/palash/Documents/C++_miniProject/VaultSync/include/storage/BackupConfig.h)
- [src/storage/BackupConfig.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/src/storage/BackupConfig.cpp)
- [include/storage/SftpSubprocessClient.h](file:///home/palash/Documents/C++_miniProject/VaultSync/include/storage/SftpSubprocessClient.h)
- [src/storage/SftpSubprocessClient.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/src/storage/SftpSubprocessClient.cpp)
- [include/auth/MasterVault.h](file:///home/palash/Documents/C++_miniProject/VaultSync/include/auth/MasterVault.h)
- [src/auth/MasterVault.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/src/auth/MasterVault.cpp)
- [src/main.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/src/main.cpp)
- [tests/test_cipher.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/tests/test_cipher.cpp)
- [CMakeLists.txt](file:///home/palash/Documents/C++_miniProject/VaultSync/CMakeLists.txt)
- [docs/prompts/README.md](file:///home/palash/Documents/C++_miniProject/VaultSync/docs/prompts/README.md)

---

## Prompt 23: Chromium Extension Workflow & Implementation Roadmap

### Summary of User Prompt
The user inquired how to begin implementing the Chromium browser extension workflow from the architectural artifact, requesting concrete execution steps, extension ID determinism, and phase sequencing.

### Key Architecture / Design Objectives
- Establish 5-phase roadmap: deterministic RSA key identity, C++ native host binary, manifest registration, MV3 DOM autofill, and security hardening.
- Guarantee static 32-character extension ID across machines using hardcoded RSA `"key"` field in `manifest.json`.
- Implement zero-daemon native messaging over `stdin`/`stdout` using 4-byte little-endian length-prefixed JSON framing.

### Orchestrator Actions & Results
- Formulated phased implementation breakdown covering cryptographic key generation, native host binary, and MV3 extension frontend.
- Provided OpenSSL workflow to derive 2048-bit RSA key pair, base64 public key, and canonical Chromium extension ID.
- Outlined branch workflow on `feature/chromium-extension` and documented interaction in prompt execution history.

### Artifacts and Files Involved
- [chromium_extension_native_messaging_plan.md](file:///home/palash/.gemini/antigravity-cli/brain/a7b6fd37-e0f7-4c91-8ca2-7809e6bba520/chromium_extension_native_messaging_plan.md)
- [docs/prompts/README.md](file:///home/palash/Documents/C++_miniProject/VaultSync/docs/prompts/README.md)

---

## Prompt 24: Chromium Extension Phase 1 & Phase 2 Technical Mechanics

### Summary of User Prompt
The user requested a detailed architectural breakdown of Phase 1 (Deterministic Identity via OpenSSL 2048-bit RSA keys and permanent 32-character extension ID derivation) and Phase 2 (C++ Native Messaging Host `vaultsync-host`, 4-byte length-prefix binary framing, JSON protocol, and `MasterVault` wiring), and instructed to document the prompt.

### Key Architecture / Design Objectives
- Explain RSA SubjectPublicKeyInfo encoding and Chromium base-16 `a-p` hashing for invariant extension IDs.
- Detail POSIX `stdin`/`stdout` 4-byte little-endian length prefix framing, stream hygiene, and buffer flushing.
- Map JSON protocol actions (`status`, `unlock`, `get_credentials`, `lock`) to `MasterVault` and memory scrubbing routines.

### Orchestrator Actions & Results
- Detailed the cryptographic derivation steps eliminating `allowed_origins` permission mismatches across machines.
- Specified binary framing protocol, IPC packet lifecycle, and `stderr` stream isolation requirements.
- Documented prompt interaction in prompt execution history without creating Git commits.

### Artifacts and Files Involved
- [chromium_extension_native_messaging_plan.md](file:///home/palash/.gemini/antigravity-cli/brain/a7b6fd37-e0f7-4c91-8ca2-7809e6bba520/chromium_extension_native_messaging_plan.md)
- [docs/prompts/README.md](file:///home/palash/Documents/C++_miniProject/VaultSync/docs/prompts/README.md)

---

## Prompt 25: Phase 1 & Phase 2 Implementation — Deterministic Identity & Native Host

### Summary of User Prompt
implement the phases 1 and 2... (document the prompt as it is, not summary)

### Key Architecture / Design Objectives
- Generate 2048-bit RSA deterministic identity to lock static 32-character extension ID across environments.
- Build C++ `vaultsync-host` binary length-prefix framing (`stdin`/`stdout`) with JSON protocol dispatching.
- Wire native host to `MasterVault` cryptographic engine and implement automated unit test suite.

### Orchestrator Actions & Results
- Derived deterministic RSA key pair, generated `extension/manifest.json` and `com.vaultsync.native.json`.
- Implemented `NativeHost` framing, action handlers (`status`, `unlock`, `get_credentials`, `lock`), and memory cleansing.
- Configured CMake targets `vaultsync-host` and `test_native_host`; verified all 5 test suites pass 100%.

### Artifacts and Files Involved
- [extension/manifest.json](file:///home/palash/Documents/C++_miniProject/VaultSync/extension/manifest.json)
- [com.vaultsync.native.json](file:///home/palash/Documents/C++_miniProject/VaultSync/com.vaultsync.native.json)
- [include/native_host/NativeHost.h](file:///home/palash/Documents/C++_miniProject/VaultSync/include/native_host/NativeHost.h)
- [src/native_host/NativeHost.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/src/native_host/NativeHost.cpp)
- [src/native_host/main.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/src/native_host/main.cpp)
- [tests/test_native_host.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/tests/test_native_host.cpp)
- [CMakeLists.txt](file:///home/palash/Documents/C++_miniProject/VaultSync/CMakeLists.txt)
- [docs/prompts/README.md](file:///home/palash/Documents/C++_miniProject/VaultSync/docs/prompts/README.md)

---

## Prompt 26: CI/CD Standby Agent Provisioning & Dual-Workstream Orchestration

### Summary of User Prompt
spawn a new ao agent and give it relevant context and the artifact generated for CI CD integration, just provide the context and ask it to stay in standby mode after knowing the context. do NOT make changes just yet (and document this prompt) and continue with phase 1 and 2 in this instance

### Key Architecture / Design Objectives
- Isolate CI/CD integration responsibilities by provisioning a dedicated standby subagent with full VPS and reprepro context.
- Prevent premature repository mutations or CI workflow changes while core Phase 1 & 2 features are being completed.
- Maintain uninterrupted execution in parent orchestrator instance for native messaging implementation.

### Orchestrator Actions & Results
- Spawned `CI/CD Standby Specialist` subagent with `github_actions_ci_cd_plan.md` context and verified standby mode.
- Retained core execution focus in parent orchestrator instance to deliver Phase 1 and 2 targets.
- Documented prompt verbatim in prompt execution history.

### Artifacts and Files Involved
- [github_actions_ci_cd_plan.md](file:///home/palash/.gemini/antigravity-cli/brain/a7b6fd37-e0f7-4c91-8ca2-7809e6bba520/github_actions_ci_cd_plan.md)
- [docs/prompts/README.md](file:///home/palash/Documents/C++_miniProject/VaultSync/docs/prompts/README.md)

---

## Prompt 27: Phase 4 — Extension Frontend & DOM Autofill

### Summary of User Prompt
proceed with phase 4: Extension Frontend & DOM Autofill (document this prompt as is)

### Key Architecture / Design Objectives
- Implement MV3 background service worker routing between content scripts, popup UI, and C++ native host.
- Build DOM observation (`MutationObserver`) with inline badge injection and bubbling synthetic events for SPA autofill.
- Construct modern dark-themed action popup (`popup.html`/`popup.js`) for vault unlock, domain lookup, and manual autofill.

### Orchestrator Actions & Results
- Configured `manifest.json` with popup, styling, accessible resources, and generated 16/48/128px PNG icons.
- Implemented `content.js` and `content.css` supporting single-click autofill and multi-credential floating dropdowns.
- Created `popup.html` and `popup.js` supporting active domain filtering, unlock form, and clipboard copy.

### Artifacts and Files Involved
- [extension/manifest.json](file:///home/palash/Documents/C++_miniProject/VaultSync/extension/manifest.json)
- [extension/background.js](file:///home/palash/Documents/C++_miniProject/VaultSync/extension/background.js)
- [extension/content.js](file:///home/palash/Documents/C++_miniProject/VaultSync/extension/content.js)
- [extension/content.css](file:///home/palash/Documents/C++_miniProject/VaultSync/extension/content.css)
- [extension/popup.html](file:///home/palash/Documents/C++_miniProject/VaultSync/extension/popup.html)
- [extension/popup.js](file:///home/palash/Documents/C++_miniProject/VaultSync/extension/popup.js)
- [extension/icons/icon-48.png](file:///home/palash/Documents/C++_miniProject/VaultSync/extension/icons/icon-48.png)
- [docs/prompts/README.md](file:///home/palash/Documents/C++_miniProject/VaultSync/docs/prompts/README.md)

---

## Prompt 28: Phase 5 — End-to-End Verification & Security Hardening

### Summary of User Prompt
the last phase 5... wrap it up and make sure no flow is broken

### Key Architecture / Design Objectives
- Harden C++ Native Host with auto-lock inactivity timeouts, activity tracking, and URL basic-auth stripping.
- Expand test suite to verify subprocess binary execution via POSIX pipes (`pipe()`, `fork()`, `execvp()`), multi-account domain matching, and auto-lock state transitions.
- Deliver standalone DOM test fixture (`test_login_page.html`) and verify zero regression across all TUI, crypto, and packaging pipelines.

### Orchestrator Actions & Results
- Wired inactivity timeout auto-lock and basic-auth URL normalization into `NativeHost.cpp`, resolving pipe-holding in `TerminalUtils.cpp`.
- Expanded `test_native_host.cpp` from 5 to 8 test suites, validating real `vaultsync-host` subprocess execution and dual-tier auto-lock.
- Verified 100% CTest pass rate (15/15 `test_cipher`, 8/8 `test_native_host`), validated extension JS syntax, and authored `test_login_page.html`.

### Artifacts and Files Involved
- [src/native_host/NativeHost.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/src/native_host/NativeHost.cpp)
- [tests/test_native_host.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/tests/test_native_host.cpp)
- [src/ui/TerminalUtils.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/src/ui/TerminalUtils.cpp)
- [extension/test_login_page.html](file:///home/palash/Documents/C++_miniProject/VaultSync/extension/test_login_page.html)
- [docs/prompts/README.md](file:///home/palash/Documents/C++_miniProject/VaultSync/docs/prompts/README.md)

---

## Prompt 29: Off-Site Backup SFTP Password & Key Auth Selection

### Summary of User Prompt
in the off-site backup function... I should be able to sftp via password as well... add an option for that. Password / Key based auth selection. and implement it

### Key Architecture / Design Objectives
- Support both SSH Key-based and Password-based authentication for off-site SFTP vault backups.
- Implement headless password injection into OpenSSH `sftp` subprocess without external dependencies.
- Add dynamic authentication method selector and credential input in FTXUI TUI Tab 4.

### Orchestrator Actions & Results
- Extended `BackupConfig` with `AuthMethod` enum, `password` field, and 0600 POSIX file persistence.
- Implemented `SSH_ASKPASS` / `SSH_ASKPASS_REQUIRE=force` headless password injection with RAII tmpfs script cleanup in `SftpSubprocessClient`.
- Integrated `Radiobox` auth mode selector and dynamic tab focusing in `src/main.cpp`, verified 100% CTest pass rate.

### Artifacts and Files Involved
- [include/storage/BackupConfig.h](file:///home/palash/Documents/C++_miniProject/VaultSync/include/storage/BackupConfig.h)
- [src/storage/BackupConfig.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/src/storage/BackupConfig.cpp)
- [src/storage/SftpSubprocessClient.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/src/storage/SftpSubprocessClient.cpp)
- [src/main.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/src/main.cpp)
- [tests/test_cipher.cpp](file:///home/palash/Documents/C++_miniProject/VaultSync/tests/test_cipher.cpp)
- [docs/prompts/README.md](file:///home/palash/Documents/C++_miniProject/VaultSync/docs/prompts/README.md)

---

## Summary of Completed Architecture Coverage

```text
Target Architecture Components (23 Sections)
├── [x] Section 4: Polymorphic Credential Hierarchy (Web, WiFi, SSH)
├── [x] Section 5: Vault Implementation & Lifecycle
├── [x] Section 6/8: Hardened PBKDF2-HMAC-SHA256 (600k iterations) & AES Key Derivation
├── [x] Section 7: Access Control Proxy (IVault & VaultProxy)
├── [x] Section 8: ICipher Abstraction & XOR/AES Implementations (AES-256-GCM)
├── [x] Section 10/11: File Storage Version 5 Tagged Binary Serialization & Atomic Temp Writes
├── [x] Section 10: XDG State Directory Specification & POSIX File Security (0700/0600)
├── [x] Section 12: Generic Template Repository<T> with Predicate Search
├── [x] Section 13/14: Password Generator, Strength Evaluator & Security Analyzer
├── [x] Section 15: Dual-Auth & Brute-Force Login Lockout Protection
├── [x] Section 20: Comprehensive Exception Hierarchy (VaultException, CorruptedVaultException, etc.)
├── [x] Section 3/9: Full TUI Menu Wiring & Interactive Application Flow
├── [x] Modern TUI: FTXUI Functional Component Interface Architecture (Phase 5)
├── [x] UI/UX Polish: Hover Jitter Elimination, Tab Isolation & Workflow Hardening
├── [x] Packaging & Distribution: Debian (.deb) & Custom APT Repository Architecture
├── [x] Off-Site Backup Architecture: Tailscale Tailnet & SFTP Integration Plan
├── [x] Off-Site Backup Implementation: OpenSSH Subprocess (sftp), Batch Mode & FTXUI Tab
├── [x] Browser Extension Integration: Native Messaging & Zero-Daemon IPC Architecture
├── [x] Chromium Extension Workflow: Deterministic RSA Identity & Phased Implementation Roadmap
├── [x] Native Messaging Host Architecture: Binary Length Framing & JSON Protocol Mechanics
├── [x] Native Host Implementation: vaultsync-host Binary, Framing & test_native_host Suite
├── [x] Extension Frontend & Autofill: MV3 Service Worker, DOM Injection & Action Popup
└── [x] E2E Verification & Hardening: Inactivity Auto-Lock, Subprocess IPC Tests & Test Bench
```
