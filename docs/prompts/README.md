# VaultSync — Prompts & Execution History

This document chronicles the prompt interactions, architectural directives, and engineering results throughout the development of **VaultSync** (a secure C++ Terminal User Interface password manager).

---

## Executive Summary & Prompt Matrix

| Prompt | Phase / Topic | Harness & Model | Key Actions & Results | Artifacts |
| :--- | :--- | :--- | :--- | :--- |
| **Prompt 1** | Architectural Specification & Ingestion | Orchestrator (Internal) | Ingested 23-section architecture specification; validated GCC, CMake, and ncurses toolchain. | `architecture.md` |
| **Prompt 2** | Role Definition & Codebase Exploration | Orchestrator (Internal) | Mapped repository structure; verified tests 1–8 in read-only pass. | Test suite 1–8 |
| **Prompt 3** | Polymorphic Core Implementation | Codex / `gpt-6-luna` | Implemented polymorphic credentials, access control proxy, repository, and password tools. | 27 files, commit `35125ae` |
| **Prompt 4 & 5** | Readability & Sandbox Diagnosis | Orchestrator (Internal) | Diagnosed model token-compression formatting; verified daemon PID namespace isolation. | Technical RCA report |
| **Prompt 6** | Readability & Doxygen Refactor | Agy / `claude-opus-4-6` | Refactored 27 files to standard 4-space indentation and full Doxygen comments. | 27 refactored files, commit `6735cca` |
| **Prompt 7** | Verification, Build & Test Suite | Orchestrator (Internal) | Built with CMake; passed all 9 test suites; verified formatting. | `test_cipher` |
| **Prompt 8** | Remote Git Sync & Roadmap Planning | Orchestrator (Internal) | Pushed commits to `origin/main`; planned OpenSSL AES-256-GCM transition. | `origin/main`, roadmap |
| **Prompt 9** | Production Security with AES-256-GCM | Agy / `claude-opus-4-6` | Implemented `AESCipher` with OpenSSL EVP AES-256-GCM, CMake linking, and unit tests. | `AESCipher.h/cpp`, tests |
| **Prompt 10** | Wire MasterVault to Proxy & AESCipher | Orchestrator (Internal) | Wired `MasterVault` to `VaultProxy` and `AESCipher`; added polymorphic persistence (v5) and Test 12. | `MasterVault`, `FileStorage`, Test 12 |
| **Prompt 11** | Interactive TUI Overhaul | Agy / `claude-opus-4-6` | Overhauled `src/main.cpp` with menus for credentials, search, generator, and security score. | `src/main.cpp` |
| **Prompt 12** | Debian APT Packaging & Feasibility | Codex | Drafted architectural guide for `.deb` CPack packaging and self-hosted APT repository. | `DEBIAN_APT_DEPLOYMENT_GUIDE.md` |
| **Prompt 13** | Modern TUI Architecture & FTXUI Plan | Orchestrator (Internal) | Formulated FTXUI embedding roadmap, evaluated TUI design tooling, and designed component tree. | Implementation roadmap, `docs/prompts/README.md` |
| **Prompt 14** | FTXUI Architecture Review & OpenCode Alignment | Orchestrator (Internal) | Reviewed TUI boundaries, verified FTXUI v5 APIs, proposed student-defensible incremental plan. | `docs/prompts/README.md` |
| **Prompt 15** | Full FTXUI TUI Implementation | Orchestrator (Internal) | Implemented full OpenCode-inspired TUI, integrated FTXUI v5 via CMake, created Theme.h, verified 100% tests. | `CMakeLists.txt`, `Theme.h`, `src/main.cpp` |

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

## Prompt 13: Modern TUI Architecture & FTXUI Implementation Planning

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

## Prompt 14: FTXUI Architecture Review & OpenCode Design Alignment

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

## Prompt 15: Full FTXUI TUI Implementation & OpenCode Redesign

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

## Prompt 16: UI Hover Jitter Elimination, Component Tab Isolation, & Vault Workflow Hardening

### Summary of User Prompt
Investigation and remediation of UI interaction defects (including mouse hover button jitter caused by dimension feedback loops) and workflow bugs across Master Vault authentication, credential creation/editing modal navigation, and dashboard state management.

### Key Architecture / Design Objectives
- Eliminate hover jitter feedback loops in buttons by enforcing strict dimension invariance across normal, hover, and focused states in `Theme::buttonOption`.
- Isolate tab components in `runMasterVaultSession` using `ftxui::Container::Tab` to prevent invisible background tabs from intercepting focus and mouse events.
- Prevent focus traps in polymorphic Add/Edit dialogs by dynamically mounting only the inputs corresponding to the active credential type.
- Harden session security by purging in-memory credentials, salts, hashes, and lockout counters on vault lock, and auto-locking when credential unlock is dismissed.
- Enhance UX with automatic password field clearing on failed auth, auto-selection of newly added credentials, and search-result navigation jumps.

### Orchestrator Actions & Results
- Resolved button hover jitter in `include/Theme.h` by maintaining `borderRounded` across all states, preventing 2-row/2-column element resizing oscillations.
- Updated `include/Theme.h` input placeholder transform with column-stable spacing between focused and unfocused states.
- Replaced flat containers in `src/main.cpp` with `Container::Tab` for main navigation and modal polymorphic fields.
- Implemented auto-hiding of passwords on selection changes and Enter-to-jump navigation from search results to dashboard entries.
- Hardened `MasterVault::lock()` in `src/MasterVault.cpp` to wipe RAM caches and reset attempt counters.
- Built cleanly and verified all 12 test suites in `test_cipher` and end-to-end interactive flows.

### Artifacts and Files Involved
- [include/Theme.h](file:///home/supreet/VaultSync/include/Theme.h)
- [src/MasterVault.cpp](file:///home/supreet/VaultSync/src/MasterVault.cpp)
- [src/main.cpp](file:///home/supreet/VaultSync/src/main.cpp)
- [docs/prompts/README.md](file:///home/supreet/VaultSync/docs/prompts/README.md)

---

## Summary of Completed Architecture Coverage

```text
Target Architecture Components (23 Sections)
├── [x] Section 4: Polymorphic Credential Hierarchy (Web, WiFi, SSH)
├── [x] Section 5: Vault Implementation & Lifecycle
├── [x] Section 7: Access Control Proxy (IVault & VaultProxy)
├── [x] Section 8: ICipher Abstraction & XOR/AES Implementations (AES-256-GCM)
├── [x] Section 10/11: File Storage Version 5 Tagged Binary Serialization
├── [x] Section 12: Generic Template Repository<T> with Predicate Search
├── [x] Section 13/14: Password Generator, Strength Evaluator & Security Analyzer
├── [x] Section 15: Dual-Auth & Brute-Force Login Lockout Protection
├── [x] Section 20: Comprehensive Exception Hierarchy (VaultException, CorruptedVaultException, etc.)
├── [x] Section 3/9: Full TUI Menu Wiring & Interactive Application Flow
├── [x] Modern TUI: FTXUI Functional Component Interface Architecture (Phase 5)
├── [x] UI/UX Polish: Hover Jitter Elimination, Tab Isolation & Workflow Hardening
└── [x] Packaging & Distribution: Debian (.deb) & Custom APT Repository Architecture
```
