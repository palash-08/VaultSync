#include "credentials/Credential.h"
#include "credentials/WebCredential.h"
#include "credentials/WiFiCredential.h"
#include "credentials/SSHCredential.h"
#include "credentials/CredentialFactory.h"
#include "auth/MasterVault.h"
#include "security/PasswordGenerator.h"
#include "security/PasswordStrength.h"
#include "security/PasswordAnalyzer.h"
#include "ui/TerminalUtils.h"
#include "security/VaultExceptions.h"
#include "ui/Theme.h"
#include "storage/BackupConfig.h"
#include "storage/SftpSubprocessClient.h"

#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/screen/color.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/component/event.hpp>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace ftxui;

namespace {

/**
 * @brief Formats an epoch timestamp into a human-readable local date/time string.
 */
std::string formatTimestamp(int64_t timestampSeconds) {
    if (timestampSeconds <= 0) {
        return "Not recorded";
    }
    std::time_t rawTime = static_cast<std::time_t>(timestampSeconds);
    std::tm* timeInfo = std::localtime(&rawTime);
    if (!timeInfo) {
        return "Unknown";
    }
    std::ostringstream oss;
    oss << std::put_time(timeInfo, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

/**
 * @brief Returns a short badge string for console / list displays.
 */
std::string getTypeBadgeStr(const std::shared_ptr<Credential>& credential) {
    if (!credential) return "[???]";
    const std::string t = credential->getType();
    if (t == "web") return "[WEB]";
    if (t == "wifi") return "[WIFI]";
    if (t == "ssh") return "[SSH]";
    return "[GEN]";
}

std::string trimString(std::string s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n')) {
        s.pop_back();
    }
    size_t start = 0;
    while (start < s.size() && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n')) {
        start++;
    }
    return s.substr(start);
}

// Forward declarations
bool ensureCredentialVaultUnlocked(MasterVault& vault);
void runMasterVaultSession(MasterVault& vault);
bool promptCreateCredential(MasterVault& vault);
void handleEditCredential(MasterVault& vault, size_t index);
bool handleDeleteCredential(MasterVault& vault, size_t index);

// ============================================================================
// Authentication Screens (Welcome, Login, Create)
// ============================================================================

/**
 * @brief Renders the centered OpenCode Login Screen.
 * @return True if login succeeded; false if cancelled.
 */
bool handleLoginMasterVault(MasterVault& vault) {
    auto screen = ScreenInteractive::Fullscreen();
    auto exit = screen.ExitLoopClosure();

    std::string username;
    std::string password;
    std::string statusMessage;
    Color statusColor = Theme::Danger;
    bool loginSuccess = false;

    Component inputUser;
    Component inputPass;

    auto loginAction = [&] {
        username = trimString(username);
        if (username.empty()) {
            statusMessage = "Username cannot be empty.";
            statusColor = Theme::Danger;
            return;
        }

        if (!MasterVault::existsForUser(username)) {
            statusMessage = "No vault found for user \"" + username + "\". Please create one first.";
            statusColor = Theme::Danger;
            return;
        }

        if (password.empty()) {
            statusMessage = "Master password cannot be empty.";
            statusColor = Theme::Danger;
            return;
        }

        // Check for active lockout
        int remainingSeconds = 0;
        if (vault.isMasterLockedOut(username, remainingSeconds)) {
            statusMessage = "Login is temporarily locked. Try again in " +
                            std::to_string(remainingSeconds) + " seconds.";
            statusColor = Theme::Danger;
            return;
        }

        int remainingAttempts = 0;
        if (vault.unlockMaster(username, password, remainingAttempts)) {
            loginSuccess = true;
            exit();
            return;
        }

        if (vault.isMasterLockedOut(username, remainingSeconds)) {
            statusMessage = "Maximum login attempts exceeded. Master Vault temporarily locked for " +
                            std::to_string(remainingSeconds) + "s.";
            statusColor = Theme::Danger;
        } else {
            statusMessage = "Invalid master password. Attempts remaining: " + std::to_string(remainingAttempts);
            statusColor = Theme::Warning;
        }
        password.clear(); // Clear so the user starts fresh on the next try
    };

    inputUser = Input(&username, "Enter username", Theme::inputOption(false, [&] {
        if (inputPass) {
            inputPass->TakeFocus();
        }
    }));
    inputPass = Input(&password, "Enter master password", Theme::inputOption(true, [&] {
        loginAction();
    }));

    auto btnLogin = Button("Login", loginAction, Theme::buttonOption(true));
    auto btnCancel = Button("Cancel", [&] { exit(); }, Theme::buttonOption(false));

    auto container = Container::Vertical({
        inputUser,
        inputPass,
        Container::Horizontal({
            btnLogin,
            btnCancel,
        }),
    });

    auto renderer = Renderer(container, [&] {
        Elements statusElements;
        if (!statusMessage.empty()) {
            statusElements.push_back(text(statusMessage) | bold | color(statusColor));
        }

        auto cardContent = vbox({
            text(" VaultSync — Master Vault Login ") | bold | color(Theme::Primary),
            text(" Enter your credentials to access encrypted storage ") | dim | color(Theme::Muted),
            separator() | color(Theme::Subtle),
            hbox({ text(" Username : ") | bold | color(Theme::TextBright), inputUser->Render() | flex_grow }) | borderRounded | color(Theme::Subtle),
            hbox({ text(" Password : ") | bold | color(Theme::TextBright), inputPass->Render() | flex_grow }) | borderRounded | color(Theme::Subtle),
            vbox(std::move(statusElements)),
            separator() | color(Theme::Subtle),
            hbox({
                btnLogin->Render(),
                text("  "),
                btnCancel->Render(),
            }) | center,
        }) | size(WIDTH, EQUAL, 56) | borderRounded | color(Theme::Primary);

        return vbox({
            filler(),
            hbox({ filler(), cardContent, filler() }),
            filler(),
        });
    });

    screen.Loop(renderer);
    return loginSuccess;
}

/**
 * @brief Renders the centered Create Master Vault Screen.
 */
void handleCreateMasterVault(MasterVault& vault) {
    auto screen = ScreenInteractive::Fullscreen();
    auto exit = screen.ExitLoopClosure();

    std::string username;
    std::string password;
    std::string confirmPassword;
    std::string statusMessage;
    Color statusColor = Theme::Danger;

    Component inputUser;
    Component inputPass;
    Component inputConfirm;

    auto createAction = [&] {
        username = trimString(username);
        if (username.empty()) {
            statusMessage = "Username cannot be empty.";
            statusColor = Theme::Danger;
            return;
        }
        if (password.empty()) {
            statusMessage = "Master password cannot be empty.";
            statusColor = Theme::Danger;
            return;
        }
        if (password != confirmPassword) {
            statusMessage = "Passwords do not match.";
            statusColor = Theme::Danger;
            return;
        }
        if (vault.existsForUser(username)) {
            statusMessage = "A vault already exists for user \"" + username + "\".";
            statusColor = Theme::Danger;
            return;
        }

        if (vault.create(username, password)) {
            statusMessage = "Vault created successfully! You can now log in.";
            statusColor = Theme::Success;
            exit();
        } else {
            statusMessage = "Failed to create vault. Please try again.";
            statusColor = Theme::Danger;
        }
    };

    inputUser = Input(&username, "Enter username", Theme::inputOption(false, [&] {
        if (inputPass) inputPass->TakeFocus();
    }));
    inputPass = Input(&password, "Enter master password", Theme::inputOption(true, [&] {
        if (inputConfirm) inputConfirm->TakeFocus();
    }));
    inputConfirm = Input(&confirmPassword, "Confirm master password", Theme::inputOption(true, [&] {
        createAction();
    }));

    auto btnCreate = Button("Create Vault", createAction, Theme::buttonOption(true));
    auto btnCancel = Button("Cancel", [&] { exit(); }, Theme::buttonOption(false));

    auto container = Container::Vertical({
        inputUser,
        inputPass,
        inputConfirm,
        Container::Horizontal({
            btnCreate,
            btnCancel,
        }),
    });

    auto renderer = Renderer(container, [&] {
        Elements statusElements;
        if (!statusMessage.empty()) {
            statusElements.push_back(text(statusMessage) | bold | color(statusColor));
        }

        auto cardContent = vbox({
            text(" VaultSync — Create Master Vault ") | bold | color(Theme::Primary),
            text(" Initialize a new encrypted local vault ") | dim | color(Theme::Muted),
            separator() | color(Theme::Subtle),
            hbox({ text(" Username : ") | bold | color(Theme::TextBright), inputUser->Render() | flex_grow }) | borderRounded | color(Theme::Subtle),
            hbox({ text(" Password : ") | bold | color(Theme::TextBright), inputPass->Render() | flex_grow }) | borderRounded | color(Theme::Subtle),
            hbox({ text(" Confirm  : ") | bold | color(Theme::TextBright), inputConfirm->Render() | flex_grow }) | borderRounded | color(Theme::Subtle),
            vbox(std::move(statusElements)),
            separator() | color(Theme::Subtle),
            hbox({
                btnCreate->Render(),
                text("  "),
                btnCancel->Render(),
            }) | center,
        }) | size(WIDTH, EQUAL, 58) | borderRounded | color(Theme::Secondary);

        return vbox({
            filler(),
            hbox({ filler(), cardContent, filler() }),
            filler(),
        });
    });

    screen.Loop(renderer);
}

/**
 * @brief Ensures the Credential Vault tier is unlocked before performing data operations.
 */
bool ensureCredentialVaultUnlocked(MasterVault& vault) {
    if (vault.isCredentialsUnlocked()) {
        return true;
    }

    auto screen = ScreenInteractive::Fullscreen();
    auto exit = screen.ExitLoopClosure();
    bool unlockSuccess = false;

    // Delayed setup: first-time configuration
    if (!vault.hasCredentialPassword()) {
        std::string credPassword;
        std::string confirmPassword;
        std::string statusMessage;

        Component inputPass;
        Component inputConfirm;

        auto setupAction = [&] {
            if (credPassword.empty()) {
                statusMessage = "Password cannot be empty.";
                return;
            }
            if (credPassword != confirmPassword) {
                statusMessage = "Passwords do not match.";
                return;
            }
            if (!vault.setupCredentialPassword(credPassword)) {
                statusMessage = "Credential password must differ from Master password.";
                return;
            }
            unlockSuccess = true;
            exit();
        };

        inputPass = Input(&credPassword, "Enter credential vault password", Theme::inputOption(true, [&] {
            if (inputConfirm) inputConfirm->TakeFocus();
        }));
        inputConfirm = Input(&confirmPassword, "Confirm credential vault password", Theme::inputOption(true, [&] {
            setupAction();
        }));

        auto btnSubmit = Button("Set Password", setupAction, Theme::buttonOption(true));
        auto btnCancel = Button("Cancel", [&] { exit(); }, Theme::buttonOption(false));

        auto container = Container::Vertical({
            inputPass,
            inputConfirm,
            Container::Horizontal({ btnSubmit, btnCancel }),
        });

        auto renderer = Renderer(container, [&] {
            return vbox({
                filler(),
                hbox({
                    filler(),
                    vbox({
                        text(" Setup Credential Vault Encryption ") | bold | color(Theme::Primary),
                        text(" Enforces dual-authentication. Derives AES-256-GCM symmetric key. ") | dim | color(Theme::Muted),
                        separator() | color(Theme::Subtle),
                        hbox({ text(" Credential Password : ") | bold, inputPass->Render() | flex_grow }) | borderRounded | color(Theme::Subtle),
                        hbox({ text(" Confirm Password    : ") | bold, inputConfirm->Render() | flex_grow }) | borderRounded | color(Theme::Subtle),
                        text(statusMessage) | color(Theme::Danger),
                        separator() | color(Theme::Subtle),
                        hbox({ btnSubmit->Render(), text("  "), btnCancel->Render() }) | center,
                    }) | size(WIDTH, EQUAL, 64) | borderRounded | color(Theme::Primary),
                    filler(),
                }),
                filler(),
            });
        });

        screen.Loop(renderer);
        return unlockSuccess;
    }

    // Existing vault unlock
    std::string credPassword;
    std::string statusMessage;
    int remaining = 3;

    Component inputPass;

    auto unlockAction = [&] {
        if (credPassword.empty()) {
            statusMessage = "Password cannot be empty.";
            return;
        }

        int remainingAttempts = 0;
        if (vault.unlockCredentials(credPassword, remainingAttempts)) {
            unlockSuccess = true;
            exit();
            return;
        }

        if (remainingAttempts <= 0) {
            statusMessage = "Maximum attempts exceeded. Credential vault access denied.";
            exit();
        } else {
            statusMessage = "Invalid password. Attempts remaining: " + std::to_string(remainingAttempts);
        }
        credPassword.clear(); // Clear so the user starts fresh
    };

    inputPass = Input(&credPassword, "Enter credential vault password", Theme::inputOption(true, [&] {
        unlockAction();
    }));

    auto btnUnlock = Button("Unlock", unlockAction, Theme::buttonOption(true));
    auto btnCancel = Button("Cancel", [&] { exit(); }, Theme::buttonOption(false));

    auto container = Container::Vertical({
        inputPass,
        Container::Horizontal({ btnUnlock, btnCancel }),
    });

    auto renderer = Renderer(container, [&] {
        return vbox({
            filler(),
            hbox({
                filler(),
                vbox({
                    text(" Unlock Credential Vault ") | bold | color(Theme::Primary),
                    text(" Enter your credential vault password to decrypt payload ") | dim | color(Theme::Muted),
                    separator() | color(Theme::Subtle),
                    hbox({ text(" Password : ") | bold, inputPass->Render() | flex_grow }) | borderRounded | color(Theme::Subtle),
                    text(statusMessage) | color(Theme::Danger),
                    separator() | color(Theme::Subtle),
                    hbox({ btnUnlock->Render(), text("  "), btnCancel->Render() }) | center,
                }) | size(WIDTH, EQUAL, 56) | borderRounded | color(Theme::Primary),
                filler(),
            }),
            filler(),
        });
    });

    screen.Loop(renderer);
    return unlockSuccess;
}

// ============================================================================
// Modals: Add, Edit, Delete
// ============================================================================

/**
 * @brief Modal dialog to add a new polymorphic credential.
 */
bool promptCreateCredential(MasterVault& vault) {
    auto screen = ScreenInteractive::Fullscreen();
    auto exit = screen.ExitLoopClosure();
    bool created = false;

    std::vector<std::string> typeEntries = {"Web Account", "Wi-Fi Network", "SSH Server", "Generic"};
    int selectedType = 0;

    std::string service, username, password, notes;
    std::string url;
    std::string ssid, securityType = "WPA2";
    std::string host, portStr = "22";
    std::string errorMessage;

    auto radioType = Radiobox(&typeEntries, &selectedType);
    Component inputService;
    Component inputUser;
    Component inputPass;
    Component inputNotes;
    Component inputUrl;
    Component inputSsid;
    Component inputSec;
    Component inputHost;
    Component inputPort;

    auto saveAction = [&] {
        if (service.empty()) {
            errorMessage = "Service name is required.";
            return;
        }
        if (password.empty()) {
            errorMessage = "Password is required.";
            return;
        }

        std::shared_ptr<Credential> newCred = nullptr;
        if (selectedType == 0) { // Web
            newCred = std::make_shared<WebCredential>(service, username, password, notes, url);
        } else if (selectedType == 1) { // WiFi
            newCred = std::make_shared<WiFiCredential>(service, username, password, notes, ssid, securityType);
        } else if (selectedType == 2) { // SSH
            int p = 22;
            try { p = std::stoi(portStr); } catch (...) { p = 22; }
            newCred = std::make_shared<SSHCredential>(service, username, password, notes, host, p);
        } else { // Generic
            newCred = std::make_shared<Credential>(service, username, password, notes);
        }

        if (newCred && vault.addCredential(newCred)) {
            created = true;
            exit();
        } else {
            errorMessage = "Failed to save credential to vault.";
        }
    };

    inputService = Input(&service, "Service / Label", Theme::inputOption(false, [&] {
        if (inputUser) inputUser->TakeFocus();
    }));
    inputUser = Input(&username, "Username / ID", Theme::inputOption(false, [&] {
        if (inputPass) inputPass->TakeFocus();
    }));
    inputPass = Input(&password, "Password", Theme::inputOption(false, [&] {
        if (inputNotes) inputNotes->TakeFocus();
    }));
    inputNotes = Input(&notes, "Notes (optional)", Theme::inputOption(false, [&] {
        if (selectedType == 0 && inputUrl) {
            inputUrl->TakeFocus();
        } else if (selectedType == 1 && inputSsid) {
            inputSsid->TakeFocus();
        } else if (selectedType == 2 && inputHost) {
            inputHost->TakeFocus();
        } else {
            saveAction();
        }
    }));

    inputUrl = Input(&url, "https://example.com", Theme::inputOption(false, [&] {
        saveAction();
    }));
    inputSsid = Input(&ssid, "Network SSID", Theme::inputOption(false, [&] {
        if (inputSec) inputSec->TakeFocus();
    }));
    inputSec = Input(&securityType, "WPA2 / WPA3", Theme::inputOption(false, [&] {
        saveAction();
    }));
    inputHost = Input(&host, "hostname or IP", Theme::inputOption(false, [&] {
        if (inputPort) inputPort->TakeFocus();
    }));
    inputPort = Input(&portStr, "22", Theme::inputOption(false, [&] {
        saveAction();
    }));

    auto btnSave = Button("Save to Vault", saveAction, Theme::buttonOption(true));
    auto btnCancel = Button("Cancel", [&] { exit(); }, Theme::buttonOption(false));

    // Dynamically activate only type-relevant inputs so hidden fields never steal keyboard focus
    auto typeSpecificContainer = Container::Tab({
        Container::Vertical({ inputUrl }),               // Type 0: Web
        Container::Vertical({ inputSsid, inputSec }),    // Type 1: WiFi
        Container::Vertical({ inputHost, inputPort }),   // Type 2: SSH
        Container::Vertical({}),                         // Type 3: Generic
    }, &selectedType);

    auto container = Container::Vertical({
        radioType,
        inputService,
        inputUser,
        inputPass,
        inputNotes,
        typeSpecificContainer,
        Container::Horizontal({ btnSave, btnCancel }),
    });

    auto renderer = Renderer(container, [&] {
        Elements formFields;
        formFields.push_back(hbox({ text(" Type     : ") | bold, radioType->Render() }));
        formFields.push_back(hbox({ text(" Service  : ") | bold, inputService->Render() | flex_grow }) | borderRounded | color(Theme::Subtle));
        formFields.push_back(hbox({ text(" Username : ") | bold, inputUser->Render() | flex_grow }) | borderRounded | color(Theme::Subtle));
        formFields.push_back(hbox({ text(" Password : ") | bold, inputPass->Render() | flex_grow }) | borderRounded | color(Theme::Subtle));
        formFields.push_back(hbox({ text(" Notes    : ") | bold, inputNotes->Render() | flex_grow }) | borderRounded | color(Theme::Subtle));

        if (selectedType == 0) {
            formFields.push_back(hbox({ text(" URL      : ") | bold, inputUrl->Render() | flex_grow }) | borderRounded | color(Theme::Primary));
        } else if (selectedType == 1) {
            formFields.push_back(hbox({ text(" SSID     : ") | bold, inputSsid->Render() | flex_grow }) | borderRounded | color(Theme::Success));
            formFields.push_back(hbox({ text(" Security : ") | bold, inputSec->Render() | flex_grow }) | borderRounded | color(Theme::Success));
        } else if (selectedType == 2) {
            formFields.push_back(hbox({ text(" Host     : ") | bold, inputHost->Render() | flex_grow }) | borderRounded | color(Theme::Secondary));
            formFields.push_back(hbox({ text(" Port     : ") | bold, inputPort->Render() | flex_grow }) | borderRounded | color(Theme::Secondary));
        }

        if (!errorMessage.empty()) {
            formFields.push_back(text(errorMessage) | bold | color(Theme::Danger));
        }

        return vbox({
            filler(),
            hbox({
                filler(),
                vbox({
                    text(" Add New Credential ") | bold | color(Theme::Primary),
                    separator() | color(Theme::Subtle),
                    vbox(std::move(formFields)),
                    separator() | color(Theme::Subtle),
                    hbox({ btnSave->Render(), text("  "), btnCancel->Render() }) | center,
                }) | size(WIDTH, EQUAL, 64) | borderRounded | color(Theme::Primary),
                filler(),
            }),
            filler(),
        });
    });

    screen.Loop(renderer);
    return created;
}

/**
 * @brief Modal dialog to edit an existing credential.
 */
void handleEditCredential(MasterVault& vault, size_t index) {
    auto current = vault.getCredential(index);
    if (!current) return;

    // Clone credential to work on a temporary editable copy
    std::shared_ptr<Credential> working(current->clone());
    working->setPassword(""); // Clear password so stored secret is not held in edit form memory

    auto screen = ScreenInteractive::Fullscreen();
    auto exit = screen.ExitLoopClosure();

    std::string service = working->getService();
    std::string username = working->getUsername();
    std::string newPassword;
    std::string notes = working->getNotes();

    std::string url;
    std::string ssid, secType;
    std::string host, portStr;

    if (auto web = std::dynamic_pointer_cast<WebCredential>(working)) {
        url = web->getUrl();
    } else if (auto wifi = std::dynamic_pointer_cast<WiFiCredential>(working)) {
        ssid = wifi->getSsid();
        secType = wifi->getSecurityType();
    } else if (auto ssh = std::dynamic_pointer_cast<SSHCredential>(working)) {
        host = ssh->getHost();
        portStr = std::to_string(ssh->getPort());
    }

    Component inputService;
    Component inputUser;
    Component inputPass;
    Component inputNotes;
    Component inputUrl;
    Component inputSsid;
    Component inputSec;
    Component inputHost;
    Component inputPort;
    Component inputCredAuth;

    std::string credAuthPassword;
    std::string errorMsg;

    auto saveAction = [&] {
        if (service.empty()) {
            errorMsg = "Service name cannot be empty.";
            return;
        }

        bool secretChanged = !newPassword.empty();
        if (secretChanged && credAuthPassword.empty()) {
            errorMsg = "Modifying the secret password requires entering your Credential Vault password.";
            return;
        }

        working->setService(service);
        working->setUsername(username);
        working->setPassword(newPassword); // Empty password signals domain layer to keep current password
        working->setNotes(notes);

        if (auto web = std::dynamic_pointer_cast<WebCredential>(working)) {
            web->setUrl(url);
        } else if (auto wifi = std::dynamic_pointer_cast<WiFiCredential>(working)) {
            wifi->setSsid(ssid);
            wifi->setSecurityType(secType);
        } else if (auto ssh = std::dynamic_pointer_cast<SSHCredential>(working)) {
            ssh->setHost(host);
            try { ssh->setPort(std::stoi(portStr)); } catch (...) {}
        }

        if (vault.updateCredential(index, working, credAuthPassword)) {
            exit();
        } else {
            if (secretChanged) {
                errorMsg = "Invalid Credential Vault password. Secret modification rejected.";
            } else {
                errorMsg = "Failed to update credential.";
            }
        }
    };

    inputService = Input(&service, "Service", Theme::inputOption(false, [&] {
        if (inputUser) inputUser->TakeFocus();
    }));
    inputUser = Input(&username, "Username", Theme::inputOption(false, [&] {
        if (inputPass) inputPass->TakeFocus();
    }));
    inputPass = Input(&newPassword, "Leave blank to keep current password", Theme::inputOption(true, [&] {
        if (inputNotes) inputNotes->TakeFocus();
    }));
    inputNotes = Input(&notes, "Notes", Theme::inputOption(false, [&] {
        if (working->getType() == "web" && inputUrl) {
            inputUrl->TakeFocus();
        } else if (working->getType() == "wifi" && inputSsid) {
            inputSsid->TakeFocus();
        } else if (working->getType() == "ssh" && inputHost) {
            inputHost->TakeFocus();
        } else {
            if (inputCredAuth) inputCredAuth->TakeFocus();
            else saveAction();
        }
    }));

    inputUrl = Input(&url, "URL", Theme::inputOption(false, [&] {
        if (inputCredAuth) inputCredAuth->TakeFocus();
        else saveAction();
    }));
    inputSsid = Input(&ssid, "SSID", Theme::inputOption(false, [&] {
        if (inputSec) inputSec->TakeFocus();
    }));
    inputSec = Input(&secType, "Security", Theme::inputOption(false, [&] {
        if (inputCredAuth) inputCredAuth->TakeFocus();
        else saveAction();
    }));
    inputHost = Input(&host, "Host", Theme::inputOption(false, [&] {
        if (inputPort) inputPort->TakeFocus();
    }));
    inputPort = Input(&portStr, "Port", Theme::inputOption(false, [&] {
        if (inputCredAuth) inputCredAuth->TakeFocus();
        else saveAction();
    }));
    inputCredAuth = Input(&credAuthPassword, "Required only if password is changed", Theme::inputOption(true, [&] {
        saveAction();
    }));

    auto btnSave = Button("Save Changes", saveAction, Theme::buttonOption(true));
    auto btnCancel = Button("Cancel", [&] { exit(); }, Theme::buttonOption(false));

    Components formComponents = {
        inputService,
        inputUser,
        inputPass,
        inputNotes,
    };

    if (working->getType() == "web") {
        formComponents.push_back(inputUrl);
    } else if (working->getType() == "wifi") {
        formComponents.push_back(inputSsid);
        formComponents.push_back(inputSec);
    } else if (working->getType() == "ssh") {
        formComponents.push_back(inputHost);
        formComponents.push_back(inputPort);
    }

    formComponents.push_back(inputCredAuth);
    formComponents.push_back(Container::Horizontal({ btnSave, btnCancel }));

    auto container = Container::Vertical(std::move(formComponents));

    auto renderer = Renderer(container, [&] {
        Elements form;
        form.push_back(hbox({ text(" Service  : ") | bold, inputService->Render() | flex_grow }) | borderRounded | color(Theme::Subtle));
        form.push_back(hbox({ text(" Username : ") | bold, inputUser->Render() | flex_grow }) | borderRounded | color(Theme::Subtle));
        form.push_back(hbox({ text(" New Pass : ") | bold, inputPass->Render() | flex_grow }) | borderRounded | color(Theme::Primary));
        form.push_back(hbox({ text(" Notes    : ") | bold, inputNotes->Render() | flex_grow }) | borderRounded | color(Theme::Subtle));

        if (working->getType() == "web") {
            form.push_back(hbox({ text(" URL      : ") | bold, inputUrl->Render() | flex_grow }) | borderRounded | color(Theme::Primary));
        } else if (working->getType() == "wifi") {
            form.push_back(hbox({ text(" SSID     : ") | bold, inputSsid->Render() | flex_grow }) | borderRounded | color(Theme::Success));
            form.push_back(hbox({ text(" Security : ") | bold, inputSec->Render() | flex_grow }) | borderRounded | color(Theme::Success));
        } else if (working->getType() == "ssh") {
            form.push_back(hbox({ text(" Host     : ") | bold, inputHost->Render() | flex_grow }) | borderRounded | color(Theme::Secondary));
            form.push_back(hbox({ text(" Port     : ") | bold, inputPort->Render() | flex_grow }) | borderRounded | color(Theme::Secondary));
        }

        form.push_back(hbox({ text(" Auth Pass: ") | bold | color(Theme::Warning), inputCredAuth->Render() | flex_grow }) | borderRounded | color(Theme::Warning));
        form.push_back(text(" (Credential Vault password required only if modifying the secret password) ") | dim | color(Theme::Muted));

        if (!errorMsg.empty()) {
            form.push_back(text(errorMsg) | bold | color(Theme::Danger));
        }

        return vbox({
            filler(),
            hbox({
                filler(),
                vbox({
                    text(" Edit Credential — " + current->getService()) | bold | color(Theme::Primary),
                    text(" Non-secret metadata can be saved without re-authentication. ") | dim | color(Theme::Muted),
                    separator() | color(Theme::Subtle),
                    vbox(std::move(form)),
                    separator() | color(Theme::Subtle),
                    hbox({ btnSave->Render(), text("  "), btnCancel->Render() }) | center,
                }) | size(WIDTH, EQUAL, 68) | borderRounded | color(Theme::Primary),
                filler(),
            }),
            filler(),
        });
    });

    screen.Loop(renderer);
}

/**
 * @brief Modal dialog to reveal a stored secret password with Credential Vault authentication.
 */
bool promptRevealPassword(MasterVault& vault, size_t index, std::string& outPassword) {
    auto screen = ScreenInteractive::Fullscreen();
    auto exit = screen.ExitLoopClosure();
    std::string authPassword;
    std::string errorMsg;
    bool success = false;

    Component inputAuth;

    auto revealAction = [&] {
        if (authPassword.empty()) {
            errorMsg = "Password cannot be empty.";
            return;
        }

        try {
            outPassword = vault.revealPassword(index, authPassword);
            success = true;
            exit();
        } catch (const UnauthorizedAccessException&) {
            errorMsg = "Invalid Credential Vault password.";
            authPassword.clear();
        } catch (const std::exception& e) {
            errorMsg = e.what();
            authPassword.clear();
        }
    };

    inputAuth = Input(&authPassword, "Credential vault password", Theme::inputOption(true, [&] {
        revealAction();
    }));

    auto btnConfirm = Button("Reveal Secret", revealAction, Theme::buttonOption(true));
    auto btnCancel = Button("Cancel", [&] { exit(); }, Theme::buttonOption(false));

    auto container = Container::Vertical({
        inputAuth,
        Container::Horizontal({ btnConfirm, btnCancel }),
    });

    auto renderer = Renderer(container, [&] {
        return vbox({
            filler(),
            hbox({
                filler(),
                vbox({
                    text(" Reveal Stored Secret ") | bold | color(Theme::Warning),
                    text(" Enter your Credential Vault password to decrypt and reveal the secret. ") | dim | color(Theme::Muted),
                    separator() | color(Theme::Subtle),
                    hbox({ text(" Vault Password : ") | bold, inputAuth->Render() | flex_grow }) | borderRounded | color(Theme::Warning),
                    text(errorMsg) | color(Theme::Danger),
                    separator() | color(Theme::Subtle),
                    hbox({ btnConfirm->Render(), text("  "), btnCancel->Render() }) | center,
                }) | size(WIDTH, EQUAL, 62) | borderRounded | color(Theme::Warning),
                filler(),
            }),
            filler(),
        });
    });

    screen.Loop(renderer);
    return success;
}

/**
 * @brief Modal dialog to authorize copying a stored secret password with Credential Vault authentication.
 */
bool promptCopyPassword(MasterVault& vault, size_t index, std::string& outPassword) {
    auto screen = ScreenInteractive::Fullscreen();
    auto exit = screen.ExitLoopClosure();
    std::string authPassword;
    std::string errorMsg;
    bool success = false;

    Component inputAuth;

    auto copyAction = [&] {
        if (authPassword.empty()) {
            errorMsg = "Password cannot be empty.";
            return;
        }

        try {
            outPassword = vault.copyPassword(index, authPassword);
            success = true;
            exit();
        } catch (const UnauthorizedAccessException&) {
            errorMsg = "Invalid Credential Vault password.";
            authPassword.clear();
        } catch (const std::exception& e) {
            errorMsg = e.what();
            authPassword.clear();
        }
    };

    inputAuth = Input(&authPassword, "Credential vault password", Theme::inputOption(true, [&] {
        copyAction();
    }));

    auto btnConfirm = Button("Authorize Copy", copyAction, Theme::buttonOption(true));
    auto btnCancel = Button("Cancel", [&] { exit(); }, Theme::buttonOption(false));

    auto container = Container::Vertical({
        inputAuth,
        Container::Horizontal({ btnConfirm, btnCancel }),
    });

    auto renderer = Renderer(container, [&] {
        return vbox({
            filler(),
            hbox({
                filler(),
                vbox({
                    text(" Copy Stored Secret ") | bold | color(Theme::Primary),
                    text(" Enter your Credential Vault password to authorize copying. ") | dim | color(Theme::Muted),
                    separator() | color(Theme::Subtle),
                    hbox({ text(" Vault Password : ") | bold, inputAuth->Render() | flex_grow }) | borderRounded | color(Theme::Primary),
                    text(errorMsg) | color(Theme::Danger),
                    separator() | color(Theme::Subtle),
                    hbox({ btnConfirm->Render(), text("  "), btnCancel->Render() }) | center,
                }) | size(WIDTH, EQUAL, 62) | borderRounded | color(Theme::Primary),
                filler(),
            }),
            filler(),
        });
    });

    screen.Loop(renderer);
    return success;
}

/**
 * @brief Modal dialog to securely delete a credential with Credential Vault re-authentication.
 */
bool handleDeleteCredential(MasterVault& vault, size_t index) {
    auto current = vault.getCredential(index);
    if (!current) return false;

    auto screen = ScreenInteractive::Fullscreen();
    auto exit = screen.ExitLoopClosure();

    std::string authPassword;
    std::string errorMsg;
    bool deleted = false;
    int attempts = 3;

    Component inputAuth;

    auto confirmAction = [&] {
        if (authPassword.empty()) {
            errorMsg = "Password cannot be empty.";
            return;
        }

        if (vault.deleteCredential(index, authPassword)) {
            deleted = true;
            exit();
            return;
        }

        attempts--;
        if (attempts > 0) {
            errorMsg = "Invalid credential vault password. Attempts remaining: " + std::to_string(attempts);
        } else {
            errorMsg = "Maximum attempts exceeded. Deletion denied.";
            exit();
        }
        authPassword.clear(); // Clear so the user starts fresh
    };

    inputAuth = Input(&authPassword, "Credential vault password", Theme::inputOption(true, [&] {
        confirmAction();
    }));

    auto btnConfirm = Button("Confirm Delete", confirmAction, Theme::buttonOption(true));
    auto btnCancel = Button("Cancel", [&] { exit(); }, Theme::buttonOption(false));

    auto container = Container::Vertical({
        inputAuth,
        Container::Horizontal({ btnConfirm, btnCancel }),
    });

    auto renderer = Renderer(container, [&] {
        return vbox({
            filler(),
            hbox({
                filler(),
                vbox({
                    text(" Delete Credential ") | bold | color(Theme::Danger),
                    text(" Permanently delete \"" + current->getService() + "\" (" + current->getType() + ")? ") | color(Theme::TextBright),
                    text(" Re-authentication with Credential Vault password is required. ") | dim | color(Theme::Muted),
                    separator() | color(Theme::Subtle),
                    hbox({ text(" Vault Password : ") | bold, inputAuth->Render() | flex_grow }) | borderRounded | color(Theme::Danger),
                    text(errorMsg) | color(Theme::Danger),
                    separator() | color(Theme::Subtle),
                    hbox({ btnConfirm->Render(), text("  "), btnCancel->Render() }) | center,
                }) | size(WIDTH, EQUAL, 58) | borderRounded | color(Theme::Danger),
                filler(),
            }),
            filler(),
        });
    });

    screen.Loop(renderer);
    return deleted;
}

// ============================================================================
// Main Split-Pane Dashboard
// ============================================================================

/**
 * @brief Coordinates the main interactive Master Session menu using an OpenCode split-pane layout.
 */
void runMasterVaultSession(MasterVault& vault) {
    vault.setInactivityTimeout(300); // 5 minutes inactivity timeout

    auto screen = ScreenInteractive::Fullscreen();
    auto exit = screen.ExitLoopClosure();

    std::vector<std::string> tabEntries = {
        " Credentials ",
        " Search ",
        " Password Tools ",
        " Security Audit ",
        " Off-Site Backup ",
        " Lock & Logout "
    };
    int selectedTab = 0;
    auto tabMenu = Menu(&tabEntries, &selectedTab, MenuOption::Horizontal());

    // --- Tab 0: Credentials Split View State ---
    int selectedCredIndex = 0;
    int previousCredIndex = -1; // Track selection changes to auto-hide password
    bool showPassword = false;
    std::string revealedPassword;
    std::string copyStatusMessage;
    std::vector<std::string> credentialLabels;

    auto refreshCredentialLabels = [&] {
        credentialLabels.clear();
        if (!vault.isCredentialsUnlocked()) {
            credentialLabels.push_back("(Credential Vault is locked)");
            selectedCredIndex = 0;
            return;
        }
        auto creds = vault.getPolymorphicCredentials();
        for (size_t i = 0; i < creds.size(); ++i) {
            std::string badge = getTypeBadgeStr(creds[i]);
            credentialLabels.push_back("[" + std::to_string(i + 1) + "] " + badge + " " + creds[i]->getService());
        }
        if (credentialLabels.empty()) {
            credentialLabels.push_back("(Vault is empty)");
            selectedCredIndex = 0;
        } else if (selectedCredIndex >= static_cast<int>(credentialLabels.size())) {
            selectedCredIndex = static_cast<int>(credentialLabels.size()) - 1;
        }
    };

    refreshCredentialLabels();

    auto tryUnlockCredentialVault = [&] {
        if (ensureCredentialVaultUnlocked(vault)) {
            refreshCredentialLabels();
        }
    };

    auto btnUnlockTab0 = Button("Unlock Credential Vault", tryUnlockCredentialVault, Theme::buttonOption(true));
    auto btnUnlockTab1 = Button("Unlock Credential Vault", tryUnlockCredentialVault, Theme::buttonOption(true));
    auto btnUnlockTab3 = Button("Unlock Credential Vault", tryUnlockCredentialVault, Theme::buttonOption(true));

    auto credMenu = Menu(&credentialLabels, &selectedCredIndex, Theme::menuOption());

    auto btnAddCred = Button("+ Add Credential", [&] {
        if (promptCreateCredential(vault)) {
            refreshCredentialLabels();
            auto creds = vault.getPolymorphicCredentials();
            if (!creds.empty()) {
                selectedCredIndex = static_cast<int>(creds.size()) - 1;
                showPassword = false;
                revealedPassword.clear();
                previousCredIndex = selectedCredIndex;
            }
        }
    }, Theme::buttonOption(true));

    auto btnToggleShow = Button("Show/Hide Password", [&] {
        auto creds = vault.getPolymorphicCredentials();
        if (creds.empty() || selectedCredIndex < 0 || selectedCredIndex >= static_cast<int>(creds.size())) {
            return;
        }
        if (showPassword) {
            showPassword = false;
            revealedPassword.clear();
        } else {
            std::string pass;
            if (promptRevealPassword(vault, selectedCredIndex, pass)) {
                revealedPassword = pass;
                showPassword = true;
            }
        }
    }, Theme::buttonOption(false));

    auto btnCopyPass = Button("Copy Password", [&] {
        auto creds = vault.getPolymorphicCredentials();
        if (creds.empty() || selectedCredIndex < 0 || selectedCredIndex >= static_cast<int>(creds.size())) {
            return;
        }
        std::string pass;
        if (promptCopyPassword(vault, selectedCredIndex, pass)) {
            if (TerminalUtils::copyToClipboard(pass)) {
                copyStatusMessage = "✓ Copied password to clipboard for \"" + creds[selectedCredIndex]->getService() + "\"";
            } else {
                copyStatusMessage = "✗ Failed to copy password to clipboard.";
            }
        }
    }, Theme::buttonOption(false));

    auto btnEdit = Button("Edit Credential", [&] {
        auto creds = vault.getPolymorphicCredentials();
        if (!creds.empty() && selectedCredIndex >= 0 && selectedCredIndex < static_cast<int>(creds.size())) {
            handleEditCredential(vault, selectedCredIndex);
            refreshCredentialLabels();
        }
    }, Theme::buttonOption(false));

    auto btnDelete = Button("Delete Credential", [&] {
        auto creds = vault.getPolymorphicCredentials();
        if (!creds.empty() && selectedCredIndex >= 0 && selectedCredIndex < static_cast<int>(creds.size())) {
            if (handleDeleteCredential(vault, selectedCredIndex)) {
                refreshCredentialLabels();
                showPassword = false;
                revealedPassword.clear();
                previousCredIndex = selectedCredIndex;
            }
        }
    }, Theme::buttonOption(false));

    // --- Tab 1: Search View State ---
    std::string searchQuery;
    int selectedSearchIndex = 0;
    std::vector<std::string> searchLabels;
    std::vector<std::shared_ptr<Credential>> currentSearchResults;

    Component inputSearch;

    auto runSearchAction = [&] {
        searchLabels.clear();
        currentSearchResults.clear();
        selectedSearchIndex = 0;
        if (!vault.isCredentialsUnlocked()) {
            searchLabels.push_back("(Unlock Credential Vault to search)");
            return;
        }
        if (!searchQuery.empty()) {
            currentSearchResults = vault.search(searchQuery);
            for (size_t i = 0; i < currentSearchResults.size(); ++i) {
                std::string badge = getTypeBadgeStr(currentSearchResults[i]);
                searchLabels.push_back("[" + std::to_string(i + 1) + "] " + badge + " " + currentSearchResults[i]->getService());
            }
        }
        if (searchLabels.empty()) {
            searchLabels.push_back("(No results matching query)");
        }
    };

    inputSearch = Input(&searchQuery, "Type query (Service, User, URL, Host...)", Theme::inputOption(false, [&] {
        runSearchAction();
    }));

    auto btnRunSearch = Button("Search", runSearchAction, Theme::buttonOption(true));

    auto searchMenu = Menu(&searchLabels, &selectedSearchIndex, Theme::menuOption([&] {
        // Jump directly to matching credential in Tab 0 on Enter
        if (!currentSearchResults.empty() &&
            selectedSearchIndex >= 0 &&
            selectedSearchIndex < static_cast<int>(currentSearchResults.size())) {
            const auto& target = currentSearchResults[selectedSearchIndex];
            auto allCreds = vault.getPolymorphicCredentials();
            for (size_t i = 0; i < allCreds.size(); ++i) {
                if (allCreds[i] == target) {
                    selectedCredIndex = static_cast<int>(i);
                    showPassword = false;
                    revealedPassword.clear();
                    previousCredIndex = selectedCredIndex;
                    selectedTab = 0;
                    break;
                }
            }
        }
    }));

    // --- Tab 2: Password Tools State ---
    std::string genLengthStr = "16";
    bool optUpper = true, optLower = true, optDigits = true, optSymbols = true;
    std::string generatedPassword;
    float genEntropyRatio = 0.0f;
    std::string genFeedback = "Click Generate to create a secure password";
    std::string genCopyMessage;
    Color genCopyColor = Theme::Success;

    Component inputGenLen;

    auto generateAction = [&] {
        size_t len = 16;
        try { len = std::stoul(genLengthStr); } catch (...) { len = 16; }
        if (len < 8) len = 8;
        if (len > 128) len = 128;
        genLengthStr = std::to_string(len);

        PasswordOptions opts;
        opts.length = len;
        opts.uppercase = optUpper;
        opts.lowercase = optLower;
        opts.digits = optDigits;
        opts.symbols = optSymbols;

        try {
            generatedPassword = PasswordGenerator::generate(opts);
            genCopyMessage.clear();
            auto result = PasswordStrength::analyze(generatedPassword);
            genEntropyRatio = std::min(1.0f, static_cast<float>(result.entropy) / 100.0f);
            genFeedback = "Entropy: " + std::to_string(static_cast<int>(result.entropy)) + " bits — " + result.feedback;
        } catch (const std::exception& e) {
            genFeedback = std::string("Error: ") + e.what();
        }
    };

    auto copyGeneratedAction = [&] {
        if (generatedPassword.empty()) {
            genCopyMessage = "Generate a password first before copying.";
            genCopyColor = Theme::Warning;
            return;
        }
        if (TerminalUtils::copyToClipboard(generatedPassword)) {
            genCopyMessage = "✓ Copied generated password to clipboard!";
            genCopyColor = Theme::Success;
        } else {
            genCopyMessage = "✗ Failed to copy to clipboard.";
            genCopyColor = Theme::Danger;
        }
    };

    inputGenLen = Input(&genLengthStr, "16", Theme::inputOption(false, [&] {
        generateAction();
    }));

    auto checkUpper = Checkbox("Uppercase (A-Z)", &optUpper);
    auto checkLower = Checkbox("Lowercase (a-z)", &optLower);
    auto checkDigits = Checkbox("Digits (0-9)", &optDigits);
    auto checkSymbols = Checkbox("Symbols (!@#$)", &optSymbols);

    auto btnGenerate = Button("Generate Random Password", generateAction, Theme::buttonOption(true));
    auto btnCopyGenerated = Button("Copy Password", copyGeneratedAction, Theme::buttonOption(false));

    std::string evalInput;
    std::string evalScoreStr = "--";
    std::string evalRatingStr = "Enter password to evaluate";
    float evalEntropyRatio = 0.0f;

    Component inputEval;

    auto evalAction = [&] {
        if (!evalInput.empty()) {
            auto res = PasswordStrength::analyze(evalInput);
            evalScoreStr = std::to_string(res.score) + "/100";
            evalEntropyRatio = std::min(1.0f, static_cast<float>(res.entropy) / 100.0f);
            evalRatingStr = res.feedback;
        }
    };

    inputEval = Input(&evalInput, "Test any password...", Theme::inputOption(false, [&] {
        evalAction();
    }));

    auto btnEval = Button("Evaluate Strength", evalAction, Theme::buttonOption(false));

    // --- Tab 4: Off-Site Backup State & Components ---
    BackupConfig backupConfig = BackupConfig::loadFromFile();
    std::string backupHost = backupConfig.host;
    std::string backupPortStr = std::to_string(backupConfig.port);
    std::string backupUser = backupConfig.user;
    std::string backupRemoteDir = backupConfig.remoteDir;
    std::string backupKeyPath = backupConfig.identityFile;
    std::string backupTimeoutStr = std::to_string(backupConfig.connectTimeout);

    std::string backupStatusMsg = "Ready. Configure remote host and click Trigger Off-Site Backup.";
    bool isBackingUp = false;
    bool lastBackupSuccess = false;
    bool hasAttemptedBackup = false;
    std::string lastTimestampedFile;

    Component inputBkpHost = Input(&backupHost, "e.g. backup-node.tailnet.ts.net or 100.x.y.z", Theme::inputOption());
    Component inputBkpPort = Input(&backupPortStr, "22", Theme::inputOption());
    Component inputBkpUser = Input(&backupUser, "e.g. palash (optional)", Theme::inputOption());
    Component inputBkpDir = Input(&backupRemoteDir, "backups/vaultsync", Theme::inputOption());
    Component inputBkpKey = Input(&backupKeyPath, "e.g. ~/.ssh/id_ed25519 (optional)", Theme::inputOption());
    Component inputBkpTimeout = Input(&backupTimeoutStr, "5", Theme::inputOption());

    auto saveConfigAction = [&] {
        backupConfig.host = trimString(backupHost);
        try { backupConfig.port = std::stoi(backupPortStr); } catch (...) { backupConfig.port = 22; }
        backupConfig.user = trimString(backupUser);
        backupConfig.remoteDir = trimString(backupRemoteDir);
        if (backupConfig.remoteDir.empty()) backupConfig.remoteDir = "backups/vaultsync";
        backupConfig.identityFile = trimString(backupKeyPath);
        try { backupConfig.connectTimeout = std::stoi(backupTimeoutStr); } catch (...) { backupConfig.connectTimeout = 5; }

        if (backupConfig.saveToFile()) {
            backupStatusMsg = "Configuration saved to " + BackupConfig::getDefaultConfigPath();
        } else {
            backupStatusMsg = "Failed to save configuration file.";
        }
    };

    auto btnSaveConfig = Button("Save Backup Settings", saveConfigAction, Theme::buttonOption(false));

    auto triggerBackupAction = [&] {
        if (isBackingUp) return;

        saveConfigAction();

        if (!backupConfig.isValid()) {
            backupStatusMsg = "Please enter a valid remote host before initiating backup.";
            hasAttemptedBackup = true;
            lastBackupSuccess = false;
            return;
        }

        isBackingUp = true;
        backupStatusMsg = "Connecting to " + backupConfig.host + " via Tailscale SFTP subprocess...";
        hasAttemptedBackup = true;

        std::thread([&screen, &vault, cfg = backupConfig, &isBackingUp, &backupStatusMsg, &lastBackupSuccess, &lastTimestampedFile]() {
            auto result = vault.performOffsiteBackup(cfg);
            screen.Post([&isBackingUp, &backupStatusMsg, &lastBackupSuccess, &lastTimestampedFile, result]() {
                isBackingUp = false;
                lastBackupSuccess = result.success;
                backupStatusMsg = result.message;
                lastTimestampedFile = result.remoteFile;
            });
        }).detach();
    };

    auto btnTriggerBackup = Button("☁ Trigger Off-Site Backup", triggerBackupAction, Theme::buttonOption(true));

    // Tab-isolated component containers
    auto tab0Unlocked = Container::Horizontal({
        Container::Vertical({ credMenu, btnAddCred }),
        Container::Vertical({ btnToggleShow, btnCopyPass, btnEdit, btnDelete }),
    });
    int tab0SubIdx = 0;
    auto tab0SubContainer = Container::Tab({
        Container::Vertical({ btnUnlockTab0 }),
        tab0Unlocked,
    }, &tab0SubIdx);

    auto tab1Unlocked = Container::Vertical({
        Container::Horizontal({ inputSearch, btnRunSearch }),
        searchMenu,
    });
    int tab1SubIdx = 0;
    auto tab1SubContainer = Container::Tab({
        Container::Vertical({ btnUnlockTab1 }),
        tab1Unlocked,
    }, &tab1SubIdx);

    auto tab2Container = Container::Horizontal({
        Container::Vertical({
            inputGenLen,
            checkUpper,
            checkLower,
            checkDigits,
            checkSymbols,
            Container::Horizontal({ btnGenerate, btnCopyGenerated })
        }),
        Container::Vertical({ inputEval, btnEval }),
    });

    int tab3SubIdx = 0;
    auto tab3SubContainer = Container::Tab({
        Container::Vertical({ btnUnlockTab3 }),
        Container::Vertical({}),
    }, &tab3SubIdx);

    auto tab4Container = Container::Vertical({
        inputBkpHost,
        Container::Horizontal({ inputBkpPort, inputBkpTimeout }),
        Container::Horizontal({ inputBkpUser, inputBkpDir }),
        inputBkpKey,
        Container::Horizontal({ btnTriggerBackup, btnSaveConfig }),
    });
    auto tab5Container = Container::Vertical({}); // Tab 5: Lock & Logout

    auto tabContainer = Container::Tab({
        tab0SubContainer,
        tab1SubContainer,
        tab2Container,
        tab3SubContainer,
        tab4Container,
        tab5Container,
    }, &selectedTab);

    // Combine top-level tab bar and active tab container
    auto mainContainer = Container::Vertical({
        tabMenu,
        tabContainer,
    });

    auto renderer = Renderer(mainContainer, [&] {
        // Record user activity
        vault.recordActivity();

        // Inactivity timeout check
        if (vault.checkInactivityTimeout()) {
            showPassword = false;
            revealedPassword.clear();
            refreshCredentialLabels();
        }

        tab0SubIdx = vault.isCredentialsUnlocked() ? 1 : 0;
        tab1SubIdx = vault.isCredentialsUnlocked() ? 1 : 0;
        tab3SubIdx = vault.isCredentialsUnlocked() ? 1 : 0;

        // Handle Tab 5: Lock & Logout
        if (selectedTab == 5) {
            vault.lock();
            exit();
            return text("Logging out and locking vault...") | bold | color(Theme::Warning);
        }

        // Top Navigation Bar
        auto headerBar = hbox({
            text(" VaultSync ") | bold | color(Theme::Primary) | bgcolor(Theme::CardBg),
            text(" ❯ ") | color(Theme::Subtle),
            text(vault.getUsername()) | bold | color(Theme::TextBright),
            text(vault.isCredentialsUnlocked() ? " (Credentials Unlocked) " : " (Credentials Locked) ")
                | color(vault.isCredentialsUnlocked() ? Theme::Success : Theme::Warning),
            filler(),
            tabMenu->Render(),
        }) | borderRounded | color(Theme::Subtle);

        Element bodyContent;

        if (selectedTab == 0) {
            // === TAB 0: Credentials Split View ===
            if (!vault.isCredentialsUnlocked()) {
                auto lockedCard = vbox({
                    text(" 🔒 Credential Vault is Locked ") | bold | color(Theme::Warning) | center,
                    separator() | color(Theme::Subtle),
                    text(" Stored credentials are encrypted with AES-256-GCM. ") | dim | color(Theme::Muted) | center,
                    text(" Enter your credential vault password to decrypt, view, and manage accounts. ") | color(Theme::TextBright) | center,
                    separator() | color(Theme::Subtle),
                    btnUnlockTab0->Render() | center,
                }) | size(WIDTH, EQUAL, 64) | borderRounded | color(Theme::Warning);

                bodyContent = vbox({
                    filler(),
                    hbox({ filler(), lockedCard, filler() }),
                    filler(),
                });
            } else {
                auto creds = vault.getPolymorphicCredentials();

                // Auto-hide password when selecting a different credential
                if (selectedCredIndex != previousCredIndex) {
                    showPassword = false;
                    revealedPassword.clear();
                    previousCredIndex = selectedCredIndex;
                }

                // Left Pane: List
                auto leftPane = vbox({
                    hbox({ text(" Credentials ") | bold | color(Theme::Primary), filler(), text(std::to_string(creds.size()) + " total") | dim }),
                    separator() | color(Theme::Subtle),
                    credMenu->Render() | flex_grow,
                    separator() | color(Theme::Subtle),
                    btnAddCred->Render() | center,
                }) | size(WIDTH, EQUAL, 38) | borderRounded | color(Theme::Subtle);

                // Right Pane: Detail Card
                Element rightPane;
                if (creds.empty() || selectedCredIndex < 0 || selectedCredIndex >= static_cast<int>(creds.size())) {
                    rightPane = vbox({
                        filler(),
                        text(" No Credential Selected ") | bold | color(Theme::Muted) | center,
                        text(" Choose a credential from the list or add a new one. ") | dim | color(Theme::Subtle) | center,
                        filler(),
                    }) | flex_grow | borderRounded | color(Theme::Subtle);
                } else {
                    const auto& active = creds[selectedCredIndex];
                    std::string displayPass = showPassword ? (revealedPassword.empty() ? active->getPassword() : revealedPassword)
                                                           : std::string(active->getPassword().size(), '*');

                    Elements detailRows;
                    detailRows.push_back(hbox({ text(" Service   : ") | bold | color(Theme::TextBright), text(active->getService()) | bold | color(Theme::Primary) }));
                    detailRows.push_back(hbox({ text(" Type      : ") | bold | color(Theme::TextBright), Theme::badge(active->getType()), text(" " + active->getType()) | dim }));
                    detailRows.push_back(hbox({ text(" Username  : ") | bold | color(Theme::TextBright), text(active->getUsername().empty() ? "(none)" : active->getUsername()) | color(Theme::TextBright) }));
                    detailRows.push_back(hbox({ text(" Password  : ") | bold | color(Theme::TextBright), text(displayPass) | bold | color(showPassword ? Theme::Warning : Theme::Muted) }));
                    detailRows.push_back(hbox({ text(" Notes     : ") | bold | color(Theme::TextBright), text(active->getNotes().empty() ? "(none)" : active->getNotes()) | color(Theme::Muted) }));

                    if (auto web = std::dynamic_pointer_cast<WebCredential>(active)) {
                        detailRows.push_back(hbox({ text(" URL       : ") | bold | color(Theme::Primary), text(web->getUrl()) | color(Theme::Primary) }));
                    } else if (auto wifi = std::dynamic_pointer_cast<WiFiCredential>(active)) {
                        detailRows.push_back(hbox({ text(" SSID      : ") | bold | color(Theme::Success), text(wifi->getSsid()) | color(Theme::Success) }));
                        detailRows.push_back(hbox({ text(" Protocol  : ") | bold | color(Theme::Success), text(wifi->getSecurityType()) | color(Theme::Success) }));
                    } else if (auto ssh = std::dynamic_pointer_cast<SSHCredential>(active)) {
                        detailRows.push_back(hbox({ text(" Host      : ") | bold | color(Theme::Secondary), text(ssh->getHost()) | color(Theme::Secondary) }));
                        detailRows.push_back(hbox({ text(" Port      : ") | bold | color(Theme::Secondary), text(std::to_string(ssh->getPort())) | color(Theme::Secondary) }));
                    }

                    detailRows.push_back(separator() | color(Theme::Subtle));
                    detailRows.push_back(hbox({ text(" Created   : ") | dim, text(formatTimestamp(active->getCreatedAt())) | dim }));

                    Elements actions;
                    actions.push_back(btnToggleShow->Render());
                    actions.push_back(text("  "));
                    actions.push_back(btnCopyPass->Render());
                    actions.push_back(text("  "));
                    actions.push_back(btnEdit->Render());
                    actions.push_back(text("  "));
                    actions.push_back(btnDelete->Render());

                    Elements paneElements;
                    paneElements.push_back(text(" Credential Details ") | bold | color(Theme::Primary));
                    paneElements.push_back(separator() | color(Theme::Subtle));
                    paneElements.push_back(vbox(std::move(detailRows)) | flex_grow);
                    if (!copyStatusMessage.empty()) {
                        paneElements.push_back(text(" " + copyStatusMessage + " ") | color(Theme::Success) | center);
                    }
                    paneElements.push_back(separator() | color(Theme::Subtle));
                    paneElements.push_back(hbox(std::move(actions)) | center);

                    rightPane = vbox(std::move(paneElements)) | flex_grow | borderRounded | color(Theme::Primary);
                }

                bodyContent = hbox({ leftPane, text(" "), rightPane }) | flex_grow;
            }

        } else if (selectedTab == 1) {
            // === TAB 1: Search View ===
            if (!vault.isCredentialsUnlocked()) {
                auto lockedSearchCard = vbox({
                    text(" 🔒 Search Encrypted Credentials ") | bold | color(Theme::Primary) | center,
                    separator() | color(Theme::Subtle),
                    text(" Stored credentials must be decrypted before searching. ") | dim | color(Theme::Muted) | center,
                    separator() | color(Theme::Subtle),
                    btnUnlockTab1->Render() | center,
                }) | size(WIDTH, EQUAL, 58) | borderRounded | color(Theme::Primary);

                bodyContent = vbox({
                    filler(),
                    hbox({ filler(), lockedSearchCard, filler() }),
                    filler(),
                });
            } else {
                bodyContent = vbox({
                    text(" Search Encrypted Credentials ") | bold | color(Theme::Primary),
                    text(" Instant query match across service, username, notes, URL, SSID, and host. ") | dim | color(Theme::Muted),
                    separator() | color(Theme::Subtle),
                    hbox({
                        inputSearch->Render() | flex_grow,
                        text(" "),
                        btnRunSearch->Render(),
                    }) | size(HEIGHT, EQUAL, 3),
                    separator() | color(Theme::Subtle),
                    searchMenu->Render() | flex_grow | borderRounded | color(Theme::Subtle),
                }) | flex_grow | borderRounded | color(Theme::Primary);
            }

        } else if (selectedTab == 2) {
            // === TAB 2: Password Tools ===
            auto genPane = vbox({
                text(" Random Password Generator ") | bold | color(Theme::Primary),
                separator() | color(Theme::Subtle),
                hbox({ text(" Length (8-128) : ") | bold, inputGenLen->Render() | size(WIDTH, EQUAL, 8) }),
                checkUpper->Render(),
                checkLower->Render(),
                checkDigits->Render(),
                checkSymbols->Render(),
                separator() | color(Theme::Subtle),
                hbox({ btnGenerate->Render(), text("  "), btnCopyGenerated->Render() }) | center,
                separator() | color(Theme::Subtle),
                hbox({ text(" Generated : ") | bold, text(generatedPassword.empty() ? "(none)" : generatedPassword) | bold | color(Theme::Warning) }),
                gauge(genEntropyRatio) | color(genEntropyRatio > 0.7f ? Theme::Success : (genEntropyRatio > 0.4f ? Theme::Warning : Theme::Danger)),
                text(genFeedback) | dim | color(Theme::Muted),
                genCopyMessage.empty() ? text("") : text(" " + genCopyMessage) | bold | color(genCopyColor),
            }) | flex_grow | borderRounded | color(Theme::Primary);

            auto evalPane = vbox({
                text(" Password Strength Evaluator ") | bold | color(Theme::Secondary),
                separator() | color(Theme::Subtle),
                hbox({ text(" Test Password : ") | bold, inputEval->Render() | flex_grow }),
                separator() | color(Theme::Subtle),
                btnEval->Render() | center,
                separator() | color(Theme::Subtle),
                hbox({ text(" Strength Score : ") | bold, text(evalScoreStr) | bold | color(Theme::Primary) }),
                gauge(evalEntropyRatio) | color(evalEntropyRatio > 0.7f ? Theme::Success : (evalEntropyRatio > 0.4f ? Theme::Warning : Theme::Danger)),
                text(evalRatingStr) | color(Theme::TextBright),
            }) | flex_grow | borderRounded | color(Theme::Secondary);

            bodyContent = hbox({ genPane, text(" "), evalPane }) | flex_grow;

        } else if (selectedTab == 3) {
            // === TAB 3: Security Health Dashboard ===
            if (!vault.isCredentialsUnlocked()) {
                auto lockedAuditCard = vbox({
                    text(" 🔒 Vault Security Health Dashboard ") | bold | color(Theme::Primary) | center,
                    separator() | color(Theme::Subtle),
                    text(" Decryption key required to audit passwords, check entropy, and detect reuse vulnerabilities. ") | dim | color(Theme::Muted) | center,
                    separator() | color(Theme::Subtle),
                    btnUnlockTab3->Render() | center,
                }) | size(WIDTH, EQUAL, 64) | borderRounded | color(Theme::Primary);

                bodyContent = vbox({
                    filler(),
                    hbox({ filler(), lockedAuditCard, filler() }),
                    filler(),
                });
            } else {
                auto creds = vault.getPolymorphicCredentials();
                SecurityScore score = PasswordAnalyzer::analyze(creds);

                float scoreRatio = std::min(1.0f, static_cast<float>(score.score) / 100.0f);
                Color scoreColor = (score.score >= 80) ? Theme::Success : (score.score >= 50 ? Theme::Warning : Theme::Danger);

                Elements warningsList;
                std::unordered_map<std::string, size_t> passFreq;
                for (const auto& c : creds) {
                    if (!c) continue;
                    passFreq[c->getPassword()]++;
                    int s = PasswordStrength::score(c->getPassword());
                    if (s < 50) {
                        warningsList.push_back(text(" ⚠ [WEAK] " + c->getService() + " score " + std::to_string(s) + "/100 — " + PasswordStrength::feedback(c->getPassword())) | color(Theme::Danger));
                    }
                }
                for (const auto& c : creds) {
                    if (c && passFreq[c->getPassword()] > 1) {
                        warningsList.push_back(text(" ⚠ [REUSED] " + c->getService() + " shares its password with another account!") | color(Theme::Warning));
                    }
                }
                if (warningsList.empty()) {
                    warningsList.push_back(text(" ✓ All stored credentials meet recommended security standards.") | color(Theme::Success));
                }

                bodyContent = vbox({
                    text(" Vault Security Health Dashboard ") | bold | color(Theme::Primary),
                    text(" Real-time cryptographic entropy, reuse detection, and vulnerability scan ") | dim | color(Theme::Muted),
                    separator() | color(Theme::Subtle),
                    hbox({
                        vbox({
                            text(" Security Health Score ") | bold | color(Theme::TextBright),
                            text(" " + std::to_string(score.score) + " / 100 ") | bold | color(scoreColor),
                            gauge(scoreRatio) | color(scoreColor),
                        }) | flex_grow | borderRounded | color(scoreColor),
                        vbox({
                            hbox({ text(" Total Credentials  : ") | bold, text(std::to_string(creds.size())) }),
                            hbox({ text(" Reused Passwords   : ") | bold, text(std::to_string(score.reusedPasswords)) | color(score.reusedPasswords > 0 ? Theme::Warning : Theme::Success) }),
                            hbox({ text(" Old/Stale Accounts : ") | bold, text(std::to_string(score.oldPasswords)) }),
                        }) | flex_grow | borderRounded | color(Theme::Subtle),
                    }),
                    separator() | color(Theme::Subtle),
                    text(" Audit Findings & Recommendations : ") | bold | color(Theme::TextBright),
                    vbox(std::move(warningsList)) | flex_grow,
                }) | flex_grow | borderRounded | color(Theme::Primary);
            }
        } else if (selectedTab == 4) {
            // === TAB 4: Tailscale SFTP Off-Site Backup ===
            Color statusColor = isBackingUp ? Theme::Primary :
                                (hasAttemptedBackup ? (lastBackupSuccess ? Theme::Success : Theme::Danger) : Theme::Subtle);

            auto configCard = vbox({
                text(" Tailscale / SFTP Off-Site Backup Settings ") | bold | color(Theme::Primary),
                text(" Headless OpenSSH subprocess executing over private WireGuard tailnet with zero shell overhead ") | dim | color(Theme::Muted),
                separator() | color(Theme::Subtle),
                hbox({
                    text(" Remote Host : ") | bold | size(WIDTH, EQUAL, 16),
                    inputBkpHost->Render() | flex_grow,
                }),
                hbox({
                    text(" SFTP Port   : ") | bold | size(WIDTH, EQUAL, 16),
                    inputBkpPort->Render() | size(WIDTH, EQUAL, 10),
                    text("   Timeout (s) : ") | bold,
                    inputBkpTimeout->Render() | size(WIDTH, EQUAL, 8),
                }),
                hbox({
                    text(" Remote User : ") | bold | size(WIDTH, EQUAL, 16),
                    inputBkpUser->Render() | flex_grow,
                    text("   Remote Dir  : ") | bold,
                    inputBkpDir->Render() | flex_grow,
                }),
                hbox({
                    text(" SSH Key     : ") | bold | size(WIDTH, EQUAL, 16),
                    inputBkpKey->Render() | flex_grow,
                }),
                separator() | color(Theme::Subtle),
                hbox({
                    btnTriggerBackup->Render(),
                    text("  "),
                    btnSaveConfig->Render(),
                }) | center,
            }) | borderRounded | color(Theme::Primary);

            auto statusCard = vbox({
                text(" Transfer Status & Audit Log ") | bold | color(Theme::TextBright),
                separator() | color(Theme::Subtle),
                hbox({
                    text(isBackingUp ? " ⟳ " : (hasAttemptedBackup ? (lastBackupSuccess ? " ✓ " : " ✗ ") : " ℹ ")) | bold | color(statusColor),
                    text(backupStatusMsg) | bold | color(statusColor) | flex_grow,
                }),
                separator() | color(Theme::Subtle),
                vbox({
                    hbox({ text(" • Local Source : ") | dim, text(vault.getVaultPath()) | color(Theme::TextBright) }),
                    hbox({ text(" • Encrypted    : ") | dim, text("AES-256-GCM ciphertext payload (no plaintext is ever exposed)") | color(Theme::Success) }),
                    hbox({ text(" • Batch Atomic : ") | dim, text("Two-phase atomic commit (.tmp upload -> atomic rename)") | color(Theme::Subtle) }),
                    hbox({ text(" • Config File  : ") | dim, text(BackupConfig::getDefaultConfigPath()) | color(Theme::Subtle) }),
                }),
            }) | borderRounded | color(statusColor);

            bodyContent = vbox({
                configCard,
                text(" "),
                statusCard,
            }) | flex_grow;
        }

        // Bottom Status Bar
        auto statusBar = hbox({
            text(" [Tab] Navigate Focus   [Enter] Select/Trigger   [Ctrl+C] Force Quit ") | dim | color(Theme::Muted),
            filler(),
            text("OpenCode Dark Theme") | dim | color(Theme::Subtle),
        });

        return vbox({
            headerBar,
            text(" "),
            bodyContent,
            text(" "),
            statusBar,
        });
    });

    screen.Loop(renderer);
}

} // anonymous namespace

// ============================================================================
// Application Entry Point
// ============================================================================

int main() {
    MasterVault vault;

    while (true) {
        auto screen = ScreenInteractive::Fullscreen();
        auto exit = screen.ExitLoopClosure();

        std::vector<std::string> options = {
            "  [1] Login to Master Vault",
            "  [2] Create New Master Vault",
            "  [3] Exit Application"
        };
        int selectedOption = 0;
        int userAction = 0;
        auto menu = Menu(&options, &selectedOption, Theme::menuOption([&] {
            userAction = selectedOption + 1;
            exit();
        }));

        auto btnSelect = Button("Continue", [&] {
            userAction = selectedOption + 1;
            exit();
        }, Theme::buttonOption(true));

        auto btnExit = Button("Exit", [&] {
            userAction = 3;
            exit();
        }, Theme::buttonOption(false));

        auto container = Container::Vertical({
            menu,
            Container::Horizontal({ btnSelect, btnExit }),
        });

        auto renderer = Renderer(container, [&] {
            auto welcomeCard = vbox({
                text(" ╔══════════════════════════════════════════╗ ") | bold | color(Theme::Primary),
                text(" ║        VaultSync Security Core          ║ ") | bold | color(Theme::Primary),
                text(" ║   Secure Polymorphic Password Manager   ║ ") | dim | color(Theme::Muted),
                text(" ╚══════════════════════════════════════════╝ ") | bold | color(Theme::Primary),
                separator() | color(Theme::Subtle),
                text(" Select an action to proceed : ") | bold | color(Theme::TextBright),
                menu->Render() | borderRounded | color(Theme::Subtle),
                separator() | color(Theme::Subtle),
                hbox({ btnSelect->Render(), text("  "), btnExit->Render() }) | center,
            }) | size(WIDTH, EQUAL, 52) | borderRounded | color(Theme::Primary);

            return vbox({
                filler(),
                hbox({ filler(), welcomeCard, filler() }),
                filler(),
                hbox({
                    text(" VaultSync C++17 | OpenSSL AES-256-GCM | FTXUI ") | dim | color(Theme::Subtle),
                    filler(),
                    text("Use [↑/↓] to navigate, [Enter] to select") | dim | color(Theme::Subtle),
                }),
            });
        });

        screen.Loop(renderer);

        if (userAction == 1) {
            if (handleLoginMasterVault(vault)) {
                runMasterVaultSession(vault);
            }
        } else if (userAction == 2) {
            handleCreateMasterVault(vault);
        } else {
            std::cout << "\nVaultSync terminated cleanly.\n";
            break;
        }
    }

    return 0;
}
