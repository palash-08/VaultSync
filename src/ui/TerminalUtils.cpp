#include "ui/TerminalUtils.h"
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <csignal>
#include <cstring>
#include <vector>
#include <unistd.h>
#include <termios.h>
#include <sys/wait.h>

namespace TerminalUtils {

namespace {

std::function<bool(const std::string&)> s_clipboardTestHook = nullptr;

struct SigPipeGuard {
    void (*prev)(int);
    SigPipeGuard() {
        prev = signal(SIGPIPE, SIG_IGN);
    }
    ~SigPipeGuard() {
        signal(SIGPIPE, prev);
    }
};

bool commandExists(const std::string& bin) {
    if (bin.find('/') != std::string::npos) {
        return (access(bin.c_str(), X_OK) == 0);
    }
    const char* home = std::getenv("HOME");
    if (home) {
        std::string localBin = std::string(home) + "/.local/bin/" + bin;
        if (access(localBin.c_str(), X_OK) == 0) {
            return true;
        }
    }
    std::string check = "PATH=\"$HOME/.local/bin:$PATH\" command -v " + bin + " >/dev/null 2>&1";
    return (system(check.c_str()) == 0);
}

std::string base64Encode(const std::string& in) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    int val = 0, valb = -6;
    for (uint8_t c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

bool tryPipeCommand(const std::string& bin, const std::string& cmd, const std::string& text) {
    if (!commandExists(bin)) {
        return false;
    }
    SigPipeGuard guard;
    std::string fullCmd = "PATH=\"$HOME/.local/bin:$PATH\" " + cmd;
    FILE* pipe = popen(fullCmd.c_str(), "w");
    if (!pipe) return false;
    size_t written = fwrite(text.data(), 1, text.size(), pipe);
    fflush(pipe);
    int status = pclose(pipe);
    bool writeOk = (written == text.size());
    bool exitOk = (status != -1) && WIFEXITED(status) && (WEXITSTATUS(status) == 0);
    return writeOk && exitOk;
}

std::string tryReadCommand(const std::string& bin, const std::string& cmd) {
    if (!commandExists(bin)) {
        return "";
    }
    std::string fullCmd = "PATH=\"$HOME/.local/bin:$PATH\" " + cmd;
    FILE* pipe = popen(fullCmd.c_str(), "r");
    if (!pipe) return "";
    std::string result;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        result += buffer;
    }
    int status = pclose(pipe);
    if (status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
            result.pop_back();
        }
        return result;
    }
    return "";
}

bool terminalSupportsOsc52() {
    const char* termProg = std::getenv("TERM_PROGRAM");
    if (termProg) {
        std::string prog(termProg);
        if (prog == "ghostty" || prog == "iTerm.app" || prog == "WezTerm" ||
            prog == "alacritty" || prog == "vscode") {
            return true;
        }
    }
    if (std::getenv("KITTY_WINDOW_ID") || std::getenv("ALACRITTY_WINDOW_ID") ||
        std::getenv("WT_SESSION") || std::getenv("FOOT_TERMINAL_PID")) {
        return true;
    }
    const char* term = std::getenv("TERM");
    if (term) {
        std::string t(term);
        if (t.find("kitty") != std::string::npos ||
            t.find("alacritty") != std::string::npos ||
            t.find("foot") != std::string::npos ||
            t.find("wezterm") != std::string::npos) {
            return true;
        }
    }
    return false;
}

} // anonymous namespace

std::string readHiddenPassword(const std::string& prompt) {
    if (!prompt.empty()) {
        std::cout << prompt << std::flush;
    }

    // Check if input stream is an interactive terminal
    if (!isatty(STDIN_FILENO)) {
        // Non-interactive mode (e.g. redirected stdin, pipes, automated tests)
        std::string password;
        if (std::getline(std::cin, password)) {
            // Echo asterisks corresponding to character length
            std::cout << std::string(password.length(), '*') << "\n";
            return password;
        }
        return "";
    }

    // Interactive terminal mode: disable ECHO and ICANON
    struct termios oldt, newt;
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        std::string password;
        std::getline(std::cin, password);
        return password;
    }

    newt = oldt;
    newt.c_lflag &= ~(ECHO | ICANON);

    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
        std::string password;
        std::getline(std::cin, password);
        return password;
    }

    std::string password;
    char ch = 0;

    while (read(STDIN_FILENO, &ch, 1) == 1) {
        if (ch == '\n' || ch == '\r') {
            std::cout << "\n";
            break;
        } else if (ch == 127 || ch == '\b' || ch == 8) { // Backspace
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b" << std::flush;
            }
        } else if (ch == 3) { // Ctrl+C
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            std::cout << "\n";
            exit(0);
        } else if (ch == 4) { // Ctrl+D (EOF)
            std::cout << "\n";
            break;
        } else if (ch >= 32 && ch <= 126) { // Printable characters
            password.push_back(ch);
            std::cout << '*' << std::flush;
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return password;
}

void setClipboardHookForTesting(std::function<bool(const std::string&)> hook) {
    s_clipboardTestHook = std::move(hook);
}

bool copyToClipboard(const std::string& text) {
    if (text.empty()) {
        return false;
    }

    if (s_clipboardTestHook) {
        return s_clipboardTestHook(text);
    }

    // 1. Prioritize native clipboard tools according to display server
    const char* waylandDisplay = std::getenv("WAYLAND_DISPLAY");
    const char* x11Display = std::getenv("DISPLAY");

    std::vector<std::pair<std::string, std::string>> candidates;

    // Prefer Wayland tool if Wayland display is present
    if (waylandDisplay && waylandDisplay[0] != '\0') {
        candidates.push_back({"wl-copy", "wl-copy"});
    }
    // Prefer X11 tools if X11 display is present
    if (x11Display && x11Display[0] != '\0') {
        candidates.push_back({"xclip", "xclip -selection clipboard"});
        candidates.push_back({"xsel", "xsel --clipboard --input"});
    }
    // macOS
    candidates.push_back({"pbcopy", "pbcopy"});
    // Windows / WSL
    candidates.push_back({"clip.exe", "clip.exe"});

    // General fallbacks in case environment variable was unset or forwarding
    candidates.push_back({"wl-copy", "wl-copy"});
    candidates.push_back({"xclip", "xclip -selection clipboard"});
    candidates.push_back({"xsel", "xsel --clipboard --input"});

    for (const auto& candidate : candidates) {
        if (tryPipeCommand(candidate.first, candidate.second, text)) {
            return true;
        }
    }

    // 2. OSC 52 fallback ONLY when the terminal emulator actually supports it
    if (terminalSupportsOsc52() && isatty(STDOUT_FILENO)) {
        std::string osc52 = "\033]52;c;" + base64Encode(text) + "\007";
        FILE* tty = fopen("/dev/tty", "w");
        if (tty) {
            size_t w = fwrite(osc52.data(), 1, osc52.size(), tty);
            fflush(tty);
            fclose(tty);
            if (w == osc52.size()) {
                return true;
            }
        } else {
            std::cout << osc52 << std::flush;
            return true;
        }
    }

    // Never report success if no clipboard transport succeeded
    return false;
}

std::string getClipboardText() {
    const char* waylandDisplay = std::getenv("WAYLAND_DISPLAY");
    const char* x11Display = std::getenv("DISPLAY");

    std::vector<std::pair<std::string, std::string>> candidates;

    if (waylandDisplay && waylandDisplay[0] != '\0') {
        candidates.push_back({"wl-paste", "wl-paste --no-newline"});
    }
    if (x11Display && x11Display[0] != '\0') {
        candidates.push_back({"xclip", "xclip -selection clipboard -o"});
        candidates.push_back({"xsel", "xsel --clipboard --output"});
    }
    candidates.push_back({"pbpaste", "pbpaste"});
    candidates.push_back({"wl-paste", "wl-paste --no-newline"});
    candidates.push_back({"xclip", "xclip -selection clipboard -o"});
    candidates.push_back({"xsel", "xsel --clipboard --output"});

    for (const auto& candidate : candidates) {
        std::string content = tryReadCommand(candidate.first, candidate.second);
        if (!content.empty()) {
            return content;
        }
    }
    return "";
}

} // namespace TerminalUtils
