#include "TerminalUtils.h"
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <termios.h>

namespace TerminalUtils {

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

} // namespace TerminalUtils
