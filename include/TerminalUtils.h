#ifndef TERMINAL_UTILS_H
#define TERMINAL_UTILS_H

#include <string>

namespace TerminalUtils {

    /**
     * @brief Reads a password from standard input while masking typed characters with asterisks (*).
     *
     * In an interactive terminal (isatty), echo is disabled and '*' is displayed for each
     * typed character, handling backspace appropriately.
     * In a non-interactive pipe or test environment (!isatty), reads via std::getline and echoes
     * asterisks so automated test scripts and redirected input function properly.
     *
     * @param prompt Prompt message to display before reading input.
     * @return Entered password string.
     */
    std::string readHiddenPassword(const std::string& prompt = "");

}

#endif // TERMINAL_UTILS_H
