#ifndef TERMINAL_UTILS_H
#define TERMINAL_UTILS_H

#include <string>
#include <functional>

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

    /**
     * @brief Copies text to the system clipboard using native platform utilities (wl-copy, xclip, xsel, pbcopy, clip.exe)
     *        or a verified terminal escape sequence (OSC 52).
     * @param text The text string to copy.
     * @return True if copying actually succeeded; false if text is empty or no clipboard transport succeeded.
     */
    bool copyToClipboard(const std::string& text);

    /**
     * @brief Reads text back from the system clipboard using native platform utilities.
     * @return Text currently stored in the clipboard, or empty string on failure.
     */
    std::string getClipboardText();

    /**
     * @brief Sets an optional clipboard hook for automated testing.
     * @param hook Callable returning bool indicating simulated success or failure.
     */
    void setClipboardHookForTesting(std::function<bool(const std::string&)> hook);

}

#endif // TERMINAL_UTILS_H
