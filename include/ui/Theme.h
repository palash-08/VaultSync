#ifndef THEME_H
#define THEME_H

#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/color.hpp>
#include <ftxui/component/component_options.hpp>
#include <string>

namespace Theme {

using namespace ftxui;

// ============================================================================
// OpenCode Inspired Palette: Modern, dark, high contrast with soft accents
// ============================================================================
inline const Color Primary    = Color::RGB(56, 189, 248);   // Electric Sky Blue
inline const Color Secondary  = Color::RGB(192, 132, 252);  // Soft Purple / Mauve
inline const Color Success    = Color::RGB(74, 222, 128);   // Mint Green
inline const Color Warning    = Color::RGB(251, 191, 36);   // Warm Amber
inline const Color Danger     = Color::RGB(248, 113, 113);  // Coral Red
inline const Color Muted      = Color::RGB(148, 163, 184);  // Slate Gray
inline const Color Subtle     = Color::RGB(100, 116, 139);  // Dim Border Slate
inline const Color TextBright = Color::RGB(248, 250, 252);  // Off-white / Crisp
inline const Color DarkBg     = Color::RGB(15, 23, 42);     // Deep Obsidian Slate
inline const Color CardBg     = Color::RGB(30, 41, 59);     // Surface Slate

/**
 * @brief Returns a styled type badge element [WEB], [WIFI], [SSH], or [GEN].
 */
inline Element badge(const std::string& type) {
    if (type == "web") {
        return text(" [WEB] ") | bold | color(Primary);
    }
    if (type == "wifi") {
        return text(" [WIFI] ") | bold | color(Success);
    }
    if (type == "ssh") {
        return text(" [SSH] ") | bold | color(Secondary);
    }
    return text(" [GEN] ") | bold | color(Warning);
}

/**
 * @brief Standardized window/card container with rounded borders and consistent styling.
 */
inline Element card(Element content) {
    return content | borderRounded | color(Subtle);
}

/**
 * @brief Top-level branding header element.
 */
inline Element header(const std::string& title, const std::string& subtitle = "") {
    Elements elms;
    elms.push_back(text("  " + title + "  ") | bold | color(Primary));
    if (!subtitle.empty()) {
        elms.push_back(text("  " + subtitle + "  ") | dim | color(Muted));
    }
    return vbox(std::move(elms));
}

/**
 * @brief Creates a customized ButtonOption matching the OpenCode theme.
 */
inline ButtonOption buttonOption(bool isPrimary = false) {
    ButtonOption opt;
    opt.transform = [isPrimary](const EntryState& s) {
        auto t = text(" " + s.label + " ");
        if (s.focused) {
            // Keep borderRounded in all states so the element size never changes
            // (removing the border on focus was causing layout jitter on hover)
            return t | bold | color(Color::Black) | bgcolor(isPrimary ? Primary : TextBright) | borderRounded;
        }
        if (isPrimary) {
            return t | bold | color(Primary) | borderRounded;
        }
        return t | color(Muted) | borderRounded;
    };
    return opt;
}

/**
 * @brief Creates a customized MenuOption matching the OpenCode theme.
 */
inline MenuOption menuOption(std::function<void()> onEnter = nullptr) {
    MenuOption opt;
    if (onEnter) {
        opt.on_enter = std::move(onEnter);
    }
    opt.entries_option.transform = [](const EntryState& s) {
        std::string prefix = s.active ? " ❯ " : "   ";
        auto t = text(prefix + s.label);
        if (s.focused) {
            return t | bold | color(Primary) | bgcolor(Color::RGB(30, 41, 59));
        }
        if (s.active) {
            return t | bold | color(TextBright);
        }
        return t | color(Muted);
    };
    return opt;
}

/**
 * @brief Creates a customized InputOption with password, placeholder, blinking cursor, and on_enter support.
 */
inline InputOption inputOption(bool isPassword = false, std::function<void()> onEnter = nullptr) {
    InputOption opt;
    opt.password = isPassword;
    opt.multiline = false; // Prevent inserting newlines on Enter
    if (onEnter) {
        opt.on_enter = std::move(onEnter);
    }
    opt.transform = [](InputState s) {
        if (s.is_placeholder) {
            if (s.focused) {
                // Render visible blinking cursor bar immediately when empty and focused
                s.element = hbox({
                    text("▏") | bold | color(Primary) | blink,
                    s.element | dim | color(Subtle)
                }) | focusCursorBarBlinking;
            } else {
                s.element = hbox({
                    text(" "),
                    s.element | dim | color(Subtle)
                });
            }
        } else {
            s.element |= color(TextBright);
        }
        return s.element;
    };
    return opt;
}

} // namespace Theme

#endif // THEME_H
