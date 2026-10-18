#include "PasswordGenerator.h"

#include <algorithm>
#include <random>
#include <stdexcept>

std::string PasswordGenerator::generate(const PasswordOptions& options) {
    std::string characterPool;
    std::string requiredCharacters;

    if (options.uppercase) {
        characterPool += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        requiredCharacters += 'A';
    }
    if (options.lowercase) {
        characterPool += "abcdefghijklmnopqrstuvwxyz";
        requiredCharacters += 'a';
    }
    if (options.digits) {
        characterPool += "0123456789";
        requiredCharacters += '0';
    }
    if (options.symbols) {
        characterPool += "!@#$%^&*()-_=+[]{};:,.?";
        requiredCharacters += '!';
    }

    if (characterPool.empty() || options.length < requiredCharacters.size()) {
        throw std::invalid_argument("Password options cannot satisfy requested length");
    }

    std::random_device randomDevice;
    std::mt19937 generator(randomDevice());
    std::uniform_int_distribution<size_t> distribution(0, characterPool.size() - 1);

    std::string password = requiredCharacters;
    while (password.size() < options.length) {
        password += characterPool[distribution(generator)];
    }

    std::shuffle(password.begin(), password.end(), generator);
    return password;
}

std::string PasswordGenerator::generate(size_t length,
                                        bool uppercase,
                                        bool lowercase,
                                        bool digits,
                                        bool symbols) {
    return generate(PasswordOptions{length, uppercase, lowercase, digits, symbols});
}
