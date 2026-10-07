#include "CryptoUtils.h"
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace CryptoUtils {

namespace {

    // SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    inline uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
        return (e & f) ^ (~e & g);
    }

    inline uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
        return (a & b) ^ (a & c) ^ (b & c);
    }

    inline uint32_t sig0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    inline uint32_t sig1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    inline uint32_t theta0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    inline uint32_t theta1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    void transformBlock(uint32_t state[8], const uint8_t block[64]) {
        uint32_t W[64];
        for (int t = 0; t < 16; ++t) {
            W[t] = (static_cast<uint32_t>(block[t * 4]) << 24) |
                   (static_cast<uint32_t>(block[t * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[t * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(block[t * 4 + 3]));
        }
        for (int t = 16; t < 64; ++t) {
            W[t] = theta1(W[t - 2]) + W[t - 7] + theta0(W[t - 15]) + W[t - 16];
        }

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        for (int t = 0; t < 64; ++t) {
            uint32_t T1 = h + sig1(e) + choose(e, f, g) + K[t] + W[t];
            uint32_t T2 = sig0(a) + majority(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

} // anonymous namespace

std::string sha256(const std::vector<uint8_t>& data) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint64_t totalBits = static_cast<uint64_t>(data.size()) * 8;
    size_t fullBlocks = data.size() / 64;

    for (size_t i = 0; i < fullBlocks; ++i) {
        transformBlock(state, data.data() + (i * 64));
    }

    size_t remainder = data.size() % 64;
    std::vector<uint8_t> lastBlock(64, 0);
    if (remainder > 0) {
        std::memcpy(lastBlock.data(), data.data() + (fullBlocks * 64), remainder);
    }
    lastBlock[remainder] = 0x80;

    if (remainder >= 56) {
        transformBlock(state, lastBlock.data());
        std::fill(lastBlock.begin(), lastBlock.end(), 0);
    }

    for (int i = 0; i < 8; ++i) {
        lastBlock[63 - i] = static_cast<uint8_t>((totalBits >> (i * 8)) & 0xFF);
    }
    transformBlock(state, lastBlock.data());

    std::ostringstream oss;
    for (int i = 0; i < 8; ++i) {
        oss << std::hex << std::setw(8) << std::setfill('0') << state[i];
    }
    return oss.str();
}

std::string sha256(const std::string& input) {
    std::vector<uint8_t> data(input.begin(), input.end());
    return sha256(data);
}

std::string generateSalt(size_t numBytes) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);

    std::ostringstream oss;
    for (size_t i = 0; i < numBytes; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
    }
    return oss.str();
}

std::string hashPassword(const std::string& password, const std::string& salt, size_t iterations) {
    // PBKDF-style iterative hashing to stretch the password and prevent brute-force attacks
    std::string current = sha256(salt + ":" + password + ":" + salt);
    for (size_t i = 1; i < iterations; ++i) {
        current = sha256(current + ":" + salt + ":" + password);
    }
    return current;
}

bool verifyPassword(const std::string& password, const std::string& salt, const std::string& expectedHash) {
    std::string computed = hashPassword(password, salt);
    if (computed.size() != expectedHash.size()) {
        return false;
    }
    // Constant-time comparison to protect against timing attacks
    int diff = 0;
    for (size_t i = 0; i < computed.size(); ++i) {
        diff |= (computed[i] ^ expectedHash[i]);
    }
    return diff == 0;
}

std::string deriveKey(const std::string& masterPassword, const std::string& salt) {
    // Derives a cryptographic key for the ICipher encryption layer
    return sha256("VAULTSYNC_KEY:" + salt + ":" + masterPassword);
}

} // namespace CryptoUtils
