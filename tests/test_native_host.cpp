#include "native_host/NativeHost.h"
#include "credentials/WebCredential.h"
#include "storage/FileStorage.h"

#include <cassert>
#include <iostream>
#include <sstream>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;

void testFramingSerialization() {
    std::cout << "[Test 1] Testing 4-byte length-prefix framing..." << std::endl;

    std::string sampleJson = R"({"action":"status","user":"testuser"})";
    std::stringstream stream;

    bool writeOk = NativeHost::writeMessage(stream, sampleJson);
    assert(writeOk && "writeMessage failed");

    // Verify 4 bytes header
    std::string data = stream.str();
    assert(data.size() == 4 + sampleJson.size() && "Stream size mismatch");

    uint32_t lenHeader = 0;
    std::memcpy(&lenHeader, data.data(), 4);
    assert(lenHeader == sampleJson.size() && "Header length mismatch");

    // Read back using readMessage
    std::string receivedJson;
    bool readOk = NativeHost::readMessage(stream, receivedJson);
    assert(readOk && "readMessage failed");
    assert(receivedJson == sampleJson && "Payload mismatch");

    std::cout << "  ✓ 4-byte framing read/write verified" << std::endl;
}

void testOverlengthPacketRejection() {
    std::cout << "[Test 2] Testing overlength packet rejection (> 1MB)..." << std::endl;

    uint32_t hugeLength = NativeHost::MAX_MESSAGE_SIZE + 100;
    std::stringstream stream;
    stream.write(reinterpret_cast<const char*>(&hugeLength), sizeof(uint32_t));

    std::string receivedJson;
    bool readOk = NativeHost::readMessage(stream, receivedJson);
    assert(!readOk && "readMessage should reject packets > 1MB");

    std::cout << "  ✓ Overlength packets correctly rejected" << std::endl;
}

void testDomainExtraction() {
    std::cout << "[Test 3] Testing URL domain extraction..." << std::endl;

    assert(NativeHost::extractDomain("https://github.com/login") == "github.com");
    assert(NativeHost::extractDomain("http://www.google.com:8080/search?q=test") == "google.com");
    assert(NativeHost::extractDomain("https://SUB.DOMAIN.CO.UK/path/to/page") == "sub.domain.co.uk");
    assert(NativeHost::extractDomain("github.com") == "github.com");
    assert(NativeHost::extractDomain("") == "");

    std::cout << "  ✓ Domain normalizer verified across protocols, ports, and subdomains" << std::endl;
}

void testStatusAndMalformedJson() {
    std::cout << "[Test 4] Testing status query and malformed JSON resilience..." << std::endl;

    NativeHost host;

    // Malformed JSON
    std::string malformedResp = host.handleMessage("{not a json");
    auto malformedJson = nlohmann::json::parse(malformedResp);
    assert(malformedJson["success"] == false && "Malformed JSON should fail");

    // Unknown action
    std::string unknownResp = host.handleMessage(R"({"action":"unknown_action"})");
    auto unknownJson = nlohmann::json::parse(unknownResp);
    assert(unknownJson["success"] == false && "Unknown action should fail");

    // Status action
    std::string statusResp = host.handleMessage(R"({"action":"status"})");
    auto statusJson = nlohmann::json::parse(statusResp);
    assert(statusJson["success"] == true && "Status action failed");
    assert(statusJson["state"] == "Locked" && "Initial state should be Locked");

    std::cout << "  ✓ Status reporting and error handling verified" << std::endl;
}

void testUnlockAndGetCredentialsLifecycle() {
    std::cout << "[Test 5] Testing full unlock, credential retrieval, and lock lifecycle..." << std::endl;

    std::string testUser = "native_test_user";
    std::string testVaultPath = MasterVault::getVaultPathForUser(testUser);

    if (fs::exists(testVaultPath)) {
        fs::remove(testVaultPath);
    }
    MasterVault::resetMasterLockout(testUser);

    // Create a vault for testUser
    {
        MasterVault mv;
        bool created = mv.create(testUser, "MasterPass@123");
        assert(created && "Failed to create test vault");

        int attempts = 0;
        bool unlocked = mv.unlockMaster(testUser, "MasterPass@123", attempts);
        assert(unlocked);

        bool credSetup = mv.setupCredentialPassword("CredPass@456");
        assert(credSetup);

        // Add a web credential for github.com
        auto cred = std::make_shared<WebCredential>(
            "GitHub",
            "octocat",
            "SuperSecretToken!",
            "Developer token",
            "https://github.com/login"
        );
        bool added = mv.addCredential(cred);
        assert(added);
    }

    // Instantiate NativeHost
    NativeHost host;

    // 1. Check status
    std::string statusMsg = R"({"action":"status","user":")" + testUser + R"("})";
    auto statusJson = nlohmann::json::parse(host.handleMessage(statusMsg));
    assert(statusJson["success"] == true);
    assert(statusJson["vault_exists"] == true);

    // 2. Query credentials while locked -> should fail
    std::string preUnlockQuery = R"({"action":"get_credentials","domain":"github.com"})";
    auto preJson = nlohmann::json::parse(host.handleMessage(preUnlockQuery));
    assert(preJson["success"] == false);

    // 3. Unlock with wrong password -> should fail
    std::string badUnlock = R"({"action":"unlock","user":")" + testUser +
                            R"(","master_password":"WrongPassword","cred_password":"CredPass@456"})";
    auto badUnlockJson = nlohmann::json::parse(host.handleMessage(badUnlock));
    assert(badUnlockJson["success"] == false);

    // 4. Unlock with correct passwords -> should succeed
    std::string goodUnlock = R"({"action":"unlock","user":")" + testUser +
                             R"(","master_password":"MasterPass@123","cred_password":"CredPass@456"})";
    auto goodUnlockJson = nlohmann::json::parse(host.handleMessage(goodUnlock));
    assert(goodUnlockJson["success"] == true);
    assert(goodUnlockJson["state"] == "CredentialsUnlocked");

    // 5. Query matching domain
    std::string matchQuery = R"({"action":"get_credentials","url":"https://github.com/session"})";
    auto matchJson = nlohmann::json::parse(host.handleMessage(matchQuery));
    assert(matchJson["success"] == true);
    assert(matchJson["credentials"].size() == 1);
    assert(matchJson["credentials"][0]["username"] == "octocat");
    assert(matchJson["credentials"][0]["password"] == "SuperSecretToken!");

    // 6. Query non-matching domain
    std::string noMatchQuery = R"({"action":"get_credentials","url":"https://gitlab.com/login"})";
    auto noMatchJson = nlohmann::json::parse(host.handleMessage(noMatchQuery));
    assert(noMatchJson["success"] == true);
    assert(noMatchJson["credentials"].empty());

    // 7. Lock vault
    std::string lockMsg = R"({"action":"lock"})";
    auto lockJson = nlohmann::json::parse(host.handleMessage(lockMsg));
    assert(lockJson["success"] == true);
    assert(lockJson["state"] == "Locked");

    // 8. Query post-lock -> should fail
    auto postLockJson = nlohmann::json::parse(host.handleMessage(matchQuery));
    assert(postLockJson["success"] == false);

    // Cleanup test vault
    if (fs::exists(testVaultPath)) {
        fs::remove(testVaultPath);
    }

    std::cout << "  ✓ Full unlock, credential query, and lock lifecycle verified" << std::endl;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << " VaultSync Native Messaging Host Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        testFramingSerialization();
        testOverlengthPacketRejection();
        testDomainExtraction();
        testStatusAndMalformedJson();
        testUnlockAndGetCredentialsLifecycle();
    } catch (const std::exception& e) {
        std::cerr << "FAILED with exception: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "========================================" << std::endl;
    std::cout << " All 5 Native Host Test Suites Passed!  " << std::endl;
    std::cout << "========================================" << std::endl;
    return 0;
}
