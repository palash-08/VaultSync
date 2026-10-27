#include "native_host/NativeHost.h"
#include "credentials/WebCredential.h"
#include "storage/FileStorage.h"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <thread>
#include <unistd.h>
#include <sys/wait.h>

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

void testInactivityTimeoutAutoLock() {
    std::cout << "[Test 6] Testing inactivity timeout auto-lock..." << std::endl;

    std::string testUser = "timeout_test_user";
    std::string testVaultPath = MasterVault::getVaultPathForUser(testUser);

    if (fs::exists(testVaultPath)) {
        fs::remove(testVaultPath);
    }
    MasterVault::resetMasterLockout(testUser);

    {
        MasterVault mv;
        bool created = mv.create(testUser, "MasterPass@123");
        assert(created && "Failed to create timeout test vault");

        int attempts = 0;
        bool unlocked = mv.unlockMaster(testUser, "MasterPass@123", attempts);
        assert(unlocked);

        bool credSetup = mv.setupCredentialPassword("CredPass@456");
        assert(credSetup);

        auto cred = std::make_shared<WebCredential>(
            "ExampleService",
            "testuser",
            "SecretPass123!",
            "Timeout test entry",
            "https://example.com/login"
        );
        bool added = mv.addCredential(cred);
        assert(added);
    }

    NativeHost host;

    // Unlock
    std::string unlockMsg = R"({"action":"unlock","user":")" + testUser +
                            R"(","master_password":"MasterPass@123","cred_password":"CredPass@456"})";
    auto unlockResp = nlohmann::json::parse(host.handleMessage(unlockMsg));
    assert(unlockResp["success"] == true);
    assert(unlockResp["state"] == "CredentialsUnlocked");

    // Set timeout to 1 second
    std::string setTimeoutMsg = R"({"action":"set_timeout","timeout_seconds":1})";
    auto setTimeoutResp = nlohmann::json::parse(host.handleMessage(setTimeoutMsg));
    assert(setTimeoutResp["success"] == true);
    assert(setTimeoutResp["timeout_seconds"] == 1);

    // Verify status confirms 1s timeout
    std::string statusMsg = R"({"action":"status"})";
    auto statusResp1 = nlohmann::json::parse(host.handleMessage(statusMsg));
    assert(statusResp1["inactivity_timeout_seconds"] == 1);
    assert(statusResp1["state"] == "CredentialsUnlocked");

    // Sleep 1.2s to exceed the 1s timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));

    // get_credentials should auto-detect timeout, lock the vault, and fail
    std::string queryMsg = R"({"action":"get_credentials","domain":"example.com"})";
    auto queryResp = nlohmann::json::parse(host.handleMessage(queryMsg));
    assert(queryResp["success"] == false);
    assert(queryResp["error"].get<std::string>().find("Vault is locked") != std::string::npos);

    // Verify status is now MasterAuthenticated (credentials locked, master state retained)
    auto statusResp2 = nlohmann::json::parse(host.handleMessage(statusMsg));
    assert(statusResp2["state"] == "MasterAuthenticated");

    // Full lock resets to Locked
    host.handleMessage(R"({"action":"lock"})");
    auto statusResp3 = nlohmann::json::parse(host.handleMessage(statusMsg));
    assert(statusResp3["state"] == "Locked");

    if (fs::exists(testVaultPath)) {
        fs::remove(testVaultPath);
    }

    std::cout << "  ✓ Inactivity timeout auto-lock verified" << std::endl;
}

void testMultiCredentialMatchingAndComplexDomains() {
    std::cout << "[Test 7] Testing multi-credential matching and basic-auth URL normalization..." << std::endl;

    std::string testUser = "multi_cred_user";
    std::string testVaultPath = MasterVault::getVaultPathForUser(testUser);

    if (fs::exists(testVaultPath)) {
        fs::remove(testVaultPath);
    }
    MasterVault::resetMasterLockout(testUser);

    {
        MasterVault mv;
        bool created = mv.create(testUser, "MasterPass@123");
        assert(created && "Failed to create multi-cred test vault");

        int attempts = 0;
        bool unlocked = mv.unlockMaster(testUser, "MasterPass@123", attempts);
        assert(unlocked);

        bool credSetup = mv.setupCredentialPassword("CredPass@456");
        assert(credSetup);

        // Credential 1: GitHub Personal
        auto cred1 = std::make_shared<WebCredential>(
            "GitHub Personal",
            "octocat",
            "PersonalPass1!",
            "Personal token",
            "https://github.com/personal"
        );
        assert(mv.addCredential(cred1));

        // Credential 2: GitHub Work
        auto cred2 = std::make_shared<WebCredential>(
            "GitHub Work",
            "octocat_work",
            "WorkPass2@",
            "Enterprise account",
            "https://github.com/enterprise"
        );
        assert(mv.addCredential(cred2));

        // Credential 3: GitLab
        auto cred3 = std::make_shared<WebCredential>(
            "GitLab Account",
            "octocat_gl",
            "GitLabSecret3#",
            "GitLab account",
            "https://gitlab.com/login"
        );
        assert(mv.addCredential(cred3));
    }

    NativeHost host;

    // Unlock
    std::string unlockMsg = R"({"action":"unlock","user":")" + testUser +
                            R"(","master_password":"MasterPass@123","cred_password":"CredPass@456"})";
    auto unlockResp = nlohmann::json::parse(host.handleMessage(unlockMsg));
    assert(unlockResp["success"] == true);

    // Query 1: Basic auth with port: https://admin:pass@github.com:8443/repos
    std::string basicAuthUrl = "https://admin:pass@github.com:8443/repos";
    assert(NativeHost::extractDomain(basicAuthUrl) == "github.com");

    std::string query1 = R"({"action":"get_credentials","url":")" + basicAuthUrl + R"("})";
    auto resp1 = nlohmann::json::parse(host.handleMessage(query1));
    assert(resp1["success"] == true);
    assert(resp1["count"] == 2);
    assert(resp1["credentials"].size() == 2);

    bool foundPersonal = false;
    bool foundWork = false;
    for (const auto& c : resp1["credentials"]) {
        if (c["username"] == "octocat") foundPersonal = true;
        if (c["username"] == "octocat_work") foundWork = true;
    }
    assert(foundPersonal && foundWork && "Both matching credentials must be returned");

    // Query 2: Non-matching domain
    std::string query2 = R"({"action":"get_credentials","url":"https://bitbucket.org/login"})";
    auto resp2 = nlohmann::json::parse(host.handleMessage(query2));
    assert(resp2["success"] == true);
    assert(resp2["count"] == 0);
    assert(resp2["credentials"].empty());

    // Query 3: Empty domain -> returns all credentials
    std::string query3 = R"({"action":"get_credentials","url":""})";
    auto resp3 = nlohmann::json::parse(host.handleMessage(query3));
    assert(resp3["success"] == true);
    assert(resp3["count"] == 3);

    // Lock and cleanup
    host.handleMessage(R"({"action":"lock"})");
    if (fs::exists(testVaultPath)) {
        fs::remove(testVaultPath);
    }

    std::cout << "  ✓ Multi-credential domain matching & basic-auth normalization verified" << std::endl;
}

void testSubprocessHostBinaryIPC() {
    std::cout << "[Test 8] Testing subprocess host binary IPC via POSIX pipes..." << std::endl;

    // Locate the vaultsync-host executable
    std::string binPath;
    if (fs::exists("./build/vaultsync-host")) {
        binPath = "./build/vaultsync-host";
    } else if (fs::exists("./vaultsync-host")) {
        binPath = "./vaultsync-host";
    } else if (fs::exists("../build/vaultsync-host")) {
        binPath = "../build/vaultsync-host";
    }
    assert(!binPath.empty() && "vaultsync-host binary not found");

    int inPipe[2];   // parent -> child (child's stdin)
    int outPipe[2];  // child -> parent (child's stdout)

    assert(pipe(inPipe) == 0 && "Failed to create inPipe");
    assert(pipe(outPipe) == 0 && "Failed to create outPipe");

    pid_t pid = fork();
    assert(pid >= 0 && "Failed to fork child process");

    if (pid == 0) {
        // Child process
        close(inPipe[1]);
        close(outPipe[0]);

        dup2(inPipe[0], STDIN_FILENO);
        dup2(outPipe[1], STDOUT_FILENO);

        close(inPipe[0]);
        close(outPipe[1]);

        char* const argv[] = { const_cast<char*>(binPath.c_str()), nullptr };
        execvp(argv[0], argv);
        _exit(127);
    }

    // Parent process
    close(inPipe[0]);
    close(outPipe[1]);

    // Send framed JSON request: {"action":"status"}
    std::string req = R"({"action":"status"})";
    uint32_t reqLen = static_cast<uint32_t>(req.size());
    ssize_t bytesWritten = write(inPipe[1], &reqLen, sizeof(reqLen));
    assert(bytesWritten == sizeof(reqLen));
    bytesWritten = write(inPipe[1], req.data(), req.size());
    assert(bytesWritten == static_cast<ssize_t>(req.size()));

    // Read 4-byte response header
    uint32_t respLen = 0;
    ssize_t bytesRead = read(outPipe[0], &respLen, sizeof(respLen));
    assert(bytesRead == sizeof(respLen) && "Failed to read 4-byte response length");
    assert(respLen > 0 && respLen <= NativeHost::MAX_MESSAGE_SIZE);

    // Read response payload
    std::string respData(respLen, '\0');
    size_t totalRead = 0;
    while (totalRead < respLen) {
        ssize_t r = read(outPipe[0], &respData[totalRead], respLen - totalRead);
        assert(r > 0 && "Unexpected EOF or read error from child");
        totalRead += r;
    }

    auto respJson = nlohmann::json::parse(respData);
    assert(respJson["success"] == true);
    assert(respJson["action"] == "status");
    assert(respJson["state"] == "Locked");

    // Close inPipe[1] to signal EOF to child
    close(inPipe[1]);
    close(outPipe[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0 && "Child did not exit cleanly");

    std::cout << "  ✓ Subprocess binary IPC over standard POSIX streams verified" << std::endl;
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
        testInactivityTimeoutAutoLock();
        testMultiCredentialMatchingAndComplexDomains();
        testSubprocessHostBinaryIPC();
    } catch (const std::exception& e) {
        std::cerr << "FAILED with exception: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "========================================" << std::endl;
    std::cout << " All 8 Native Host Test Suites Passed!  " << std::endl;
    std::cout << "========================================" << std::endl;
    return 0;
}
