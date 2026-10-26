/**
 * VaultSync Chromium Extension — Background Service Worker
 *
 * Phase 3: Native Messaging Host Smoke-Test & Registration Check
 *
 * NOTE: Full credential autofill, popup UI, and DOM interactions are deferred to Phase 4.
 * This script is strictly limited to verifying native messaging port connectivity.
 * No credentials, passwords, or secret tokens are retrieved, cached, or logged here.
 */

const NATIVE_HOST_NAME = "com.vaultsync.native";

chrome.runtime.onInstalled.addListener(() => {
  console.log(`[VaultSync] Extension installed. Performing registration smoke test with '${NATIVE_HOST_NAME}'...`);
  try {
    chrome.runtime.sendNativeMessage(
      NATIVE_HOST_NAME,
      { action: "status" },
      (response) => {
        if (chrome.runtime.lastError) {
          console.warn(`[VaultSync] Native host status check: ${chrome.runtime.lastError.message}`);
        } else {
          console.log("[VaultSync] Native host responded with status:", response);
        }
      }
    );
  } catch (err) {
    console.error("[VaultSync] Error dispatching native message:", err);
  }
});
