/**
 * VaultSync Chromium Extension — Background Service Worker
 *
 * Phase 4: Native Messaging Host Routing & Extension Coordination
 *
 * Coordinates asynchronous IPC between page content scripts, popup UI,
 * and the native C++ binary (vaultsync-host) over POSIX stdin/stdout.
 */

const NATIVE_HOST_NAME = "com.vaultsync.native";

/**
 * Sends a length-prefixed JSON request to the C++ native messaging host.
 * @param {Object} message JSON request object.
 * @returns {Promise<Object>} Response object from host or error descriptor.
 */
function sendNativeMessage(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, message, (response) => {
        if (chrome.runtime.lastError) {
          resolve({
            success: false,
            error: chrome.runtime.lastError.message || "Failed to communicate with native host."
          });
        } else if (!response) {
          resolve({
            success: false,
            error: "Native host closed connection without returning data."
          });
        } else {
          resolve(response);
        }
      });
    } catch (err) {
      resolve({
        success: false,
        error: `Runtime exception: ${err.message}`
      });
    }
  });
}

/**
 * Updates browser action badge reflecting vault lock state.
 * @param {string} state "Locked" | "MasterAuthenticated" | "CredentialsUnlocked"
 */
function updateBadgeState(state) {
  if (state === "CredentialsUnlocked") {
    chrome.action.setBadgeText({ text: "✓" });
    chrome.action.setBadgeBackgroundColor({ color: "#a6e3a1" }); // Catppuccin Green
  } else if (state === "MasterAuthenticated") {
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#f9e2af" }); // Catppuccin Yellow
  } else {
    chrome.action.setBadgeText({ text: "" });
  }
}

// Initial status check upon installation or reload
chrome.runtime.onInstalled.addListener(async () => {
  console.log(`[VaultSync] Service Worker initialized. Checking host '${NATIVE_HOST_NAME}'...`);
  const resp = await sendNativeMessage({ action: "status" });
  if (resp && resp.success) {
    updateBadgeState(resp.state);
  }
});

// Runtime message listener for content script and popup requests
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const { action } = request;

  if (action === "status") {
    sendNativeMessage({ action: "status", user: request.user }).then((resp) => {
      if (resp && resp.success) {
        updateBadgeState(resp.state);
      }
      sendResponse(resp);
    });
    return true; // Keep channel open for async response
  }

  if (action === "unlock") {
    sendNativeMessage({
      action: "unlock",
      user: request.user,
      master_password: request.master_password,
      cred_password: request.cred_password
    }).then((resp) => {
      if (resp && resp.success) {
        updateBadgeState(resp.state);
      }
      sendResponse(resp);
    });
    return true;
  }

  if (action === "get_credentials") {
    sendNativeMessage({
      action: "get_credentials",
      domain: request.domain,
      url: request.url
    }).then((resp) => {
      sendResponse(resp);
    });
    return true;
  }

  if (action === "lock") {
    sendNativeMessage({ action: "lock" }).then((resp) => {
      updateBadgeState("Locked");
      sendResponse(resp);
    });
    return true;
  }

  if (action === "autofill_active_tab") {
    // Forward credential payload to content script in the active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs.length > 0 && tabs[0].id) {
        chrome.tabs.sendMessage(tabs[0].id, {
          action: "autofill_credential",
          credential: request.credential
        }, (tabResp) => {
          sendResponse(tabResp || { success: true });
        });
      } else {
        sendResponse({ success: false, error: "No active browser tab found." });
      }
    });
    return true;
  }

  return false;
});
