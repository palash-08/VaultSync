/**
 * VaultSync Chromium Extension — Background Service Worker
 *
 * Phase 4: Native Messaging Host Routing & Extension Coordination
 *
 * Coordinates asynchronous IPC between page content scripts, popup UI,
 * and the native C++ binary (vaultsync-host) over POSIX stdin/stdout.
 */

const NATIVE_HOST_NAME = "com.vaultsync.native";
const REQUEST_TIMEOUT_MS = 10000; // 10s timeout to prevent stuck host from hanging autofill

let nativePort = null;
const pendingRequests = [];

/**
 * Handles port disconnection and resets queue state.
 * @param {string} [reason] Optional override error reason (e.g. "timeout").
 */
function handlePortDisconnect(reason) {
  const errorMsg = reason || chrome.runtime.lastError?.message || "Native host disconnected.";
  if (nativePort) {
    try {
      nativePort.disconnect();
    } catch (_) {}
    nativePort = null;
  }
  updateBadgeState("Locked");

  while (pendingRequests.length > 0) {
    const { resolve, timer } = pendingRequests.shift();
    if (timer) {
      clearTimeout(timer);
    }
    resolve({
      success: false,
      error: errorMsg
    });
  }
}

/**
 * Lazily creates and returns a persistent native messaging port.
 * @returns {chrome.runtime.Port | null} Active native messaging port.
 */
function getOrCreateNativePort() {
  if (nativePort) {
    return nativePort;
  }

  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);
  } catch (err) {
    nativePort = null;
    return null;
  }

  // MV3 service workers can be suspended; a fresh connection or reconnect begins in locked state
  updateBadgeState("Locked");

  nativePort.onMessage.addListener((response) => {
    if (pendingRequests.length > 0) {
      const { resolve, timer } = pendingRequests.shift();
      if (timer) {
        clearTimeout(timer);
      }
      resolve(response);
    }
  });

  nativePort.onDisconnect.addListener(() => {
    handlePortDisconnect();
  });

  return nativePort;
}

/**
 * Sends a JSON request to the persistent C++ native messaging host port.
 * Responses are matched sequentially in FIFO order.
 * @param {Object} message JSON request object.
 * @returns {Promise<Object>} Response object from host or error descriptor.
 */
function sendNativeMessage(message) {
  return new Promise((resolve) => {
    try {
      const port = getOrCreateNativePort();
      if (!port) {
        resolve({
          success: false,
          error: chrome.runtime.lastError?.message || "Failed to connect to native host."
        });
        return;
      }

      const timer = setTimeout(() => {
        // Disconnect and reset port on timeout so later responses do not land on the wrong request
        handlePortDisconnect("timeout");
      }, REQUEST_TIMEOUT_MS);

      pendingRequests.push({ resolve, timer });
      port.postMessage(message);
    } catch (err) {
      const idx = pendingRequests.findIndex((req) => req.resolve === resolve);
      if (idx !== -1) {
        const [removed] = pendingRequests.splice(idx, 1);
        if (removed.timer) {
          clearTimeout(removed.timer);
        }
      }
      handlePortDisconnect();
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
    // Determine trusted target URL from sender frame or tab, never from unverified request body
    // If login form is in a cross-origin iframe, sender.url gives that frame's own URL
    let targetUrl = "";
    if (sender?.url && !sender.url.startsWith("chrome-extension://")) {
      targetUrl = sender.url;
    } else if (sender?.tab?.url) {
      targetUrl = sender.tab.url;
    } else {
      // Internal extension page (e.g. popup UI) querying active tab
      targetUrl = request.url || request.domain || "";
    }

    sendNativeMessage({
      action: "get_credentials",
      url: targetUrl
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
