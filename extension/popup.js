/**
 * VaultSync — Popup UI Controller
 *
 * Phase 4: Extension Action Popup & User Session Management
 *
 * Inspects vault lock state, handles user authentication, displays site-specific
 * credentials, and dispatches autofill commands to active browser tabs.
 */

document.addEventListener("DOMContentLoaded", async () => {
  const statusBadge = document.getElementById("vault-status-badge");
  const activeDomainText = document.getElementById("active-domain-text");
  const alertBox = document.getElementById("alert-box");

  const lockedView = document.getElementById("locked-view");
  const unlockedView = document.getElementById("unlocked-view");
  const credsContainer = document.getElementById("credentials-container");

  const inputUser = document.getElementById("input-user");
  const inputMasterPass = document.getElementById("input-master-pass");
  const inputCredPass = document.getElementById("input-cred-pass");
  const btnUnlock = document.getElementById("btn-unlock");
  const btnLock = document.getElementById("btn-lock");

  let activeTabUrl = "";
  let activeDomain = "";

  /**
   * Displays an alert message inside the popup.
   * @param {string} msg Text to display.
   * @param {"error" | "success"} type Alert style.
   */
  function showAlert(msg, type = "error") {
    alertBox.textContent = msg;
    alertBox.className = `alert alert-${type}`;
    alertBox.style.display = "block";
  }

  function hideAlert() {
    alertBox.style.display = "none";
  }

  /**
   * Identifies the domain of the active tab.
   */
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs.length > 0 && tabs[0].url) {
      activeTabUrl = tabs[0].url;
      try {
        const parsed = new URL(activeTabUrl);
        activeDomain = parsed.hostname;
        activeDomainText.textContent = activeDomain || activeTabUrl;
      } catch {
        activeDomainText.textContent = activeTabUrl;
      }
    } else {
      activeDomainText.textContent = "No active page";
    }
  } catch (err) {
    activeDomainText.textContent = "Unknown domain";
  }

  /**
   * Renders matched credentials in the unlocked view.
   * @param {Array<Object>} credentials
   */
  function renderCredentials(credentials) {
    credsContainer.innerHTML = "";

    if (!credentials || credentials.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = `No credentials found for ${activeDomain || "this domain"}.`;
      credsContainer.appendChild(empty);
      return;
    }

    credentials.forEach((cred) => {
      const card = document.createElement("div");
      card.className = "cred-card";

      const meta = document.createElement("div");
      meta.className = "cred-meta";

      const user = document.createElement("div");
      user.className = "cred-user";
      user.textContent = cred.username || "(Empty username)";

      const service = document.createElement("div");
      service.className = "cred-service";
      service.textContent = cred.service || "Web Account";

      meta.appendChild(user);
      meta.appendChild(service);

      const actions = document.createElement("div");
      actions.className = "cred-actions";

      // 1. Autofill Button
      const btnFill = document.createElement("button");
      btnFill.type = "button";
      btnFill.className = "btn btn-primary btn-small";
      btnFill.textContent = "Autofill";
      btnFill.addEventListener("click", async () => {
        try {
          const resp = await chrome.runtime.sendMessage({
            action: "autofill_active_tab",
            credential: cred
          });
          if (resp && resp.success) {
            window.close(); // Close popup upon successful autofill
          } else {
            showAlert(resp?.error || "Autofill failed.", "error");
          }
        } catch (err) {
          showAlert("Error sending autofill command to tab.", "error");
        }
      });

      // 2. Copy Password Button
      const btnCopy = document.createElement("button");
      btnCopy.type = "button";
      btnCopy.className = "btn btn-secondary btn-small";
      btnCopy.textContent = "Copy";
      btnCopy.addEventListener("click", async () => {
        if (cred.password) {
          await navigator.clipboard.writeText(cred.password);
          btnCopy.textContent = "Copied!";
          setTimeout(() => {
            btnCopy.textContent = "Copy";
          }, 1500);
        }
      });

      actions.appendChild(btnFill);
      actions.appendChild(btnCopy);

      card.appendChild(meta);
      card.appendChild(actions);

      credsContainer.appendChild(card);
    });
  }

  /**
   * Refreshes the popup interface based on native host state.
   */
  async function refreshState() {
    hideAlert();
    try {
      const statusResp = await chrome.runtime.sendMessage({ action: "status" });

      if (!statusResp || !statusResp.success) {
        statusBadge.textContent = "Error";
        statusBadge.className = "status-badge locked";
        showAlert(statusResp?.error || "Cannot connect to VaultSync host.", "error");
        return;
      }

      if (statusResp.state === "CredentialsUnlocked") {
        statusBadge.textContent = "Unlocked";
        statusBadge.className = "status-badge unlocked";
        lockedView.style.display = "none";
        unlockedView.style.display = "block";

        // Query credentials for active domain
        const credResp = await chrome.runtime.sendMessage({
          action: "get_credentials",
          domain: activeDomain,
          url: activeTabUrl
        });

        if (credResp && credResp.success) {
          renderCredentials(credResp.credentials);
        } else {
          renderCredentials([]);
        }
      } else {
        statusBadge.textContent = "Locked";
        statusBadge.className = "status-badge locked";
        lockedView.style.display = "block";
        unlockedView.style.display = "none";

        if (statusResp.user && !inputUser.value) {
          inputUser.value = statusResp.user;
        }
      }
    } catch (err) {
      statusBadge.textContent = "Disconnected";
      statusBadge.className = "status-badge locked";
      showAlert("VaultSync host is not responding. Ensure native host is registered.", "error");
    }
  }

  // Handle Unlock Button Click
  btnUnlock.addEventListener("click", async () => {
    hideAlert();
    const user = inputUser.value.trim();
    const masterPass = inputMasterPass.value;
    const credPass = inputCredPass.value;

    if (!user) {
      showAlert("Vault username is required.");
      return;
    }
    if (!masterPass) {
      showAlert("Master password is required.");
      return;
    }

    btnUnlock.disabled = true;
    btnUnlock.textContent = "Unlocking...";

    try {
      const resp = await chrome.runtime.sendMessage({
        action: "unlock",
        user: user,
        master_password: masterPass,
        cred_password: credPass
      });

      if (resp && resp.success) {
        inputMasterPass.value = "";
        inputCredPass.value = "";
        await refreshState();
      } else {
        showAlert(resp?.error || "Invalid credentials.", "error");
      }
    } catch (err) {
      showAlert("Unlock failed: Host disconnected.", "error");
    } finally {
      btnUnlock.disabled = false;
      btnUnlock.textContent = "Unlock Vault";
    }
  });

  // Handle Lock Button Click
  btnLock.addEventListener("click", async () => {
    hideAlert();
    try {
      await chrome.runtime.sendMessage({ action: "lock" });
      await refreshState();
    } catch (err) {
      showAlert("Error locking vault.", "error");
    }
  });

  // Initial load
  await refreshState();
});
