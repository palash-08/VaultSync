/**
 * VaultSync — Content Script
 *
 * Phase 4: DOM Input Detection, Inline Badge Rendering & Reactive Autofill
 *
 * Scans web forms for password/username fields, renders inline VaultSync
 * key badges, communicates with background service worker, and autofills
 * credentials using synthetic bubbling events for SPA reactivity.
 */

(function () {
  const INJECTED_ATTR = "data-vaultsync-injected";
  const KEY_ICON_SVG = `
    <svg viewBox="0 0 24 24">
      <path d="M7 14c-2.76 0-5-2.24-5-5s2.24-5 5-5c2.42 0 4.44 1.72 4.9 4h6.1l2 2-2 2h-2l-1 1h-1.1l-1.9-1.9c-.46.56-1.14.9-1.9.9zm0-8C5.34 6 4 7.34 4 9s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3zm1 4a1 1 0 110-2 1 1 0 010 2z"/>
    </svg>
  `;

  let activeDropdown = null;

  /**
   * Displays an ephemeral floating toast notification.
   * @param {string} message Text to display.
   * @param {"info" | "success" | "error"} type Notification visual style.
   */
  function showToast(message, type = "info") {
    const existing = document.querySelector(".vaultsync-toast");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.className = `vaultsync-toast vaultsync-toast-${type}`;
    toast.textContent = message;

    document.body.appendChild(toast);
    setTimeout(() => {
      toast.remove();
    }, 3500);
  }

  /**
   * Injects value into input field and dispatches bubbling events
   * so modern virtual DOM frameworks (React, Vue, Angular) register changes.
   * @param {HTMLInputElement} input Target DOM input.
   * @param {string} value Plaintext value to set.
   */
  function setFieldValue(input, value) {
    if (!input || value === undefined || value === null) return;
    input.focus();

    // Use native prototype value setter to bypass React 16+ input hooks
    const nativeSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      "value"
    )?.set;

    if (nativeSetter) {
      nativeSetter.call(input, value);
    } else {
      input.value = value;
    }

    input.dispatchEvent(new Event("input", { bubbles: true, cancelable: true }));
    input.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
    input.blur();
  }

  /**
   * Finds the best corresponding username or email input for a password input.
   * @param {HTMLInputElement} passwordInput
   * @returns {HTMLInputElement | null}
   */
  function findAssociatedUsernameInput(passwordInput) {
    const form = passwordInput.form;
    if (form) {
      // 1. Explicit autocomplete attribute
      const explicit = form.querySelector('input[autocomplete="username"], input[autocomplete="email"]');
      if (explicit) return explicit;

      // 2. Text or email input preceding password input
      const inputs = Array.from(form.querySelectorAll("input"));
      const passIdx = inputs.indexOf(passwordInput);
      for (let i = passIdx - 1; i >= 0; i--) {
        const type = inputs[i].type.toLowerCase();
        if ((type === "text" || type === "email") && inputs[i].offsetParent !== null) {
          return inputs[i];
        }
      }
    }

    // Fallback: document-wide preceding input
    const allInputs = Array.from(document.querySelectorAll('input[type="text"], input[type="email"]'));
    return allInputs.length > 0 ? allInputs[0] : null;
  }

  /**
   * Executes dual-field credential autofill.
   * @param {HTMLInputElement} passwordInput
   * @param {string} username
   * @param {string} password
   */
  function performAutofill(passwordInput, username, password) {
    const usernameInput = findAssociatedUsernameInput(passwordInput);
    if (usernameInput && username) {
      setFieldValue(usernameInput, username);
    }
    if (passwordInput && password) {
      setFieldValue(passwordInput, password);
    }
    showToast(`VaultSync: Autofilled for ${username || "account"}`, "success");
  }

  /**
   * Renders floating dropdown selection when multiple credentials match the domain.
   */
  function showCredentialDropdown(badge, passwordInput, credentials) {
    if (activeDropdown) {
      activeDropdown.remove();
      activeDropdown = null;
    }

    const dropdown = document.createElement("div");
    dropdown.className = "vaultsync-dropdown";

    const header = document.createElement("div");
    header.className = "vaultsync-dropdown-header";
    header.textContent = "Select Account (VaultSync)";
    dropdown.appendChild(header);

    credentials.forEach((cred) => {
      const item = document.createElement("div");
      item.className = "vaultsync-dropdown-item";

      const userSpan = document.createElement("span");
      userSpan.className = "vaultsync-dropdown-username";
      userSpan.textContent = cred.username || "(Empty username)";

      const serviceSpan = document.createElement("span");
      serviceSpan.className = "vaultsync-dropdown-service";
      serviceSpan.textContent = cred.service ? `${cred.service} • ${window.location.hostname}` : window.location.hostname;

      item.appendChild(userSpan);
      item.appendChild(serviceSpan);

      item.addEventListener("click", (e) => {
        e.stopPropagation();
        performAutofill(passwordInput, cred.username, cred.password);
        dropdown.remove();
        activeDropdown = null;
      });

      dropdown.appendChild(item);
    });

    badge.parentElement.appendChild(dropdown);
    activeDropdown = dropdown;
  }

  // Dismiss dropdown when clicking outside
  document.addEventListener("click", (e) => {
    if (activeDropdown && !activeDropdown.contains(e.target)) {
      activeDropdown.remove();
      activeDropdown = null;
    }
  });

  /**
   * Mounts VaultSync badge inside password inputs.
   * @param {HTMLInputElement} input
   */
  function attachBadgeToInput(input) {
    if (input.getAttribute(INJECTED_ATTR) === "true") return;
    input.setAttribute(INJECTED_ATTR, "true");

    // Ensure parent has position relative or wrap input
    const parent = input.parentElement;
    if (parent && window.getComputedStyle(parent).position === "static") {
      parent.style.position = "relative";
    }

    const badge = document.createElement("button");
    badge.type = "button";
    badge.className = "vaultsync-badge";
    badge.title = "Autofill with VaultSync";
    badge.innerHTML = KEY_ICON_SVG;

    badge.addEventListener("click", async (e) => {
      e.preventDefault();
      e.stopPropagation();

      try {
        const response = await chrome.runtime.sendMessage({
          action: "get_credentials",
          domain: window.location.hostname,
          url: window.location.href
        });

        if (!response || !response.success) {
          const err = response?.error || "Vault is locked.";
          showToast(`VaultSync: ${err}`, "error");
          return;
        }

        const creds = response.credentials || [];
        if (creds.length === 0) {
          showToast(`VaultSync: No saved credentials for ${window.location.hostname}`, "info");
        } else if (creds.length === 1) {
          performAutofill(input, creds[0].username, creds[0].password);
        } else {
          showCredentialDropdown(badge, input, creds);
        }
      } catch (err) {
        showToast("VaultSync: Could not reach extension background worker.", "error");
      }
    });

    if (input.nextSibling) {
      input.parentNode.insertBefore(badge, input.nextSibling);
    } else {
      input.parentNode.appendChild(badge);
    }
  }

  /**
   * Scans DOM for visible password input fields.
   */
  function scanInputs() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    passwordFields.forEach((field) => {
      // Only attach to visible inputs
      if (field.offsetParent !== null || field.offsetWidth > 0 || field.offsetHeight > 0) {
        attachBadgeToInput(field);
      }
    });
  }

  // Initial scan upon document idle
  scanInputs();

  // Observe DOM for dynamically loaded forms (SPAs)
  const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    for (const mutation of mutations) {
      if (mutation.addedNodes.length > 0) {
        shouldScan = true;
        break;
      }
    }
    if (shouldScan) {
      scanInputs();
    }
  });

  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true
  });

  // Listen for direct messages from extension popup
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "autofill_credential") {
      const passwordFields = document.querySelectorAll('input[type="password"]');
      if (passwordFields.length > 0) {
        const cred = request.credential;
        performAutofill(passwordFields[0], cred.username, cred.password);
        sendResponse({ success: true });
      } else {
        sendResponse({ success: false, error: "No password fields found on page." });
      }
      return true;
    }
  });
})();
