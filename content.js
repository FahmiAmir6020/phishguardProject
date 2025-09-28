/**
 * Displays the phishing warning overlay.
 * @param {string} reason - The reason why the site was flagged.
 * @param {string} url - The URL of the flagged site.
 */
function displayWarning(reason, url) {
  // Prevent duplicate warnings.
  if (document.querySelector('.phishguard-overlay')) {
    return;
  }

  // Create the overlay container.
  const overlay = document.createElement("div");
  overlay.className = "phishguard-overlay";

  // Create the warning box with the specific reason.
  const warningBox = document.createElement("div");
  warningBox.className = "phishguard-warning-box";
  warningBox.innerHTML = `
    <h1>Warning: Potential Threat Detected</h1>
    <p>${reason || 'This site is considered suspicious.'}</p>
    <p>URL: <strong>${url}</strong></p>
    <div class="phishguard-button-container">
      <button class="phishguard-button phishguard-button--back" id="phishguard-back-btn">Go Back</button>
      <button class="phishguard-button phishguard-button--proceed" id="phishguard-proceed-btn">Proceed Anyway</button>
    </div>
  `;

  // Append the warning box to the overlay, and the overlay to the body.
  overlay.appendChild(warningBox);
  document.body.appendChild(overlay);

  // Add event listeners for the buttons.
  document.getElementById("phishguard-back-btn").addEventListener("click", () => {
    window.history.back();
  });

  document.getElementById("phishguard-proceed-btn").addEventListener("click", () => {
    overlay.remove();
  });
}

/**
 * Checks for login forms that submit credentials to a different domain.
 * @returns {string|null} A reason string if a suspicious form is found, otherwise null.
 */
function checkForSuspiciousForms() {
  const pageHostname = window.location.hostname;
  const forms = document.querySelectorAll('form');

  for (const form of forms) {
    // Only check forms that contain a password field.
    if (!form.querySelector('input[type="password"]')) {
      continue;
    }

    const formAction = form.action;
    if (formAction) {
      try {
        const actionHostname = new URL(formAction).hostname;
        // Flag if the form's domain is different and not a subdomain of the page's domain.
        if (actionHostname !== pageHostname && !actionHostname.endsWith(`.${pageHostname}`)) {
           return `This page contains a login form that sends your credentials to a different domain (${actionHostname}).`;
        }
      } catch (e) {
        // Ignore invalid URLs in action attributes, which are likely relative paths.
      }
    }
  }
  return null;
}

/**
 * Checks for password fields that are hidden from the user.
 * @returns {string|null} A reason string if a hidden password field is found, otherwise null.
 */
function checkForHiddenPasswordFields() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    for (const field of passwordFields) {
        const style = window.getComputedStyle(field);
        if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) < 0.1) {
            return "This page contains a hidden password field, which could be used to secretly capture your input.";
        }

        const rect = field.getBoundingClientRect();
        if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) {
            return "This page contains a password field that is positioned off-screen, which could be used to secretly capture your input.";
        }
    }
    return null;
}

/**
 * Runs all HTML analysis checks.
 */
function runHtmlAnalysis() {
    const suspiciousFormReason = checkForSuspiciousForms();
    if (suspiciousFormReason) {
        displayWarning(suspiciousFormReason, window.location.href);
        return;
    }

    const hiddenFieldReason = checkForHiddenPasswordFields();
    if (hiddenFieldReason) {
        displayWarning(hiddenFieldReason, window.location.href);
    }
}

// --- Message Listener ---

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "PHISHING_DETECTED") {
    displayWarning(request.reason, request.url);
    sendResponse({ status: "VirusTotal warning displayed" });
  } else if (request.type === "ANALYZE_HTML") {
    // Wait a brief moment for the DOM to be more settled before analyzing.
    setTimeout(runHtmlAnalysis, 500);
    sendResponse({ status: "HTML analysis scheduled" });
  }
  return true; // Keep the message channel open for async response if needed.
});