/**
 * Injects the warning overlay into the page. This function is designed to be
 * called safely even when the DOM is not fully loaded.
 */
function injectWarningOverlay(reason, url) {
    // Since this script now runs at document_start, we must not assume document.body exists.
    // We will wait until the DOM is ready enough to be manipulated.
    const doInject = () => {
        // Prevent duplicate warnings if the message is received multiple times.
        if (document.querySelector('.phishguard-overlay')) {
            return;
        }

        // Stop the page from loading any further resources or running scripts.
        window.stop();

        // Create the overlay container.
        const overlay = document.createElement("div");
        overlay.className = "phishguard-overlay";

        // Create the warning box.
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

        // Append to the body if it exists, otherwise to the root element.
        const parent = document.body || document.documentElement;
        overlay.appendChild(warningBox);
        parent.appendChild(overlay);

        // Add event listeners for the buttons.
        document.getElementById("phishguard-back-btn").addEventListener("click", () => {
            window.history.back();
        });

        document.getElementById("phishguard-proceed-btn").addEventListener("click", () => {
            // This is intentionally left blank to allow the user to "escape" the overlay
            // if they choose to proceed, but the page will remain stopped.
            // A more advanced implementation might reload the page without the extension's interference.
            overlay.remove();
        });
    };

    if (document.readyState === 'loading') {
        // If the document is still loading, wait for the DOM content to be ready.
        document.addEventListener('DOMContentLoaded', doInject, { once: true });
    } else {
        // If the DOM is already interactive or complete, inject immediately.
        doInject();
    }
}

/**
 * Checks for login forms that submit credentials to a different domain.
 */
function checkForSuspiciousForms() {
    const pageHostname = window.location.hostname;
    const forms = document.querySelectorAll('form[action]');

    for (const form of forms) {
        if (!form.querySelector('input[type="password"]')) continue;

        try {
            const actionHostname = new URL(form.action).hostname;
            if (actionHostname !== pageHostname && !actionHostname.endsWith(`.${pageHostname}`)) {
                return `This page contains a login form that sends your credentials to a different domain (${actionHostname}).`;
            }
        } catch (e) { /* Ignore relative or invalid URLs */ }
    }
    return null;
}

/**
 * Checks for password fields that are hidden from the user.
 */
function checkForHiddenPasswordFields() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    for (const field of passwordFields) {
        const style = window.getComputedStyle(field);
        if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) < 0.1) {
            return "This page contains a hidden password field, which could be used to secretly capture your input.";
        }
    }
    return null;
}

/**
 * Runs all HTML analysis checks once the DOM is ready.
 */
function runHtmlAnalysis() {
    const doAnalysis = () => {
        const formReason = checkForSuspiciousForms();
        if (formReason) {
            injectWarningOverlay(formReason, window.location.href);
            return;
        }

        const hiddenFieldReason = checkForHiddenPasswordFields();
        if (hiddenFieldReason) {
            injectWarningOverlay(hiddenFieldReason, window.location.href);
        }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', doAnalysis, { once: true });
    } else {
        doAnalysis();
    }
}

// --- Message Listener ---

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    switch (request.type) {
        case "PHISHING_DETECTED":
            injectWarningOverlay(request.reason, request.url);
            sendResponse({ status: "Phishing warning displayed" });
            break;
        case "ANALYZE_HTML":
            runHtmlAnalysis();
            sendResponse({ status: "HTML analysis scheduled" });
            break;
        default:
            // Ignore other message types.
            break;
    }
});