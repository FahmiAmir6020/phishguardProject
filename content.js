/**
 * Injects the warning overlay instantly. It stops the page load and
 * injects the UI without waiting for the DOM to be fully ready.
 */
function injectWarningOverlay(reason, url) {
    // Stop the page from loading any further resources or running scripts.
    // This is the most critical step for immediate action.
    window.stop();

    // Prevent duplicate warnings.
    if (document.querySelector('.phishguard-overlay')) {
        return;
    }

    // Since this runs at document_start, document.body may not exist.
    // We replace the entire document content with our warning.
    document.documentElement.innerHTML = '';

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

    // Append the overlay to the now-empty root element.
    overlay.appendChild(warningBox);
    document.documentElement.appendChild(overlay);

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