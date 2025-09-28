import { inspect } from './email_inspector.js';
import { setupAdblocker } from './adblocker.js';

const API_KEY = "YOUR_API_KEY_HERE";

// --- VirusTotal Reputation Logic (for URL scanning) ---

async function checkDomainReputation(domain) {
  if (!API_KEY || API_KEY === "YOUR_API_KEY_HERE") {
    console.log("VirusTotal API key is not set. Skipping reputation check.");
    return false;
  }

  const apiUrl = `https://www.virustotal.com/api/v3/domains/${domain}`;

  try {
    const response = await fetch(apiUrl, {
      method: 'GET',
      headers: { 'x-apikey': API_KEY }
    });

    if (response.status === 404) {
      return false;
    }

    if (!response.ok) {
      console.error(`VirusTotal API error for domain ${domain}: ${response.status}`);
      return false;
    }

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;

    if (stats.malicious > 0 || stats.suspicious > 0) {
      console.log(`VirusTotal flagged domain ${domain} as malicious or suspicious.`);
      return true;
    }
  } catch (error) {
    console.error(`Error checking domain ${domain} with VirusTotal:`, error);
  }
  return false;
}

// --- URL Scanning Logic ---

/**
 * Sends a message to a content script with a retry mechanism.
 * This is crucial because the content script might not be ready to receive messages
 * immediately, especially when injected at `document_start`.
 * @param {number} tabId The ID of the tab to send the message to.
 * @param {object} message The message object to send.
 * @param {number} retries The number of retries remaining.
 */
function sendMessageWithRetry(tabId, message, retries = 3) {
  chrome.tabs.sendMessage(tabId, message, (response) => {
    if (chrome.runtime.lastError && retries > 0) {
      console.log(`PhishGuard: Could not send message to tab ${tabId}, retrying... (${retries} retries left)`);
      setTimeout(() => {
        sendMessageWithRetry(tabId, message, retries - 1);
      }, 250); // Retry after a short delay
    } else if (chrome.runtime.lastError) {
      console.error(`PhishGuard: Failed to send message to tab ${tabId} after multiple retries.`, chrome.runtime.lastError.message);
    }
  });
}

async function handleNavigation(details) {
  if (details.frameId !== 0) {
    return;
  }

  const { url, tabId } = details;
  let isMalicious = false;

  try {
    const domain = new URL(url).hostname;
    isMalicious = await checkDomainReputation(domain);
  } catch (e) {
    console.error(`Could not parse URL to get domain: ${url}`, e);
    return;
  }

  if (isMalicious) {
    const reason = "This site is flagged as malicious or suspicious by VirusTotal.";
    console.log(`Threat detected at ${url}. Reason: ${reason}`);
    sendMessageWithRetry(tabId, {
      type: "PHISHING_DETECTED",
      url: url,
      reason: reason
    });
  } else {
    sendMessageWithRetry(tabId, { type: "ANALYZE_HTML" });
  }
}

// --- Event Listeners ---

// Listener for URL scanning on page navigation.
chrome.webNavigation.onCommitted.addListener(handleNavigation, {
  url: [{ schemes: ['http', 'https'] }]
});

// Listener for email header inspection requests from the popup.
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Ensure the message is from our extension's popup.
  if (sender.id === chrome.runtime.id && request.type === 'INSPECT_EMAIL') {
    console.log("Background script received INSPECT_EMAIL request.");
    if (request.headers) {
      const result = inspect(request.headers);
      sendResponse(result);
    }
    // Return true to indicate an asynchronous response.
    return true;
  }
});

// Listener for when the extension is installed or updated.
chrome.runtime.onInstalled.addListener(() => {
  setupAdblocker();
});