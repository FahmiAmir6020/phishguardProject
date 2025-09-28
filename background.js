// Import external scripts.
importScripts('email_inspector.js');
importScripts('adblocker.js');

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

    if (stats.malicious > 0 || stats.phishing > 0) {
      console.log(`VirusTotal flagged domain ${domain} as malicious or for phishing.`);
      return true;
    }
  } catch (error) {
    console.error(`Error checking domain ${domain} with VirusTotal:`, error);
  }
  return false;
}

// --- URL Scanning Logic ---

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
    const reason = "This site is flagged as malicious or for phishing by VirusTotal.";
    console.log(`Threat detected at ${url}. Reason: ${reason}`);
    chrome.tabs.sendMessage(tabId, {
      type: "PHISHING_DETECTED",
      url: url,
      reason: reason
    });
  } else {
    try {
      chrome.tabs.sendMessage(tabId, { type: "ANALYZE_HTML" });
    } catch (e) {
      console.log(`Could not send message to content script for tab ${tabId}. It may have been closed.`, e);
    }
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