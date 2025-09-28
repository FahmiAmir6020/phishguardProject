const API_KEY = "YOUR_API_KEY_HERE";

// --- VirusTotal Reputation Logic ---

async function checkDomainReputation(domain) {
  // Don't run the check if the API key placeholder is still present.
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

    // A 404 means the domain is not in VirusTotal's database, which we treat as safe.
    if (response.status === 404) {
      return false;
    }

    if (!response.ok) {
      console.error(`VirusTotal API error for domain ${domain}: ${response.status}`);
      return false;
    }

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;

    // Check for malicious or phishing flags as per the requirements.
    if (stats.malicious > 0 || stats.phishing > 0) {
      console.log(`VirusTotal flagged domain ${domain} as malicious or for phishing.`);
      return true;
    }
  } catch (error) {
    console.error(`Error checking domain ${domain} with VirusTotal:`, error);
  }

  return false;
}

// --- Main Extension Logic ---

async function handleNavigation(details) {
  // Only run on the main frame to avoid checking URLs of iframes.
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
    return; // Cannot proceed without a valid domain.
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
    // If the VirusTotal check is clean, ask the content script to perform HTML analysis.
    // Use a try-catch block in case the content script is not yet ready.
    try {
      chrome.tabs.sendMessage(tabId, { type: "ANALYZE_HTML" });
    } catch (e) {
      console.log(`Could not send message to content script for tab ${tabId}. It may have been closed.`, e);
    }
  }
}

// Listen for when the browser commits to a new navigation.
chrome.webNavigation.onCommitted.addListener(handleNavigation, {
  url: [{ schemes: ['http', 'https'] }]
});