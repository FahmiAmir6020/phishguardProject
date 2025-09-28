const trustedDomains = [
  "paypal.com", "google.com", "facebook.com", "twitter.com", "instagram.com",
  "linkedin.com", "amazon.com", "apple.com", "microsoft.com", "netflix.com", "github.com"
];

// --- Cryptography Helper ---
async function sha256(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.prototype.map.call(new Uint8Array(buf), x => (('00' + x.toString(16)).slice(-2))).join('');
}


// --- URL Similarity Logic (unchanged) ---

function levenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const matrix = Array(a.length + 1).fill(null).map(() => Array(b.length + 1).fill(null));
  for (let i = 0; i <= a.length; i += 1) { matrix[i][0] = i; }
  for (let j = 0; j <= b.length; j += 1) { matrix[0][j] = j; }
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + cost);
    }
  }
  return matrix[a.length][b.length];
}

function getRegisteredDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 1) return hostname;
  if (parts.length > 2 && (parts[parts.length - 2].length <= 3 && parts[parts.length - 1].length <= 3)) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function checkUrlSimilarity(url) {
  try {
    const hostname = new URL(url).hostname;
    const registeredDomain = getRegisteredDomain(hostname);

    if (trustedDomains.includes(registeredDomain) || trustedDomains.some(t => hostname.endsWith(`.${t}`))) {
      return false;
    }

    for (const trusted of trustedDomains) {
      const distance = levenshtein(registeredDomain, trusted);
      if (distance > 0 && distance <= 2) {
        return true;
      }
    }
  } catch (e) { /* Ignore parsing errors */ }
  return false;
}

// --- VirusTotal Reputation Logic (Corrected) ---

async function checkUrlReputation(url, apiKey) {
  if (!apiKey) return false;

  try {
    const urlId = await sha256(url); // Correctly use SHA-256 hash
    const apiUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;

    const response = await fetch(apiUrl, {
      method: 'GET',
      headers: { 'x-apikey': apiKey }
    });

    if (response.status === 404) { // 404 means URL not found in VT, which is fine
        return false;
    }
    if (!response.ok) {
        console.error(`VirusTotal API error for ${url}: ${response.status}`);
        return false;
    }

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;

    if (stats.malicious > 0 || stats.suspicious > 0) {
      console.log(`VirusTotal flagged ${url} as malicious/suspicious.`);
      return true;
    }
  } catch (error) {
    console.error("Error checking URL with VirusTotal:", error);
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
  let reason = null;

  // First, check for URL similarity, which doesn't require an API key.
  if (checkUrlSimilarity(url)) {
    reason = "URL is suspiciously similar to a trusted site.";
  } else {
    // If no similarity match, proceed to the reputation check.
    const { vtApiKey } = await chrome.storage.local.get('vtApiKey');

    if (vtApiKey) {
      // If the key exists, perform the reputation check.
      if (await checkUrlReputation(url, vtApiKey)) {
        reason = "This site is flagged as potentially malicious by VirusTotal.";
      }
    } else {
      // If the key is missing, notify the user once per session.
      const { notified_about_key } = await chrome.storage.session.get(['notified_about_key']);
      if (!notified_about_key) {
        chrome.notifications.create('missingApiKeyNotif', {
          type: 'basic',
          iconUrl: 'icon.png',
          title: 'PhishGuard API Key Needed',
          message: 'Please set your VirusTotal API key in the extension settings for full protection.',
          priority: 1
        });
        // Set a flag to prevent spamming the user with notifications.
        await chrome.storage.session.set({ notified_about_key: true });
      }
    }
  }

  if (reason) {
    console.log(`Phishing attempt detected at ${url}. Reason: ${reason}`);
    chrome.tabs.sendMessage(tabId, {
      type: "PHISHING_DETECTED",
      url: url,
      reason: reason
    });
  }
}

// Listen for when the browser commits to a new navigation.
// This is more reliable than onUpdated for ensuring the warning appears consistently.
chrome.webNavigation.onCommitted.addListener(handleNavigation, {
  url: [{ schemes: ['http', 'https'] }]
});