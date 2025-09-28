const trustedDomains = [
  "paypal.com", "google.com", "facebook.com", "twitter.com", "instagram.com",
  "linkedin.com", "amazon.com", "apple.com", "microsoft.com", "netflix.com", "github.com"
];

// Levenshtein distance function to measure string similarity
function levenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const matrix = Array(a.length + 1).fill(null).map(() => Array(b.length + 1).fill(null));
  for (let i = 0; i <= a.length; i += 1) {
    matrix[i][0] = i;
  }
  for (let j = 0; j <= b.length; j += 1) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }
  return matrix[a.length][b.length];
}

/**
 * Extracts the registered domain from a hostname.
 * e.g., "www.google.com" -> "google.com"
 * e.g., "google.co.uk" -> "google.co.uk"
 * This is a simplified implementation for common TLDs.
 */
function getRegisteredDomain(hostname) {
  const parts = hostname.split('.');
  // Handles cases like 'localhost' or single-name domains
  if (parts.length <= 1) {
      return hostname;
  }
  // Handles common TLDs like .com, .org, .net and common ccTLDs like .co.uk, .com.au
  if (parts.length > 2 && (parts[parts.length - 2].length <= 3 && parts[parts.length - 1].length <= 3)) {
      // e.g., 'google.co.uk' -> return 'google.co.uk'
      return parts.slice(-3).join('.');
  }
  // e.g., 'www.google.com' -> return 'google.com'
  return parts.slice(-2).join('.');
}


function isPhishingUrl(url) {
  try {
    const hostname = new URL(url).hostname;
    const registeredDomain = getRegisteredDomain(hostname);

    // Rule: Never flag an exact match of a registered domain
    if (trustedDomains.includes(registeredDomain)) {
        return false;
    }

    // Rule: Never flag a legitimate subdomain of a trusted target
    for (const trusted of trustedDomains) {
        if (hostname.endsWith(`.${trusted}`)) {
            return false;
        }
    }

    for (const trusted of trustedDomains) {
      const distance = levenshtein(registeredDomain, trusted);
      // Rule: Flag if distance is 1 or 2
      if (distance > 0 && distance <= 2) {
        return true; // Found a suspicious domain
      }
    }
  } catch (e) {
    console.error("Could not parse or check URL:", url, e);
  }
  return false;
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    if (isPhishingUrl(changeInfo.url)) {
      console.log(`Phishing attempt detected: ${changeInfo.url}`);
      chrome.tabs.sendMessage(tabId, { type: "PHISHING_DETECTED", url: changeInfo.url });
    }
  }
});