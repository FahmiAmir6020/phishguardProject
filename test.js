// --- Crypto and Mocking Setup ---
const { subtle } = require('crypto').webcrypto;

async function sha256(str) {
  const buf = await subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.prototype.map.call(new Uint8Array(buf), x => (('00' + x.toString(16)).slice(-2))).join('');
}

// Mock chrome.storage.local for testing purposes
const mockChromeStorage = {
  local: {
    get: (keys, callback) => {
      // Simulate providing the API key
      callback({ vtApiKey: "fake-api-key-for-testing" });
    }
  }
};
global.chrome = mockChromeStorage;


// --- Logic copied and adapted from background.js for testing ---

const trustedDomains = [
  "paypal.com", "google.com", "facebook.com", "twitter.com", "instagram.com",
  "linkedin.com", "amazon.com", "apple.com", "microsoft.com", "netflix.com", "github.com"
];

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
      if (levenshtein(registeredDomain, trusted) <= 2) return true;
    }
  } catch (e) {}
  return false;
}

// --- Mock VirusTotal Reputation Logic (Corrected) ---
const mockMaliciousUrls = [
  "http://malicious-site.com/login",
  "http://another-bad-domain.org"
];
const mockMaliciousHashes = {};

async function setupMockHashes() {
    for (const url of mockMaliciousUrls) {
        const hash = await sha256(url);
        mockMaliciousHashes[hash] = true;
    }
}

async function mockCheckUrlReputation(url, apiKey) {
  if (!apiKey) return false;
  try {
    const urlId = await sha256(url);
    if (mockMaliciousHashes[urlId]) {
      return true;
    }
  } catch(e) {}
  return false;
}

// --- Test Execution ---
async function runTests() {
  // Dynamically generate hashes before running tests
  await setupMockHashes();

  const testCases = {
    "http://paypa1.com": "URL is suspiciously similar to a trusted site.",
    "http://google.com": null,
    "http://www.accounts.google.com": null,
    "http://malicious-site.com/login": "This site is flagged as potentially malicious by VirusTotal.",
    "http://another-bad-domain.org": "This site is flagged as potentially malicious by VirusTotal.",
    "http://googgle.com/search": "URL is suspiciously similar to a trusted site.",
    "http://good-site.com": null,
  };

  console.log("Running corrected and secured detection tests...");
  console.log("----------------------------------------------------------------------------------");

  const { vtApiKey } = await new Promise(resolve => chrome.local.get('vtApiKey', resolve));

  for (const [url, expectedReason] of Object.entries(testCases)) {
    let actualReason = null;

    if (checkUrlSimilarity(url)) {
      actualReason = "URL is suspiciously similar to a trusted site.";
    } else if (await mockCheckUrlReputation(url, vtApiKey)) {
      actualReason = "This site is flagged as potentially malicious by VirusTotal.";
    }

    const status = (actualReason === expectedReason) ? "PASS" : "FAIL";
    console.log(`[${status}] URL: ${url}`);
    console.log(`  - Expected: ${expectedReason}`);
    console.log(`  - Got:      ${actualReason}`);
    console.log("----------------------------------------------------------------------------------");
  }
}

runTests();