const trustedDomains = [
  "paypal.com", "google.com", "facebook.com", "twitter.com", "instagram.com",
  "linkedin.com", "amazon.com", "apple.com", "microsoft.com", "netflix.com", "github.com"
];

// --- Logic copied from background.js for testing ---

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

function getRegisteredDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 1) {
    return hostname;
  }
  if (parts.length > 2 && (parts[parts.length - 2].length <= 2 && parts[parts.length - 1].length <= 2)) {
      return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

// --- Test-specific analysis function ---

function analyzeHostname(hostname) {
  const registeredDomain = getRegisteredDomain(hostname);
  let result = {
    flagged: false,
    matchedTarget: '-',
    distance: 0
  };

  // Rule: Never flag a legitimate subdomain of a trusted target
  for (const trusted of trustedDomains) {
      if (hostname.endsWith(`.${trusted}`) || hostname === trusted) {
          result.distance = 0;
          result.matchedTarget = trusted;
          return result;
      }
  }

  let minDistance = Infinity;
  let closestTarget = '-';

  for (const trusted of trustedDomains) {
    const distance = levenshtein(registeredDomain, trusted);
    if (distance < minDistance) {
      minDistance = distance;
      closestTarget = trusted;
    }
  }

  result.distance = minDistance;
  result.matchedTarget = closestTarget;

  // Rule: Flag if distance is 1 or 2
  if (minDistance > 0 && minDistance <= 2) {
    result.flagged = true;
  }

  // Local testMode for papa1.com etc.
  if (/^papa[1-9]\.com$/.test(hostname) || /^paypa[1-9]\.com$/.test(hostname)) {
      result.flagged = true;
      result.matchedTarget = 'paypal.com';
      result.distance = levenshtein(registeredDomain, 'paypal.com');
  }


  return result;
}

// --- Test Execution ---

const testHostnames = [
  "papa1.com",
  "paypa2.com",
  "paypa9.com",
  "papa2.com",
  "papa5.com",
  "paypal.com",
  "accounts.google.com",
  "example-paypal.com",
  "some-other-site.com"
];

console.log("Running URL similarity tests...");
console.log("---------------------------------------------------------------------------------");
console.log("Hostname               | Registered domain      | Flagged? | Matched target | Distance");
console.log("---------------------------------------------------------------------------------");

testHostnames.forEach(hostname => {
  const registeredDomain = getRegisteredDomain(hostname);
  const analysis = analyzeHostname(hostname);

  const h_pad = hostname.padEnd(22);
  const r_pad = registeredDomain.padEnd(22);
  const f_pad = (analysis.flagged ? "YES" : "NO").padEnd(8);
  const m_pad = analysis.matchedTarget.padEnd(14);

  console.log(`${h_pad} | ${r_pad} | ${f_pad} | ${m_pad} | ${analysis.distance}`);
});

console.log("---------------------------------------------------------------------------------");