const trustedDomains = [
  "paypal.com",
  "google.com",
  "facebook.com",
  "twitter.com",
  "instagram.com",
  "linkedin.com",
  "amazon.com",
  "apple.com",
  "microsoft.com",
  "netflix.com",
  "github.com"
];

// Levenshtein distance function to measure string similarity
function levenshtein(a, b) {
    if(a.length == 0) return b.length;
    if(b.length == 0) return a.length;

    var matrix = [];

    var i;
    for(i = 0; i <= b.length; i++){
        matrix[i] = [i];
    }

    var j;
    for(j = 0; j <= a.length; j++){
        matrix[0][j] = j;
    }

    for(i = 1; i <= b.length; i++){
        for(j = 1; j <= a.length; j++){
            if(b.charAt(i-1) == a.charAt(j-1)){
                matrix[i][j] = matrix[i-1][j-1];
            } else {
                matrix[i][j] = Math.min(matrix[i-1][j-1] + 1,
                                        Math.min(matrix[i][j-1] + 1,
                                                 matrix[i-1][j] + 1));
            }
        }
    }

    return matrix[b.length][a.length];
}


function isPhishingUrl(url) {
  try {
    const urlHostname = new URL(url).hostname.replace(/^www\./, '');

    for (const trustedDomain of trustedDomains) {
      const distance = levenshtein(urlHostname, trustedDomain);
      if (distance > 0 && distance <= 2) {
        if (Math.abs(urlHostname.length - trustedDomain.length) <= 1) {
            return true;
        }
      }
    }
  } catch (e) {
    console.error("Could not parse URL:", url, e);
  }
  return false;
}

// --- Test Cases ---
const testUrls = {
    // Should be detected as phishing
    "http://paypa1.com": true,
    "http://www.googgle.com": true,
    "http://faceboook.com": true,
    "https://microsfot.com": true,
    "https://amazoon.com": true,
    "http://gihub.com": true,


    // Should NOT be detected as phishing
    "http://paypal.com": false,
    "https://www.google.com": false,
    "http://example.com": false,
    "https://www.github.com/features": false,
    "https://developer.chrome.com/docs/extensions/mv3/getstarted/": false
};

console.log("Running URL analysis tests...");
let failures = 0;
for (const [url, expected] of Object.entries(testUrls)) {
    const result = isPhishingUrl(url);
    if (result !== expected) {
        console.error(`FAIL: For URL "${url}", expected ${expected}, but got ${result}.`);
        failures++;
    } else {
        console.log(`PASS: For URL "${url}", got correct result: ${result}.`);
    }
}

console.log("--------------------");
if (failures === 0) {
    console.log("All tests passed!");
} else {
    console.log(`${failures} test(s) failed.`);
}