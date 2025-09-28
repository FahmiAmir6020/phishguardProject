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

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    if (isPhishingUrl(changeInfo.url)) {
      console.log(`Phishing attempt detected: ${changeInfo.url}`);
      chrome.tabs.sendMessage(tabId, { type: "PHISHING_DETECTED", url: changeInfo.url });
    }
  }
});