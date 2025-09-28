// A list of common ad and tracker domains to block.
// This list can be easily expanded in the future.
const BLOCKED_DOMAINS = [
    "doubleclick.net",
    "googlesyndication.com",
    "adservice.google.com",
    "analytics.google.com",
    "googletagservices.com",
    "scorecardresearch.com",
    "adnxs.com",
    "crwdcntrl.net",
    "criteo.com",
    "pubmatic.com",
    "rubiconproject.com",
    "facebook.net", // Covers FB ads and trackers
    "connect.facebook.net"
];

const RULE_ID_START = 1000; // A starting ID for our dynamic rules to avoid conflicts.

/**
 * Sets up the ad and tracker blocking rules using the declarativeNetRequest API.
 * It first clears any existing rules from this extension and then adds the new ones.
 */
export async function setupAdblocker() {
    console.log("PhishGuard: Setting up adblocker rules...");

    // Get existing rules to remove them before adding new ones.
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const existingRuleIds = existingRules.map(rule => rule.id);

    const newRules = BLOCKED_DOMAINS.map((domain, index) => ({
        id: RULE_ID_START + index,
        priority: 1,
        action: { type: "block" },
        condition: {
            "urlFilter": `||${domain}/`, // Standard adblock filter syntax
            "resourceTypes": [
                "main_frame",
                "sub_frame",
                "script",
                "image",
                "xmlhttprequest",
                "ping",
                "media",
                "websocket"
            ]
        }
    }));

    try {
        await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: existingRuleIds,
            addRules: newRules
        });
        console.log("PhishGuard: Adblocker rules have been successfully updated.");
    } catch (error) {
        console.error("PhishGuard: Error updating adblocker rules:", error);
    }
}