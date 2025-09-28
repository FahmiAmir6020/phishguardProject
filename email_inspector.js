const protectedTargets = [
    "paypal.com", "google.com", "facebook.com", "twitter.com", "instagram.com",
    "linkedin.com", "amazon.com", "apple.com", "microsoft.com", "netflix.com", "github.com",
    // Common banks
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com", "usbank.com"
];

// --- Utility Functions ---

/**
 * Parses a raw email header string into an object.
 * Handles multi-line headers and stores multiple headers with the same name in an array.
 * @param {string} rawHeaders - The raw email header text.
 * @returns {object} A dictionary of header keys and values.
 */
function parseHeaders(rawHeaders) {
    const headers = {};
    const lines = rawHeaders.replace(/\r\n/g, '\n').split('\n');
    let currentKey = '';

    for (const line of lines) {
        if (line.startsWith(' ') || line.startsWith('\t')) {
            // This is a continuation of the previous header
            if (currentKey && headers[currentKey]) {
                const lastValue = Array.isArray(headers[currentKey]) ? headers[currentKey][headers[currentKey].length - 1] : headers[currentKey];
                if (typeof lastValue === 'string') {
                    if (Array.isArray(headers[currentKey])) {
                        headers[currentKey][headers[currentKey].length - 1] += ' ' + line.trim();
                    } else {
                        headers[currentKey] += ' ' + line.trim();
                    }
                }
            }
        } else {
            const separatorIndex = line.indexOf(':');
            if (separatorIndex > 0) {
                const key = line.substring(0, separatorIndex).trim().toLowerCase();
                const value = line.substring(separatorIndex + 1).trim();
                currentKey = key;
                if (headers[key]) {
                    if (!Array.isArray(headers[key])) {
                        headers[key] = [headers[key]];
                    }
                    headers[key].push(value);
                } else {
                    headers[key] = value;
                }
            }
        }
    }
    return headers;
}

/**
 * Extracts the domain from an email address (e.g., "user@example.com" -> "example.com").
 * @param {string} email - The email address.
 * @returns {string|null} The domain or null if invalid.
 */
function getDomainFromEmail(email) {
    if (!email || !email.includes('@')) return null;
    return email.split('@').pop().replace('>', '').trim();
}

/**
 * Levenshtein distance function for string similarity.
 */
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

// --- Analysis Functions ---

/**
 * Analyzes Authentication-Results headers for SPF, DKIM, and DMARC.
 * @param {object} headers - The parsed headers object.
 * @param {object} result - The inspection result object to be populated.
 */
function analyzeAuthResults(headers, result) {
    const authResults = headers['authentication-results'];
    if (!authResults) return;

    const resultsArray = Array.isArray(authResults) ? authResults : [authResults];
    for (const res of resultsArray) {
        // SPF Check
        const spfMatch = res.match(/spf=(\w+)/);
        if (spfMatch) {
            result.details.spf = { result: spfMatch[1], source: "Authentication-Results" };
            if (['fail', 'softfail'].includes(spfMatch[1])) {
                result.reasons.push('SPF_FAIL');
            }
        }

        // DKIM Check
        const dkimMatch = res.match(/dkim=(\w+)/);
        if (dkimMatch) {
            result.details.dkim = { result: dkimMatch[1], source: "Authentication-Results" };
            if (dkimMatch[1] === 'fail') {
                result.reasons.push('DKIM_FAIL');
            }
        }

        // DMARC Check
        const dmarcMatch = res.match(/dmarc=(\w+)/);
        if (dmarcMatch) {
            result.details.dmarc = { result: dmarcMatch[1], source: "Authentication-Results" };
            if (dmarcMatch[1] === 'fail') {
                result.reasons.push('DMARC_FAIL');
            }
        }
    }
}


/**
 * Checks for a mismatch between the From and Return-Path headers.
 * @param {object} headers - The parsed headers object.
 * @param {object} result - The inspection result object to be populated.
 */
function checkFromAndReturnPath(headers, result) {
    const fromDomain = getDomainFromEmail(headers['from']);
    const returnPathDomain = getDomainFromEmail(headers['return-path']);

    result.details.from_domain = fromDomain;
    result.details.return_path_domain = returnPathDomain;

    if (fromDomain && returnPathDomain && fromDomain !== returnPathDomain) {
        // Mismatch is only suspicious if SPF didn't pass for the 'From' domain.
        if (!result.reasons.includes('SPF_PASS')) { // Assuming SPF_PASS would be added if it passed.
            result.reasons.push('FROM_ENVELOPE_MISMATCH');
        }
    }
}

/**
 * Checks the "From" domain for suspicious similarity to protected targets.
 * @param {object} headers - The parsed headers object.
 * @param {object} result - The inspection result object to be populated.
 */
function checkDomainSimilarity(headers, result) {
    const fromDomain = getDomainFromEmail(headers['from']);
    if (!fromDomain) return;

    for (const target of protectedTargets) {
        const distance = levenshtein(fromDomain, target);
        if (distance > 0 && distance <= 2) {
            result.reasons.push(`SIMILARITY_${target.toUpperCase().split('.')[0]}`);
            result.details.similarity = {
                found: fromDomain,
                target: target,
                distance: distance
            };
            return; // Found a match, no need to check others.
        }
    }
}


/**
 * The main inspection function.
 * @param {string} rawHeaders - The raw email header text.
 * @returns {object} The structured JSON result.
 */
export function inspect(rawHeaders) {
    console.debug("Starting email header inspection.");
    const headers = parseHeaders(rawHeaders);
    const result = {
        summary: 'CLEAN',
        reasons: [],
        details: {}
    };

    if (Object.keys(headers).length === 0) {
        result.summary = 'UNKNOWN';
        result.reasons.push('INVALID_HEADERS');
        return result;
    }

    // Run all checks
    analyzeAuthResults(headers, result);
    checkFromAndReturnPath(headers, result);
    checkDomainSimilarity(headers, result);

    // Final summary determination
    const maliciousReasons = ['SPF_FAIL', 'DKIM_FAIL', 'DMARC_FAIL'];
    const suspiciousReasons = ['FROM_ENVELOPE_MISMATCH', 'SIMILARITY_']; // Use startsWith for similarity

    if (result.reasons.some(r => maliciousReasons.includes(r))) {
        result.summary = 'MALICIOUS';
    } else if (result.reasons.some(r => suspiciousReasons.some(s => r.startsWith(s)))) {
        result.summary = 'SUSPICIOUS';
    } else if (result.reasons.length > 0) {
        // If there are reasons but none are explicitly malicious/suspicious, mark as suspicious.
        // This can happen for softfail, etc.
        result.summary = 'SUSPICIOUS';
    }

    // If all checks passed but no explicit pass signals were found, it could be UNKNOWN
    if (result.summary === 'CLEAN' && !result.details.spf && !result.details.dkim) {
        result.summary = 'UNKNOWN';
        result.reasons.push('INSUFFICIENT_DATA');
    }

    // A strong pass signal can override suspicion
    if (result.details.spf?.result === 'pass' && result.details.dkim?.result === 'pass') {
        if(result.summary === 'SUSPICIOUS') {
            result.summary = 'CLEAN'; // Upgrade to clean if strong signals exist
        }
    }


    console.debug("Inspection complete. Result:", JSON.stringify(result, null, 2));
    return result;
}