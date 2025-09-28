document.addEventListener('DOMContentLoaded', () => {
    const headerInput = document.getElementById('headerInput');
    const inspectBtn = document.getElementById('inspectBtn');
    const resultContainer = document.getElementById('resultContainer');
    const summaryEl = document.getElementById('summary');
    const reasonsEl = document.getElementById('reasons');
    const copyJsonBtn = document.getElementById('copyJsonBtn');
    const detailsEl = document.getElementById('details');

    let fullReport = {};

    inspectBtn.addEventListener('click', () => {
        const headers = headerInput.value.trim();
        if (!headers) {
            // Optionally, provide feedback if the input is empty
            headerInput.placeholder = "Please paste headers first!";
            return;
        }

        // Send headers to the background script for inspection
        chrome.runtime.sendMessage({ type: 'INSPECT_EMAIL', headers: headers }, (response) => {
            if (chrome.runtime.lastError) {
                console.error("Error sending message:", chrome.runtime.lastError.message);
                summaryEl.textContent = "Error: Could not connect to the inspector.";
                summaryEl.className = 'summary malicious';
                resultContainer.classList.remove('hidden');
                return;
            }
            fullReport = response;
            renderResult(response);
        });
    });

    copyJsonBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(JSON.stringify(fullReport, null, 2)).then(() => {
            copyJsonBtn.textContent = 'Copied!';
            setTimeout(() => {
                copyJsonBtn.textContent = 'Copy Full Report (JSON)';
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy JSON:', err);
        });
    });

    function renderResult(result) {
        // Show the result container
        resultContainer.classList.remove('hidden');

        // Display summary
        summaryEl.textContent = result.summary;
        summaryEl.className = `summary ${result.summary.toLowerCase()}`;

        // Display reasons
        reasonsEl.innerHTML = ''; // Clear previous reasons
        if (result.reasons && result.reasons.length > 0) {
            const reasonsList = document.createElement('ul');
            result.reasons.forEach(reasonCode => {
                const li = document.createElement('li');
                li.textContent = formatReason(reasonCode);
                reasonsList.appendChild(li);
            });
            reasonsEl.appendChild(reasonsList);
        } else if (result.summary === 'CLEAN') {
             reasonsEl.innerHTML = '<p>This email appears to be legitimate based on standard authentication checks.</p>';
        }

        // Add recommended actions for dangerous emails
        if (result.summary === 'MALICIOUS' || result.summary === 'SUSPICIOUS') {
            const recommendations = document.createElement('div');
            recommendations.className = 'recommendations';
            recommendations.innerHTML = `
                <h4>Recommended Actions:</h4>
                <ul>
                    <li>Do not click any links or download attachments.</li>
                    <li>Mark this email as spam or phishing in your email client.</li>
                    <li>Delete the email.</li>
                </ul>
            `;
            reasonsEl.appendChild(recommendations);
        }
    }

    function formatReason(reasonCode) {
        const reasonMap = {
            'SPF_FAIL': 'SPF check failed. The sender\'s server is not authorized to send emails for this domain.',
            'DKIM_FAIL': 'DKIM signature is invalid. The email may have been altered after it was sent.',
            'DMARC_FAIL': 'DMARC policy check failed, indicating a likely spoofing attempt.',
            'FROM_ENVELOPE_MISMATCH': 'The "From" address does not match the technical sender (Return-Path), a common tactic in spoofing.',
            'INSUFFICIENT_DATA': 'Not enough authentication data (like SPF or DKIM) was found to make a confident decision.',
            'INVALID_HEADERS': 'The provided text does not appear to be valid email headers.'
        };

        if (reasonCode.startsWith('SIMILARITY_')) {
            const target = reasonCode.replace('SIMILARITY_', '').toLowerCase();
            return `The "From" domain looks suspiciously similar to ${target}.com, which could be a homoglyph or typosquatting attack.`;
        }

        return reasonMap[reasonCode] || reasonCode;
    }
});