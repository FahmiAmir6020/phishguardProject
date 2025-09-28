chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "PHISHING_DETECTED") {
    // Create the warning overlay
    const warningDiv = document.createElement("div");
    warningDiv.className = "phishguard-warning";
    warningDiv.innerHTML = `
      <div>
        <h1>Phishing Attempt Detected!</h1>
        <p>This website at <strong>${request.url}</strong> is suspected of being a phishing site.</p>
        <p>We strongly advise you not to enter any personal information.</p>
      </div>
    `;

    // Block the rest of the page
    document.body.innerHTML = '';
    document.body.appendChild(warningDiv);

    // Stop all other scripts from running
    window.stop();
  }
});