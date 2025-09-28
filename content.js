chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "PHISHING_DETECTED") {
    // Prevent duplicate warnings
    if (document.querySelector('.phishguard-overlay')) {
      return;
    }

    // Create the overlay container
    const overlay = document.createElement("div");
    overlay.className = "phishguard-overlay";

    // Create the warning box
    const warningBox = document.createElement("div");
    warningBox.className = "phishguard-warning-box";
    warningBox.innerHTML = `
      <h1>Suspicious Website</h1>
      <p>This website at <strong>${request.url}</strong> looks like a potential phishing attempt. We advise you to go back.</p>
      <div class="phishguard-button-container">
        <button class="phishguard-button phishguard-button--back" id="phishguard-back-btn">Go Back</button>
        <button class="phishguard-button phishguard-button--proceed" id="phishguard-proceed-btn">Proceed Anyway</button>
      </div>
    `;

    // Append the warning box to the overlay
    overlay.appendChild(warningBox);
    // Append the overlay to the body
    document.body.appendChild(overlay);

    // Add event listeners for the buttons
    document.getElementById("phishguard-back-btn").addEventListener("click", () => {
      window.history.back();
    });

    document.getElementById("phishguard-proceed-btn").addEventListener("click", () => {
      overlay.remove();
    });

    sendResponse({ status: "Warning displayed" });
  }
});