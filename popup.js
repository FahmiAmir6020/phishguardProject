document.addEventListener('DOMContentLoaded', () => {
  const apiKeyInput = document.getElementById('apiKey');
  const saveBtn = document.getElementById('saveBtn');
  const statusEl = document.getElementById('status');

  // Load the current key when the popup opens
  chrome.storage.local.get(['vtApiKey'], (result) => {
    if (result.vtApiKey) {
      apiKeyInput.value = result.vtApiKey;
      statusEl.textContent = 'API Key is currently set.';
      statusEl.className = 'status-message success';
    } else {
      statusEl.textContent = 'API Key is not set.';
      statusEl.className = 'status-message';
    }
  });

  // Save the new key
  saveBtn.addEventListener('click', () => {
    const apiKey = apiKeyInput.value.trim();
    if (apiKey) {
      chrome.storage.local.set({ vtApiKey: apiKey }, () => {
        // Also reset the session notification flag so the user can be notified again if they remove the key later.
        chrome.storage.session.set({ notified_about_key: false });
        statusEl.textContent = 'API Key saved successfully!';
        statusEl.className = 'status-message success';
        setTimeout(() => { statusEl.textContent = ''; }, 3000);
      });
    } else {
      chrome.storage.local.remove('vtApiKey', () => {
        statusEl.textContent = 'API Key removed.';
        statusEl.className = 'status-message';
        setTimeout(() => { statusEl.textContent = ''; }, 3000);
      });
    }
  });
});