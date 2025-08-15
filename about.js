(() => {
  try {
    const manifest = chrome.runtime.getManifest();
    const vEl = document.getElementById('version');
    if (vEl) vEl.textContent = manifest.version || '-';
  } catch {}
  try {
    const yEl = document.getElementById('year');
    if (yEl) yEl.textContent = new Date().getFullYear();
  } catch {}
})();