importScripts('utils.js');

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    extensionActive: false,
    findings: {},
    scopes: [],
    scopeEnabled: false
  });
});

const state = {
  extensionActive: false,
  scopes: [],
  scopeEnabled: false
};

chrome.storage.local.get(['extensionActive', 'scopes', 'scopeEnabled'], (data) => {
  state.extensionActive = !!data.extensionActive;
  state.scopes = data.scopes || [];
  state.scopeEnabled = !!data.scopeEnabled;
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (changes.extensionActive) state.extensionActive = !!changes.extensionActive.newValue;
  if (changes.scopes) state.scopes = changes.scopes.newValue || [];
  if (changes.scopeEnabled) state.scopeEnabled = !!changes.scopeEnabled.newValue;
});

const contentTabs = new Set();

chrome.tabs.onRemoved.addListener((tabId) => contentTabs.delete(tabId));

function urlMatchesScopes(url) {
  if (!state.scopeEnabled) return true;
  if (!state.scopes || state.scopes.length === 0) return false;
  return state.scopes.some(scope => {
    const pattern = scope
      .replace(/\./g, '\\.')
      .replace(/\*/g, '.*')
      .replace(/^https?:\/\//, 'https?://');
    return new RegExp(`^${pattern}`, 'i').test(url);
  });
}

function safeSendToTab(tabId, message) {
  try {
    chrome.tabs.sendMessage(tabId, message, () => {
      if (chrome.runtime.lastError) {
      }
    });
  } catch {}
}

const requestContentType = new Map();

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const ct = details.requestHeaders?.find(h => h.name.toLowerCase() === 'content-type')?.value;
    if (ct) requestContentType.set(details.requestId, ct.toLowerCase());
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders', 'extraHeaders']
);

const paramsBlacklist = new Set([
  "meta[event]", "meta[section]", "v", "tid", "gtm", "_p", "gcd", "npa",
  "dma_cps", "dma", "tag_exp", "cid", "ul", "sr", "uaa", "uab", "uafvl", "uamb", "uam",
  "uap", "uapv", "uaw", "are", "frm", "pscdl", "_eu", "_s", "sid", "sct", "seg",
  "dl", "dr", "dt"
]);

function decodeBodyParams(details) {
  try {
    if (!details.requestBody) return [];
    if (details.requestBody.formData) {
      return Object.keys(details.requestBody.formData);
    }
    if (details.requestBody.raw && details.requestBody.raw.length) {
      const bytes = details.requestBody.raw[0].bytes;
      if (!bytes) return [];
      const bodyText = new TextDecoder('utf-8').decode(new Uint8Array(bytes));
      const ct = requestContentType.get(details.requestId) || '';
      const trimmed = bodyText.trim();

      if (ct.includes('application/json') || trimmed.startsWith('{') || trimmed.startsWith('[')) {
        try {
          const json = JSON.parse(trimmed);
          if (json && typeof json === 'object' && !Array.isArray(json)) {
            return Object.keys(json);
          }
          return [];
        } catch {
          return [];
        }
      }

      if (ct.includes('application/x-www-form-urlencoded')) {
        return [...new URLSearchParams(bodyText).keys()];
      }

      try {
        return [...new URLSearchParams(bodyText).keys()];
      } catch {
        return [];
      }
    }
    return [];
  } catch {
    return [];
  } finally {
    requestContentType.delete(details.requestId);
  }
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!state.extensionActive) return;
    if (details.tabId == null || details.tabId === -1) return;
    if (!contentTabs.has(details.tabId)) return;
    if (!/^https?:\/\//i.test(details.url)) return;

    const inScope = urlMatchesScopes(details.url) || (details.initiator && urlMatchesScopes(details.initiator));
    if (!inScope) return;

    try {
      const urlObj = new URL(details.url);
      const queryParams = [...urlObj.searchParams.keys()];
      const bodyParams = decodeBodyParams(details);

      const allParams = [...new Set([...queryParams, ...bodyParams])]
        .filter(p => p && !paramsBlacklist.has(p));

      if (allParams.length) {
        safeSendToTab(details.tabId, { action: 'addParameters', parameters: allParams });
      }

      if (isValidEndpoint(details.url)) {
        safeSendToTab(details.tabId, { action: 'addEndpoint', endpoint: details.url });
      }
    } catch {
    }
  },
  { urls: ['<all_urls>'] },
  ['requestBody']
);

function pLimit(concurrency) {
  const queue = [];
  let activeCount = 0;
  const next = () => {
    activeCount--;
    if (queue.length) queue.shift()();
  };
  const run = (fn, resolve, ...args) => {
    activeCount++;
    const result = fn(...args);
    result.then(resolve).then(next).catch(next);
  };
  return (fn, ...args) => new Promise(resolve => {
    const task = () => run(fn, resolve, ...args);
    if (activeCount < concurrency) task();
    else queue.push(task);
  });
}

const fetchLimit = pLimit(6);

async function safeFetchText(url, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      method: 'GET',
      credentials: 'omit',
      cache: 'no-store',
      signal: controller.signal
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.text();
  } finally {
    clearTimeout(timer);
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.action === 'nx:hello') {
    const tabId = sender.tab && sender.tab.id;
    if (tabId != null) contentTabs.add(tabId);
    sendResponse({ ok: true });
    return; 
  }

  if (msg && msg.action === 'autoExtractProgress') {
    sendResponse({ ok: true });
    return; 
  }

  if (msg && msg.action === 'fetchMany') {
    const urls = Array.isArray(msg.urls) ? [...new Set(msg.urls)] : [];
    const results = {};
    const tasks = urls.map(u => fetchLimit(() => safeFetchText(u)
      .then(text => { results[u] = text; })
      .catch(() => {})));
    Promise.allSettled(tasks).then(() => sendResponse({ ok: true, results }));
    return true;
  }

  if (msg && msg.action === 'activateNoNavGuard') {
    const tabId = sender.tab && sender.tab.id;
    if (!tabId) {
      sendResponse({ ok: false });
      return;
    }
    const duration = Math.min(Math.max(msg.durationMs || 4000, 500), 15000);
    chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      world: 'MAIN',
      func: (d) => {
        try {
          if (window.__NarrowX_NoNavGuardActive) return;
          window.__NarrowX_NoNavGuardActive = true;
          const origOpen = window.open;
          window.open = function() {
            try { console.debug('[NarrowX] blocked window.open'); } catch {}
            return null;
          };
          const clickBlocker = function(e) {
            if (e && e.isTrusted === false) {
              try { e.preventDefault(); } catch {}
            }
          };
          document.addEventListener('click', clickBlocker, true);

          setTimeout(() => {
            try {
              document.removeEventListener('click', clickBlocker, true);
              window.open = origOpen;
              delete window.__NarrowX_NoNavGuardActive;
            } catch {}
          }, d);
        } catch {}
      },
      args: [duration]
    }, () => {
      if (chrome.runtime.lastError) {
        sendResponse({ ok: false, error: chrome.runtime.lastError.message });
      } else {
        sendResponse({ ok: true });
      }
    });
    return true;
  }

  return false;
});