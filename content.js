let findings = {
  endpoints: new Set(),
  apiKeys: new Set(),
  databaseUrls: new Set(),
  internalIps: new Set(),
  tokens: new Set(),
  passwords: new Set(),
  parameters: new Set(),
};
let isExtensionActive = false;

try {
  chrome.runtime.sendMessage({ action: 'nx:hello' }, () => {
    if (chrome.runtime.lastError) {  }
  });
} catch {}

function loadFindingsFromStorage(callback) {
  chrome.storage.local.get("findings", (data) => {
    if (data.findings) {
      findings = {
        endpoints: new Set(data.findings.endpoints || []),
        apiKeys: new Set(data.findings.apiKeys || []),
        databaseUrls: new Set(data.findings.databaseUrls || []),
        internalIps: new Set(data.findings.internalIps || []),
        tokens: new Set(data.findings.tokens || []),
        passwords: new Set(data.findings.passwords || []),
        parameters: new Set(data.findings.parameters || []),
      };
    }
    callback();
  });
}

let saveTimeout;
function saveFindings() {
  clearTimeout(saveTimeout);
  saveTimeout = setTimeout(() => {
    chrome.storage.local.set({
      findings: {
        endpoints: Array.from(findings.endpoints),
        apiKeys: Array.from(findings.apiKeys),
        databaseUrls: Array.from(findings.databaseUrls),
        internalIps: Array.from(findings.internalIps),
        tokens: Array.from(findings.tokens),
        passwords: Array.from(findings.passwords),
        parameters: Array.from(findings.parameters),
      },
    });
  }, 500);
}

function matchesScope(url, scopes, scopeEnabled) {
  if (!scopeEnabled) return true;
  if (!scopes || scopes.length === 0) return false;
  return scopes.some(scope => {
    const pattern = scope
      .replace(/\./g, '\\.')
      .replace(/\*/g, '.*')
      .replace(/^https?:\/\//, 'https?://');
    return new RegExp(`^${pattern}`, 'i').test(url);
  });
}

function extractFindingsFromText(text) {
  const relRegex = /(?:['"`])?(\/[a-zA-Z0-9_/?&=.\-#%{}]+)(?:['"`])?/g;
  let m;
  while ((m = relRegex.exec(text)) !== null) {
    const ep = m[1];
    if (ep && isValidEndpoint(ep) && ep.length > 1) {
      findings.endpoints.add(ep);
    }
  }

  const absRegex = /\bhttps?:\/\/[a-zA-Z0-9.-]+(?::\d+)?\/[a-zA-Z0-9_/?&=.\-#%{}]+/g;
  let a;
  while ((a = absRegex.exec(text)) !== null) {
    const url = a[0];
    if (isValidEndpoint(url)) {
      findings.endpoints.add(url);
    }
  }

  const apiKeyRegex = /(api[-_]?key|secret[-_]?key|access[-_]?key)['"]?\s*[:=]\s*['"]([0-9a-zA-Z_\-]{20,64}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{39})['"]/gi;
  let apiMatch;
  while ((apiMatch = apiKeyRegex.exec(text)) !== null) {
    findings.apiKeys.add(apiMatch[0]);
  }

  const dbUrlRegex = /(redis|sqlite|mysql|postgres|postgresql|sqlserver|oracle|mongodb):\/\/[a-zA-Z0-9_\-:.]+(?::[a-zA-Z0-9_\-:.]+)?(@|%40)[a-zA-Z0-9_\-:.]+(?::\d+)?\/[a-zA-Z0-9_\-]+/gi;
  let dbMatch;
  while ((dbMatch = dbUrlRegex.exec(text)) !== null) {
    findings.databaseUrls.add(dbMatch[0]);
  }

  const ipRegex = /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|fe80::[a-f0-9:]+|fd[0-9a-f]{2}:[a-f0-9:]+)\b/gi;
  let ipMatch;
  while ((ipMatch = ipRegex.exec(text)) !== null) {
    findings.internalIps.add(ipMatch[0]);
  }

  const tokenRegex = /(auth|authorization|token|api[-_]?token|access[-_]?token|bearer|jwt)['"]?\s*[:=]\s*['"](eyJ|[a-zA-Z0-9_\-\.=]{32,256})['"]/gi;
  let tokenMatch;
  while ((tokenMatch = tokenRegex.exec(text)) !== null) {
    findings.tokens.add(tokenMatch[0]);
  }

  const passwordRegex = /(pwd|password|passwd|hash|secret)['"]?\s*[:=]\s*['"]([^\s'"<>]{6,64})['"]/gi;
  let pwMatch;
  while ((pwMatch = passwordRegex.exec(text)) !== null) {
    if (!/^<\w+/.test(pwMatch[2])) {
      findings.passwords.add(pwMatch[0]);
    }
  }
}

function fetchManyInBackground(urls) {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendMessage({ action: 'fetchMany', urls }, (res) => {
        if (!res || !res.ok || chrome.runtime.lastError) return resolve({});
        resolve(res.results || {});
      });
    } catch {
      resolve({});
    }
  });
}

function reportProgress(percent, status) {
  try {
    chrome.runtime.sendMessage({ action: 'autoExtractProgress', percent, status }, () => {
      if (chrome.runtime.lastError) {  }
    });
  } catch {}
}

async function enableNavGuard() {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendMessage({ action: 'enableNavGuard' }, () => resolve());
    } catch { resolve(); }
  });
}

async function disableNavGuard() {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendMessage({ action: 'disableNavGuard' }, () => resolve());
    } catch { resolve(); }
  });
}

function startExtraction() {
  chrome.storage.local.get(["scopes", "scopeEnabled"], async (data) => {
    const scopes = data.scopes || [];
    const scopeEnabled = data.scopeEnabled || false;

    const scripts = Array.from(document.getElementsByTagName("script"));
    const pageUrl = window.location.href;

    for (let script of scripts) {
      if (!script.src && script.innerHTML && matchesScope(pageUrl, scopes, scopeEnabled)) {
        try {
          extractFindingsFromText(script.innerHTML);
        } catch (e) { logError("Inline script parsing failed", e); }
      }
    }

    const scriptUrls = scripts
      .map(s => s.src)
      .filter(Boolean)
      .filter(src => /\.(m?js)(?:$|\?)/i.test(src || ""))
      .filter(src => matchesScope(src, scopes, scopeEnabled))
      .map(src => {
        try { return new URL(src, location.href).toString(); } catch { return null; }
      })
      .filter(Boolean);

    if (scriptUrls.length) {
      try {
        const results = await fetchManyInBackground(scriptUrls);
        Object.values(results).forEach(text => {
          try { extractFindingsFromText(text); } catch {}
        });
      } catch (e) { logError("External script fetch failed", e); }
    }

    saveFindings();
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
async function waitForNetworkIdle(timeout = 6000, idleTime = 800) {
  const start = Date.now();
  let lastCount = performance.getEntriesByType('resource').length;
  let lastChange = Date.now();
  while (Date.now() - start < timeout) {
    await sleep(200);
    const count = performance.getEntriesByType('resource').length;
    if (count !== lastCount) {
      lastCount = count;
      lastChange = Date.now();
    } else if (Date.now() - lastChange >= idleTime) {
      break;
    }
  }
}

async function autoExtractEndpoints() {
  const endpoints = new Set();
  const baseUrl = window.location.origin;

  const { scopes = [], scopeEnabled = false } = await new Promise(res =>
    chrome.storage.local.get(['scopes', 'scopeEnabled'], res)
  );
  const inScope = (u) => matchesScope(u, scopes, scopeEnabled);

  try {
    reportProgress(2, "Initializing");

    await enableNavGuard();

    await new Promise(resolve => {
      let y = 0;
      const dist = 200;
      const maxScroll = Math.max(
        document.body.scrollHeight,
        document.documentElement.scrollHeight
      );
      const timer = setInterval(() => {
        window.scrollBy(0, dist);
        y += dist;
        if (y >= maxScroll) {
          clearInterval(timer);
          resolve();
        }
      }, 80);
    });
    reportProgress(12, "Scrolling page");

    reportProgress(17, "Preparing safe clicks");

    const clickable = Array.from(document.querySelectorAll('button, [role="button"], a, [onclick], [data-action]')).slice(0, 60);
    const capturePrevent = (e) => { if (!e.isTrusted) e.preventDefault(); };
    document.addEventListener('click', capturePrevent, true);

    for (const el of clickable) {
      try {
        if (el.tagName === 'A') {
          const href = el.getAttribute('href') || '';
          if (/^(mailto:|javascript:|tel:)/i.test(href)) continue;
        }
        let saved = null;
        if (el.tagName === 'A') {
          saved = { href: el.getAttribute('href'), target: el.getAttribute('target') };
          el.setAttribute('href', '#');
          el.setAttribute('target', '_self');
        }
        ['mouseover', 'mousedown', 'mouseup', 'click'].forEach(type => {
          const ev = new MouseEvent(type, { bubbles: true, cancelable: true, view: window });
          el.dispatchEvent(ev);
        });
        if (el.tagName === 'A' && saved) {
          if (saved.href === null) el.removeAttribute('href'); else el.setAttribute('href', saved.href);
          if (saved.target === null) el.removeAttribute('target'); else el.setAttribute('target', saved.target);
        }
      } catch {}
      await sleep(50);
    }
    document.removeEventListener('click', capturePrevent, true);
    reportProgress(32, "Clicks done");

    await waitForNetworkIdle(7000, 1000);
    reportProgress(42, "Network idle");

    performance.getEntriesByType('resource').forEach(entry => {
      let url = entry.name;
      let relative = '';
      if (url.startsWith(baseUrl)) relative = url.replace(baseUrl, '');
      else if (url.startsWith('/')) relative = url;
      const candidate = relative || url;
      if (inScope(url) && isValidEndpoint(candidate)) endpoints.add(candidate);
    });
    reportProgress(52, "Analyzing network entries");

    (window.__autoExtractedRequests || []).forEach(url => {
      const abs = url.startsWith('http') ? url : baseUrl + url;
      if (inScope(abs) && isValidEndpoint(url)) endpoints.add(url);
    });
    reportProgress(57, "Collecting XHR/Fetch");

    document.querySelectorAll('script:not([src])').forEach(script => {
      if (script.innerText) {
        const regex = /(?:['"`])?(\/[a-zA-Z0-9_/?&=.\-#%{}]+)(?:['"`])?/g;
        let m;
        while ((m = regex.exec(script.innerText)) !== null) {
          const ep = m[1];
          const abs = ep.startsWith('http') ? ep : baseUrl + ep;
          if (inScope(abs) && isValidEndpoint(ep)) endpoints.add(ep);
        }
      }
    });
    reportProgress(65, "Parsing inline scripts");

    const scriptSrcs = new Set();
    document.querySelectorAll('script[src]').forEach(s => {
      const src = s.src || '';
      if ((src.startsWith('/') || src.startsWith('http')) && /\.(m?js)(?:$|\?)/i.test(src)) {
        scriptSrcs.add(src.startsWith('http') ? src : baseUrl + src);
      }
    });
    performance.getEntriesByType('resource').forEach(entry => {
      if (/\.(m?js)(?:$|\?)/i.test(entry.name)) {
        scriptSrcs.add(entry.name);
      }
    });

    const jsUrls = [...scriptSrcs].filter(u => inScope(u));
    reportProgress(70, `Collecting external scripts (${jsUrls.length})`);

    if (jsUrls.length) {
      const results = await fetchManyInBackground(jsUrls);
      Object.entries(results).forEach(([u, jsText]) => {
        const regex = /(?:['"`])?(\/[a-zA-Z0-9_/?&=.\-#%{}]+)(?:['"`])?/g;
        let match;
        while ((match = regex.exec(jsText)) !== null) {
          const ep = match[1];
          const abs = ep.startsWith('http') ? ep : baseUrl + ep;
          if (inScope(abs) && isValidEndpoint(ep)) endpoints.add(ep);
        }
        const absRegex = /\bhttps?:\/\/[a-zA-Z0-9.-]+(?::\d+)?\/[a-zA-Z0-9_/?&=.\-#%{}]+/g;
        let a;
        while ((a = absRegex.exec(jsText)) !== null) {
          const url = a[0];
          if (inScope(url) && isValidEndpoint(url)) endpoints.add(url);
        }
      });
    }
    reportProgress(90, "Parsing external JavaScript");

    document.querySelectorAll('[href], [src], [action]').forEach(el => {
      ['href', 'src', 'action'].forEach(attr => {
        const val = el.getAttribute(attr);
        if (!val) return;
        const abs = val.startsWith('http') ? val : baseUrl + (val.startsWith('/') ? val : '/' + val);
        if (inScope(abs) && val.startsWith('/') && isValidEndpoint(val)) {
          endpoints.add(val);
        }
      });
    });
    reportProgress(95, "Scanning attributes");

    try {
      const pageContent = document.documentElement.outerHTML;
      const regex1 = /(?<=(["'`]))\/[a-zA-Z0-9_/?&=.\-#%{}]*(?=(["'`]))/g;
      let m1;
      while ((m1 = regex1.exec(pageContent)) !== null) {
        const ep = m1[0];
        const abs = baseUrl + ep;
        if (inScope(abs) && isValidEndpoint(ep)) endpoints.add(ep);
      }
      const absRegex2 = /\bhttps?:\/\/[a-zA-Z0-9.-]+(?::\d+)?\/[a-zA-Z0-9_/?&=.\-#%{}]+/g;
      let m2;
      while ((m2 = absRegex2.exec(pageContent)) !== null) {
        const url = m2[0];
        if (inScope(url) && isValidEndpoint(url)) endpoints.add(url);
      }
    } catch {}
    reportProgress(97, "Parsing page HTML");

    await runBookmarkletLogicAndAddEndpoints(endpoints, inScope);
    reportProgress(99, "Finalizing");

    return new Promise(resolve => {
      chrome.storage.local.get("findings", (data) => {
        const findingsData = data.findings || {};
        const existing = new Set(findingsData.endpoints || []);
        endpoints.forEach(ep => existing.add(ep));
        findingsData.endpoints = Array.from(existing);
        chrome.storage.local.set({ findings: findingsData }, () => {
          reportProgress(100, "Done");
          resolve(endpoints.size);
        });
      });
    });
  } catch (e) {
    logError("Auto extraction failed", e);
    reportProgress(100, "Done (with errors)");
    return 0;
  } finally {
    try { await disableNavGuard(); } catch {}
  }
}

async function runBookmarkletLogicAndAddEndpoints(endpointsSet, inScopeFn) {
  const baseUrl = window.location.origin;
  const regex = /(?<=(["'`]))\/[a-zA-Z0-9_/?&=.\-#%{}]*(?=(["'`]))/g;
  const results = new Set();

  const scripts = Array.from(document.getElementsByTagName("script"))
    .map(s => s.src)
    .filter(Boolean);
  if (scripts.length) {
    const resultsMap = await fetchManyInBackground(scripts);
    Object.values(resultsMap).forEach(text => {
      const matches = text.matchAll(regex);
      for (const match of matches) {
        if (match[0]) results.add(match[0]);
      }
      const absRegex = /\bhttps?:\/\/[a-zA-Z0-9.-]+(?::\d+)?\/[a-zA-Z0-9_/?&=.\-#%{}]+/g;
      const absMatches = text.matchAll(absRegex);
      for (const m of absMatches) {
        if (m[0]) results.add(m[0]);
      }
    });
  }

  const pageContent = document.documentElement.outerHTML;
  const matches = pageContent.matchAll(regex);
  for (const match of matches) {
    if (match[0]) results.add(match[0]);
  }
  const absRegex2 = /\bhttps?:\/\/[a-zA-Z0-9.-]+(?::\d+)?\/[a-zA-Z0-9_/?&=.\-#%{}]+/g;
  const absMatches2 = pageContent.matchAll(absRegex2);
  for (const m of absMatches2) {
    if (m[0]) results.add(m[0]);
  }

  results.forEach(ep => {
    const abs = ep.startsWith('http') ? ep : baseUrl + ep;
    if (inScopeFn(abs) && isValidEndpoint(ep)) {
      endpointsSet.add(ep);
    }
  });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "toggleExtension") {
    isExtensionActive = request.isActive;
    chrome.storage.local.set({ extensionActive: request.isActive });
    if (isExtensionActive) {
      loadFindingsFromStorage(() => startExtraction());
    }
    sendResponse({ success: true });
  } else if (request.action === "getFindings") {
    sendResponse({
      findings: {
        endpoints: Array.from(findings.endpoints),
        apiKeys: Array.from(findings.apiKeys),
        databaseUrls: Array.from(findings.databaseUrls),
        internalIps: Array.from(findings.internalIps),
        tokens: Array.from(findings.tokens),
        passwords: Array.from(findings.passwords),
        parameters: Array.from(findings.parameters),
      },
    });
  } else if (request.action === "resetFindings") {
    findings = {
      endpoints: new Set(),
      apiKeys: new Set(),
      databaseUrls: new Set(),
      internalIps: new Set(),
      tokens: new Set(),
      passwords: new Set(),
      parameters: new Set(),
    };
    chrome.storage.local.remove("findings", () => {
      chrome.storage.local.set({ findings: {} }, () => {
        sendResponse({ success: true });
      });
    });
    return true;
  } else if (request.action === "addEndpoint") {
    if (isValidEndpoint(request.endpoint)) {
      findings.endpoints.add(request.endpoint);
      saveFindings();
    }
    sendResponse({ success: true });
  } else if (request.action === "addParameters") {
    if (request.parameters && request.parameters.length > 0) {
      request.parameters.forEach(param => findings.parameters.add(param));
      saveFindings();
    }
    sendResponse({ success: true });
  } else if (request.action === "autoExtractEndpoints") {
    autoExtractEndpoints().then(count => {
      sendResponse({ success: true, count });
    }).catch((e) => {
      logError("Auto extraction failed", e);
      sendResponse({ success: false });
    });
    return true; 
  }
});

chrome.storage.local.get("extensionActive", (data) => {
  isExtensionActive = data.extensionActive || false;
  if (isExtensionActive) {
    loadFindingsFromStorage(() => startExtraction());
  }
});

if (!window.__autoExtractedRequests) {
  window.__autoExtractedRequests = [];
  (function(open) {
    XMLHttpRequest.prototype.open = function(method, url) {
      try { if (typeof url === "string" && url.startsWith('/')) window.__autoExtractedRequests.push(url); } catch {}
      open.apply(this, arguments);
    };
  })(XMLHttpRequest.prototype.open);

  (function(nativeFetch) {
    window.fetch = function() {
      try {
        const url = arguments[0];
        if (typeof url === "string" && url.startsWith('/')) {
          window.__autoExtractedRequests.push(url);
        }
      } catch {}
      return nativeFetch.apply(this, arguments);
    };
  })(window.fetch);
}

function logError(message, error) {
  try {
    console.error(`[NarrowX] ${message}:`, error);
  } catch {}
}
