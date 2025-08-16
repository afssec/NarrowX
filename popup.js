document.addEventListener("DOMContentLoaded", () => {
  const toggleBtn = document.getElementById("toggleBtn");
  const downloadBtn = document.getElementById("downloadBtn");
  const resetBtn = document.getElementById("resetBtn");
  const endpointList = document.getElementById("endpointList");
  const messageDiv = document.getElementById("message");
  const newScopeInput = document.getElementById("newScopeInput");
  const addScopeBtn = document.getElementById("addScopeBtn");
  const scopesList = document.getElementById("scopesList");
  const scopeEnabledCheckbox = document.getElementById("scopeEnabledCheckbox");
  const autoExtractBtn = document.getElementById("autoExtractBtn");
  const aboutBtn = document.getElementById("aboutBtn");

  const progressSection = document.getElementById("progressSection");
  const progressBar = document.getElementById("progressBar");
  const progressText = document.getElementById("progressText");

  let autoExtractRunning = false;

  function setButtonsDisabled(disabled) {
    if (toggleBtn) toggleBtn.disabled = disabled;
    if (downloadBtn) downloadBtn.disabled = disabled;
    if (resetBtn) resetBtn.disabled = disabled;
    if (addScopeBtn) addScopeBtn.disabled = disabled;
    if (scopeEnabledCheckbox) scopeEnabledCheckbox.disabled = disabled;
    if (autoExtractBtn) autoExtractBtn.disabled = disabled;
  }

  function showMessage(text, isError = false) {
    if (!messageDiv) return;
    messageDiv.textContent = text;
    messageDiv.style.color = isError ? "#d32f2f" : "#C0C0C0";
    setTimeout(() => (messageDiv.textContent = ""), 3000);
  }

  function showProgress(pct, status) {
    if (!progressSection) return;
    progressSection.style.display = "block";
    progressBar.style.width = Math.max(0, Math.min(100, pct)) + "%";
    progressText.textContent = `${Math.floor(pct)}% \u2022 ${status || ""}`;
  }

  function hideProgress() {
    if (!progressSection) return;
    progressSection.style.display = "none";
    progressBar.style.width = "0%";
    progressText.textContent = "0%";
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (changes.findings) updateFindingsList();
  });

  chrome.storage.local.get("extensionActive", (data) => {
    if (toggleBtn) {
      toggleBtn.textContent = data.extensionActive ? "Turn Off" : "Turn On";
    }
  });

  function updateFindingsList() {
    chrome.storage.local.get("findings", (data) => {
      if (!endpointList) return;
      endpointList.innerHTML = "";
      const findings = data.findings || {
        endpoints: [],
        apiKeys: [],
        databaseUrls: [],
        internalIps: [],
        tokens: [],
        passwords: [],
        parameters: [],
      };

      const categories = [
        { name: "Endpoints", data: findings.endpoints || [] },
        { name: "API Keys", data: findings.apiKeys || [] },
        { name: "Database URLs", data: findings.databaseUrls || [] },
        { name: "Internal IPs", data: findings.internalIps || [] },
        { name: "Tokens", data: findings.tokens || [] },
        { name: "Passwords", data: findings.passwords || [] },
        { name: "Parameters", data: findings.parameters || [] },
      ];

      if (categories.every((c) => !c.data || c.data.length === 0)) {
        const li = document.createElement("li");
        li.textContent = "No findings yet.";
        endpointList.appendChild(li);
      } else {
        categories.forEach((category) => {
          if (category.data && category.data.length > 0) {
            const h4 = document.createElement("h4");
            h4.textContent = `${category.name} (${category.data.length})`;
            endpointList.appendChild(h4);
            category.data.forEach((item) => {
              const li = document.createElement("li");
              li.textContent = item;
              endpointList.appendChild(li);
            });
          }
        });
      }
    });
  }
  updateFindingsList();

  function updateScopesList() {
    chrome.storage.local.get("scopes", (data) => {
      if (!scopesList) return;
      scopesList.innerHTML = "";
      const scopes = data.scopes || [];
      scopes.forEach((scope, index) => {
        const li = document.createElement("li");
        li.className = "scope-item";
        li.innerHTML = `<span>${scope}</span>`;

        const editBtn = document.createElement("button");
        editBtn.textContent = "Edit";
        editBtn.className = "edit";
        editBtn.onclick = () => {
          const input = document.createElement("input");
          input.value = scope;
          li.innerHTML = "";
          li.appendChild(input);
          const saveBtn = document.createElement("button");
          saveBtn.textContent = "Save";
          saveBtn.onclick = () => {
            const newValue = input.value.trim();
            if (newValue) {
              scopes[index] = newValue;
              chrome.storage.local.set({ scopes }, () => {
                updateScopesList();
                showMessage("Scope updated!");
              });
            }
          };
          li.appendChild(saveBtn);
        };
        li.appendChild(editBtn);

        const deleteBtn = document.createElement("button");
        deleteBtn.textContent = "Delete";
        deleteBtn.className = "delete";
        deleteBtn.onclick = () => {
          scopes.splice(index, 1);
          chrome.storage.local.set({ scopes }, () => {
            updateScopesList();
            showMessage("Scope deleted!");
          });
        };
        li.appendChild(deleteBtn);

        scopesList.appendChild(li);
      });
    });
  }
  updateScopesList();

  if (addScopeBtn) {
    addScopeBtn.addEventListener("click", () => {
      const newScope = (newScopeInput && newScopeInput.value || "").trim();
      if (newScope) {
        chrome.storage.local.get("scopes", (data) => {
          const scopes = data.scopes || [];
          if (!scopes.includes(newScope)) {
            scopes.push(newScope);
            chrome.storage.local.set({ scopes }, () => {
              if (newScopeInput) newScopeInput.value = "";
              updateScopesList();
              showMessage("Scope added!");
            });
          } else {
            showMessage("Scope already exists!", true);
          }
        });
      } else {
        showMessage("Please enter a valid scope!", true);
      }
    });
  }

  chrome.storage.local.get("scopeEnabled", (data) => {
    if (scopeEnabledCheckbox) {
      scopeEnabledCheckbox.checked = data.scopeEnabled || false;
    }
  });

  if (scopeEnabledCheckbox) {
    scopeEnabledCheckbox.addEventListener("change", () => {
      const isEnabled = scopeEnabledCheckbox.checked;
      chrome.storage.local.set({ scopeEnabled: isEnabled }, () => {
        if (isEnabled) {
          chrome.storage.local.get("scopes", (data) => {
            if (!data.scopes || data.scopes.length === 0) {
              showMessage("Warning: Scope filtering is ON but no scopes are defined.", true);
            } else {
              showMessage("Scope filtering enabled.");
            }
          });
        } else {
          showMessage("Scope filtering disabled.");
        }
        updateFindingsList();
      });
    });
  }

  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      chrome.storage.local.get("extensionActive", (data) => {
        const isActive = !data.extensionActive;
        chrome.storage.local.set({ extensionActive: isActive });
        toggleBtn.textContent = isActive ? "Turn Off" : "Turn On";
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          const tab = tabs && tabs[0];
          if (!tab || !/^https?:\/\//i.test(tab.url || '')) {
            showMessage("Unsupported page. Open a regular website (http/https).", true);
            return;
          }
          chrome.tabs.sendMessage(tab.id, { action: "toggleExtension", isActive }, () => {
            if (chrome.runtime.lastError) return;
            showMessage(`Extension ${isActive ? "enabled" : "disabled"}`);
            updateFindingsList();
          });
        });
      });
    });
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.action === "autoExtractProgress") {
      const pct = typeof msg.percent === "number" ? msg.percent : 0;
      const status = msg.status || "";
      showProgress(pct, status);

      if (pct >= 100) {
        autoExtractRunning = false;
        setButtonsDisabled(false);
        setTimeout(() => {
          hideProgress();
          updateFindingsList();
          showMessage("Auto extraction completed!");
        }, 600);
      }
    }
  });

  if (autoExtractBtn) {
    autoExtractBtn.addEventListener("click", () => {
      if (autoExtractRunning) return;
      autoExtractRunning = true;
      setButtonsDisabled(true);
      showProgress(2, "Initializing...");

      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs && tabs[0];
        if (!tab || !/^https?:\/\//i.test(tab.url || '')) {
          showProgress(100, "Unsupported page");
          autoExtractRunning = false;
          setButtonsDisabled(false);
          setTimeout(() => {
            hideProgress();
            showMessage("Unsupported page. Open a regular website (http/https).", true);
          }, 600);
          return;
        }

        chrome.tabs.sendMessage(tab.id, { action: "autoExtractEndpoints" }, (response) => {
          if (chrome.runtime.lastError) return;
          if (!response || !response.success) {
            showProgress(100, "Done (no data)");
            autoExtractRunning = false;
            setButtonsDisabled(false);
            setTimeout(() => {
              hideProgress();
              showMessage("Auto extraction failed or returned no data", true);
            }, 700);
          }
        });
      });
    });
  }

  if (downloadBtn) {
    downloadBtn.addEventListener("click", () => {
      chrome.storage.local.get("findings", (data) => {
        try {
          const findings = data.findings || {
            endpoints: [],
            apiKeys: [],
            databaseUrls: [],
            internalIps: [],
            tokens: [],
            passwords: [],
            parameters: [],
          };
          const blob = new Blob([JSON.stringify(findings, null, 2)], {
            type: "application/json",
          });
          const url = URL.createObjectURL(blob);
          const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
          chrome.downloads.download(
            {
              url,
              filename: `findings_${timestamp}.json`,
              saveAs: true,
            },
            () => {
              if (chrome.runtime.lastError) {
                showMessage("Failed to start download: " + chrome.runtime.lastError.message, true);
              } else {
                showMessage("Download started successfully!");
              }
              URL.revokeObjectURL(url);
            }
          );
        } catch (error) {
          showMessage("Error preparing download: " + error.message, true);
        }
      });
    });
  }

  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs && tabs[0];
        if (!tab || !/^https?:\/\//i.test(tab.url || '')) {
          showMessage("Unsupported page. Open a regular website (http/https).", true);
          return;
        }
        chrome.tabs.sendMessage(tab.id, { action: "resetFindings" }, (response) => {
          if (chrome.runtime.lastError) return;
          if (response && response.success) {
            showMessage("All findings have been reset successfully!");
            updateFindingsList();
          } else {
            showMessage("Failed to reset findings", true);
          }
        });
      });
    });
  }

  if (aboutBtn) {
    aboutBtn.addEventListener("click", () => {
      chrome.tabs.create({ url: chrome.runtime.getURL("about.html") });
    });
  }
});
