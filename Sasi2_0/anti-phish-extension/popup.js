// popup.js
// AntiPhish Guardian - Phase 2 Tuned UI
// AntiPhish Guardian - Phase 3 UI

document.addEventListener('DOMContentLoaded', async () => {
    const statusEl = document.getElementById('status');
    const pageInfoEl = document.getElementById('pageInfo');
    const toggleBtn = document.getElementById('toggleProtectBtn');
    const protectStatusEl = document.getElementById('protectStatus');
    const logEl = document.getElementById('actionLog');

    // Assistant Toggles
    const toggleBubble = document.getElementById('toggleBubble');
    const toggleVoice = document.getElementById('toggleVoice');

    // 1. Load Settings
    // 1. Load Settings
    // Default values
    let settings = { autoProtect: true, assistant_enabled: true, voice_enabled: true };

    // Load from storage
    chrome.storage.local.get(['autoProtect', 'assistant_enabled', 'voice_enabled'], (res) => {
        if (res.autoProtect !== undefined) settings.autoProtect = res.autoProtect;
        if (res.assistant_enabled !== undefined) settings.assistant_enabled = res.assistant_enabled;
        if (res.voice_enabled !== undefined) settings.voice_enabled = res.voice_enabled;
        renderSettings();
    });

    const renderSettings = () => {
        // Auto Protect
        protectStatusEl.innerText = settings.autoProtect ? "ON" : "OFF";
        protectStatusEl.style.color = settings.autoProtect ? "green" : "red";
        toggleBtn.innerText = settings.autoProtect ? "Disable Protection" : "Enable Protection";

        // Assistant
        toggleBubble.checked = settings.assistant_enabled;
        toggleVoice.checked = settings.voice_enabled;
    };

    // Handlers
    toggleBtn.onclick = () => {
        settings.autoProtect = !settings.autoProtect;
        chrome.storage.local.set({ autoProtect: settings.autoProtect });
        renderSettings();
    };

    toggleBubble.onchange = () => {
        settings.assistant_enabled = toggleBubble.checked;
        chrome.storage.local.set({ assistant_enabled: settings.assistant_enabled });
    };

    toggleVoice.onchange = () => {
        settings.voice_enabled = toggleVoice.checked;
        chrome.storage.local.set({ voice_enabled: settings.voice_enabled });
    };

    // --- PHASE 7: Telegram Voice Alert Toggle ---
    const toggleTelegram = document.getElementById('toggleTelegram');
    const telegramStatusEl = document.getElementById('telegramStatus');
    const telegramInfoEl = document.getElementById('telegramInfo');
    const telegramUserIdDisplay = document.getElementById('telegramUserIdDisplay');

    // Load Telegram state
    chrome.storage.local.get(['telegram_enabled', 'telegram_userId'], (res) => {
        settings.telegram_enabled = res.telegram_enabled || false;
        settings.telegram_userId = res.telegram_userId || null;
        renderTelegramState();
    });

    const renderTelegramState = () => {
        toggleTelegram.checked = settings.telegram_enabled;
        telegramStatusEl.innerText = settings.telegram_enabled ? "ON" : "OFF";
        telegramStatusEl.style.color = settings.telegram_enabled ? "green" : "#999";
        if (settings.telegram_enabled && settings.telegram_userId) {
            telegramInfoEl.style.display = "block";
            telegramUserIdDisplay.innerText = settings.telegram_userId.substring(0, 8) + "…";
        } else {
            telegramInfoEl.style.display = "none";
        }
    };

    toggleTelegram.onchange = () => {
        if (toggleTelegram.checked) {
            // CONSENT DIALOG
            const consent = confirm(
                "🔔 Enable Telegram Voice Alerts?\n\n" +
                "When a phishing site is BLOCKED, a minimal summary will be sent to your Telegram via our secure backend.\n\n" +
                "Data sent: URL, risk score, reasons, timestamp.\n" +
                "NOT sent: cookies, passwords, page content, phone number.\n\n" +
                "You will need to link your Telegram account by messaging our bot.\n\n" +
                "Do you consent?"
            );

            if (!consent) {
                toggleTelegram.checked = false;
                return;
            }

            // Generate unique userId
            const userId = crypto.randomUUID();
            settings.telegram_enabled = true;
            settings.telegram_userId = userId;

            chrome.storage.local.set({
                telegram_enabled: true,
                telegram_userId: userId
            });

            // Register with backend
            chrome.runtime.sendMessage({ type: "TELEGRAM_REGISTER", userId: userId }, (resp) => {
                if (resp && resp.success) {
                    console.log("[AntiPhish] Telegram registration successful.");
                } else {
                    console.warn("[AntiPhish] Telegram registration failed:", resp?.message);
                }
            });

            renderTelegramState();
        } else {
            // DISABLE
            settings.telegram_enabled = false;
            settings.telegram_userId = null;
            chrome.storage.local.set({
                telegram_enabled: false,
                telegram_userId: null
            });
            renderTelegramState();
        }
    };

    // 2. Load Logs
    chrome.storage.local.get({ actions: [] }, (res) => {
        if (res.actions && res.actions.length > 0) {
            logEl.innerHTML = res.actions.slice(0, 3).map(a =>
                `<div style="margin-bottom:4px;">
                    <strong>${new Date(a.ts).toLocaleTimeString()}:</strong> ${a.action}<br>
                    <span style="color:#d93025;">${a.hostname}</span>
                </div>`
            ).join("");
        }
    });

    // TAB SWITCHING LOGIC
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach(tabBtn => {
        tabBtn.addEventListener('click', () => {
            // Remove active class from all
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            // Add active to clicked
            tabBtn.classList.add('active');
            document.getElementById(tabBtn.dataset.tab).classList.add('active');
        });
    });

    // 2.5 Load FULL Security Dashboard (Scanner)
    chrome.storage.local.get({ extension_scan_results: [] }, (res) => {
        const scanResults = res.extension_scan_results || [];
        const scannerList = document.getElementById('scannerList');
        const scannerStats = document.getElementById('scannerStats');

        if (scanResults.length > 0) {
            // Stats
            const critical = scanResults.filter(r => r.score >= 100).length;
            const high = scanResults.filter(r => r.score >= 75 && r.score < 100).length;
            const medium = scanResults.filter(r => r.score >= 50 && r.score < 75).length;

            scannerStats.innerHTML = `
                Found ${scanResults.length} extensions. 
                <span style="color:#d93025">${critical} Critical</span>, 
                <span style="color:#e37400">${high} High</span>.
            `;

            // Render List
            scannerList.innerHTML = scanResults.map(ext => {
                let riskClass = "risk-safe";
                let riskLabel = "SAFE";
                if (ext.score >= 100) { riskClass = "risk-critical"; riskLabel = "CRITICAL"; }
                else if (ext.score >= 75) { riskClass = "risk-high"; riskLabel = "HIGH"; }
                else if (ext.score >= 50) { riskClass = "risk-medium"; riskLabel = "MEDIUM"; }
                else if (ext.score >= 10) { riskClass = "risk-low"; riskLabel = "LOW"; }

                // Truncate name if too long
                const safeName = ext.name.length > 30 ? ext.name.substring(0, 28) + "..." : ext.name;

                return `
                <div style="display:flex; flex-direction:column; margin-bottom:8px; border-bottom:1px solid #eee; padding-bottom:6px;">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                        <div style="display:flex; align-items:center; gap:8px;">
                            <img src="${ext.icon || 'icons/48.png'}" style="width:20px; height:20px; border-radius:4px;">
                            <div style="font-weight:600; font-size:12px;">${safeName}</div>
                        </div>
                        <span class="risk-badge ${riskClass}">${riskLabel}</span>
                    </div>
                    
                    ${ext.reasons.length > 0 ? `
                    <div style="margin-top:4px; margin-left:28px; font-size:10px; color:#5f6368;">
                        ${ext.reasons.map(r => `• ${r}`).join("<br>")}
                    </div>
                    ` : ''}
                    
                    ${(ext.score >= 50) ? `
                    <div style="text-align:right; margin-top:4px;">
                         <button class="neutralize-btn" data-id="${ext.id}" style="width:auto; padding:2px 8px; font-size:10px; background:#f1f3f4; color:#d93025; border:1px solid #d93025;">Disable Extension</button>
                    </div>
                    ` : ''}
                </div>
                `;
            }).join('');

            // Add Click Handlers for Disable
            document.querySelectorAll('.neutralize-btn').forEach(btn => {
                btn.onclick = () => {
                    const extId = btn.getAttribute('data-id');
                    chrome.management.setEnabled(extId, false, () => {
                        // Optimistic UI update
                        btn.innerText = "Disabled";
                        btn.disabled = true;
                        btn.style.opacity = 0.5;
                        // Trigger background re-audit?
                        // For now just RELOAD popup to refresh
                        setTimeout(() => location.reload(), 500);
                    });
                };
            });

        } else {
            scannerList.innerHTML = `<div style="padding:10px; color:#666;">No extensions scanned yet. Waiting for background service...</div>`;
        }
    });

    // 3. Main Analysis Flow
    try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tabs || tabs.length === 0) return;
        const tab = tabs[0];

        statusEl.innerText = "Analyzing...";
        try { await chrome.tabs.sendMessage(tab.id, { type: "RUN_ANALYSIS" }); } catch (e) { }

        chrome.runtime.sendMessage({ type: "GET_ANALYSIS", tabId: tab.id }, (resp) => {
            if (!resp || !resp.ok || !resp.analysis) {
                statusEl.innerText = "Ready";
                pageInfoEl.innerText = "No analysis data.";
                return;
            }
            renderResult(resp.analysis, pageInfoEl, statusEl);
        });

    } catch (err) {
        console.error("Popup Error:", err);
    }

    document.getElementById('refreshBtn').addEventListener('click', () => location.reload());
});


function renderResult(data, infoEl, statusEl) {
    const score = data.score;
    const cats = data.categoriesHit || []; // Array from Set
    const catCount = cats.length;

    // Classification Rules
    // LOW: < 0.30
    // MEDIUM: >= 0.30 AND < 0.60 (OR high score but single category?)
    // HIGH: >= 0.60 AND categoriesHit >= 2

    let level = "LOW";
    let color = "#28a745"; // Green

    if (score >= 0.60 && catCount >= 2) {
        level = "HIGH";
        color = "#dc3545"; // Red
    } else if (score >= 0.30 || (score >= 0.60 && catCount < 2)) {
        // Fallback for high score but single category (e.g. just massive keyword stuffing)
        level = "MEDIUM";
        color = "#ffc107"; // Amber
    }

    statusEl.innerText = `Risk Level: ${level}`;
    statusEl.style.color = color;

    // Formatting Reasons (Top 3)
    const topReasons = (data.reasons || []).slice(0, 3).map(r => `• ${r}`).join("\n");

    // Display
    // Display
    infoEl.innerHTML = `
        <strong>Final Score:</strong> ${score.toFixed(2)}<br>
        <div style="font-size:10px; color:#5f6368; margin-bottom:6px;">
           Base: ${(data.phase2_score || score).toFixed(2)} 
           ${renderP4Adj(data.phase4)}
        </div>
        <strong>Categories:</strong> ${cats.join(", ") || "None"}<br>
        <hr>
        <strong>Top Indicators:</strong><br>
        <div style="font-size: 12px; margin-top:4px; line-height: 1.4;">
        ${topReasons || "No suspicious signals detected."}
        </div>
    `;

    // Phase 4 Panel Update
    const aiDiv = document.getElementById('aiBreakdown');
    if (aiDiv) {
        if (data.phase4) {
            aiDiv.innerHTML = `AI Adj: ${(data.phase4.finalScore - (data.phase2_score || score)).toFixed(2)} (${data.phase4.reputation.reason || "Neutral"})`;
        } else {
            aiDiv.innerText = "No AI adjustments.";
        }
    }
}

function renderP4Adj(p4) {
    if (!p4) return "";
    const diff = (p4.finalScore - (p4.phase2_score || 0)); // this is fuzzy since we don't pass p4.phase2_score fully in obj yet
    const rep = p4.reputation.value.toFixed(2);
    const rr = p4.reRank.value.toFixed(2);
    return `| Rep: ${rep > 0 ? '+' + rep : rep} | Rank: ${rr > 0 ? '+' + rr : rr}`;
}
