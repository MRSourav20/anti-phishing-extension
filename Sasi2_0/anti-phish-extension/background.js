// background.js (service worker)
// AntiPhish Guardian - Phase 7
// Manages per-tab analysis storage with Time-To-Live (TTL).
// Phase 7: Remote Telegram Voice Alert Mode.

const analysisByTab = {}; // { tabId: { ...payload, ts } }
const TTL_MS = 300000; // 5 minutes

// =============================================================================
// PHASE 7: TELEGRAM VOICE ALERT CONFIGURATION
// =============================================================================

// IMPORTANT: Using 127.0.0.1 for local testing to avoid IPv6 binding issues
const BACKEND_URL = "http://127.0.0.1:3000";

/**
 * Send a Telegram voice alert to the backend for a HIGH/CRITICAL block event.
 * Only sends if the user has enabled Telegram alerts and registered.
 * Payload is minimal and privacy-safe: no cookies, DOM, or passwords.
 */
async function sendTelegramAlert(analysis) {
    const hostLog = analysis.url || analysis.hostname || "unknown";
    try {
        logAction(hostLog, "Debug: Alert Triggered", "Checking settings...");
        const storage = await chrome.storage.local.get(['telegram_enabled', 'telegram_userId']);

        if (!storage.telegram_enabled) {
            logAction(hostLog, "Debug: Alert Cancelled", "Telegram toggle is OFF in storage");
            return;
        }
        if (!storage.telegram_userId) {
            logAction(hostLog, "Debug: Alert Cancelled", "No User ID found in storage");
            return;
        }

        const incidentId = crypto.randomUUID();
        const payload = {
            userId: storage.telegram_userId,
            incidentId: incidentId,
            url: hostLog,
            riskScore: analysis.score || 0,
            reasons: (analysis.reasons || []).slice(0, 5), // Cap at 5 for brevity
            timestamp: new Date().toISOString()
        };

        logAction(hostLog, "Debug: Sending Fetch", `${BACKEND_URL}/alert`);

        const response = await fetch(`${BACKEND_URL}/alert`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            console.log("[AntiPhish] Telegram alert sent successfully. Incident:", incidentId);
            logAction(hostLog, "Telegram Alert Sent", incidentId);
        } else {
            const errText = await response.text();
            console.warn("[AntiPhish] Telegram alert failed:", response.status, errText);
            logAction(hostLog, "Debug: Backend Rejected", `Status: ${response.status}`);
        }
    } catch (err) {
        console.error("[AntiPhish] Telegram alert network error:", err.message);
        logAction(hostLog, "Debug: Network Error", err.message);
    }
}

/**
 * Register user with backend. Called once when user enables Telegram alerts.
 * Returns { success: boolean, message: string }
 */
async function registerTelegramUser(userId) {
    try {
        const response = await fetch(`${BACKEND_URL}/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ userId: userId })
        });

        const data = await response.json();
        return { success: response.ok, message: data.message || "Registered" };
    } catch (err) {
        console.error("[AntiPhish] Registration error:", err.message);
        return { success: false, message: err.message };
    }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    try {
        // 1. Content Script Logic
        if (message && message.type === "PAGE_LOADED") {
            // Phase 1 legacy support (optional, keeping for compatibility if needed)
            // console.log("Legacy PAGE_LOADED", message.url);
            sendResponse({ ok: true });
        }

        // 2. STORE ANALYSIS
        if (message && message.type === "PHISHING_ANALYSIS" && sender && sender.tab) {
            const tabId = sender.tab.id;
            const payload = message.payload || {};

            // Ensure timestamp exists
            if (!payload.ts) payload.ts = Date.now();

            analysisByTab[tabId] = payload;
            console.log("STORED_ANALYSIS", tabId, payload);
            // No response needed
            return;
        }

        // 3. RETRIEVE ANALYSIS
        if (message && message.type === "GET_ANALYSIS") {
            const tabId = message.tabId;
            const data = analysisByTab[tabId];

            // Check existence and TTL
            if (data) {
                const age = Date.now() - data.ts;
                if (age < TTL_MS) {
                    sendResponse({ ok: true, analysis: data });
                } else {
                    console.log(`Analysis for tab ${tabId} expired (Age: ${age}ms)`);
                    delete analysisByTab[tabId]; // Cleanup
                    sendResponse({ ok: false, error: "Analysis expired" });
                }
            } else {
                sendResponse({ ok: false, error: "No analysis found" });
            }
            return true; // Async response
        }

        // --- PHASE 3: PROTECTION HANDLERS ---

        // 4. FORM SUBMIT ATTEMPT
        if (message && message.type === "FORM_SUBMIT_ATTEMPT") {
            const tabId = sender.tab.id;
            const analysis = analysisByTab[tabId];

            // Default settings (simulated for simplicity, real impl would fetch from storage)
            const settings = message.settings || { autoProtectEnabled: true, highOnly: true };

            const decision = shouldAutoProtect(analysis, settings);
            console.log("DECISION:", decision);

            if (decision.block) {
                // EXECUTE PROTECTION
                clearCookiesForHost(analysis.hostname)
                    .then(cleared => {
                        logAction(analysis.hostname, "Form Blocked + Cookies Cleared", cleared);
                    });

                // PHASE 7: Send Telegram Voice Alert on block
                sendTelegramAlert(analysis);

                sendResponse({ block: true, reason: decision.reason, analysis: analysis });
            } else {
                sendResponse({ block: false });
            }
            return true; // Async
        }

        // --- PHASE 7: TELEGRAM HANDLERS ---

        // 5. Content script requests Telegram alert (page-load blocks)
        if (message && message.type === "SEND_TELEGRAM_ALERT") {
            const payload = message.analysis || {};
            sendTelegramAlert(payload);
            sendResponse({ ok: true });
            return;
        }

        // 6. Popup requests user registration
        if (message && message.type === "TELEGRAM_REGISTER") {
            const userId = message.userId;
            registerTelegramUser(userId).then(result => {
                sendResponse(result);
            });
            return true; // Async
        }

    } catch (err) {
        console.error("AntiPhish Background Error:", err);
    }
});


// --- PHASE 3: PROTECTION LOGIC ---

function shouldAutoProtect(analysis, settings) {
    if (!analysis) return { block: false };
    if (!settings.autoProtectEnabled) return { block: false };

    // Threshold Check
    const isHigh = analysis.score >= 0.60 && analysis.categoriesHit && analysis.categoriesHit.length >= 2;
    // Medium logic if enabled (mocked for now as we default to High only per prompt)

    if (isHigh) {
        // Allowlist check (already dampened in score, but double check)
        if (analysis.reasons.some(r => r.includes("allowlist"))) return { block: false };

        return { block: true, reason: "High Risk Phishing Detected" };
    }

    return { block: false };
}

// Cookie Management
async function clearCookiesForHost(hostname) {
    if (!hostname) return [];
    try {
        // Broad domain match 
        // Note: This is aggressive. Production needs accurate TLD parsing.
        const domain = hostname.startsWith("www.") ? hostname.substring(4) : hostname;

        const cookies = await chrome.cookies.getAll({ domain: domain });
        const cleared = [];

        for (const c of cookies) {
            const protocol = c.secure ? "https:" : "http:";
            const url = `${protocol}//${c.domain}${c.path}`;
            await chrome.cookies.remove({ url: url, name: c.name });
            cleared.push(c.name);
        }
        console.log(`Cleared ${cleared.length} cookies for ${domain}:`, cleared);
        return cleared;
    } catch (e) {
        console.error("Cookie clear failed:", e);
        return [];
    }
}

// Action Logging
function logAction(hostname, action, details) {
    const entry = {
        ts: Date.now(),
        hostname: hostname,
        action: action,
        details: details
    };

    chrome.storage.local.get({ actions: [] }, (res) => {
        const list = res.actions;
        list.unshift(entry);
        if (list.length > 50) list.pop(); // Keep log small
        chrome.storage.local.set({ actions: list });
    });
}

// =============================================================================
// PHASE 6: PERSISTENT COOKIE SENTINEL & TOXIC DUO SCANNER
// =============================================================================

/**
 * Scan all installed extensions for "Toxic Duo" permissions.
 * Toxic Duo = "cookies" + ("<all_urls>" OR "all hosts pattern")
 */
/**
 * Scan all installed extensions for permissions and calculate Risk Score.
 * RISK SCORING:
 * 100 (CRITICAL): "cookies" + ("<all_urls>" OR "all hosts") -> Toxic Duo
 * 75 (HIGH): debugger, declarativeNetRequest, browsingData, proxy, pageCapture
 * 50 (MEDIUM): tabs, history, bookmarks, management, scripting, privacy
 * 25 (LOW): storage, alarms, contextMenus, idle, notifications
 * 0 (SAFE): No significant permissions
 */
const TRUSTED_EXTENSIONS = [
    "cjpalhdlnbpafiamejdnhcphjbkeiagm", // uBlock Origin
    "hdokiejnpimakedhajhdlcegeplioahd", // LastPass
    "fheoggkfdfchfphceeifdbepaooicaho", // McAfee WebAdvisor
    "aapbdbdomjkkjkaonfhkkikfgjllcleb", // Google Translate
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi", // Google Docs Offline
    "kbfnbcaeplbcioakkpcpgfkobkghlhen", // Grammarly
];

function performFullAudit() {
    chrome.management.getAll((extensions) => {
        const auditResults = [];

        extensions.forEach((ext) => {
            if (!ext.enabled || ext.id === chrome.runtime.id) return; // Skip self and disabled

            const perms = ext.permissions || [];
            const hostPerms = ext.hostPermissions || [];

            let riskScore = 0;
            let riskReasons = [];

            // 0. TRUSTED VENDOR CHECK
            if (TRUSTED_EXTENSIONS.includes(ext.id)) {
                auditResults.push({
                    id: ext.id,
                    name: ext.name,
                    icon: ext.icons ? ext.icons[0].url : "",
                    score: 0,
                    reasons: ["Trusted Vendor (Allowlisted)"],
                    permissions: perms,
                    hostPermissions: hostPerms
                });
                return; // Skip further analysis
            }

            // 1. CRITICAL: Toxic Duo Check
            const hasCookies = perms.includes("cookies");
            const hasAllUrls = hostPerms.includes("<all_urls>") ||
                hostPerms.some(h => h.includes("*://*/*"));

            if (hasCookies && hasAllUrls) {
                riskScore = 100;
                riskReasons.push("CRITICAL: Can read/modify ALL cookies on ALL sites (Session Hijacking Risk)");
            }

            // 2. HIGH RISK Permissions
            const highRisks = ["debugger", "declarativeNetRequest", "browsingData", "proxy", "pageCapture", "webRequestBlocking"];
            const foundHigh = perms.filter(p => highRisks.includes(p));
            if (foundHigh.length > 0) {
                riskScore = Math.max(riskScore, 75);
                riskReasons.push(`HIGH: ${foundHigh.join(", ")}`);
            }

            // 3. MEDIUM RISK Permissions
            const medRisks = ["tabs", "history", "bookmarks", "management", "scripting", "privacy", "topSites"];
            const foundMed = perms.filter(p => medRisks.includes(p));
            if (foundMed.length > 0) {
                riskScore = Math.max(riskScore, 50);
                riskReasons.push(`MEDIUM: ${foundMed.join(", ")}`);
            }

            // 4. LOW RISK Permissions
            if (riskScore === 0 && (perms.length > 0 || hostPerms.length > 0)) {
                riskScore = 10;
                riskReasons.push("LOW: Basic utility permissions");
            }

            auditResults.push({
                id: ext.id,
                name: ext.name,
                icon: ext.icons ? ext.icons[0].url : "", // Use largest icon if available? 0 is usually smallest.
                score: riskScore,
                reasons: riskReasons,
                permissions: perms,
                hostPermissions: hostPerms
            });
        });

        // Sort by Risk Score Descending
        auditResults.sort((a, b) => b.score - a.score);

        // Store findings
        chrome.storage.local.set({ extension_scan_results: auditResults }, () => {
            // Check for Critical Threats to Alert User
            const criticalCount = auditResults.filter(r => r.score >= 100).length;
            if (criticalCount > 0) {
                chrome.notifications.create("critical-alert", {
                    type: "basic",
                    iconUrl: "icons/128.png",
                    title: "CRITICAL Security Risk Detected!",
                    message: `Found ${criticalCount} extension(s) with dangerous permissions. Check the Scanner tab.`,
                    priority: 2
                });
            }
        });
    });
}

/**
 * Real-time monitoring of specific session cookies (e.g., LinkedIn).
 * Detects if they are accessed or changed by other processes.
 */
function setupCookieSentinel() {
    chrome.cookies.onChanged.addListener((changeInfo) => {
        const cookie = changeInfo.cookie;

        // Target: LinkedIn Session Cookie
        if (cookie.domain.includes("linkedin.com") && cookie.name === "li_at") {
            const cause = changeInfo.cause;
            // Filter noise (we only care about meaningful changes or removals)
            // 'explicit' = user or extension action. 'expired_overwrite' = legit rotation.

            if (cause === "explicit") {
                console.warn(`[AntiPhish] Sensitive cookie modified: ${cookie.name} on ${cookie.domain}`);

                // Alert User
                chrome.notifications.create("cookie-sentinel", {
                    type: "basic",
                    iconUrl: "icons/128.png",
                    title: "Session Cookie Alert",
                    message: "LinkedIn session cookie was just modified or accessed. Verify if this was you.",
                    priority: 2
                });

                logAction("linkedin.com", "Sensitive Cookie Event", `li_at changed by ${cause}`);
            }
        }
    });
}

// --- BOOTSTRAP LISTENERS ---

// 1. Install/Startup Audit
chrome.runtime.onInstalled.addListener(() => {
    console.log("[AntiPhish] Extension Installed/Updated. Running Audit...");
    performFullAudit();
});

chrome.runtime.onStartup.addListener(() => {
    console.log("[AntiPhish] Browser Startup. Running Persistent Audit...");
    performFullAudit();
});

// 2. Watch for new extensions or state changes
if (chrome.management) {
    chrome.management.onInstalled.addListener((ext) => {
        console.log("[AntiPhish] New extension detected. Auditing...");
        performFullAudit();
    });

    chrome.management.onEnabled.addListener((ext) => {
        console.log("[AntiPhish] Extension enabled. Auditing...");
        performFullAudit();
    });

    chrome.management.onDisabled.addListener((ext) => {
        console.log("[AntiPhish] Extension disabled. Re-auditing...");
        performFullAudit();
    });
}

// 3. Start Cookie Sentinel
if (chrome.cookies) {
    setupCookieSentinel();
}
