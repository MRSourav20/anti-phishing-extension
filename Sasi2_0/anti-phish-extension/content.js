// content.js
// AntiPhish Guardian - Phase 2 Tuned Implementation
// Injected into pages to perform deterministic locally-executed risk analysis.

// =============================================================================
// 1. CONFIGURATION (Embedded synchronously as required)
// =============================================================================
const CONFIG = {
    "weights": {
        "keyword": 0.08,
        "keyword_max": 0.30,
        "password_field": 0.35,
        "email_form_with_keyword": 0.18,
        "generic_submit": 0.10,
        "hidden_inputs": 0.08,
        "js_submit": 0.12,
        "typosquat": 0.30,
        "brand_in_url": 0.20,
        "suspicious_tld": 0.12,
        "ip_url": 0.20,
        "form_action_mismatch": 0.30,
        "form_http": 0.25,
        "cookie_weak_flags": 0.10, // Reserved for Phase 3
        "cookie_long_expiry": 0.08, // Reserved for Phase 3
        "redirect_chain": 0.12,
        "ai_hidden_text": 0.20,
        "ai_invisible_chars": 0.15,
        "ai_prompt_injection": 0.25
    },
    "caps": {
        "language_max": 0.30,    // Hard cap for keyword contributions alone
        "lang_only_cap": 0.45,   // Total score cap if ONLY language signals are present
        "password_only_cap": 0.55 // Total score cap if ONLY password field is present
    },
    "thresholds": {
        "low_upper": 0.30,
        "medium_upper": 0.59,
        "high_lower": 0.60
    },
    "allowlist": {
        // Tier 1: Silent Trusted (No Bubble/Voice, Hard Cap 0.25)
        "tier1": [
            "google.com", "accounts.google.com", "youtube.com", "youtu.be", "gmail.com",
            "microsoft.com", "login.microsoftonline.com", "outlook.com", "live.com",
            "apple.com", "icloud.com",
            "amazon.com", "amazon.in", "aws.amazon.com",
            "meta.com", "facebook.com", "instagram.com", "whatsapp.com"
        ],
        // Tier 2: Trusted Professional (No Bubble/Voice, Hard Cap 0.35)
        "tier2": [
            "linkedin.com", "github.com", "gitlab.com", "bitbucket.org",
            "stackoverflow.com", "stackexchange.com", "slack.com", "discord.com",
            "notion.so", "atlassian.com"
        ],
        // Tier 3: Sensitive Legit (Monitor, Bubble only if High, Voice only if Block)
        "tier3": [
            "paypal.com", "stripe.com", "razorpay.com", "paytm.com", "phonepe.com", "gpay.com",
            "aws.amazon.com", "cloud.google.com", "azure.microsoft.com", "salesforce.com",
            "zoom.us", "dropbox.com",
            "coursera.org", "udemy.com", "edx.org", "kaggle.com", "leetcode.com", "hackerrank.com"
        ]
    },
    "ttl_ms": 300000
};

// =============================================================================
// 2. HELPERS
// =============================================================================

/**
 * Extract hostname from URL.
 * Handles DEV overrides via <meta name="test-hostname"> for testing.
 */
function getHostname(url) {
    try {
        // DEV OVERRIDE: Check for test meta tag
        const testMeta = document.querySelector('meta[name="test-hostname"]');
        if (testMeta && testMeta.content) {
            console.warn("AntiPhish: Using test-hostname override:", testMeta.content);
            return testMeta.content.toLowerCase();
        }
        return new URL(url).hostname.replace(/^www\./, "").toLowerCase();
    } catch (e) {
        return "";
    }
}

/**
 * Levenshtein Distance for Typosquatting
 */
function levenshtein(a, b) {
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    const m = [];
    for (let i = 0; i <= b.length; i++) m[i] = [i];
    for (let j = 0; j <= a.length; j++) m[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            m[i][j] = b.charAt(i - 1) === a.charAt(j - 1)
                ? m[i - 1][j - 1]
                : Math.min(m[i - 1][j] + 1, m[i][j - 1] + 1, m[i - 1][j - 1] + 1);
        }
    }
    return m[b.length][a.length];
}

/**
 * Detect Prompt Injection Attempts (Phase 5)
 * Returns { score, reasons } for AI manipulation detection
 */
function detectPromptInjection() {
    let aiScore = 0;
    const aiReasons = [];

    // 1. Hidden Text Detection
    const allElements = document.querySelectorAll('*');
    let hiddenTextCount = 0;
    const aiKeywords = [
        "ignore previous", "disregard", "you are now", "new role", "system message",
        "override instructions", "forget everything", "act as", "pretend you are",
        "jailbreak", "bypass", "sudo mode", "developer mode", "admin mode"
    ];

    for (const el of allElements) {
        const styles = window.getComputedStyle(el);
        const text = (el.textContent || "").toLowerCase();

        // Check if element is hidden from user but visible to scrapers
        const isHidden = (
            styles.display === 'none' ||
            styles.visibility === 'hidden' ||
            parseFloat(styles.opacity) === 0 ||
            styles.color === styles.backgroundColor ||
            parseFloat(styles.fontSize) < 2
        );

        if (isHidden && text.length > 20) {
            // Check if hidden text contains AI manipulation keywords
            const hasAIKeyword = aiKeywords.some(kw => text.includes(kw));
            if (hasAIKeyword) {
                hiddenTextCount++;
                aiReasons.push(`Hidden text detected with AI instruction patterns`);
                break; // Only report once
            }
        }
    }

    if (hiddenTextCount > 0) {
        aiScore += CONFIG.weights.ai_hidden_text;
    }

    // 2. Invisible Unicode Detection
    const pageText = document.body ? document.body.textContent : "";
    const invisibleChars = [
        '\u200B', // Zero-width space
        '\u200C', // Zero-width non-joiner
        '\u200D', // Zero-width joiner
        '\uFEFF', // Zero-width no-break space
        '\u202A', // Left-to-right embedding
        '\u202C', // Pop directional formatting
        '\u202D', // Left-to-right override
        '\u202E'  // Right-to-left override
    ];

    let invisibleCount = 0;
    for (const char of invisibleChars) {
        const count = (pageText.match(new RegExp(char, 'g')) || []).length;
        invisibleCount += count;
    }

    if (invisibleCount > 5) {
        aiScore += CONFIG.weights.ai_invisible_chars;
        aiReasons.push(`Invisible characters detected (${invisibleCount} instances, potential manipulation)`);
    }

    // 3. Prompt Injection Pattern Detection
    const bodyText = (document.body && document.body.innerText || "").toLowerCase();
    let injectionPatternsFound = 0;

    for (const keyword of aiKeywords) {
        if (bodyText.includes(keyword)) {
            injectionPatternsFound++;
            aiReasons.push(`AI manipulation keyword detected: "${keyword}"`);
        }
    }

    if (injectionPatternsFound > 0) {
        aiScore += CONFIG.weights.ai_prompt_injection;
    }

    // 4. Check Meta Tags for AI Targeting
    const metaTags = document.querySelectorAll('meta[name], meta[property]');
    for (const meta of metaTags) {
        const content = (meta.getAttribute('content') || "").toLowerCase();
        const hasAIPattern = aiKeywords.some(kw => content.includes(kw));
        if (hasAIPattern) {
            aiScore += 0.10;
            aiReasons.push("Suspicious meta tag targeting AI crawlers");
            break;
        }
    }

    return { score: aiScore, reasons: aiReasons };
}

// 5. Header Inspector (Phase 6)
// Checks for basic security headers via HEAD request
async function checkSecurityHeaders(url) {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000); // 2s timeout

        const res = await fetch(url, {
            method: 'HEAD',
            signal: controller.signal,
            mode: 'same-origin' // Only check same-origin to avoid CORS errors on some sites
        });
        clearTimeout(timeoutId);

        const headers = res.headers;
        const missing = [];

        if (!headers.get('Content-Security-Policy')) missing.push("CSP");
        if (!headers.get('X-Frame-Options')) missing.push("X-Frame-Options");
        if (!headers.get('X-Content-Type-Options')) missing.push("X-Content-Type-Options");

        // Strict Transport Security (HSTS) only relevant on HTTPS
        if (window.location.protocol === 'https:' && !headers.get('Strict-Transport-Security')) {
            missing.push("HSTS");
        }

        return { score: missing.length * 0.05, missing: missing };
    } catch (e) {
        // console.log("Header check failed/skipped:", e);
        return null;
    }
}

// 6. Redirect Validator (Phase 6)
// Scans for Open Redirect patterns in links
function detectOpenRedirects() {
    const links = document.links;
    let suspiciousLinks = 0;
    const redirectParams = ["url", "redirect", "next", "target", "dest", "out"];

    for (const link of links) {
        try {
            const url = new URL(link.href);
            if (url.hostname === window.location.hostname) {
                // Check query params for HTTP/HTTPS urls
                for (const [key, val] of url.searchParams) {
                    if (redirectParams.includes(key) && val.startsWith("http")) {
                        // It's a redirect param. Check if destination is different.
                        const destUrl = new URL(val);
                        if (destUrl.hostname !== window.location.hostname) {
                            suspiciousLinks++;
                        }
                    }
                }
            }
        } catch (e) { }
    }

    if (suspiciousLinks > 0) {
        return {
            score: Math.min(suspiciousLinks * 0.10, 0.30),
            reasons: [`Open Redirects detected (${suspiciousLinks} links found)`]
        };
    }
    return { score: 0, reasons: [] };
}

// 7. Behavioral Heuristics (Typing Speed)
// Setup listener to detect bot-like typing in password fields
function setupBehavioralAnalysis() {
    const passwordFields = document.querySelectorAll('input[type="password"]');

    passwordFields.forEach(field => {
        let lastTime = 0;
        let fastKeyCount = 0;

        field.addEventListener('keydown', (e) => {
            const now = Date.now();
            if (lastTime > 0) {
                const diff = now - lastTime;
                // < 50ms is superhuman for sustained typing
                if (diff < 50) {
                    fastKeyCount++;
                } else {
                    fastKeyCount = Math.max(0, fastKeyCount - 1); // Decay
                }

                if (fastKeyCount > 5) {
                    // Trigger Warning
                    assistant.showBubble("caution", "You are typing unusually fast. Please ensure you are not using a script or under pressure.");
                    fastKeyCount = 0; // Reset
                }
            }
            lastTime = now;
        });
    });
}

function analyzePageForPhishTuned() {
    const url = window.location.href;
    const hostname = getHostname(url);
    const textBody = (document.body && document.body.innerText || "").toLowerCase();
    const textHTML = (document.body && document.body.innerHTML || "").toLowerCase();

    let totalScore = 0;
    let reasons = [];
    const categoriesHit = new Set(); // Track unique categories contributing to risk

    // --- A. LANGUAGE CATEGORY ---
    let langScore = 0;
    const suspiciousKeywords = [
        "verify your account", "confirm your password", "update your account",
        "security alert", "unusual activity", "account suspended", "urgent action",
        "click here to login", "verify identity", "billing problem"
    ];

    let kwCount = 0;
    for (const kw of suspiciousKeywords) {
        if (textBody.includes(kw)) {
            kwCount++;
            reasons.push(`Suspicious keyword: "${kw}"`);
        }
    }

    // Weight: 0.08 per keyword, hard capped at keyword_max (0.30)
    langScore = Math.min(kwCount * CONFIG.weights.keyword, CONFIG.weights.keyword_max);
    if (langScore > 0) {
        totalScore += langScore;
        categoriesHit.add("Language");
    }


    // --- B. FORM CATEGORY ---
    // Detect forms, password fields, hidden inputs
    let formScore = 0;
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    const forms = Array.from(document.forms || []);

    // 1. Password Field
    if (passwordInputs.length > 0) {
        formScore += CONFIG.weights.password_field;
        reasons.push("Password input field detected");
    }

    // 2. Hidden inputs (indicative of data exfiltration or state passing)
    // Check specifically for hidden inputs in forms that also have passwords or text
    const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
    if (hiddenInputs.length > 2 && forms.length > 0) {
        formScore += CONFIG.weights.hidden_inputs;
        reasons.push("Multiple hidden fields detected in form");
    }

    // 3. Generic Submit (lazy coding often seen in phishing kits)
    const submitButtons = document.querySelectorAll('button[type="submit"], input[type="submit"]');
    for (const btn of submitButtons) {
        const txt = (btn.innerText || btn.value || "").toLowerCase();
        if (txt === "submit" || txt === "login" || txt === "sign in") {
            // Only penalize if very generic and on a page with other signals
            if (passwordInputs.length > 0) {
                formScore += CONFIG.weights.generic_submit;
                reasons.push("Generic submit button detected");
                break;
            }
        }
    }

    // 4. Javascript Submit Handlers (basic heuristic)
    if (textHTML.includes('onsubmit="return') || textHTML.includes('javascript:void(0)')) {
        formScore += CONFIG.weights.js_submit;
        reasons.push("Legacy/Obfuscated JS submit handler detected");
    }

    // Specific combination: Email form requests + Suspicious Keywords
    const emailInputs = document.querySelectorAll('input[type="email"], input[name*="email"]');
    if (emailInputs.length > 0 && kwCount > 0) {
        formScore += CONFIG.weights.email_form_with_keyword;
        reasons.push("Email collection form combined with urgent keywords");
    }

    if (formScore > 0) {
        totalScore += formScore;
        categoriesHit.add("Form");
    }


    // --- C. DOMAIN CATEGORY ---
    let domainScore = 0;

    // 1. IP Address URL
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
        domainScore += CONFIG.weights.ip_url;
        reasons.push("Site is hosted on a raw IP address");
    }

    // 2. Suspicious TLDs
    const susTLDs = [".xyz", ".top", ".club", ".info", ".live", ".pro", ".gq", ".cf", ".tk", ".ml"];
    if (susTLDs.some(tld => hostname.endsWith(tld))) {
        domainScore += CONFIG.weights.suspicious_tld;
        reasons.push("Suspicious Top-Level Domain (TLD) detected");
    }

    // 3. Typosquatting (Levenshtein against popular - Tier 1 & 2)
    let typoFound = false;
    // Flatten trusted domains for check
    const protectionList = [...CONFIG.allowlist.tier1, ...CONFIG.allowlist.tier2, ...CONFIG.allowlist.tier3];

    for (const popular of protectionList) {
        if (hostname === popular) continue;
        if (hostname.endsWith("." + popular)) continue;

        const dist = levenshtein(hostname, popular);
        const ratio = dist / Math.max(hostname.length, popular.length);

        if (ratio > 0 && ratio < 0.25) {
            domainScore += CONFIG.weights.typosquat;
            reasons.push(`Possible typosquatting of ${popular}`);
            typoFound = true;
            break;
        }
    }

    // 4. Brand name in URL path/subdomain but NOT exact host
    // e.g. "paypal-verification.com" or "login-google-security.com"
    const brands = ["paypal", "google", "microsoft", "apple", "facebook", "amazon"];
    for (const brand of brands) {
        if (url.includes(brand) && !hostname.includes(brand)) {
            domainScore += CONFIG.weights.brand_in_url;
            reasons.push(`Brand "${brand}" found in URL path but not in domain`);
            break;
        }
    }

    if (domainScore > 0) {
        totalScore += domainScore;
        categoriesHit.add("Domain");
    }


    // --- D. BEHAVIOR CATEGORY ---
    let behaviorScore = 0;

    // 1. Form Action Mismatch (Cross-domain post)
    // Cross-origin posts are suspicious for login forms
    for (const f of forms) {
        let action = f.getAttribute("action");
        if (action && !action.startsWith("javascript")) {
            try {
                // Resolve relative URLs
                const actionUrl = new URL(action, window.location.href);
                if (actionUrl.hostname !== hostname && actionUrl.hostname !== "") {
                    // Ignore common SSO/OAuth endpoints if needed, but for now flag all
                    behaviorScore += CONFIG.weights.form_action_mismatch;
                    reasons.push(`Form sends data to external domain: ${actionUrl.hostname}`);
                    break;
                }
            } catch (e) { }
        }
    }

    // 2. HTTP Form Action on HTTPS page
    if (window.location.protocol === "https:") {
        for (const f of forms) {
            const action = f.getAttribute("action") || "";
            if (action.toLowerCase().startsWith("http:")) {
                behaviorScore += CONFIG.weights.form_http;
                reasons.push("Insecure (HTTP) form submission on HTTPS page");
                break;
            }
        }
    }

    // Cookie checks (Phase 3 reserved) -> Skipped per config/constraints

    if (behaviorScore > 0) {
        totalScore += behaviorScore;
        categoriesHit.add("Behavior");
    }


    // --- E. AI MANIPULATION CATEGORY (Phase 5) ---
    const aiDetection = detectPromptInjection();
    if (aiDetection.score > 0) {
        totalScore += aiDetection.score;
        categoriesHit.add("AI Manipulation");
        reasons.push(...aiDetection.reasons);
    }


    // ===========================================================================
    // 4. SCORING ADJUSTMENTS & CAPS
    // ===========================================================================

    let tierMatch = null;

    // Helper to check match
    const checkTier = (list) => list.some(d => hostname === d || hostname.endsWith("." + d));

    // A. Tiered Allowlist Logic
    if (checkTier(CONFIG.allowlist.tier1)) {
        tierMatch = 1;
        totalScore = Math.min(totalScore * 0.25, 0.25);
        reasons.push("Tier 1 Trusted Platform (Risk Dampened)");
    } else if (checkTier(CONFIG.allowlist.tier2)) {
        tierMatch = 2;
        totalScore = Math.min(totalScore * 0.40, 0.35);
        reasons.push("Tier 2 Professional Platform (Risk Dampened)");
    } else if (checkTier(CONFIG.allowlist.tier3)) {
        tierMatch = 3;
        totalScore = totalScore * 0.80; // Slight dampening
        reasons.push("Tier 3 Verified Platform");
    }

    // B. Safety Caps (Only applying if NOT already trusted, to avoid conflict)
    if (!tierMatch) {
        // If ONLY Language signals present, cap score
        if (categoriesHit.size === 1 && categoriesHit.has("Language")) {
            totalScore = Math.min(totalScore, CONFIG.caps.lang_only_cap);
        }
        // If ONLY Form (e.g. just a password field) present, cap score
        if (categoriesHit.size === 1 && categoriesHit.has("Form")) {
            totalScore = Math.min(totalScore, CONFIG.caps.password_only_cap);
        }
    }

    // Final Clamp
    if (totalScore > 1.0) totalScore = 1.0;
    totalScore = Math.round(totalScore * 100) / 100;

    // --- F. OPEN REDIRECTS (Phase 6) ---
    const redirectAnalysis = detectOpenRedirects(); // This function is now available
    if (redirectAnalysis.score > 0) {
        totalScore += redirectAnalysis.score;
        categoriesHit.add("Behavior"); // Group under Behavior
        reasons.push(...redirectAnalysis.reasons);
    }

    // Header analysis is async, so we return what we have here. 
    // Headers will be appended in the execution runner.

    return {
        url: window.location.href,
        hostname: hostname,
        score: totalScore,
        reasons: reasons,
        categoriesHit: Array.from(categoriesHit),
        tier: tierMatch, // Pass tier for UI logic
        ts: Date.now()
    };
}

// =============================================================================
// 5. EXECUTION & MESSAGING
// =============================================================================

async function runAndSendExectuion() {
    try {
        // 1. Static Analysis (Sync)
        const payload = analyzePageForPhishTuned();

        // 2. Async Header Check (Phase 6)
        // We warn if headers are missing on sensitive pages (Login/Form)
        // Only run if checking a form-heavy page to save resources
        if (payload.categoriesHit.includes("Form") || payload.score > 0.1) {
            const headerRes = await checkSecurityHeaders(window.location.href);
            if (headerRes && headerRes.score > 0) {
                payload.score += headerRes.score;
                // Cap score
                if (payload.score > 1.0) payload.score = 1.0;
                payload.reasons.push(`Weak Security Headers: ${headerRes.missing.join(", ")}`);
            }
        }

        console.log("ANALYSIS_SENT", payload);

        // 3. Start Behavioral Monitoring
        setupBehavioralAnalysis();

        // PHASE 4.5 & 4.6: Trigger Assistant on Load (Tiered Logic)
        const tier = payload.tier;

        // Tier 1 & 2: NEVER show Bubble/Voice on load
        if (tier === 1 || tier === 2) {
            console.log("AntiPhish: Assistant suppressed (Tier matched).");
        }
        // Tier 3: Only High Risk Bubble (Voice suppressed unless Blocked) 
        else if (tier === 3) {
            if (payload.score >= 0.60 && payload.categoriesHit.length >= 2) {
                const msg = "Warning. Sensitive platform showing unusual behavior.";
                assistant.showBubble("warning", msg);
                // No voice for Tier 3 load, only visual
            }
        }
        // Non-Tiered: Normal Behavior
        else {
            // PHASE 5: Check for AI Manipulation specifically
            const hasAIManipulation = payload.categoriesHit.includes("AI Manipulation");

            if (hasAIManipulation) {
                // Show dedicated AI manipulation warning
                showAIManipulationWarning(payload);
            } else if (payload.score >= 0.60 && payload.categoriesHit.length >= 2) {
                const msg = "Warning. This page closely matches phishing behavior. I recommend leaving this site.";
                assistant.showBubble("warning", msg);
                assistant.speak(msg);
            } else if (payload.score >= 0.30) {
                const msg = "Caution. This page shows suspicious signs. Avoid entering sensitive information.";
                assistant.showBubble("caution", msg);
            }
        }

        chrome.runtime.sendMessage({
            type: "PHISHING_ANALYSIS",
            payload: payload
        });
    } catch (err) {
        console.error("AntiPhish analysis error:", err);
    }
}

// 1. Run on Load
// Moved to end of file to ensure Assistant is initialized
// runAndSendExectuion();

// 2. Listen for re-run requests from popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "RUN_ANALYSIS") {
        runAndSendExectuion();
        sendResponse({ initiated: true });
    }
});


// =============================================================================
// PHASE 3: AUTOMATED PROTECTION & INTERCEPTION
// =============================================================================

// High-confidence override for current page load
let ignoreBlock = false;

// 1. Form Submission Interceptor (Capture Phase)
window.addEventListener("submit", async function (e) {
    if (ignoreBlock) return;

    const target = e.target;
    // Heuristic: Only protect relevant forms
    // Check for password fields OR suspicious email forms
    // We re-scan the specific form triggering the submit
    const hasPassword = target.querySelector('input[type="password"]');
    const hasEmail = target.querySelector('input[type="email"], input[name*="email"]');

    // Skip benign forms (search bars etc) unless strictly configured
    if (!hasPassword && !hasEmail) return;

    // Halt immediately to query background
    e.preventDefault();
    e.stopPropagation();
    console.log("AntiPhish: Intercepted potentially dangerous form submission.");

    // Function to proceed if allowed
    const releaseForm = () => {
        ignoreBlock = true;
        // Re-trigger submit programmatically
        if (target.requestSubmit) {
            target.requestSubmit();
        } else {
            target.submit();
        }
    };

    // Ask Background for decision
    // Note: We send current settings if we had them, OR background fetches values
    // For local simplicity, we assume generic defaults or fetch async
    chrome.runtime.sendMessage({
        type: "FORM_SUBMIT_ATTEMPT",
        settings: { autoProtectEnabled: true } // In real app, sync this
    }, (response) => {
        if (response && response.block) {
            console.warn("AntiPhish: BLOCKED submission. Reason:", response.reason);
            showBlockingModal(response.analysis, releaseForm);
        } else {
            console.log("AntiPhish: Allowed submission.");
            releaseForm();
        }
    });

}, true); // Use Capture to beat other listeners


// =============================================================================
// PHASE 4.5: GUARDIAN ASSISTANT (Presentation Layer)
// =============================================================================

class GuardianAssistant {
    constructor() {
        this.bubbleOpen = false;
        this.settings = { assistant_enabled: true, voice_enabled: true };
        this.voicesLoaded = false;

        this.loadSettings();
        this.initVoice();
    }

    loadSettings() {
        // Default to ON if not set
        chrome.storage.local.get(['assistant_enabled', 'voice_enabled'], (res) => {
            if (res.assistant_enabled !== undefined) this.settings.assistant_enabled = res.assistant_enabled;
            if (res.voice_enabled !== undefined) this.settings.voice_enabled = res.voice_enabled;
        });

        // Listen for changes
        chrome.storage.onChanged.addListener((changes) => {
            if (changes.assistant_enabled) this.settings.assistant_enabled = changes.assistant_enabled.newValue;
            if (changes.voice_enabled) this.settings.voice_enabled = changes.voice_enabled.newValue;
        });
    }

    initVoice() {
        if (window.speechSynthesis.onvoiceschanged !== undefined) {
            window.speechSynthesis.onvoiceschanged = () => {
                this.voicesLoaded = true;
            };
        }
    }

    // --- UI: Bubble ---

    showBubble(type, message) {
        if (!this.settings.assistant_enabled) return;
        if (this.bubbleOpen) return; // Prevent spam

        const host = document.createElement('div');
        host.id = "antiphish-assistant-host";
        document.body.appendChild(host);
        const shadow = host.attachShadow({ mode: 'closed' });

        // CRITICAL: Use getURL for icon
        const iconUrl = chrome.runtime.getURL("icons/assistant.png");

        shadow.innerHTML = `
        <style>
            :host { all: initial; }
            .assistant-container {
                position: fixed; bottom: 20px; right: 20px; z-index: 2147483646;
                display: flex; flex-direction: column; align-items: flex-end;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                pointer-events: none; /* Let clicks pass near it */
            }
            .bubble {
                background: #fff; color: #333; padding: 12px 16px; border-radius: 12px;
                border-bottom-right-radius: 2px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                margin-bottom: 8px; font-size: 13px; line-height: 1.4;
                max-width: 260px; pointer-events: auto; opacity: 0;
                transform: translateY(10px); animation: fadeIn 0.3s forwards;
                border: 1px solid #e0e0e0;
            }
            .bubble.caution { border-left: 4px solid #f9ab00; }
            .bubble.warning { border-left: 4px solid #d93025; }
            
            .avatar {
                width: 44px; height: 44px; border-radius: 50%;
                box-shadow: 0 2px 5px rgba(0,0,0,0.2);
                border: 2px solid #fff; pointer-events: auto;
                cursor: pointer;
                background: #eee;
            }
            
            @keyframes fadeIn {
                to { opacity: 1; transform: translateY(0); }
            }
            @keyframes fadeOut {
                to { opacity: 0; transform: translateY(5px); }
            }
        </style>
        <div class="assistant-container">
            <div class="bubble ${type}">
                ${message}
            </div>
            <img src="${iconUrl}" class="avatar" width="44" height="44" alt="Assistant">
        </div>
        `;

        this.bubbleOpen = true;

        // Auto-dismiss logic (8 seconds)
        const container = shadow.querySelector('.assistant-container');
        setTimeout(() => {
            if (host.isConnected) {
                container.style.animation = "fadeOut 0.5s forwards";
                setTimeout(() => host.remove(), 500);
                this.bubbleOpen = false;
            }
        }, 8000);

        // Manual Dismiss
        shadow.querySelector('.avatar').onclick = () => {
            host.remove();
            this.bubbleOpen = false;
        };
    }

    // --- Audio: TTS ---

    speak(text) {
        if (!this.settings.voice_enabled) return;

        // Cancel previous
        window.speechSynthesis.cancel();

        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = 0.95;
        utterance.volume = 0.9;
        utterance.pitch = 1.1; // Slightly higher pitch for female-leaning

        const voices = window.speechSynthesis.getVoices();

        // Female Voice Selection Strategy
        // Priority: Specific female names -> general female signs -> Google US English -> First English
        const priorityNames = ["zira", "aria", "susan", "emma", "samantha"];

        let selectedVoice = voices.find(v => priorityNames.some(name => v.name.toLowerCase().includes(name)));

        if (!selectedVoice) {
            selectedVoice = voices.find(v => v.name.toLowerCase().includes("google us english"));
        }

        if (!selectedVoice) {
            selectedVoice = voices.find(v => v.lang.startsWith('en'));
        }

        if (selectedVoice) {
            utterance.voice = selectedVoice;
            // console.log("Guardian Voice:", selectedVoice.name);
        }

        window.speechSynthesis.speak(utterance);
    }
}

// Instantiate Global Assistant
const assistant = new GuardianAssistant();


// --- INTEGRATION POINTS ---

// 1. AI Manipulation Warning Popup (Phase 5)
function showAIManipulationWarning(analysis) {
    // Show Guardian bubble first
    const bubbleMsg = "Alert! This page is attempting to manipulate AI assistants. It may be trying to steal information or provide harmful instructions.";
    assistant.showBubble("warning", bubbleMsg);
    assistant.speak("Warning. This website contains hidden instructions targeting AI assistants. I recommend leaving immediately.");

    // PHASE 7: Send Telegram Voice Alert for AI manipulation
    chrome.runtime.sendMessage({ type: "SEND_TELEGRAM_ALERT", analysis: analysis });

    // Create dedicated popup
    const host = document.createElement('div');
    host.id = "antiphish-ai-warning-host";
    document.body.appendChild(host);

    const shadow = host.attachShadow({ mode: 'closed' });

    const score = analysis.score || 0;
    const aiReasons = analysis.reasons.filter(r =>
        r.includes('Hidden text') ||
        r.includes('Invisible characters') ||
        r.includes('AI manipulation') ||
        r.includes('meta tag')
    ).slice(0, 4);

    const reasonsList = aiReasons.map(r => `<li>🔴 ${r}</li>`).join('');

    shadow.innerHTML = `
    <style>
        :host { all: initial; }
        .overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(135deg, rgba(220, 38, 38, 0.95), rgba(153, 27, 27, 0.95));
            z-index: 2147483647;
            display: flex; align-items: center; justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            animation: fadeIn 0.3s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        .modal {
            background: #fff; 
            max-width: 550px; 
            width: 90%;
            padding: 0;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            overflow: hidden;
            animation: slideUp 0.4s ease-out;
        }
        @keyframes slideUp {
            from { transform: translateY(50px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        .header {
            background: linear-gradient(135deg, #dc2626, #991b1b);
            padding: 30px;
            text-align: center;
            color: white;
            position: relative;
            overflow: hidden;
        }
        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: rotate 10s linear infinite;
        }
        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        .icon {
            font-size: 64px;
            margin-bottom: 10px;
            animation: pulse 2s ease-in-out infinite;
            position: relative;
            z-index: 1;
        }
        h2 {
            margin: 0;
            font-size: 24px;
            font-weight: 700;
            position: relative;
            z-index: 1;
        }
        .subtitle {
            font-size: 13px;
            opacity: 0.95;
            margin-top: 8px;
            font-weight: 500;
            position: relative;
            z-index: 1;
        }
        .content {
            padding: 30px;
        }
        .alert-box {
            background: #fef2f2;
            border-left: 4px solid #dc2626;
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .alert-title {
            font-weight: 700;
            color: #991b1b;
            margin-bottom: 8px;
            font-size: 15px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .alert-text {
            font-size: 13px;
            color: #7f1d1d;
            line-height: 1.5;
        }
        .threat-details {
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 20px;
        }
        .threat-details h3 {
            margin: 0 0 12px 0;
            font-size: 14px;
            color: #374151;
            font-weight: 600;
        }
        .threat-details ul {
            margin: 0;
            padding-left: 0;
            list-style: none;
        }
        .threat-details li {
            font-size: 13px;
            color: #6b7280;
            margin-bottom: 8px;
            padding-left: 8px;
            line-height: 1.4;
        }
        .risk-meter {
            background: #f3f4f6;
            border-radius: 8px;
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .risk-label {
            font-size: 12px;
            font-weight: 600;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .risk-value {
            font-size: 20px;
            font-weight: 700;
            color: #dc2626;
        }
        .actions {
            display: flex;
            gap: 12px;
        }
        button {
            flex: 1;
            padding: 14px;
            border-radius: 8px;
            border: none;
            font-weight: 600;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }
        .btn-safe {
            background: #dc2626;
            color: #fff;
            box-shadow: 0 4px 12px rgba(220, 38, 38, 0.3);
        }
        .btn-safe:hover {
            background: #b91c1c;
            transform: translateY(-1px);
            box-shadow: 0 6px 16px rgba(220, 38, 38, 0.4);
        }
        .btn-dismiss {
            background: transparent;
            border: 2px solid #d1d5db;
            color: #6b7280;
        }
        .btn-dismiss:hover {
            background: #f3f4f6;
            border-color: #9ca3af;
        }
        .footer {
            margin-top: 20px;
            padding-top: 16px;
            border-top: 1px solid #e5e7eb;
            font-size: 11px;
            color: #9ca3af;
            text-align: center;
        }
    </style>
    <div class="overlay">
        <div class="modal">
            <div class="header">
                <div class="icon">🤖⚠️</div>
                <h2>AI Manipulation Attempt Detected</h2>
                <div class="subtitle">This page is trying to manipulate AI assistants</div>
            </div>
            <div class="content">
                <div class="alert-box">
                    <div class="alert-title">
                        <span>⚡</span>
                        <span>Client-Side Information Theft Risk</span>
                    </div>
                    <div class="alert-text">
                        This website contains hidden instructions designed to manipulate AI assistants 
                        (like ChatGPT, Perplexity, Claude). These instructions may attempt to:
                        <br>• Extract your browsing data or personal information
                        <br>• Provide harmful or malicious advice
                        <br>• Bypass security guidelines
                    </div>
                </div>

                <div class="threat-details">
                    <h3>🔍 Detected Threats:</h3>
                    <ul>${reasonsList}</ul>
                </div>

                <div class="risk-meter">
                    <span class="risk-label">Threat Level</span>
                    <span class="risk-value">CRITICAL (${(score * 100).toFixed(0)}%)</span>
                </div>

                <div class="actions">
                    <button class="btn-safe" id="leaveBtn">🛡️ Leave Immediately</button>
                    <button class="btn-dismiss" id="dismissBtn">Dismiss Warning</button>
                </div>

                <div class="footer">
                    🔒 AntiPhish Guardian • Phase 5: AI Manipulation Defense
                </div>
            </div>
        </div>
    </div>
    `;

    shadow.getElementById('leaveBtn').onclick = () => {
        window.location.href = "about:blank";
    };

    shadow.getElementById('dismissBtn').onclick = () => {
        if (confirm("⚠️ Are you sure? This page may attempt to manipulate AI assistants to steal your data or provide harmful advice.\n\nOnly dismiss if you understand the risks.")) {
            host.remove();
            // Remove assistant bubble
            const bubble = document.getElementById("antiphish-assistant-host");
            if (bubble) bubble.remove();
        }
    };
}

// 2. Blocking Modal (Shadow DOM)
// Updated to integrate with Assistant
function showBlockingModal(analysis, onOverride) {
    // 1. Show Assistant Message (Blocked)
    const blockedMsg = "I blocked this action to protect your account from credential theft.";
    assistant.showBubble("warning", blockedMsg);
    assistant.speak(blockedMsg);

    // PHASE 7: Send Telegram Voice Alert for form block
    chrome.runtime.sendMessage({ type: "SEND_TELEGRAM_ALERT", analysis: analysis });

    const host = document.createElement('div');
    host.id = "antiphish-guardian-host";
    document.body.appendChild(host);

    const shadow = host.attachShadow({ mode: 'closed' });

    const score = analysis.score || 0;
    const reasons = (analysis.reasons || []).slice(0, 3).map(r => `<li>${r}</li>`).join("");

    shadow.innerHTML = `
    <style>
        :host { all: initial; }
        .overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.85);
            z-index: 2147483647;
            display: flex; align-items: center; justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
        }
        .modal {
            background: #fff; width: 450px; padding: 30px; border-radius: 8px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5); text-align: center;
            border-top: 6px solid #d93025;
        }
        h2 { margin-top: 0; color: #d93025; font-size: 22px; }
        .risk { font-size: 14px; color: #5f6368; margin-bottom: 20px; }
        .reasons { text-align: left; background: #fdf2f2; padding: 15px; border-radius: 4px; margin-bottom: 20px; font-size: 13px; color: #a50e0e; }
        .reasons ul { margin: 0; padding-left: 20px; }
        .reasons li { margin-bottom: 6px; }
        .actions { display: flex; justify-content: space-between; gap: 10px; }
        button {
            flex: 1; padding: 10px; border-radius: 4px; border: none; font-weight: 600; cursor: pointer;
            font-size: 14px;
        }
        .btn-safe { background: #1a73e8; color: #fff; }
        .btn-safe:hover { background: #1557b0; }
        .btn-danger { background: transparent; border: 1px solid #dadce0; color: #5f6368; }
        .btn-danger:hover { background: #f1f3f4; color: #1a73e8; }
        .footer { margin-top: 15px; font-size: 11px; color: #70757a; }
    </style>
    <div class="overlay">
        <div class="modal">
            <h2>🚫 Phishing Attempt Blocked</h2>
            <div class="risk">
                This page (<strong>${analysis.hostname}</strong>) has been identified as High Risk (Score: ${score}).
            </div>
            <div class="reasons">
                <strong>Why?</strong>
                <ul>${reasons}</ul>
                <div style="margin-top:8px; font-weight:normal;"><i>Session cookies for this domain have been cleared.</i></div>
            </div>
            <div class="actions">
                <button class="btn-danger" id="overrideBtn">Continue Anyway (Unsafe)</button>
                <button class="btn-safe" id="leaveBtn">Leave Page</button>
            </div>
            <div class="footer">
                AntiPhish Guardian • Automated Protection
            </div>
        </div>
    </div>
    `;

    shadow.getElementById('leaveBtn').onclick = () => {
        window.location.href = "about:blank"; // Or google.com
    };

    shadow.getElementById('overrideBtn').onclick = () => {
        if (confirm("Are you sure? This will submit your credentials to a potentially malicious site.")) {
            // PHASE 4: Log Override
            chrome.runtime.sendMessage({
                type: "PHASE4_FEEDBACK",
                action: "override",
                hostname: analysis.hostname
            });
            host.remove();

            // Remove Assistant Bubble on override
            const bubble = document.getElementById("antiphish-assistant-host");
            if (bubble) bubble.remove();

            onOverride();
        }
    };
}

// 1. Run on Load (Delayed to ensure Assistant is ready)
runAndSendExectuion();
