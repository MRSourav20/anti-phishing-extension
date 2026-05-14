# AntiPhish Guardian — Phase 2 (Rule-Based Detection)
Deterministic, explainable phishing detection foundation.

## Purpose
Phase 2: Adds real-time analysis of page content to detect likely phishing attempts.
- computes a 0–1 risk score
- provides human-readable reasons (suspicious keywords, password fields, mismatches)
- displays risk level in the popup

## Files
- manifest.json
- content.js (Detection logic added)
- background.js (Analysis storage added)
- popup.html
- popup.js (Analysis visualization added)
- phish_test.html (Test file)
- icons/*

## How to load (Chrome)
1. Open Chrome and go to: chrome://extensions
2. Enable "Developer mode" (top-right).
3. If already loaded: Click the **Reload** (circular arrow) icon on the AntiPhish card.
4. If not loaded: Click "Load unpacked" and select the `anti-phish-extension/` folder.

## How to verify (Phase 2 Checks)

### 1. Safe Page Test (e.g., example.com)
1. Visit https://example.com.
2. Click the extension icon.
3. **Expect:**
   - Status: "Phase 2 analysis loaded."
   - Risk Level: **Low**
   - Reasons: "None detected" (or similar)

### 2. Phishing Test Page
1. Open the local file `phish_test.html` in Chrome (drag and drop it into a tab).
2. Click the extension icon.
3. **Expect:**
   - Risk Level: **High** (Score >= 0.7)
   - Reasons list should include:
     - `Suspicious keyword: "verify your account"`
     - `Password field detected on this page`
     - `Form posts to different domain...` (if applicable)

### 3. Background Logs
1. Inspect the Service Worker (chrome://extensions).
2. Reload a page.
3. **Expect log:** `AntiPhish: stored analysis for tab <id> { ... }`.

## Common issues & fixes
- **Popup says "No analysis yet":** Wait 1 second after page load, then click refresh. Ensure extension was reloaded.
- **Score is 0 on test page:** Ensure scripts are allowed to run on local files (or host `phish_test.html` on a local server).
- **Errors in console:** Check if `content.js` sent the message successfully.
