# AntiPhish Guardian: Comprehensive Technical Report

**Project Version:** 0.5.0 (Phase 5: AI Manipulation Defense)
**Platform:** Google Chrome Extension (Manifest V3)
**Architecture:** Client-Side Heuristic Analysis + Local Intelligence Layer

---

## 1. Executive Summary

AntiPhish Guardian is a **privacy-first, client-side browser extension** designed to detect and block phishing attacks in real-time. Unlike traditional solutions that rely on cloud-based blocklists, AntiPhish Guardian employs a **deterministic local detection engine**. It analyzes the content, structure, and behavior of every visited page to calculate a risk score.

**New in Version 0.5.0 (Phase 5):**
*   **AI Manipulation Defense:** Detection of prompt injection attacks targeting AI assistants (ChatGPT, Perplexity, Claude). Identifies hidden text, invisible Unicode, and AI manipulation keywords.
*   **Fifth Detection Category:** "AI Manipulation" with weights for hidden text (0.20), invisible chars (0.15), and prompt injection patterns (0.25).

**Previous Features:**
*   **Adaptive Intelligence:** A local Reputation Store that learns from user context (e.g., dampening risk for overrides, increasing risk for repeated offenders).
*   **Guardian Assistant:** A user-friendly "Assistant" bubble and Text-to-Speech (TTS) engine that explains threats clearly to non-technical users.
*   **Tiered Trusted Sites:** A fine-tuned system that suppresses alarms on known-safe platforms (e.g., Google, GitHub) while maintaining background vigilance.

---

## 2. Core Philosophy & Theoretical Concepts

### A. Threat Modeling
The system defends against specific attack vectors:
*   **Social Engineering:** Exploitation of human psychology (urgency, fear, authority).
*   **Typosquatting (URL Hijacking):** Domains visually similar to legitimate ones (e.g., `g0ogle.com`).
*   **Data Exfiltration:** Forms submitting data to cross-origin or insecure endpoints.
*   **AI Manipulation (Phase 5):** Prompt injection attacks targeting AI assistants through hidden text, invisible Unicode, and manipulation keywords.

### B. Heuristic vs. Reputation-Based Security
*   **Reputation-Based (Traditional):** Checks a URL against a known database. Vulnerable to 0-day attacks.
*   **Heuristic (AntiPhish Guardian):** Analyzes the page's anatomy real-time. **Zero-latency detection** of brand new attacks.

### C. Privacy by Design
*   **Local Processing:** No URL, DOM content, or user input is ever sent to a remote server.
*   **Isolated Contexts:** Utilizing Chrome's isolated world architecture.

---

## 3. Technical Architecture (Manifest V3)

The extension comprises three primary components communicating via the Chrome Messaging API.

### 1. Content Script (`content.js`) — The "Eye"
Injects into the user's web page (DOM).
*   **Responsibility:** Analysis & Interception & Assistant UI.
*   **Detection Logic:** Parses DOM for high-risk signals (password fields, hidden inputs), calculates **Levenshtein Distance**, scans text for NLP triggers.
*   **Guardian Assistant:** Renders a Shadow DOM floating bubble and speaks audio warnings for High Risk sites.

### 2. Service Worker (`background.js`) — The "Brain"
Runs in the background, independent of tabs.
*   **Responsibility:** State, Decisions, & Privileged Actions.
*   **Reputation Store (Phase 4):** Tracks `encounterCount`, `blockCount`, and `overrideCount` locally. Adjusts scores based on history.
*   **Logic:** Evaluates `shouldAutoProtect()` policies and executes **Cookie Clearing**.

### 3. User Interface (`popup.html/js`) — The "Control"
*   **Responsibility:** Transparency.
*   **Features:** Displays Risk Score, specific reasons (e.g., "New Domain"), and controls for Assistant/Voice.

---

## 4. Detection Engine (Scoring Algorithm)

The engine calculates a cumulative score based on weighted categories.

| Category | Weight | Description |
| :--- | :--- | :--- |
| **Language** | Low (0.08) | Urgency keywords ("Verify", "Suspended"). |
| **Form** | High (0.35) | Presence of `input[type="password"]`, generic submit buttons. |
| **Domain** | High (0.30) | Typosquatting distance < 25%, Raw IP URLs, Suspicious TLDs. |
| **Behavior** | Medium (0.25) | Cross-origin form actions, HTTP POST on HTTPS. |
| **AI Manipulation (Phase 5)** | **High (0.60 max)** | **Hidden text (0.20), Invisible chars (0.15), Prompt injection (0.25).** |
| **Reputation (New)** | Dynamic | +/- 0.35 based on Domain Age and Block History. |

**Verdict Logic:**
*   **SAFE:** Score < 0.30
*   **MEDIUM:** Score ≥ 0.30 (Caution Bubble)
*   **HIGH:** Score ≥ 0.60 **AND** ≥ 2 Categories triggered (Auto-Block + Voice Warning).

---

## 5. Automated Protection Workflow (Active Defense)

When a user attempts to submit a form on a **High Risk** page:

1.  **Interception:** `content.js` captures the `submit`.
2.  **Kill Switch:** `background.js` wipes all cookies for the `hostname`.
3.  **Notification:** A Red Warning Modal appears via Shadow DOM.
4.  **Assistant:** Voice engine speaks: *"I blocked this action to protect your account..."*
5.  **User Choice:**
    *   **Leave Page:** Redirects to safety.
    *   **Continue Anyway:** One-time override. The system *learns* this decision and dampens risk for future visits.

---

## 6. Tiered Authorized Sites (Fine-Tuning)

To prevent "Warning Fatigue", the system uses a tiered approach for known entities:

*   **Tier 1 (Silent Trusted):** Google, Microsoft, Amazon. Score dampened significantly. No UI alerts.
*   **Tier 2 (Professional):** GitHub, LinkedIn. Score dampened. No UI alerts.
*   **Tier 3 (Sensitive):** PayPal, Zoom. Monitored strictly. Alerts only on Block.

---

## 7. Verification & Testing

A Proof-of-Concept test suite (`tests_phase3/`) validates the engine:

*   **`high_typosquat.html`:** Simulates `g0ogle.com` + Login Form. -> **Blocked + Voice Warning.**
*   **`high_http_form.html`:** Simulates insecure HTTP submission. -> **Blocked.**
*   **`legit_login.html`:** Clean login page. -> **Allowed (Silent).**

---

## 8. Conclusion

AntiPhish Guardian illustrates that **Adaptive Intelligence** can exist entirely client-side. By combining static heuristics with a local reputation store and user-friendly "Assistant" persona, it achieves high security without the privacy trade-offs of cloud scanning.
