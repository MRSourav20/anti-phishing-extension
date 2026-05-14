# AntiPhish Guardian — Phase 2 (Tuned Implementation)

## Overview
This phase introduces a sophisticated, deterministic phishing detection engine that runs entirely client-side. It evaluates pages based on four signal categories: **Language**, **Form**, **Domain**, and **Behavior**.

## How to Load
1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer Mode**.
3. Click **Load Unpacked** and select the `anti-phish-extension` folder.
4. **IMPORTANT:** To run local file tests, find the extension in the list, click **Details**, and toggle **"Allow access to file URLs"** to ON.

## How to Run Tests
Open the HTML files in the `tests/` directory directly in Chrome.

| Test File | Expected Level | Expected Reason |
|-----------|----------------|----------------|
| `low_test.html` | **LOW** | Score < 0.3. No signals. |
| `medium_kw_only.html` | **LOW/MED** | Score ~0.2-0.3. "Suspicious keyword". Capped by `lang_only_cap`. |
| `medium_pwd_no_domain.html` | **MEDIUM** | Score ~0.35. "Password field detected". Single category (Form). |
| `high_http_form.html` | **HIGH** | Score > 0.6. "Insecure (HTTP) form submission" + Password + Keywords. |
| `high_typosquat.html` | **HIGH** | Score > 0.6. "Possible typosquatting of google.com" + Password. |

## Tuning Philosophy
- **Weights:** Granular weights (0.05 - 0.35) allow for nuance.
- **Caps:** Single-category signals (e.g., just a password field on a safe internal tool) are capped to prevent False Positives.
- **Combination Rule:** A **HIGH** risk verdict requires both a high score (≥ 0.60) AND detection in at least **2 distinct categories** (e.g., Form + Domain).

## Tuning Log
**Iteration 1:**
- Initial tests showed `medium_kw_only.html` hit High score due to keyword spamming.
- *Action:* Introduced `keyword_max` (0.30) and `lang_only_cap` (0.45).
- *Result:* Test now correctly classifies as Low/Medium risk, requiring corroborating signals (like a password field) to escalate.

**Iteration 2:**
- `google.com` login page triggered "Password field" score.
- *Action:* Added `allowlist` damping. If domain matches allowlist, total score is halved.
- *Result:* Known safe sites stay green.
