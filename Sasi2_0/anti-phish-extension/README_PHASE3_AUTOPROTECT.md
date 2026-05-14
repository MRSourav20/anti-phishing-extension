# AntiPhish Guardian — Phase 3 (Automated Protection)

## Overview
Phase 3 upgrades the extension from a passive detector to an active **prevention tool**. It intercepts submissions on pages identified as High Risk (Score >= 0.60 + 2 categories) and clears session cookies for the malicious host.

## Features
- **Auto-Block:** Intercepts `submit` events on forms with passwords or emails.
- **Cookie Clearing:** Removes all cookies for the detected hostname (and subdomains) upon block logic trigger.
- **Fail-Safe UI:** Shadow DOM modal allows "Emergency Override" (Continue Anyway).
- **Local Logs:** Popup shows recent automated actions.

## Privacy & Security
- **Local Execution:** All decisions happen content-side and in the service worker. No URL or input data is sent to cloud servers.
- **Cookie Safety:** Only deletes cookies for the *detected unsafe domain*.
- **Undo:** Users can "Continue Anyway" if it was a false positive (one-time override).

## How to Test Protection

### 1. High Risk Block
1. Open `tests_phase3/high_typosquat.html`.
2. Enter dummy credentials.
3. Click "Log In".
4. **Result:**
   - Form submission halted.
   - Red "Phishing Attempt Blocked" modal appears.
   - Background console logs: `Cleared X cookies for ...`.

### 2. Override
1. On the valid block modal, click **"Continue Anyway (Unsafe)"**.
2. Confirm the alert.
3. Form submits.

### 3. Medium Risk (No Block)
1. Open `tests_phase3/medium_form.html`.
2. Click Submit.
3. Result: Form submits normally (Auto-Protect defaults to HIGH only).

## Architecture
1. **User Cliks Submit** -> 2. **Content Script Intercepts** -> 3. **Msg Background** -> 4. **Check Risk Score** -> 5. **If High: Clear Cookies + Return Block** -> 6. **Show Modal**.
