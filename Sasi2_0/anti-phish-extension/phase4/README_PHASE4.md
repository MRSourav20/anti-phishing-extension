# AntiPhish Guardian - Phase 4: Adaptive Intelligence

## Overview
Phase 4 introduces an **Adaptive Intelligence Layer** that runs locally on the user's machine. It augments the static rules (Phase 2) with a **Reputation Store** and **Re-Ranker** to detect borderline threats that strictly rule-based systems might miss (e.g., "freshly registered domains" or "repeatedly blocked" sites).

## Features

### 1. Reputation Store (Persistent Memory)
- Tracks `encounterCount`, `blockCount`, and `overrideCount` for every hostname.
- **Privacy:** Stored locally in `chrome.storage.local`. Hostnames are hashed (SHA-256) internally (though stored as samples for debug).
- **Decay:** Reputation influence decays over time (default 30 days).

### 2. Explainable Re-Ranker
- Adjusts the **Base Risk Score** (Phase 2) based on context.
- **Example:**
    - Base Score: 0.50 (Medium)
    - Re-Ranker: +0.18 (New Domain < 30 days)
    - Evaluation: 0.68 (High) -> **BLOCK**
- **Transparency:** The popup displays the exact math: `Base: 0.50 | Rep: +0.18 | Final: 0.68`.

### 3. Feedback Loop
- **Override Dampening:** If a user clicks "Continue Anyway" on a block, the system learns and applies a negative score adjustment (`-0.08`) to that domain for future visits, preventing "Warning Fatigue" on false positives.

## Configuration
Tunable parameters in `config/phase4_config.json`:
- `newDomainAdjustment`: Score penalty for young domains.
- `blockMassAdjustmentPerBlock`: Score penalty for repeated blocks.
- `sensitivityPresets`: Scaling factors for different risk appetites.

## Testing Phase 4
See `demo_script_phase4.txt` for a step-by-step walkthrough.

1. **Verify Score Uplift:** Visit a site with overrides/blocks and watch the score change in the Popup.
2. **Verify New Domain:** (Simulated via code or config tweak) triggers higher scores.
3. **Verify Privacy:** Check `chrome.storage.local` to see only hashed/local data.
