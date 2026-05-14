# Quick Test Guide - Phase 5 Prompt Injection Detection

## Step-by-Step Testing

### 1. Reload the Extension ⚙️

**Before testing, you MUST reload the extension to apply code changes:**

1. Open Chrome and go to: `chrome://extensions`
2. Find **AntiPhish Guardian** in the list
3. Click the **↻ Reload** button (circular arrow icon)
4. ✅ Extension is now running with Phase 5 code

---

### 2. Test Prompt Injection Detection 🧪

**Page already open in your browser:** `http://localhost:8000/tests/prompt_injection_test.html`

#### What to Do:

1. **Refresh the page** (F5) to trigger detection
2. **Wait 1-2 seconds** for analysis
3. **Click the extension icon** in toolbar (puzzle piece icon → AntiPhish Guardian)

#### Expected Results:

✅ **Risk Level:** HIGH (score ~0.85+)  
✅ **Categories Hit:** Should include **"AI Manipulation"**  
✅ **Reasons displayed:**
- "Hidden text detected with AI instruction patterns"
- "Invisible characters detected (X instances, potential manipulation)"
- "AI manipulation keyword detected: [keyword name]"

✅ **Guardian Assistant:** Warning bubble should appear in bottom-right corner  
✅ **Voice Alert:** May trigger if voice is enabled

---

### 3. Test Hidden Text Page 🔍

**URL:** `http://localhost:8000/tests/hidden_text_test.html`

1. Navigate to URL
2. Wait for analysis
3. Click extension icon

**Expected:** MEDIUM-HIGH risk with "AI Manipulation" category

---

### 4. Verify No False Positives ✓

Test on legitimate sites:
- `https://google.com` → Should be SAFE (Tier 1)
- `https://github.com` → Should be SAFE (Tier 2)

---

## Troubleshooting

**If detection doesn't work:**

1. ✅ **Did you reload the extension?** (Step 1 above)
2. ✅ **Refresh the test page** after reloading extension
3. ✅ **Check console:** Right-click page → Inspect → Console tab
   - Look for: `ANALYSIS_SENT` with payload object
   - Should show `categoriesHit` including "AI Manipulation"

4. ✅ **Check Service Worker:**
   - Go to `chrome://extensions`
   - Click "Inspect views: Service Worker" under AntiPhish Guardian
   - Look for analysis storage logs

---

## Console Commands (Advanced)

Open console on test page (F12) and run:

```javascript
// Check if detection function exists
console.log(typeof detectPromptInjection);
// Should output: "function"

// Manually trigger detection
analyzePageForPhishTuned();
```

---

## What's Being Detected

The **prompt_injection_test.html** page contains:

1. **Hidden divs** with text like:
   - "ignore previous instructions"
   - "jailbreak mode"
   - "bypass all filters"

2. **~50+ zero-width characters** embedded invisibly

3. **Visible keywords** mentioned in educational sections

**All of these should trigger the AI Manipulation detection!**

---

## Next: Real-World Testing

After verifying test pages work, try browsing normally. The extension will now protect you from:
- Malicious sites trying to manipulate AI assistants
- Hidden prompt injection attacks
- Invisible Unicode smuggling

**All while maintaining 100% privacy - no data leaves your browser!**
