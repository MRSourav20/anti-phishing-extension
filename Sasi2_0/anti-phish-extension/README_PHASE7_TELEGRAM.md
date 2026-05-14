# AntiPhish Guardian — Phase 7: Remote Telegram Voice Alerts

**Version:** 0.7.0  
**New Feature:** Telegram Bot integration with TTS voice alerts

---

## Overview

Phase 7 adds **Remote Telegram Voice Alerts** — when the extension blocks a phishing site (HIGH or CRITICAL risk), a voice summary is generated and delivered to the user's Telegram account.

**Architecture:**
```
Extension → Backend (HTTPS POST) → TTS Provider → Telegram Bot → User
```

---

## How It Works

1. **User enables** "Telegram Voice Alerts" in the extension popup.
2. **Consent dialog** explains exactly what data is sent (URL, score, reasons, timestamp — never cookies/passwords/DOM).
3. **Unique userId** is generated (`crypto.randomUUID()`) and registered with the backend.
4. **User messages** the Telegram bot with their userId to link their Telegram account.
5. **On every HIGH/CRITICAL block**, the extension sends a minimal payload to the backend.
6. **Backend generates** a TTS voice summary (ElevenLabs or Sarvam AI) and sends it as a Telegram voice message.

---

## Setup Guide

### Step 1: Create a Telegram Bot

1. Open Telegram and search for **@BotFather**.
2. Send `/newbot` and follow the prompts.
3. Copy the **Bot Token** (e.g., `7123456789:AAF...`).
4. Note the bot username (e.g., `@AntiPhishGuardianBot`).

### Step 2: Configure the Backend

```bash
cd backend
cp .env.example .env
```

Edit `.env`:
```
TELEGRAM_BOT_TOKEN=7123456789:AAFyour_token_here
TTS_PROVIDER=elevenlabs
TTS_API_KEY=your_elevenlabs_key_here
PORT=3000
```

### Step 3: Install & Run

```bash
npm install
npm start
```

You should see:
```
╔══════════════════════════════════════════════════╗
║   AntiPhish Guardian — Telegram Alert Backend    ║
║   Port: 3000                                     ║
║   TTS Provider: elevenlabs                       ║
║   Bot Token: ✅ Set                               ║
║   TTS Key: ✅ Set                                 ║
╚══════════════════════════════════════════════════╝
```

### Step 4: Set Up Telegram Webhook (Optional)

For automatic chatId linking via the bot, set up a webhook:

```bash
curl "https://api.telegram.org/bot<YOUR_TOKEN>/setWebhook?url=https://your-domain.com/telegram-webhook"
```

### Step 5: Link Your Telegram Account

1. Open AntiPhish Guardian popup → enable "Telegram Voice Alerts".
2. Copy your User ID shown in the popup.
3. Open Telegram → message your bot: `/start YOUR_USER_ID`
4. You'll receive a confirmation message.

---

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/register` | POST | Register userId (from extension) |
| `/alert` | POST | Receive incident, generate TTS, send to Telegram |
| `/telegram-webhook` | POST | Telegram bot webhook for chatId linking |
| `/health` | GET | Server health check |

### Alert Payload (sent by extension)

```json
{
  "userId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "incidentId": "f9e8d7c6-b5a4-3210-fedc-ba9876543210",
  "url": "http://g0ogle-login.xyz/verify",
  "riskScore": 0.85,
  "reasons": ["Typosquatting of google.com", "Password field detected"],
  "timestamp": "2026-02-27T01:00:00.000Z"
}
```

---

## TTS Providers

| Provider | Language | Config Key |
|----------|----------|------------|
| **ElevenLabs** | English | `TTS_PROVIDER=elevenlabs` |
| **Sarvam AI** | Hindi | `TTS_PROVIDER=sarvam` |

Switch providers by changing `TTS_PROVIDER` in `.env`.

---

## Security & Privacy

| Principle | Implementation |
|-----------|---------------|
| **No API keys in extension** | All keys stored server-side in `.env` |
| **Minimal data** | Only URL, score, reasons, timestamp sent |
| **No sensitive data** | No cookies, passwords, DOM, or phone numbers |
| **Rate limiting** | 5 alerts per user per minute, 10 req/min global |
| **HTTPS only** | Extension uses `fetch()` over HTTPS |
| **CORS restricted** | Backend restricts origins (configurable) |
| **Helmet** | Security headers on all responses |
| **Consent required** | User must explicitly opt-in with consent dialog |

---

## Files Modified / Created

| File | Change |
|------|--------|
| `manifest.json` | Version 0.7.0, updated description |
| `background.js` | `sendTelegramAlert()`, `registerTelegramUser()`, message handlers |
| `content.js` | `SEND_TELEGRAM_ALERT` triggers in block modals |
| `popup.html` | Telegram toggle, status, userId display |
| `popup.js` | Consent, UUID, registration, toggle persistence |
| `backend/server.js` | **[NEW]** Full Express server |
| `backend/package.json` | **[NEW]** Dependencies |
| `backend/.env.example` | **[NEW]** Secret template |
