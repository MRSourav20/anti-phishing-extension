// =============================================================================
// AntiPhish Guardian — Backend Server (Phase 7: Telegram Voice Alerts)
// =============================================================================
//
// Architecture: Extension → This Server → TTS Provider → Telegram Bot → User
//
// Endpoints:
//   POST /register  — Register userId with Telegram chatId
//   POST /alert     — Receive incident, generate TTS voice, send to Telegram
//
// Security: helmet, CORS, rate limiting, no sensitive data storage.
// =============================================================================

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import fetch from 'node-fetch';
import FormData from 'form-data';
import { Buffer } from 'buffer';

const app = express();
const PORT = process.env.PORT || 3000;

// =============================================================================
// 1. MIDDLEWARE
// =============================================================================

app.use(helmet());
app.use(express.json({ limit: '10kb' })); // Small payload limit for safety

// CORS — restrict to your extension origin in production
app.use(cors({
    origin: '*', // In production, restrict to chrome-extension://<your-extension-id>
    methods: ['POST'],
    allowedHeaders: ['Content-Type']
}));

// Rate Limiting: max 10 requests per minute per IP
const globalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests. Please try again later." }
});
// app.use(globalLimiter); // DISABLING FOR LOCAL TESTING

// Per-user alert rate limiting: max 5 alerts per userId per minute
const alertUserLimits = new Map(); // userId -> { count, resetTime }

function checkUserRateLimit(userId) {
    return true; // DISABLING FOR LOCAL TESTING
}

// =============================================================================
// 2. IN-MEMORY USER STORE
//    Production: Replace with a database (SQLite, PostgreSQL, etc.)
// =============================================================================

const userStore = new Map(); // userId -> { chatId, registeredAt }

// =============================================================================
// 3. ENDPOINTS
// =============================================================================

// ─── POST /register ─────────────────────────────────────────────────────────
// Called once when user enables Telegram alerts.
// The user must then message the Telegram bot with their userId to get their
// chatId linked. This endpoint can also accept chatId directly for bot-side
// registration.
app.post('/register', (req, res) => {
    const { userId, chatId } = req.body;

    if (!userId || typeof userId !== 'string' || userId.length < 8) {
        return res.status(400).json({ error: "Invalid userId" });
    }

    // Store or update user
    userStore.set(userId, {
        chatId: chatId || null, // chatId may come later from Telegram bot webhook
        registeredAt: new Date().toISOString()
    });

    console.log(`[Register] User ${userId.substring(0, 8)}… registered. ChatId: ${chatId || "pending"}`);

    res.json({
        success: true,
        message: chatId
            ? "Registered and linked to Telegram."
            : "Registered. Please message the Telegram bot with your userId to complete linking."
    });
});

// ─── POST /alert ─────────────────────────────────────────────────────────────
// Receives incident payload from extension, generates TTS, sends to Telegram.
app.post('/alert', async (req, res) => {
    console.log("[DEBUG] Received POST /alert request from:", req.ip);
    console.log("[DEBUG] Payload:", JSON.stringify(req.body, null, 2));

    const { userId, incidentId, url, riskScore, reasons, timestamp } = req.body;

    // --- Validation ---
    if (!userId || !url || riskScore === undefined) {
        console.error("[DEBUG] ❌ Validation Failed! Missing fields in payload.");
        return res.status(400).json({ error: "Missing required fields: userId, url, riskScore" });
    }

    // --- Rate Limit Check ---
    /* DISABLING FOR LOCAL TESTING
    if (!checkUserRateLimit(userId)) {
        console.warn(`[Alert] Rate limited: ${userId.substring(0, 8)}…`);
        return res.status(429).json({ error: "Alert rate limit exceeded. Try again later." });
    }
    */

    // --- Lookup User ---
    let targetChatId = null;
    const user = userStore.get(userId);

    if (user && user.chatId) {
        targetChatId = user.chatId; // Linked via webhook
    } else if (process.env.TELEGRAM_CHAT_ID) {
        targetChatId = process.env.TELEGRAM_CHAT_ID; // Fallback for local testing
        console.log(`[Alert] Using hardcoded TELEGRAM_CHAT_ID from .env`);
    }

    if (!targetChatId) {
        console.warn(`[Alert] No chatId for user ${userId.substring(0, 8)}… and no TELEGRAM_CHAT_ID in .env`);
        return res.status(404).json({
            error: "User not linked to Telegram and no fallback CHAT_ID found."
        });
    }

    // --- Generate Voice Summary Text ---
    const riskPercent = Math.round((riskScore || 0) * 100);
    const reasonsList = (reasons || []).slice(0, 3).join(". ");

    const summaryText =
        `AntiPhish Guardian Alert. ` +
        `A phishing website has been blocked. ` +
        `URL: ${sanitizeUrl(url)}. ` +
        `Risk Score: ${riskPercent} percent. ` +
        `Detected threats: ${reasonsList || "Multiple suspicious indicators"}. ` +
        `Time: ${new Date(timestamp || Date.now()).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" })}. ` +
        `Please stay safe and avoid this website.`;

    console.log(`[Alert] Processing incident ${incidentId || "N/A"} for user ${userId.substring(0, 8)}…`);
    console.log(`[Alert] Summary: ${summaryText}`);

    try {
        // --- Generate TTS Audio ---
        const provider = (process.env.TTS_PROVIDER || "elevenlabs").toLowerCase();
        let audioBuffer;

        if (provider === "elevenlabs") {
            audioBuffer = await generateTTS_ElevenLabs(summaryText);
        } else if (provider === "sarvam") {
            audioBuffer = await generateTTS_Sarvam(summaryText);
        } else {
            console.error(`[Alert] Unknown TTS provider: ${provider}`);
            return res.status(500).json({ error: "TTS provider misconfigured" });
        }

        if (!audioBuffer) {
            console.error("[Alert] TTS generation returned empty buffer");
            return res.status(500).json({ error: "TTS generation failed" });
        }

        // --- Send to Telegram ---
        await sendTelegramVoice(targetChatId, audioBuffer, incidentId, riskPercent);

        console.log(`[Alert] ✅ Voice alert sent to Telegram for incident ${incidentId}`);
        res.json({ success: true, message: "Voice alert sent to Telegram." });

    } catch (err) {
        console.error("[Alert] Processing error:", err.message);
        res.status(500).json({ error: "Failed to process alert." });
    }
});

// ─── GET / ───────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
    res.send("<h1>🤖 AntiPhish Guardian Backend is Running Live!</h1><p>The server is awake and waiting for alerts from your Chrome Extension.</p>");
});

// ─── GET /health ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
    res.json({ status: "ok", uptime: process.uptime(), users: userStore.size });
});

// =============================================================================
// 4. TTS PROVIDERS
// =============================================================================

/**
 * Generate TTS audio using ElevenLabs API.
 * Returns a Buffer containing the audio data (mp3).
 */
async function generateTTS_ElevenLabs(text) {
    const apiKey = process.env.TTS_API_KEY;
    const voiceId = process.env.ELEVENLABS_VOICE_ID || "21m00Tcm4TlvDq8ikWAM"; // Rachel

    if (!apiKey) throw new Error("TTS_API_KEY not set for ElevenLabs");

    const response = await fetch(
        `https://api.elevenlabs.io/v1/text-to-speech/${voiceId}`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "xi-api-key": apiKey
            },
            body: JSON.stringify({
                text: text,
                model_id: "eleven_turbo_v2_5", // Replaced deprecated eleven_monolingual_v1
                voice_settings: {
                    stability: 0.5,
                    similarity_boost: 0.75
                }
            })
        }
    );

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`ElevenLabs API error ${response.status}: ${errorText}`);
    }

    const arrayBuffer = await response.arrayBuffer();
    return Buffer.from(arrayBuffer);
}

/**
 * Generate TTS audio using Sarvam AI API.
 * Returns a Buffer containing the audio data.
 */
async function generateTTS_Sarvam(text) {
    const apiKey = process.env.TTS_API_KEY;
    if (!apiKey) throw new Error("TTS_API_KEY not set for Sarvam");

    const response = await fetch("https://api.sarvam.ai/text-to-speech", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "API-Subscription-Key": apiKey
        },
        body: JSON.stringify({
            inputs: [text],
            target_language_code: "hi-IN", // Hindi output for Sarvam
            speaker: "meera",
            pitch: 0,
            pace: 1.0,
            loudness: 1.5,
            speech_sample_rate: 22050,
            enable_preprocessing: true,
            model: "bulbul:v1"
        })
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Sarvam API error ${response.status}: ${errorText}`);
    }

    const data = await response.json();

    // Sarvam returns base64 encoded audio in audios array
    if (data.audios && data.audios.length > 0) {
        return Buffer.from(data.audios[0], 'base64');
    }

    throw new Error("Sarvam API returned no audio data");
}

// =============================================================================
// 5. TELEGRAM BOT API
// =============================================================================

/**
 * Send a voice message to a Telegram user via the Bot API.
 * @param {string} chatId - Telegram chat ID
 * @param {Buffer} audioBuffer - Audio file buffer
 * @param {string} incidentId - Incident reference
 * @param {number} riskPercent - Risk percentage for caption
 */
async function sendTelegramVoice(chatId, audioBuffer, incidentId, riskPercent) {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    if (!botToken) throw new Error("TELEGRAM_BOT_TOKEN not set");

    const form = new FormData();
    form.append('chat_id', chatId);
    form.append('voice', audioBuffer, {
        filename: `alert_${incidentId || 'unknown'}.ogg`,
        contentType: 'audio/ogg'
    });
    form.append('caption',
        `🚨 AntiPhish Guardian Alert\n` +
        `Risk: ${riskPercent}%\n` +
        `Incident: ${incidentId || 'N/A'}`
    );

    const response = await fetch(
        `https://api.telegram.org/bot${botToken}/sendVoice`,
        {
            method: "POST",
            body: form,
            headers: form.getHeaders()
        }
    );

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(`Telegram API error ${response.status}: ${JSON.stringify(errorData)}`);
    }

    return await response.json();
}

// =============================================================================
// 6. HELPERS
// =============================================================================

/**
 * Sanitize a URL for TTS reading — strips protocol, truncates long URLs.
 */
function sanitizeUrl(url) {
    try {
        const parsed = new URL(url);
        let clean = parsed.hostname + parsed.pathname;
        if (clean.length > 60) clean = clean.substring(0, 57) + "...";
        return clean;
    } catch {
        return url.substring(0, 50);
    }
}

// =============================================================================
// 7. TELEGRAM BOT WEBHOOK (Optional — for linking chatId)
// =============================================================================
//
// When a user messages the bot with their userId (e.g., "/start abc123-def4"),
// the bot links their Telegram chatId to that userId.
//
// To use this, set up a webhook with Telegram:
//   https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://your-domain.com/telegram-webhook
//
app.post('/telegram-webhook', (req, res) => {
    const update = req.body;

    if (update.message && update.message.text) {
        const chatId = update.message.chat.id.toString();
        const text = update.message.text.trim();

        // Expected format: /start <userId>
        if (text.startsWith('/start ')) {
            const userId = text.replace('/start ', '').trim();

            if (userStore.has(userId)) {
                const user = userStore.get(userId);
                user.chatId = chatId;
                userStore.set(userId, user);

                // Send confirmation
                sendTelegramText(chatId,
                    "✅ Account linked successfully!\n\n" +
                    "You will now receive voice alerts from AntiPhish Guardian when phishing sites are blocked.\n\n" +
                    `Your ID: ${userId.substring(0, 8)}…`
                );

                console.log(`[Webhook] Linked chatId ${chatId} to userId ${userId.substring(0, 8)}…`);
            } else {
                sendTelegramText(chatId,
                    "❌ User ID not found.\n\n" +
                    "Please enable Telegram Voice Alerts in your AntiPhish Guardian extension first, then try again."
                );
            }
        } else if (text === '/start') {
            sendTelegramText(chatId,
                "👋 Welcome to AntiPhish Guardian Bot!\n\n" +
                "To link your account:\n" +
                "1. Open AntiPhish Guardian extension\n" +
                "2. Enable 'Telegram Voice Alerts'\n" +
                "3. Copy your User ID\n" +
                "4. Send: /start YOUR_USER_ID"
            );
        }
    }

    res.sendStatus(200);
});

/**
 * Send a plain text message to a Telegram user.
 */
async function sendTelegramText(chatId, text) {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    if (!botToken) return;

    try {
        await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ chat_id: chatId, text: text, parse_mode: "HTML" })
        });
    } catch (err) {
        console.error("[Telegram] Send text error:", err.message);
    }
}

// =============================================================================
// 8. START SERVER
// =============================================================================

app.listen(PORT, () => {
    console.log(`\n╔══════════════════════════════════════════════════╗`);
    console.log(`║   AntiPhish Guardian — Telegram Alert Backend    ║`);
    console.log(`║   Port: ${PORT}                                     ║`);
    console.log(`║   TTS Provider: ${(process.env.TTS_PROVIDER || 'elevenlabs').padEnd(32)}║`);
    console.log(`║   Bot Token: ${process.env.TELEGRAM_BOT_TOKEN ? '✅ Set' : '❌ Missing'}                           ║`);
    console.log(`║   TTS Key: ${process.env.TTS_API_KEY ? '✅ Set' : '❌ Missing'}                             ║`);
    console.log(`╚══════════════════════════════════════════════════╝\n`);
});
