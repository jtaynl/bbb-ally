import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import axios from "axios";
import Redis from "ioredis";
import { XMLParser } from "fast-xml-parser";

const {
  BBB_API_BASE,
  BBB_SECRET,
  PUBLIC_BASE_URL,
  DASHSCOPE_API_KEY,
  APP_ID,
  ALLY_TRIGGER = "@ask ally",
  ALLY_NAME = "Ally",
  REDIS_URL = "redis://localhost:6379",
  WEBHOOK_CHECKSUM_ALG = "sha256",
  WEBHOOK_STRICT = "false",
  PORT = 8080,
} = process.env;

if (!BBB_API_BASE || !BBB_SECRET || !PUBLIC_BASE_URL || !DASHSCOPE_API_KEY || !APP_ID) {
  console.error("Missing required env vars. Check .env");
  process.exit(1);
}

const app = express();

// Keep raw body for signature verification
const rawSaver = (req, res, buf) => { req.rawBody = buf ? buf.toString("utf8") : ""; };
app.use(bodyParser.urlencoded({ extended: false, verify: rawSaver }));
app.use(bodyParser.json({ verify: rawSaver }));

const redis = new Redis(REDIS_URL);
const xml = new XMLParser({ ignoreAttributes: false });

/* ---------- BBB helpers ---------- */
function urlEncodeParams(params) { return new URLSearchParams(params).toString(); }
function bbbChecksum(callName, qsNoChecksum) {
  return crypto.createHash("sha1").update(callName + qsNoChecksum + BBB_SECRET).digest("hex");
}
async function bbbGet(callName, params = {}) {
  const qs = urlEncodeParams(params);
  const checksum = bbbChecksum(callName, qs);
  const url = `${BBB_API_BASE}/${callName}?${qs}&checksum=${checksum}`;
  const res = await axios.get(url, { timeout: 10000 });
  return xml.parse(res.data);
}
async function bbbSendChatRobust({ extMeetingId, intMeetingId }, text) {
  const MAX = 500;
  const chunks = [];
  for (let i = 0; i < text.length; i += MAX) chunks.push(text.slice(i, i + MAX));

  async function sendWith(meetingID) {
    for (const c of chunks) {
      const params = { meetingID, message: c };
      const qs = urlEncodeParams(params);
      const checksum = bbbChecksum("sendChatMessage", qs);
      const url = `${BBB_API_BASE}/sendChatMessage?${qs}&checksum=${checksum}`;
      await axios.get(url, { timeout: 10000 });
    }
  }

  try {
    if (extMeetingId) { await sendWith(extMeetingId); return true; }
  } catch (e) {
    console.warn("sendChat (external) failed:", e?.response?.status || e.message);
  }
  if (intMeetingId) {
    try { await sendWith(intMeetingId); return true; }
    catch (e) { console.warn("sendChat (internal) failed:", e?.response?.status || e.message); }
  }
  return false;
}

/* ---------- Signature ---------- */
function constantTimeEquals(a, b) {
  try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); }
  catch { return false; }
}
function verifyWebhookSignature(req) {
  const strict = String(WEBHOOK_STRICT).toLowerCase() === "true";
  const received = req.query.checksum || "";
  if (!received) return !strict;

  const cb = `${PUBLIC_BASE_URL}${req.path}`;
  const candidates = [];
  if (req.rawBody) candidates.push(req.rawBody);
  try { const enc = new URLSearchParams(req.body).toString(); if (enc) candidates.push(enc); } catch {}
  try {
    const nl = Object.entries(req.body)
      .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
      .join("\n");
    if (nl) candidates.push(nl);
  } catch {}

  const algs = [WEBHOOK_CHECKSUM_ALG, "sha1", "sha256", "sha384", "sha512"];
  for (const bodyStr of candidates) {
    for (const alg of algs) {
      const h = crypto.createHash(alg).update(cb + bodyStr + BBB_SECRET).digest("hex");
      if (constantTimeEquals(h, received)) return true;
    }
  }
  return !strict;
}

/* ---------- Event parsing ---------- */
function normalizeWebhookEvents(req) {
  let body = req.body;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch { return []; } }
  if (body && body.event) {
    const ev = typeof body.event === "string" ? JSON.parse(body.event) : body.event;
    return [ev];
  }
  if (Array.isArray(body)) return body.map(ev => (typeof ev === "string" ? JSON.parse(ev) : ev));
  if (body && body.data) return [body];
  return [];
}
function looksLikeChatEvent(ev) {
  const id = ev?.data?.id?.toLowerCase?.() || "";
  const attrs = ev?.data?.attributes || {};
  if (id.includes("chat")) return true;
  if (attrs?.message || attrs?.chat || attrs?.["message-id"]) return true;
  return false;
}
function extractMessage(ev) {
  const a = ev?.data?.attributes || {};
  return (a?.message?.message || a?.message || a?.content || "").toString();
}
function extractMeetingIds(ev) {
  const a = ev?.data?.attributes || {};
  const ext =
    (a?.meeting && (a.meeting["external-meeting-id"] || a.meeting.externalMeetingID)) ||
    a["external-meeting-id"] || a.externalMeetingID || a.meeting_id || a.meetingId || "";
  const intr =
    (a?.meeting && (a.meeting["internal-meeting-id"] || a.meeting.internalMeetingID)) ||
    a["internal-meeting-id"] || a.internalMeetingID || "";
  return { extMeetingId: String(ext || ""), intMeetingId: String(intr || "") };
}
function extractUser(ev) {
  const a = ev?.data?.attributes || {};
  const s = a?.sender || a?.user || {};
  return {
    internalUserId: String(
      s?.["internal-user-id"] || s?.internalUserId || s?.id || a?.["user-id"] || a?.userId || ""
    ),
    name: String(s?.["user-name"] || s?.name || a?.["user-name"] || a?.fullName || ""),
    role: String(s?.role || (a?.message?.sender && a.message.sender.role) || "").toUpperCase(),
  };
}

/* ---------- Trigger handling (tolerant) ---------- */
function extractQuestion(text, trigger = ALLY_TRIGGER) {
  if (!text) return null;
  const norm = text.replace(/\s+/g, " ").trim(); // collapse spaces
  // Build a regex that matches the trigger at start or after leading space,
  // allows optional punctuation, then captures the rest as the question.
  const esc = trigger.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`^(?:\\s*)${esc}\\s*[:,-]?\\s*(.*)$`, "i");
  const m = norm.match(re);
  if (m) return m[1] || ""; // may be empty if user typed only the trigger
  return null;
}

/* ---------- Model call ---------- */
async function callQwen(meetingID, userKey, prompt) {
  const redisKey = `ally:sess:${meetingID}:${userKey}`;
  const sessionId = (await redis.get(redisKey)) || null;

  const url = `https://dashscope-intl.aliyuncs.com/api/v1/apps/${APP_ID}/completion`;
  const payload = { input: { prompt }, ...(sessionId ? { session_id: sessionId } : {}), parameters: {} };

  const res = await axios.post(url, payload, {
    headers: { Authorization: `Bearer ${DASHSCOPE_API_KEY}`, "Content-Type": "application/json" },
    timeout: 20000,
  });

  const out = res.data?.output || {};
  if (out.session_id) await redis.set(redisKey, out.session_id, "EX", 60 * 60 * 24);
  return out.text || "(no answer)";
}

/* ---------- Routes ---------- */
app.get("/healthz", (req, res) => res.json({ ok: true }));

app.post("/webhook", async (req, res) => {
  try {
    if (!verifyWebhookSignature(req)) return res.status(403).send("bad signature");

    const events = normalizeWebhookEvents(req);
    console.log("WEBHOOK EVENTS", Array.isArray(events) ? events.length : 0);
    if (!events.length) return res.status(200).send("ok");

    for (const ev of events) {
      // DEBUG: show event id, keys, and extracted text
      const id = ev?.data?.id;
      const attrs = ev?.data?.attributes || {};
      const textPreview = (extractMessage(ev) || "").slice(0, 120);
      console.log("EV", { id, keys: Object.keys(attrs), text: textPreview });

      if (!looksLikeChatEvent(ev)) continue;

      const ids = extractMeetingIds(ev);
      const user = extractUser(ev);
      const text = extractMessage(ev);
      if (!text) continue;

      const question = extractQuestion(text);
      const isMod = user.role ? user.role === "MODERATOR" : true; // allow if role missing

      console.log("PARSED", {
        trigger: question !== null,
        role: user.role || "(unknown)",
        isMod,
        ext: ids.extMeetingId,
        int: ids.intMeetingId,
        user: user.name || user.internalUserId,
        q: (question || "").slice(0, 120),
      });

      if (question === null) continue;         // trigger not matched
      if (!isMod) continue;                    // not a moderator
      if (!question) {
        await bbbSendChatRobust(ids, `Usage: ${ALLY_TRIGGER} <your question>`);
        continue;
      }

      try {
        const answer = await callQwen(ids.extMeetingId || ids.intMeetingId, user.internalUserId || user.name, question);
        const ok = await bbbSendChatRobust(ids, `${ALLY_NAME}: ${answer}`);
        if (!ok) console.warn("Failed to send chat message via both meeting IDs");
      } catch (e) {
        console.error("Qwen or sendChat error:", e?.response?.data || e.message);
        await bbbSendChatRobust(ids, `${ALLY_NAME}: Sorry, I hit an error answering that.`);
      }
    }

    return res.status(200).send("ok");
  } catch (e) {
    console.error("webhook error:", e);
    return res.status(500).send("err");
  }
});

/* ---------- Startup ---------- */
async function registerWebhook() {
  try {
    const callbackURL = `${PUBLIC_BASE_URL}/webhook`;
    const params = { callbackURL };
    const qs = urlEncodeParams(params);
    const checksum = crypto.createHash("sha1").update("hooks/create" + qs + BBB_SECRET).digest("hex");
    const url = `${BBB_API_BASE}/hooks/create?${qs}&checksum=${checksum}`;
    await axios.get(url, { timeout: 10000 });
    console.log("Registered BBB webhook at", callbackURL);
  } catch (e) {
    console.warn("Webhook registration failed:", e?.response?.data || e.message);
  }
}

app.listen(Number(PORT), async () => {
  console.log(`Ally bot listening on :${PORT}`);
  await registerWebhook();
  setInterval(registerWebhook, 5 * 60 * 1000);
});
