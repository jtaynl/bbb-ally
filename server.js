import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import axios from "axios";
import Redis from "ioredis";
import { XMLParser } from "fast-xml-parser";

const {
  BBB_API_BASE,
  BBB_SECRET,
  PUBLIC_BASE_URL,           // e.g. https://skillsfuture.io/ally
  DASHSCOPE_API_KEY,
  APP_ID,
  ALLY_TRIGGER = "@ask ally",
  ALLY_NAME = "Ally",
  REDIS_URL = "redis://localhost:6379",
  WEBHOOK_CHECKSUM_ALG = "sha256",  // bbb-webhooks default
  WEBHOOK_STRICT = "true",          // recommended
  PORT = 8080,
} = process.env;

if (!BBB_API_BASE || !BBB_SECRET || !PUBLIC_BASE_URL || !DASHSCOPE_API_KEY || !APP_ID) {
  console.error("Missing required env vars. Check .env");
  process.exit(1);
}

const app = express();

// Keep raw body for signature verification + custom parsing
const rawSaver = (req, res, buf) => { req.rawBody = buf ? buf.toString("utf8") : ""; };
app.use(bodyParser.urlencoded({ extended: false, verify: rawSaver }));
app.use(bodyParser.json({ verify: rawSaver }));

const redis = new Redis(REDIS_URL);
const xml = new XMLParser({ ignoreAttributes: false });

/* ---------------- BBB helpers ---------------- */
function urlEncodeParams(params) { return new URLSearchParams(params).toString(); }

function bbbChecksum(callName, qsNoChecksum) {
  // BBB API: sha1(callName + queryString + secret)
  return crypto.createHash("sha1").update(callName + qsNoChecksum + BBB_SECRET).digest("hex");
}

async function bbbGet(callName, params = {}) {
  const qs = urlEncodeParams(params);
  const checksum = bbbChecksum(callName, qs);
  const url = `${BBB_API_BASE}/${callName}?${qs}&checksum=${checksum}`;
  const res = await axios.get(url, { timeout: 10000 });
  return xml.parse(res.data);
}

// Send chat: try external meeting ID, then internal
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

/* ---------------- Signature verification ---------------- */
// bbb-webhooks builds checksum over: callbackURL + body + secret (with chosen hash alg)
function constantTimeEquals(a, b) { try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch { return false; } }

function verifyWebhookSignature(req) {
  const strict = String(WEBHOOK_STRICT).toLowerCase() === "true";
  const received = req.query.checksum || "";
  if (!received) return !strict;

  const cb = `${PUBLIC_BASE_URL}${req.path}`;
  const candidates = [];

  // 1) exact raw body string
  if (req.rawBody) candidates.push(req.rawBody);

  // 2) urlencoded re-encoding
  try {
    const enc = new URLSearchParams(req.body).toString();
    if (enc) candidates.push(enc);
  } catch {}

  // 3) newline-joined key=value fallback
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

/* ---------------- Normalization & parsing ---------------- */
const safeParse = (v) =>
  (typeof v === "string" ? (() => { try { return JSON.parse(v); } catch { return undefined; } })() : v);

// Handle raw bodies including URL-encoded `event=[{...}]`
function normalizeFromRaw(raw) {
  const events = [];
  if (!raw) return events;
  const s = raw.trim();

  // application/x-www-form-urlencoded: event=<json or json-array>&timestamp=...
  if (s.includes("event=")) {
    try {
      const params = new URLSearchParams(s);
      const evStr = params.get("event");          // may be an array: "[{...}]"
      const parsed = safeParse(evStr);
      if (Array.isArray(parsed)) events.push(...parsed);
      else if (parsed) events.push(parsed);
      return events;
    } catch {}
  }

  // Raw JSON bodies (rare)
  if (s.startsWith("[") || s.startsWith("{")) {
    const parsed = safeParse(s);
    if (!parsed) return events;

    if (Array.isArray(parsed)) {
      for (const item of parsed) {
        const i = safeParse(item) ?? item;
        if (i?.event) {
          const ev = safeParse(i.event) ?? i.event;
          if (Array.isArray(ev)) events.push(...ev); else if (ev) events.push(ev);
          continue;
        }
        if (i?.core?.body) {
          const ev = safeParse(i.core.body) ?? i.core.body;
          if (Array.isArray(ev)) events.push(...ev); else if (ev) events.push(ev);
          continue;
        }
        if (i?.data) { events.push(i); continue; }
        if (i?.payload?.data) { events.push(i.payload); continue; }
      }
      return events;
    } else {
      if (parsed?.data) { events.push(parsed); return events; }
      if (parsed?.core?.body) {
        const ev = safeParse(parsed.core.body) ?? parsed.core.body;
        if (Array.isArray(ev)) events.push(...ev); else if (ev) events.push(ev);
        return events;
      }
    }
  }
  return events;
}

function normalizeWebhookEvents(req) {
  let events = [];

  // 1) Parsed object with `event` (may be array or object)
  if (req.body && req.body.event) {
    const parsed = safeParse(req.body.event) ?? req.body.event;
    if (Array.isArray(parsed)) events.push(...parsed);
    else if (parsed) events.push(parsed);
  }

  // 2) Parsed array body
  if (!events.length && Array.isArray(req.body)) {
    for (const item of req.body) {
      const i = safeParse(item) ?? item;
      if (i?.event) {
        const inner = safeParse(i.event) ?? i.event;
        if (Array.isArray(inner)) events.push(...inner); else if (inner) events.push(inner);
        continue;
      }
      if (i?.core?.body) {
        const inner = safeParse(i.core.body) ?? i.core.body;
        if (Array.isArray(inner)) events.push(...inner); else if (inner) events.push(inner);
        continue;
      }
      if (i?.data) { events.push(i); continue; }
      if (i?.payload?.data) { events.push(i.payload); continue; }
    }
  }

  // 3) Single object with data/core
  if (!events.length && req.body && typeof req.body === "object" && !Array.isArray(req.body)) {
    if (req.body.data) events.push(req.body);
    else if (req.body.core?.body) {
      const inner = safeParse(req.body.core.body) ?? req.body.core.body;
      if (Array.isArray(inner)) events.push(...inner); else if (inner) events.push(inner);
    }
  }

  // 4) Fallback to raw string
  if (!events.length) events = normalizeFromRaw(req.rawBody);

  // 5) Edge: urlencoded parsed into a single-key object of JSON text
  if (!events.length && req.body && typeof req.body === "object") {
    const keys = Object.keys(req.body);
    if (keys.length === 1 && (keys[0].startsWith("[") || keys[0].startsWith("{"))) {
      const parsed = safeParse(keys[0]);
      if (Array.isArray(parsed)) events = parsed;
      else if (parsed?.data) events = [parsed];
    }
  }

  return events;
}

/* ---------------- Event helpers ---------------- */
function looksLikeChatEvent(ev) {
  const id = ev?.data?.id?.toLowerCase?.() || "";
  const attrs = ev?.data?.attributes || {};
  if (id.includes("chat")) return true;
  if (attrs?.["chat-message"] || attrs?.message || attrs?.chat || attrs?.["message-id"]) return true;
  return false;
}

// Extract text from attributes["chat-message"] (observed on your server)
function extractMessage(ev) {
  const a = ev?.data?.attributes || {};
  const cm = a?.["chat-message"];
  if (cm) {
    if (typeof cm === "string") return cm.toString();
    const txt = cm.message ?? cm.text ?? cm.content ?? "";
    return String(txt || "");
  }
  // fallback for other shapes
  return String(a?.message?.message || a?.message || a?.content || "");
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
  const cm = a?.["chat-message"];
  const s = (cm && cm.sender) || a?.sender || a?.user || {};
  return {
    internalUserId: String(
      s?.["internal-user-id"] || s?.internalUserId || s?.id || a?.["user-id"] || a?.userId || ""
    ),
    name: String(s?.["user-name"] || s?.name || a?.["user-name"] || a?.fullName || ""),
    role: String(s?.role || (a?.message?.sender && a.message.sender.role) || "").toUpperCase(),
  };
}

/* ---------------- Trigger handling ---------------- */
function extractQuestion(text, trigger = ALLY_TRIGGER) {
  if (!text) return null;
  const norm = text.replace(/\s+/g, " ").trim();
  const esc = trigger.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`^(?:\\s*)${esc}\\s*[:,-]?\\s*(.*)$`, "i");
  const m = norm.match(re);
  return m ? (m[1] ?? "") : null;
}

/* ---------------- Model call (Alibaba Cloud Model Studio App) ---------------- */
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

/* ---------------- Moderator-only strict fallback ---------------- */
async function isModeratorStrict({ extMeetingId, intMeetingId }, user) {
  const meetingIDs = [extMeetingId, intMeetingId].filter(Boolean);
  for (const meetingID of meetingIDs) {
    try {
      const res = await bbbGet("getMeetingInfo", { meetingID });
      const node = res?.response?.attendees?.attendee;
      const attendees = node ? (Array.isArray(node) ? node : [node]) : [];
      const found = attendees.find(a =>
        a?.userID === user.internalUserId ||
        a?.internalUserID === user.internalUserId ||
        (a?.fullName || "").toLowerCase() === (user.name || "").toLowerCase()
      );
      if (found) return String(found.role || "").toUpperCase() === "MODERATOR";
    } catch (e) {
      console.warn("getMeetingInfo failed:", e?.message);
    }
  }
  return false;
}

/* ---------------- Routes ---------------- */
app.get("/healthz", (req, res) => res.json({ ok: true }));

app.post("/webhook", async (req, res) => {
  try {
    if (!verifyWebhookSignature(req)) return res.status(403).send("bad signature");

    const events = normalizeWebhookEvents(req);
    console.log("WEBHOOK EVENTS", Array.isArray(events) ? events.length : 0);
    console.log("CT", req.headers["content-type"], "RAW", (req.rawBody || "").slice(0, 200));

    if (!events.length) return res.status(200).send("ok");

    for (const ev of events) {
      const id = ev?.data?.id;
      const attrs = ev?.data?.attributes || {};
      const textPreview = (extractMessage(ev) || "").slice(0, 120);
      console.log("EV", { id, keys: Object.keys(attrs), text: textPreview });

      if (!looksLikeChatEvent(ev)) continue;

      const ids = extractMeetingIds(ev);
      const user = extractUser(ev);
      const text = extractMessage(ev);
      if (!text) continue;

      // Skip Ally's own messages or System echoes of Ally:
      const uname = (user.name || "").trim().toLowerCase();
      if (uname === (ALLY_NAME || "").toLowerCase()) continue;
      if (uname === "system" && text.trim().startsWith(`${ALLY_NAME}:`)) continue;

      const question = extractQuestion(text);

      // STRICT moderator-only: use role if provided, else confirm via getMeetingInfo
      let isMod = false;
      if (user.role) {
        isMod = user.role === "MODERATOR";
      } else {
        isMod = await isModeratorStrict(ids, user);
      }

      console.log("PARSED", {
        trigger: question !== null,
        role: user.role || "(unknown)",
        isMod,
        ext: ids.extMeetingId,
        int: ids.intMeetingId,
        user: user.name || user.internalUserId,
        q: (question || "").slice(0, 120),
      });

      if (question === null) continue; // trigger not matched
      if (!isMod) continue;            // not a moderator

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

/* ---------------- Webhook ensure (dedupe) ---------------- */
async function ensureWebhook() {
  try {
    const callbackURL = `${PUBLIC_BASE_URL}/webhook`;

    // List hooks
    const listChecksum = crypto.createHash("sha1").update("hooks/list" + "" + BBB_SECRET).digest("hex");
    const listUrl = `${BBB_API_BASE}/hooks/list?checksum=${listChecksum}`;
    const listRes = await axios.get(listUrl, { timeout: 10000 });
    const xmlHooks = xml.parse(listRes.data)?.response?.hooks?.hook;
    const hooks = xmlHooks ? (Array.isArray(xmlHooks) ? xmlHooks : [xmlHooks]) : [];
    const exists = hooks.some(h => h?.callbackURL === callbackURL);

    if (!exists) {
      const params = { callbackURL };
      const qs = urlEncodeParams(params);
      const checksum = crypto.createHash("sha1").update("hooks/create" + qs + BBB_SECRET).digest("hex");
      const url = `${BBB_API_BASE}/hooks/create?${qs}&checksum=${checksum}`;
      await axios.get(url, { timeout: 10000 });
      console.log("Registered BBB webhook at", callbackURL);
    }
  } catch (e) {
    console.warn("ensureWebhook failed:", e?.response?.data || e.message);
  }
}

/* ---------------- Startup ---------------- */
app.listen(Number(PORT), async () => {
  console.log(`Ally bot listening on :${PORT}`);
  await ensureWebhook();
  // Re-ensure every 5 minutes (harmless if already present)
  setInterval(ensureWebhook, 5 * 60 * 1000);
});
