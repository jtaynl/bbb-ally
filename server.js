import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import axios from "axios";
import Redis from "ioredis";
import { XMLParser } from "fast-xml-parser";

const {
  BBB_API_BASE,
  BBB_SECRET,
  PUBLIC_BASE_URL,                  // e.g. https://skillsfuture.io/ally   (NO trailing slash)
  DASHSCOPE_API_KEY,
  APP_ID,
  ALLY_TRIGGER = "@ally",
  ALLY_NAME = "Ally",
  REDIS_URL = "redis://localhost:6379",
  WEBHOOK_CHECKSUM_ALG = "sha256",  // matches bbb-webhooks default
  WEBHOOK_STRICT = "true",          // set to "false" to bypass signature checks (not recommended)
  WEBHOOK_PRUNE = "false",          // set "true" to delete stale hooks not matching callbackURL
  ALLY_REQUIRE_MOD = "true",        // require moderator role to invoke Ally
  DUP_TTL_SECONDS = "8",            // dedupe identical prompt/user/meeting for N seconds
  PORT = 8080,
  QWEN_CONCISE = "false",           // if "true", nudge model for concise answers

  // Loader (typing...) indicator
  ALLY_LOADING_ENABLED = "true",
  ALLY_LOADING_DELAY_MS = "1000",
  ALLY_LOADING_TEXT = "⏳ Assistant is thinking…",

  // DashScope robustness
  QWEN_TIMEOUT_MS = "60000",        // HTTP timeout per attempt
  QWEN_MAX_RETRIES = "2",           // retry count on 429/5xx/timeouts
  QWEN_RETRY_BACKOFF_MS = "800",    // base backoff in ms (exponential)

  // Overflow protection / session rollover
  QWEN_MAX_INPUT_CHARS = "7000",    // hard cap on prompt we send
  AUTO_RESET_ON_OVERFLOW = "true",  // on "Range of input length" error, clear session & retry once

  // Manual reset phrases (comma-separated)
  ALLY_RESET_PHRASES = "reset,new topic,clear,forget,reset chat,reset session,start over",
} = process.env;

function normalizeBaseUrl(u) { if (!u) return ""; return u.endsWith("/") ? u.slice(0, -1) : u; }
const BASE = normalizeBaseUrl(PUBLIC_BASE_URL);

if (!BBB_API_BASE || !BBB_SECRET || !BASE || !DASHSCOPE_API_KEY || !APP_ID) {
  console.error("Missing required env vars. Check .env (BBB_API_BASE, BBB_SECRET, PUBLIC_BASE_URL, DASHSCOPE_API_KEY, APP_ID)");
  process.exit(1);
}

const app = express();

// Keep raw body for signature + custom parsing
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
function constantTimeEquals(a, b) { try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch { return false; } }

function candidateBodies(req) {
  const list = [];
  if (req.rawBody) list.push(req.rawBody);
  try { const enc = new URLSearchParams(req.body).toString(); if (enc) list.push(enc); } catch {}
  try {
    const nl = Object.entries(req.body).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join("\n");
    if (nl) list.push(nl);
  } catch {}
  return list;
}

function verifyWebhookSignature(req) {
  const strict = String(WEBHOOK_STRICT).toLowerCase() === "true";
  const received = req.query.checksum || "";
  const cb = `${BASE}${req.path}`;

  if (!received) {
    if (strict) { console.warn("WEBHOOK signature missing, strict mode on. cb=", cb); return false; }
    return true;
  }

  const bodies = candidateBodies(req);
  const algs = [WEBHOOK_CHECKSUM_ALG, "sha1", "sha256", "sha384", "sha512"];

  for (const bodyStr of bodies) {
    for (const alg of algs) {
      const h = crypto.createHash(alg).update(cb + bodyStr + BBB_SECRET).digest("hex");
      if (constantTimeEquals(h, received)) return true;
    }
  }

  console.warn("WEBHOOK signature mismatch", {
    cb, received_len: received.length, bodies_tried: bodies.map((b) => b.length),
    algs_tried: algs, ct: req.headers["content-type"], raw_prefix: (req.rawBody || "").slice(0, 180),
  });

  return !strict;
}

/* ---------------- Normalization & parsing ---------------- */
const safeParse = (v) =>
  (typeof v === "string" ? (() => { try { return JSON.parse(v); } catch { return undefined; } })() : v);

function normalizeFromRaw(raw) {
  const events = [];
  if (!raw) return events;
  const s = raw.trim();

  // application/x-www-form-urlencoded: event=<json or json-array>&timestamp=...
  if (s.includes("event=")) {
    try {
      const params = new URLSearchParams(s);
      const evStr = params.get("event");
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

  if (req.body && req.body.event) {
    const parsed = safeParse(req.body.event) ?? req.body.event;
    if (Array.isArray(parsed)) events.push(...parsed);
    else if (parsed) events.push(parsed);
  }

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

  if (!events.length && req.body && typeof req.body === "object" && !Array.isArray(req.body)) {
    if (req.body.data) events.push(req.body);
    else if (req.body.core?.body) {
      const inner = safeParse(req.body.core.body) ?? req.body.core.body;
      if (Array.isArray(inner)) events.push(...inner); else if (inner) events.push(inner);
    }
  }

  if (!events.length) events = normalizeFromRaw(req.rawBody);

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

function extractMessage(ev) {
  const a = ev?.data?.attributes || {};
  const cm = a?.["chat-message"];
  if (cm) {
    if (typeof cm === "string") return cm.toString();
    const txt = cm.message ?? cm.text ?? cm.content ?? "";
    return String(txt || "");
  }
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

/* ---------------- Trigger & reset handling ---------------- */
function extractQuestion(text, trigger = ALLY_TRIGGER) {
  if (!text) return null;
  const norm = text.replace(/\s+/g, " ").trim();
  const esc = trigger.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`^(?:\\s*)${esc}\\s*[:,-]?\\s*(.*)$`, "i");
  const m = norm.match(re);
  return m ? (m[1] ?? "") : null;
}

const RESET_LIST = (ALLY_RESET_PHRASES || "")
  .split(",")
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

function isResetCommand(q) {
  const t = (q || "").trim().toLowerCase();
  return RESET_LIST.some(p => t === p || t.startsWith(p));
}

/* ---------------- Model call (Alibaba Cloud Model Studio App) ---------------- */
async function callQwen(meetingID, userKey, prompt) {
  const redisKey = `ally:sess:${meetingID}:${userKey}`;
  let sessionId = (await redis.get(redisKey)) || null;

  // Safety: trim excessive prompt to avoid hitting the app’s total length cap
  const cap = Math.max(1, Number(QWEN_MAX_INPUT_CHARS) || 7000);
  let userPrompt = String(prompt || "");
  if (userPrompt.length > cap) {
    userPrompt = userPrompt.slice(0, cap - 200) + "\n\n[...truncated...]";
  }

  let finalPrompt = userPrompt;
  if (String(QWEN_CONCISE).toLowerCase() === "true") {
    finalPrompt = `Answer concisely (<= 6 sentences). If a list is needed, keep it short.\n\nUser: ${userPrompt}`;
  }

  const url = `https://dashscope-intl.aliyuncs.com/api/v1/apps/${APP_ID}/completion`;

  // Build payload (session_id MUST be inside input for multi-turn)
  const buildPayload = (sid) => ({
    input: {
      prompt: finalPrompt,
      ...(sid ? { session_id: sid } : {}),
    },
    parameters: {}
  });

  const timeout = Math.max(1000, Number(QWEN_TIMEOUT_MS) || 60000);
  const maxRetries = Math.max(0, Number(QWEN_MAX_RETRIES) || 2);
  const backoffBase = Math.max(0, Number(QWEN_RETRY_BACKOFF_MS) || 800);
  const autoReset = String(AUTO_RESET_ON_OVERFLOW).toLowerCase() === "true";

  let lastErr = null;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const res = await axios.post(url, buildPayload(sessionId), {
        headers: { Authorization: `Bearer ${DASHSCOPE_API_KEY}`, "Content-Type": "application/json" },
        timeout,
      });
      const out = res.data?.output || {};
      if (out.session_id && out.session_id !== sessionId) {
        console.log("Qwen returned new session_id:", out.session_id);
      }
      if (out.session_id) await redis.set(redisKey, out.session_id, "EX", 60 * 60 * 24); // 24h TTL
      return out.text || "(no answer)";
    } catch (e) {
      lastErr = e;
      const status = e?.response?.status;
      const code = e?.code || "";
      const body = e?.response?.data;
      const msg = (body && (body.message || body.error || body.msg)) || e.message || "";

      // If context got too large, reset session and retry once (fresh context)
      const looksLikeOverflow =
        status === 400 && typeof msg === "string" &&
        msg.toLowerCase().includes("range of input length") &&
        msg.includes("30720");

      if (looksLikeOverflow && autoReset) {
        console.warn("DashScope overflow; clearing session and retrying once.");
        if (sessionId) { await redis.del(redisKey); sessionId = null; }
        // retry immediately without counting against generic retry budget
        try {
          const res2 = await axios.post(url, buildPayload(null), {
            headers: { Authorization: `Bearer ${DASHSCOPE_API_KEY}`, "Content-Type": "application/json" },
            timeout,
          });
          const out2 = res2.data?.output || {};
          if (out2.session_id) await redis.set(redisKey, out2.session_id, "EX", 60 * 60 * 24);
          return out2.text || "(no answer)";
        } catch (e2) {
          lastErr = e2;
          // fall through to normal retry handling
        }
      }

      // Generic retry on transient issues
      const retriable =
        !e.response || status === 429 || status >= 500 ||
        code === "ECONNABORTED" || code === "ETIMEDOUT" || code === "ECONNRESET";
      if (attempt < maxRetries && retriable) {
        const delay = backoffBase * Math.pow(2, attempt);
        await new Promise(r => setTimeout(r, delay));
        continue;
      }
      throw e;
    }
  }
  throw lastErr;
}

/* ---------------- Moderator-only strict check ---------------- */
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

/* ---------------- Webhook ensure (dedupe + optional prune) ---------------- */
async function ensureWebhook() {
  try {
    const callbackURL = `${BASE}/webhook`;

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
    } else {
      console.log("Webhook already registered:", callbackURL);
    }

    if (String(WEBHOOK_PRUNE).toLowerCase() === "true") {
      // Optional: remove any other hooks that do not match our callbackURL
      for (const h of hooks) {
        const cb = h?.callbackURL;
        if (cb && cb !== callbackURL) {
          try {
            const params = { hookID: h.hookID || h.id || h["hook-id"] };
            if (!params.hookID) continue;
            const qs = urlEncodeParams(params);
            const checksum = crypto.createHash("sha1").update("hooks/destroy" + qs + BBB_SECRET).digest("hex");
            const url = `${BBB_API_BASE}/hooks/destroy?${qs}&checksum=${checksum}`;
            await axios.get(url, { timeout: 10000 });
            console.log("Pruned old webhook:", cb);
          } catch (e) {
            console.warn("Failed to prune webhook:", cb, e?.message);
          }
        }
      }
    }
  } catch (e) {
    console.warn("ensureWebhook failed:", e?.response?.data || e.message);
  }
}

/* ---------------- Routes ---------------- */
app.get("/healthz", async (req, res) => {
  try {
    await redis.ping();
    res.json({ ok: true, redis: "ok" });
  } catch {
    res.json({ ok: true, redis: "error" });
  }
});

app.post("/webhook", async (req, res) => {
  console.log("INCOMING /webhook", { ct: req.headers["content-type"], qkeys: Object.keys(req.query || {}) });

  try {
    if (!verifyWebhookSignature(req)) {
      return res.status(403).send("bad signature");
    }

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

      // Skip Ally/System self-echo
      const uname = (user.name || "").trim().toLowerCase();
      if (uname === (ALLY_NAME || "").toLowerCase()) continue;
      if (uname === "system" && text.trim().startsWith(`${ALLY_NAME}:`)) continue;

      const question = extractQuestion(text);

      // Moderator-only: if role provided use it; else confirm via getMeetingInfo when enabled
      let isMod = true;
      if (String(ALLY_REQUIRE_MOD).toLowerCase() === "true") {
        if (user.role) isMod = user.role === "MODERATOR";
        else isMod = await isModeratorStrict(ids, user);
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

      // Manual reset commands
      if (isResetCommand(question)) {
        const meetingKey = ids.extMeetingId || ids.intMeetingId;
        const userKey = user.internalUserId || user.name || "";
        if (meetingKey && userKey) {
          await redis.del(`ally:sess:${meetingKey}:${userKey}`);
        }
        await bbbSendChatRobust(ids, `${ALLY_NAME}: Context cleared. What would you like to talk about next?`);
        continue;
      }

      if (!question) {
        await bbbSendChatRobust(ids, `Usage: ${ALLY_TRIGGER} <your question>`);
        continue;
      }

      // Dedupe identical asks briefly
      const dedupKey = `ally:dedup:${ids.extMeetingId || ids.intMeetingId}:${user.internalUserId || user.name}:${crypto.createHash('sha1').update(question).digest('hex')}`;
      const dupTtl = Math.max(0, Number(DUP_TTL_SECONDS) || 0);
      if (dupTtl > 0) {
        if (await redis.get(dedupKey)) { continue; }
        await redis.set(dedupKey, "1", "EX", dupTtl);
      }

      // ---------- LOADING INDICATOR ----------
      const LOADING_ENABLED = String(ALLY_LOADING_ENABLED).toLowerCase() === "true";
      const LOADING_DELAY = Math.max(0, Number(ALLY_LOADING_DELAY_MS) || 1000);
      const LOADING_TXT = ALLY_LOADING_TEXT || "⏳ Ally is thinking…";
      let loaderTimer = null;
      if (LOADING_ENABLED && LOADING_DELAY > 0) {
        loaderTimer = setTimeout(async () => { try { await bbbSendChatRobust(ids, LOADING_TXT); } catch {} }, LOADING_DELAY);
      }

      try {
        const answer = await callQwen(
          ids.extMeetingId || ids.intMeetingId,
          user.internalUserId || user.name,
          question
        );
        if (loaderTimer) clearTimeout(loaderTimer);

        const ok = await bbbSendChatRobust(ids, `${ALLY_NAME}: ${answer}`);
        if (!ok) console.warn("Failed to send chat message via both meeting IDs");
      } catch (e) {
        if (loaderTimer) clearTimeout(loaderTimer);
        const detail = e?.response?.data || e.message;
        console.error("Qwen or sendChat error:", detail);
        await bbbSendChatRobust(ids, `${ALLY_NAME}: Sorry, I hit an error answering that.`);
      }
    }

    return res.status(200).send("ok");
  } catch (e) {
    console.error("webhook error:", e);
    return res.status(500).send("err");
  }
});

/* ---------------- Startup ---------------- */
app.listen(Number(PORT), async () => {
  console.log(`Ally bot listening on :${PORT}`);
  await ensureWebhook();
  setInterval(ensureWebhook, 5 * 60 * 1000);
});
