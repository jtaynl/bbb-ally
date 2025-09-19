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
  WEBHOOK_CHECKSUM_ALG = "sha1",
  WEBHOOK_STRICT = "true",
  PORT = 8080,
} = process.env;

if (!BBB_API_BASE || !BBB_SECRET || !PUBLIC_BASE_URL || !DASHSCOPE_API_KEY || !APP_ID) {
  console.error("Missing required env vars. Check .env");
  process.exit(1);
}

const app = express();

// Capture raw body for accurate signature verification
const rawSaver = (req, res, buf) => {
  req.rawBody = buf ? buf.toString("utf8") : "";
};
app.use(bodyParser.urlencoded({ extended: false, verify: rawSaver }));
app.use(bodyParser.json({ verify: rawSaver }));

const redis = new Redis(REDIS_URL);
const xml = new XMLParser({ ignoreAttributes: false });

function urlEncodeParams(params) {
  return new URLSearchParams(params).toString();
}

function bbbChecksum(callName, queryStringNoChecksum) {
  // BBB API checksum = sha1(callName + queryString + secret)
  return crypto.createHash("sha1").update(callName + queryStringNoChecksum + BBB_SECRET).digest("hex");
}

async function bbbGet(callName, params = {}) {
  const qs = urlEncodeParams(params);
  const checksum = bbbChecksum(callName, qs);
  const url = `${BBB_API_BASE}/${callName}?${qs}&checksum=${checksum}`;
  const res = await axios.get(url, { timeout: 10000 });
  return xml.parse(res.data);
}

async function bbbSendChat(meetingID, text) {
  // BBB 3.0 sendChatMessage: message 1..500 chars; split if needed
  const MAX = 500;
  const chunks = [];
  for (let i = 0; i < text.length; i += MAX) chunks.push(text.slice(i, i + MAX));
  for (const c of chunks) {
    const params = { meetingID, message: c };
    const qs = urlEncodeParams(params);
    const checksum = bbbChecksum("sendChatMessage", qs);
    const url = `${BBB_API_BASE}/sendChatMessage?${qs}&checksum=${checksum}`;
    await axios.get(url, { timeout: 10000 });
  }
}

function constantTimeEquals(a, b) {
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch { return false; }
}

function verifyWebhookSignature(req) {
  const strict = String(WEBHOOK_STRICT).toLowerCase() === "true";
  const received = req.query.checksum || "";
  if (!received) return !strict; // allow if not strict

  const cb = `${PUBLIC_BASE_URL}${req.path}`;
  const bodies = [];

  // Candidate encodings seen in the wild:
  // 1) exact raw body
  if (req.rawBody) bodies.push(req.rawBody);
  // 2) urlencoded (re-encoded) in stable key order
  const enc = new URLSearchParams(req.body).toString();
  bodies.push(enc);
  // 3) newline-joined key=value (older examples)
  const nl = Object.entries(req.body).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join("\n");
  bodies.push(nl);

  const algs = [WEBHOOK_CHECKSUM_ALG, "sha1", "sha256", "sha384", "sha512"];

  for (const bodyStr of bodies) {
    for (const alg of algs) {
      const h = crypto.createHash(alg).update(cb + bodyStr + BBB_SECRET).digest("hex");
      if (constantTimeEquals(h, received)) return true;
    }
  }
  return !strict; // if not strict, allow; else reject
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

function extractMeetingId(ev) {
  const a = ev?.data?.attributes || {};
  return (
    a?.meeting?.["external-meeting-id"] ||
    a?.["external-meeting-id"] ||
    a?.meeting_id ||
    a?.meetingId ||
    ""
  ).toString();
}

function extractUser(ev) {
  const a = ev?.data?.attributes || {};
  const s = a?.sender || a?.user || {};
  return {
    internalUserId: (s?.["internal-user-id"] || s?.internalUserId || s?.id || a?.["user-id"] || a?.userId || "").toString(),
    name: (s?.["user-name"] || s?.name || a?.["user-name"] || a?.fullName || "").toString(),
  };
}

async function isModerator(meetingID, internalUserId) {
  try {
    const res = await bbbGet("getMeetingInfo", { meetingID });
    const attendeesNode = res?.response?.attendees?.attendee;
    const attendees = attendeesNode ? (Array.isArray(attendeesNode) ? attendeesNode : [attendeesNode]) : [];
    const att = attendees.find(x =>
      x?.userID === internalUserId ||
      x?.internalUserID === internalUserId ||
      (x?.fullName || "").toLowerCase() === (internalUserId || "").toLowerCase()
    );
    return (att?.role || "").toUpperCase() === "MODERATOR";
  } catch (e) {
    console.warn("getMeetingInfo failed:", e?.message);
    return false;
  }
}

async function callQwen(meetingID, userKey, prompt) {
  const redisKey = `ally:sess:${meetingID}:${userKey}`;
  const sessionId = (await redis.get(redisKey)) || null;

  const url = `https://dashscope-intl.aliyuncs.com/api/v1/apps/${APP_ID}/completion`;
  const payload = {
    input: { prompt },
    ...(sessionId ? { session_id: sessionId } : {}),
    parameters: {}
  };

  const res = await axios.post(url, payload, {
    headers: {
      Authorization: `Bearer ${DASHSCOPE_API_KEY}`,
      "Content-Type": "application/json",
    },
    timeout: 20000,
  });

  const out = res.data?.output || {};
  if (out.session_id) {
    await redis.set(redisKey, out.session_id, "EX", 60 * 60 * 24);
  }
  return out.text || "(no answer)";
}

app.get("/healthz", (req, res) => res.json({ ok: true }));

app.post("/webhook", async (req, res) => {
  try {
    if (!verifyWebhookSignature(req)) {
      return res.status(403).send("bad signature");
    }
    const raw = req.body?.event;
    if (!raw) return res.status(200).send("ok");

    const ev = typeof raw === "string" ? JSON.parse(raw) : raw;
    if (!looksLikeChatEvent(ev)) return res.status(200).send("ok");

    const meetingID = extractMeetingId(ev);
    const user = extractUser(ev);
    const text = extractMessage(ev);
    if (!meetingID || !text) return res.status(200).send("ok");

    const t = (text || "").trim();
    if (!t.toLowerCase().startsWith(ALLY_TRIGGER.toLowerCase())) return res.status(200).send("ok");

    const mod = await isModerator(meetingID, user.internalUserId || user.name);
    if (!mod) return res.status(200).send("ok");

    const question = t.slice(ALLY_TRIGGER.length).trim();
    if (!question) {
      await bbbSendChat(meetingID, `Usage: ${ALLY_TRIGGER} <your question>`);
      return res.status(200).send("ok");
    }

    const answer = await callQwen(meetingID, user.internalUserId || user.name, question);
    await bbbSendChat(meetingID, `${ALLY_NAME}: ${answer}`);
    return res.status(200).send("ok");
  } catch (e) {
    console.error("webhook error:", e);
    return res.status(500).send("err");
  }
});

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
