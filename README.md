# bbb-ally

Moderator-only AI chat for **BigBlueButton 3.0** backed by **Alibaba Cloud Model Studio (Qwen)**.

- Trigger: `@ally` (moderators only)
- Multi-turn via Model Studio `session_id` (stored per meeting+user in Redis)
- Posts answers back using BBB **sendChatMessage** (auto-chunked to 500 chars)
- Uses **bbb-webhooks** to receive chat events and verifies signatures
- Runs as a Docker sidecar (upgrade-safe from BBB perspective)
- Shows a **typing indicator** (`⏳ Assistant is thinking…`) while waiting for replies
- Resilient to overflow errors from long context; supports manual reset with phrases like `@ally reset`

## Quick start

### 0) Prereqs on your BBB host
- Docker + compose plugin
- `bbb-webhooks` package installed
- Nginx available (standard on BBB)

Also configure `/etc/bigbluebutton/bbb-webhooks/production.yml` to ensure checksum-based auth works:

```yaml
bbb:
  serverDomain: "YOUR_BBB_HOST"      # host only (no scheme, no path)
  sharedSecret: "YOUR_BBB_SECRET"    # from bbb-conf --secret
  auth2_0: false                     # force checksum mode
  checksumAlgo: sha1                 # default, explicit is fine
```

### 1) Clone & configure
```bash
git clone https://github.com/YOUR_ORG/bbb-ally.git
cd bbb-ally
cp .env.example .env
nano .env   # fill BBB_API_BASE, BBB_SECRET, PUBLIC_BASE_URL, DASHSCOPE_API_KEY, APP_ID
```

Get BBB API base & secret:
```bash
bbb-conf --secret
# Use API base: https://YOUR_BBB_HOST/bigbluebutton/api
```

### 2) Expose the bot via Nginx
Add the `nginx-ally.conf` `location /ally/` block to your BBB nginx site (or drop into `/etc/nginx/conf.d/ally.conf`) and reload:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 3) Start
```bash
sudo docker compose build
sudo docker compose up -d
curl -fsS https://YOUR_BBB_HOST/ally/healthz   # -> {"ok":true}
```

The service auto-registers a webhook to `https://YOUR_BBB_HOST/ally/webhook` every 5 minutes.

### 4) Test in a meeting
As a **moderator** in BBB public chat:

```
@ally What is the difference between TCP and UDP?
```

Ally replies in chat with a multi-turn-capable response.

## Environment variables
See `.env.example` for all options. Key ones:

- `BBB_API_BASE` — e.g. `https://HOST/bigbluebutton/api`
- `BBB_SECRET` — from `bbb-conf --secret`
- `PUBLIC_BASE_URL` — e.g. `https://HOST/ally`
- `DASHSCOPE_API_KEY` — your Alibaba Cloud DashScope key
- `APP_ID` — Model Studio Application ID (your Qwen app)
- `ALLY_TRIGGER` — default `@ally`
- `ALLY_NAME` — bot display name in chat
- `WEBHOOK_CHECKSUM_ALG` — default `sha256`; must match your `production.yml`
- `WEBHOOK_STRICT` — set `false` temporarily if your signature format differs
- `ALLY_REQUIRE_MOD` — require moderator role to invoke Ally (default `true`)
- `DUP_TTL_SECONDS` — dedupe identical asks briefly (default `8`)
- `QWEN_CONCISE` — `true` to nudge concise answers
- `ALLY_LOADING_ENABLED` — show loading indicator while waiting
- `AUTO_RESET_ON_OVERFLOW` — auto-clear session on DashScope overflow errors
- `ALLY_RESET_PHRASES` — manual reset triggers (default: reset,new topic,clear,…)

## Notes
- Configure **bbb-webhooks** with `auth2_0: false` and `checksumAlgo: sha1` or Ally will not receive events.
- The webhook verifier accepts multiple known encodings; set `WEBHOOK_STRICT=true` for strict checking.
- Redis stores Qwen `session_id` per (meeting,user) for 24h; reset clears it.
- Ally chunks long answers automatically (500 chars per chat message).
- Only moderators can invoke Ally; enforced via `getMeetingInfo` if needed.

## License
MIT
