---
title: TOTP Access Gate
sidebar_position: 6
description: Protect the entire Yopass instance — UI and API — behind a shared TOTP code. No license required.
---

# TOTP Access Gate

The TOTP access gate acts as a door lock in front of the whole instance: until the visitor enters a valid 6-digit code from an authenticator app, **nothing** responds — not the UI, not the API, not the static assets. It is a single shared gate for the deployment, not per-user authentication; it is completely independent of [OpenID Connect](./openid-connect), and both can be enabled at once (the TOTP code first, then OIDC sign-in on top).

> **No license required.** Unlike OIDC, the access gate is a plain server feature.

## How it works

| Step | Result |
|------|--------|
| Browser opens any URL | A minimal login page is served (language follows the browser's `Accept-Language`; Simplified Chinese is built in). The address bar keeps the deep link — after login you land back on the page you originally wanted (e.g. a secret link). |
| API client calls any endpoint | `401 {"message":"TOTP authentication required"}` |
| Visitor submits the code | Code is verified against the shared secret (RFC 6238, SHA-1, 30-second steps, ±1 step tolerance for clock drift). On success the server sets a signed, HttpOnly session cookie valid for **7 days**. |
| Any later request | Passes with the cookie, until it expires or the secret is rotated. |

The signed cookie is derived from the TOTP secret itself, so sessions survive restarts **and work across multiple instances** running with the same secret — no extra session-key configuration like OIDC requires.

Failed attempts are rate-limited **per IP to 10 per minute** (reject with `429` after that). Health endpoints `/health` and `/ready` and the gate's own `/auth/totp` endpoint stay reachable without the cookie so probes and the login flow keep working.

## Enable

All configuration goes through one setting (the startup log prints a ready-to-scan provisioning URI):

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--totp-secret` | `TOTP_SECRET` | — (gate off) | Base32 TOTP secret |

### 1. Generate a secret

```bash
head -c 20 /dev/urandom | base32 | tr -d '='
# e.g. GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
```

### 2. Start with the secret

```bash
# flag
yopass-server --totp-secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ

# or environment variable
TOTP_SECRET=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ yopass-server
```

### 3. Scan the secret into your authenticator app

On startup the server logs the provisioning URI for the configured secret:

```
{"level":"info","msg":"TOTP access gate enabled",
 "provisioning_uri":"otpauth://totp/Yopass:admin?issuer=Yopass&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}
```

Convert it to a QR code and scan it (any QR tool: `qrencode -t ANSIUTF8 'otpauth://…'`), or add the secret manually in your authenticator (Google Authenticator, Aegis, 1Password, KeePassXC, …).

## Deploy with Docker Compose

The gate ships with the local build. Once the feature reaches an upstream release you can swap `build:` for the `jhaals/yopass` image.

```yaml
# docker-compose.yml
services:
  memcached:
    image: memcached:alpine
    restart: always

  yopass:
    build: .                 # local build from the branch that has the gate
    # image: jhaals/yopass   # upstream image once released
    restart: always
    ports:
      - "127.0.0.1:80:80"    # bind to localhost; put a reverse proxy in front
    environment:
      - MEMCACHED=memcached:11211
      - PORT=80
      - TOTP_SECRET=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    healthcheck:
      test: ["CMD", "/yopass-server", "--health-check"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s
```

```bash
docker compose up -d --build
docker compose logs yopass | grep provisioning_uri   # grab the QR URI
```

### Behind a reverse proxy

When nginx/Traefik/Caddy sits in front, additionally set `TRUSTED_PROXIES` so the rate limiter sees real client IPs (and HTTPS is detected correctly for the cookie's `Secure` flag):

```yaml
    environment:
      - TRUSTED_PROXIES=172.16.0.0/12   # your proxy network, or e.g. 10.0.0.1/32
```

The ready-made templates in `deploy/docker-compose/` (`insecure/`, `with-nginx-proxy-and-letsencrypt/`) work as-is — just add the `TOTP_SECRET` line to the `yopass` service.

### Split-origin note

The gate lives on the backend. In split deployments where the frontend is hosted on a *different* origin (e.g. Netlify) the gate cannot protect that static site and API calls from it will be blocked. In that setup, put the gate at the reverse proxy in front of the whole deployment instead.

## Operation

- **Rotate / recover the secret** — set a new `TOTP_SECRET` and restart. All outstanding cookies stop working immediately (they are signed with the old secret), i.e. everyone must re-enter a code — there is no lockout, just a re-login.
- **Multiple instances** — same `TOTP_SECRET` on every instance; cookies and rate limits work per instance (rate-limit at the proxy if you need it aggregated).
- **Audit logging** — with `--audit-log` enabled, gate events are recorded as `auth.totp_passed`, `auth.totp_failed` and `auth.totp_blocked`.
- **CLI client** — the `yopass` CLI cannot complete the interactive code prompt; use the web UI. Machine clients can programmatically obtain a session by POSTing a freshly computed code to `/auth/totp` and reusing the returned cookie (crafted scripts only — a 30-second rotating code is not a durable machine credential).