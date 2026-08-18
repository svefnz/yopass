---
title: Docker Compose Deployment
sidebar_position: 4
description: "Production-grade Docker Compose deployment: storage backends, TOTP access gate, reverse proxy with TLS, health checks, and operations."
---

# Docker Compose Deployment

This guide builds a production-ready Yopass with Docker Compose: storage backend, the [TOTP access gate](./totp-access-gate), TLS termination via a reverse proxy, and the operational details the quick start skips. Every template in this guide is complete — copy, adjust the placeholders, run.

## 1. Production template

**Memcached** is what the [quick start](./quickstart) uses. It is ephemeral by design: a restart of the memcached container wipes all stored secrets. That is acceptable for yopass semantics (secrets self-destruct within a week anyway), but if you want data to survive restarts, use the [Redis variant](#redis-persistence) instead.

```yaml title="docker-compose.yml"
services:
  memcached:
    image: memcached:1.6-alpine
    restart: always
    # no ports: reachable only inside the compose network

  yopass:
    # image: jhaals/yopass:latest        # released image (stable channel)
    build: .                             # or local build of this branch
    restart: always
    ports:
      - "127.0.0.1:80:80"                # reverse proxy picks it up from localhost
    environment:
      - PORT=80
      - MEMCACHED=memcached:11211
      # - DATABASE=redis                 # switch to Redis instead (section 2)
      # - REDIS=redis://redis:6379/0
      # - TOTP_SECRET=${TOTP_SECRET}     # access gate (section 4); keep it out of this file
      # - TRUSTED_PROXIES=172.16.0.0/12  # CIDR of the reverse proxy network
    depends_on:
      memcached:
        condition: service_started
    healthcheck:
      test: ["CMD", "/yopass-server", "--health-check"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s
```

```bash
docker compose up -d
curl -s localhost/health   # {"status":"healthy"} once up
```

:::tip Bind to localhost
`127.0.0.1:80:80` exposes Yopass only to the host. Put a reverse proxy in front (section 3) — never publish the port to the world without TLS.
:::

## 2. Redis (persistence)

Swap the storage backend to Redis and let a volume persist data:

```yaml title="docker-compose.yml"
services:
  yopass:
    image: jhaals/yopass:latest
    restart: always
    ports:
      - "127.0.0.1:80:80"
    environment:
      - PORT=80
      - DATABASE=redis
      - REDIS=redis://redis:6379/0
      - TOTP_SECRET=${TOTP_SECRET}
      - TRUSTED_PROXIES=172.16.0.0/12
    depends_on:
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "/yopass-server", "--health-check"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s

  redis:
    image: redis:7-alpine
    restart: always
    command: redis-server --appendonly yes
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5

volumes:
  redis-data:
```

Enable the [disk file store](./file-storage) the same way if you upload large files:

```yaml
    environment:
      - FILE_STORE=disk
      - FILE_STORE_PATH=/data/files
    volumes:
      - yopass-files:/data/files
```

## 3. TLS via reverse proxy

Terminating TLS at a reverse proxy is the recommended setup — see [TLS guide](./tls) for the trade-offs. Bind Yopass to `localhost` only and let the proxy bridge the public port.

### Caddy (one file, automatic Let's Encrypt)

```yaml title="docker-compose.yml"
services:
  caddy:
    image: caddy:2-alpine
    restart: always
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config

  yopass:
    image: jhaals/yopass:latest
    restart: always
    environment:
      - PORT=80
      - MEMCACHED=memcached:11211
      - TOTP_SECRET=${TOTP_SECRET}
      - TRUSTED_PROXIES=172.18.0.0/16   # default compose bridge network
    healthcheck:
      test: ["CMD", "/yopass-server", "--health-check"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s

  memcached:
    image: memcached:1.6-alpine
    restart: always

volumes:
  caddy-data:
  caddy-config:
```

```text title="Caddyfile"
secrets.example.com {
    reverse_proxy yopass:80
}
```

```bash
docker compose up -d
```

HTTPS + certificate are handled automatically for `secrets.example.com` (point the DNS record at the host first).

### Nginx proxy + Let's Encrypt

The repository ships a complete template: [`deploy/docker-compose/with-nginx-proxy-and-letsencrypt/docker-compose.yml`](https://github.com/jhaals/yopass/tree/master/deploy/docker-compose/with-nginx-proxy-and-letsencrypt). Set `VIRTUAL_HOST`, `LETSENCRYPT_HOST`, `LETSENCRYPT_EMAIL`, and add `TOTP_SECRET` to the `yopass` service.

## 4. The TOTP access gate

Set one environment variable to lock the whole instance behind a 6-digit authenticator code. Generate the secret, put it in `.env` (never commit it), and scan the provisioning URI printed at startup:

```bash
head -c 20 /dev/urandom | base32 | tr -d '='
echo "TOTP_SECRET=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" >> .env
docker compose up -d
docker compose logs yopass | grep provisioning_uri
```

Full walkthrough — QR scanning, rotation, rate limiting, multi-instance behavior — in the [TOTP access gate](./totp-access-gate) guide.

## 5. Configuration cheat sheet

| Setting | Env var | Purpose |
|---------|---------|---------|
| Storage | `MEMCACHED` / `DATABASE` + `REDIS` | Backend; Redis survives restarts |
| Port | `PORT` | Inside the container it must match what the proxy targets (`80` in the templates) |
| Access gate | `TOTP_SECRET` | Lock the instance behind a TOTP code |
| Trusted proxies | `TRUSTED_PROXIES` | Comma-separated proxy CIDRs; required for correct client IPs and `Secure` cookies behind a proxy |
| Generated links | `PUBLIC_URL` | Base URL used in generated secret links (optional) |
| Uploads | `MAX_FILE_SIZE`, `FILE_STORE`, `FILE_STORE_PATH` | Large-file support ([File Storage](./file-storage)) |
| OIDC | `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_REDIRECT_URL`, `REQUIRE_AUTH` | Per-user authentication *(license)* — see [OpenID Connect](./openid-connect) |

Every flag has an equivalent env var; the full list is in [Server Options](./server-options).

## 6. Operations

- **Upgrades** — `docker compose pull && docker compose up -d`. For local builds: `docker compose up -d --build`. The single-file template keeps no state, so the old container can simply be replaced.
- **Backups** — secrets are ephemeral by design; there is nothing meaningful to back up beyond the Redis volume / file-store volume (the default backend stores everything in memory). If an empty instance after a crash is unacceptable, use Redis + `--appendonly yes`.
- **Scaling / HA** — multiple yopass replicas can share one Redis backend and one `TOTP_SECRET` behind a load balancer; sessions (TOTP cookie, OIDC) remain valid because TOTP keys are derived from the shared secret (OIDC additionally needs a shared `OIDC_SESSION_KEY`). Memcached cannot be shared — keep a single replica with it.
- **Security checklist**
  - Never publish memcached/redis ports (`expose` only, or no `ports:` at all)
  - Bind the app port to `127.0.0.1` unless the proxy is another container
  - Set `TRUSTED_PROXIES` when behind any proxy (otherwise `Secure` cookies break over HTTP-within-proxy and rate limiting sees one IP)
  - Put `TOTP_SECRET` and license keys in `.env` or a secret manager, not the compose file