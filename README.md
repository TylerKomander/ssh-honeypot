# SSH Honeypot

A low-interaction SSH honeypot that speaks just enough of the SSH protocol to capture
credential-stuffing and brute-force attempts — the source IP, the client banner, and every username,
password and public key tried — as one JSON event per line. **It never authenticates anyone and never
grants a shell: it records the attempt, returns failure, and disconnects.**

Not a raw port listener, and not a real SSH server with the login ripped out: it completes the SSH
handshake with a real host key so attackers actually send their credentials, then fails every auth
callback by design. It runs fully contained — Docker, loopback-bound — for safe experimentation, and
the same image drops onto an internet-facing VPS when you want real capture.

## Run it

Docker is the recommended path because the container *is* the containment boundary:

```bash
docker compose up --build
```

Captured events stream to stdout and persist to `./logs/honeypot.jsonl`. From another terminal:

```bash
ssh -p 2222 root@localhost      # type any password — it is logged and rejected
```

Without Docker:

```bash
python -m venv venv
# Windows: venv\Scripts\activate    |    Unix: source venv/bin/activate
pip install -r requirements.txt
python honeypot.py
```

Configurable via env: `HONEYPOT_HOST`, `HONEYPOT_PORT`, `HONEYPOT_BANNER`, `HONEYPOT_LOG_DIR`,
`HONEYPOT_HOST_KEY`.

## How it works

A plain socket on port 22 only ever sees the client's version banner. Real SSH clients negotiate an
encrypted transport **before** they send a username or password, so a raw listener captures zero
credentials. To log what attackers actually try, you have to complete the handshake and present a
host key — which is why this uses [Paramiko](https://www.paramiko.org/) to implement a fake SSH
*server* that accepts the auth exchange, records it, and always returns `AUTH_FAILED`.

```
  attacker ──TCP──▶ :2222 ──▶ Paramiko Transport
                                  │  SSH handshake + host key
                                  │  auth callbacks (always fail)
                                  ▼
                          logs/honeypot.jsonl   (one JSON event per line)
```

One thread per connection, so the listener never blocks on a slow client. Every credential attempt is
logged and rejected — there is no code path that returns success — and no shell, command execution or
file access is ever exposed to the client.

### Event schema

| event            | key fields                                                        |
|------------------|-------------------------------------------------------------------|
| `listener_start` | `host`, `port`                                                    |
| `connection`     | `src_ip`, `src_port`, `client_banner`, `session_id`               |
| `auth_attempt`   | `method` (`password`/`publickey`), `username`, `password` or `key_fingerprint`, `session_id` |
| `error`          | `detail` — scanners and banner-grabbers that bail mid-handshake    |

`session_id` correlates a connection with all of its auth attempts. A sample of real captured output
ships as [`sample-honeypot.jsonl`](sample-honeypot.jsonl):

```json
{"event":"connection","timestamp":"2026-06-15T22:40:38.412192+00:00","session_id":"5a7e817bdf1b","src_ip":"127.0.0.1","src_port":58602,"client_banner":"SSH-2.0-paramiko_5.0.0"}
{"event":"auth_attempt","timestamp":"2026-06-15T22:40:38.413193+00:00","session_id":"5a7e817bdf1b","src_ip":"127.0.0.1","src_port":58602,"method":"password","username":"root","password":"hunter2"}
```

## Containment

A honeypot deliberately attracts hostile traffic, so isolation is the whole point. The sandbox config
is hardened, not incidental:

- **Loopback-only by default** — `127.0.0.1:2222:2222`. Out of the box it is reachable only from the
  host; nothing touches your LAN or the internet until you change that.
- **Non-root** — runs as an unprivileged user (`uid 10001`).
- **Read-only root filesystem** — the container cannot modify its own code; only the mounted `/data`
  log volume is writable.
- **`cap_drop: ALL` + `no-new-privileges`** — no Linux capabilities, no privilege escalation.
- **No shell, ever** — the strongest control is architectural: there is no success path and no command
  execution, so there is nothing to escape *from*.
- **Private host key is git-ignored** — generated at first run, never committed.

## Deploying it for real

A ready-to-run production config and a step-by-step guide live in [`deploy/`](deploy/):
[`docker-compose.prod.yml`](deploy/docker-compose.prod.yml) (host networking, real-IP capture, port
22) and [`DEPLOY.md`](deploy/DEPLOY.md). **Read the guide before exposing anything.** In summary, what
changes from the sandbox:

1. **A dedicated VM** (VMware / Proxmox) on an **isolated VLAN**, with Docker running *inside* it — so
   even a container escape lands in a throwaway network with no route to anything real.
2. **Bind to `0.0.0.0` and map host `:22 → container :2222`**, since real scanners hammer port 22.
   Preserve the real client IP: behind Docker's default bridge the userland proxy SNATs inbound
   traffic, so `src_ip` logs as the bridge gateway (e.g. `172.18.0.1`) instead of the attacker. For
   real attribution, use host networking (`network_mode: host`) or a setup that forwards the original
   source address.
3. **An egress firewall defaulting to deny** — a honeypot has no legitimate reason to make outbound
   connections.
4. **Ship `honeypot.jsonl` off-box** to a central log store (Loki / ELK), so compromising the trap
   can't tamper with the evidence.
5. **Rotate and alert on the data** — flag spikes from a single ASN, or newly-trending
   username/password pairs.

## What it deliberately leaves out

The code here is the *capture engine* — complete and production-sound on its own. A real deployment
wraps it with operational scaffolding that is intentionally out of scope, because the trap should stay
small and the analysis should live elsewhere:

- **Log shipping and storage** — forward `honeypot.jsonl` off-box (Promtail→Loki, Filebeat→ELK, or
  `journald` plus a collector). The trap should never be the only copy of its own evidence.
- **Enrichment** — resolve `src_ip` to ASN, geo and known-scanner lists (GreyNoise, AbuseIPDB) at
  ingest, so the raw log stays minimal and the analysis layer adds the context.
- **Alerting** — thresholds on attempt volume, new credential patterns, or non-scanner clients.
- **Uptime** — `restart: unless-stopped` (already set) plus external monitoring, so a wedged container
  is noticed rather than silently missed.
- **Retention** — rotate and compress logs; a high-traffic honeypot fills disk fast.

## Disclaimer

For research and education. Only deploy a honeypot on infrastructure you own or are explicitly
authorized to operate, and review your provider's terms — some prohibit intentionally inviting attack
traffic. Not affiliated with the OpenSSH project or Paramiko beyond using the latter as a library.
