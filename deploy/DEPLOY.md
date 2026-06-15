# Real Deployment Guide

The sandbox config (`docker-compose.yml` in the repo root) is loopback-bound and safe to
run anywhere. **This guide is different** — it puts the honeypot on the open internet, where
it will be attacked within minutes. Treat every step as load-bearing.

> A honeypot deliberately invites hostile traffic. Only deploy on infrastructure you own or
> are explicitly authorized to operate, and check your provider's terms — some prohibit it.

---

## Threat model in one line

You are running a service whose entire purpose is to be attacked. Assume it **will** be
compromised, and design so that a compromise costs you nothing: a throwaway host, on an
isolated network, that cannot reach anything you care about, with its evidence already
copied off-box.

---

## Steps

### 1. Dedicated, disposable host
Provision a VM you are willing to delete — a cheap VPS, or a local VM (Proxmox/VMware) on an
**isolated VLAN** with no route to your LAN. Nothing else of value runs on it. Docker runs
*inside* this VM, so even a container escape only lands you on a host that's already garbage.

### 2. Move your real SSH off port 22 — BEFORE deploying
The honeypot wants port 22. Your administrative SSH must move first, or you'll lock the trap
over your own admin door.

```bash
sudo sed -i 's/^#\?Port 22/Port 2200/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

Open a **new** session on the new port and confirm it works *before* closing your current
one. Update your firewall to allow your admin port from your IP only.

### 3. Egress firewall — default deny
A honeypot has no legitimate reason to make outbound connections. Block egress except what
you explicitly need (e.g. your log shipper's destination). If the trap starts beaconing out,
that deny rule is your containment.

```bash
sudo ufw default deny outgoing
sudo ufw allow out 53          # DNS
sudo ufw allow out to <log-store-ip> port <port>
sudo ufw allow 22             # inbound to the honeypot
sudo ufw allow 2200           # inbound admin SSH (from your IP only, ideally)
sudo ufw enable
```

### 4. Deploy
```bash
docker compose -f deploy/docker-compose.prod.yml up --build -d
```
This uses **host networking** so the real attacker IP is preserved, binds **0.0.0.0:22**, and
adds only `NET_BIND_SERVICE` (everything else dropped, root filesystem read-only).

### 5. Verify real-IP capture
```bash
docker compose -f deploy/docker-compose.prod.yml logs -f
```
Within minutes you'll see `connection` and `auth_attempt` events from real scanner IPs — and
critically, `src_ip` is now the **attacker's** address, not a bridge gateway. Confirm that.

### 6. Ship the evidence off-box
The trap must never be the only copy of its own logs. Tail `./data/honeypot.jsonl` to an
off-host store (Promtail→Loki, Filebeat→ELK, or a vector/fluent-bit sidecar). A compromise of
the honeypot must not be able to erase what it recorded.

---

## Recommended before you expose it: code hardening

The capture engine is correct but written for a sandbox. The open internet hammers port 22
continuously, and `honeypot.py` spawns one unbounded thread per connection. Before real
exposure, add:

- **A connection cap** — a `threading.Semaphore(N)` (e.g. 500) acquired in `main()` before
  spawning each handler thread, released in the handler's `finally`. Caps memory/thread blowup
  under a flood so the trap doesn't DoS itself.
- **A handshake/idle timeout** — `transport.banner_timeout` and a socket timeout so a client
  that connects and stalls can't pin a thread forever.

These are small, surgical changes to `honeypot.py`. They're left out of the committed engine
to keep the sandbox version minimal and readable — apply them in your deployment fork.

---

## Residual risks you're accepting

- **Host networking drops the container's network-namespace isolation.** That's the deliberate
  trade for real-IP capture — which is why step 1 (throwaway, isolated host) is non-negotiable.
- A determined attacker who finds a Paramiko or kernel bug could escape. The whole design
  assumes this and makes it not matter.
- Running an SSH honeypot on a provider that forbids it can get your account terminated. Check.
