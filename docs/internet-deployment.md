# Controlling a machine anywhere in the world from a browser

This is the step-by-step for the "AnyDesk-style" setup: a machine somewhere
gets a **userid (its ID)** and a **password**, and you control it from any
browser on Earth by entering that ID + password. Nothing is installed on the
controlling side.

## How it works (and why NAT/firewalls don't block it)

```
┌─────────┐  browser    ┌──────────────────────────────┐  outbound  ┌─────────────┐
│ You,     │  https/ws   │  YOUR SERVER (public IP)     │  TCP from  │ Controlled  │
│ anywhere ├────────────►│  kbdesk-web      :8080 / 443 │◄───────────┤ machine,    │
│          │  ID+password│  kbdesk-server   :21118      │  (host     │ anywhere —  │
└─────────┘              │  (`kbdesk serve`)            │  dials out)│ home/office │
                         └──────────────────────────────┘            └─────────────┘
```

Three roles:

| Piece | Runs where | Needs public IP / open ports? |
|-------|-----------|-------------------------------|
| **Relay + web viewer** (`kbdesk serve`) | One server that is always on | **Yes** — this is the only public piece |
| **Host agent** (`kbdesk-host`) | Each machine to be controlled | **No.** It makes one *outbound* connection to the relay and stays registered, so it works behind any home/office router, hotel Wi-Fi, or mobile hotspot with zero router configuration |
| **Browser** | Your laptop/phone/tablet | No — just open the server's URL |

"Userid" in KB-Desk terms:

- **ID = the userid.** By default the relay assigns a 9-digit ID
  (e.g. `544 228 382`) when the host first registers. Prefer a memorable
  userid? Start the host with `--id officepc` and that fixed ID is its
  userid forever (letters/digits; spaces and dashes are ignored when typing
  it into the browser).
- **Password = per-machine password** you set on the host
  (`--password …`). Use a different, long, random one for every machine.
  There are deliberately no central user accounts: whoever knows a machine's
  ID + password can control that machine, so treat the password accordingly.

## Option A — a small VPS (the standard way)

A ₹400–500/mo (or free-tier) VPS anywhere is plenty — the relay is a byte
pump, so 1 vCPU / 1 GB RAM handles several sessions. A domain name is
optional but recommended: you need one for HTTPS (step 5).

### 1. Install KB-Desk on the server

Either build it (needs Rust from <https://rustup.rs>):

```bash
git clone https://github.com/mylab12345/KB-Desk.git
cd KB-Desk
# Server only needs these three crates (skips host/client system deps):
cargo build --release -p kbdesk-launcher -p kbdesk-server -p kbdesk-web
```

…or download the ready-made `kbdesk-linux-x86_64` artifact from the latest
green **Actions** run on GitHub and unzip it, or install the `.deb` from
`packaging/` (puts binaries in `/usr/bin` plus systemd units).

### 2. Open the firewall

Two inbound TCP ports on the server (OS firewall **and** your cloud
provider's security group, if any):

```bash
sudo ufw allow 21118/tcp   # relay (hosts register, pairing)
sudo ufw allow 8080/tcp    # web viewer (or 443 if you add HTTPS in step 5)
```

### 3. First run (manual, to prove it works)

```bash
./target/release/kbdesk serve
# → prints the browser URL and the host command to use in the next section
```

From your laptop browser open `http://<server-public-ip>:8080/` — you should
see the KB-Desk login form. Leave it running and set up a host (next big
section), then connect end-to-end once before making it permanent.

### 4. Make it survive reboots

For production prefer the packaged **separate systemd units** (they restart
independently and are sandbox-hardened) over supervising `kbdesk serve`:

```bash
# With the .deb installed, units already exist. Point the web viewer at the
# relay on the same box, then enable both:
sudo sed -i 's|^KB_DESK_WEB_ARGS=.*|KB_DESK_WEB_ARGS=--listen 0.0.0.0:8080 --relay 127.0.0.1:21118|' /etc/kbdesk/kbdesk-web.env
sudo systemctl enable --now kbdesk-server kbdesk-web
```

Without the .deb, copy `packaging/systemd/kbdesk-{server,web}.service` to
`/etc/systemd/system/`, adjust the binary paths, create
`/etc/kbdesk/kbdesk-web.env` with the line above, `systemctl daemon-reload`,
then enable both.

### 5. HTTPS for the browser leg (strongly recommended with a domain)

Put Caddy in front of the web viewer — it gets a Let's Encrypt certificate
automatically and upgrades the page to `wss://`:

```
# /etc/caddy/Caddyfile
desk.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Then bind kbdesk-web to loopback (`--listen 127.0.0.1:8080` in
`kbdesk-web.env`), open only **443 + 21118** in the firewall, and use
`https://desk.example.com/` from the browser.

> ⚠️ **Read this before exposing anything:** in the current version the
> host↔relay leg (TCP 21118) is **plaintext** — the password check and the
> screen stream are not encrypted, and HTTPS above only protects the
> browser↔server leg. On the open internet that means anyone who can sniff
> the host↔server path (or guess an ID and brute-force the password
> online) is a real threat. Use long random passwords, keep the relay
> patched, and for anything sensitive prefer **Option B** (VPN) until TLS
> transport lands (see the Security section of the README). Do not skip
> this decision just because "it works".

## Option B — worldwide over a VPN (safest today)

If every controlling device can run a VPN client (your own laptop/phone),
this gives you "anywhere in the world" with **zero public exposure**:

1. Install Tailscale (or WireGuard) on: the server, each controlled
   machine, and your controlling devices; put them on one tailnet/network.
2. Run `kbdesk serve` (or the two systemd units) on the server as in
   Option A, but **don't open any router/cloud firewall ports**.
3. Hosts register with the server's VPN address:
   `kbdesk-host --server <server-vpn-ip>:21118 …` (Tailscale also gives it
   a stable `*.ts.net` name you can use instead of the IP).
4. From any browser on a VPN-connected device, open
   `http://<server-vpn-ip>:8080/`. Everything is inside the encrypted VPN,
   so the plaintext limitation above does not apply.

Works even if the "server" is a PC at home — no public IP needed at all.

## Option C — a PC at home as the server (public internet, no VPS)

Only works if your ISP gives your router a **real public IPv4**:

1. Compare your router's WAN IP with what a "what is my IP" site shows.
   If they differ — or the WAN IP is in `100.64.0.0/10` — you're behind
   CGNAT (common on Indian home/mobile ISPs) and port forwarding **cannot**
   work; use Option A or B instead (or ask your ISP for a public/static IP).
2. In the router, port-forward TCP **21118** and **8080** (or 443 behind
   Caddy) to the always-on PC running `kbdesk serve`.
3. If your public IP changes, use a dynamic-DNS name and give hosts /
   browsers that name instead of the raw IP.

## Set up each machine to be controlled

One-time, per machine. The host must be running (and auto-start at login)
for the machine to be reachable.

```bash
# Linux/macOS (from a clone with cargo build --release):
target/release/kbdesk-host --server desk.example.com:21118 --password '<long-random-password>'
# Windows (PowerShell):
.\target\release\kbdesk-host.exe --server desk.example.com:21118 --password '<long-random-password>'
# → KB-Desk ID: 544228382        ← this is the machine's "userid"; note it down
```

- **Fixed/memorable userid:** add `--id officepc` (pick your own). Without
  it, the ID stays stable while the process runs but a *new random ID is
  assigned after a restart*, so unattended machines should use `--id`.
- **Auto-start:**
  - *Linux:* the packaged **user** service —
    edit `~/.config/kbdesk/host.env` (`KB_DESK_SERVER=`,
    `KB_DESK_PASSWORD=`), then `systemctl --user enable --now kbdesk-host`.
    For a fixed ID, add `--id officepc` to the unit's `ExecStart`.
    Capture works on X11 (or Wayland via XWayland); the agent must run
    inside the logged-in desktop session, not as root.
  - *Windows:* Task Scheduler → "At log on" → run
    `kbdesk-host.exe --server … --password … --id …`
    (or a shortcut in `shell:startup`). To control elevated (UAC) windows,
    run it elevated.
  - *macOS:* grant **Screen Recording** and **Accessibility** in
    System Settings → Privacy & Security on first run, then add it as a
    Login Item with the same arguments.
- The host re-registers automatically after every session and after network
  drops — once it's auto-starting, the machine is simply "always there"
  under its ID.

## Control it

1. Open `https://desk.example.com/` (or `http://<server-ip>:8080/`) in any
   browser — desktop or phone.
2. Enter the machine's **ID** (spaces are fine) and its **password** →
   **Connect**. Bookmark `https://desk.example.com/?id=544228382` to
   prefill the ID.
3. Click the screen to give it your keyboard; use **Fullscreen** so
   Esc/F-keys go to the remote, **Send keys** for Ctrl+Alt+Del etc., and
   **Paste text** to type long strings (passwords, commands) into it.

## Security checklist before you go live

- [ ] Long, unique, random password per machine (password manager).
- [ ] Prefer Option B (VPN), or at minimum HTTPS for the browser leg.
- [ ] Firewall: only 21118 + 8080/443 open on the server; consider
      source-IP allow-listing 8080/443 to your own networks if feasible.
- [ ] `kbdesk-web` always runs with `--relay` set (as `kbdesk serve` and
      the env example do) — never expose it without `--relay`, or visitors
      could ask it to dial arbitrary addresses.
- [ ] Keep the server OS and KB-Desk updated (`git pull && cargo build
      --release`, restart services).
- [ ] Understand the current plaintext-relay limitation (Option A note).

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `kbdesk-server: command not found` | Not built/installed — use `./run.sh`, `target/release/…`, or `cargo install` (see README "Run it") |
| Browser page doesn't load from outside | Firewall/security-group: 8080 (or 443) not open, or web unit not running (`systemctl status kbdesk-web`, `curl http://127.0.0.1:8080/healthz` on the server) |
| "no host is registered with that id" | Host agent not running, registered with a different/new ID after restart (set `--id`), pointing at the wrong `--server`, or server's 21118 not reachable from the host (`curl -v telnet://desk.example.com:21118`) |
| "authentication failed" | Wrong password for *that* machine (each host has its own) |
| Connects, black/frozen screen | Host capture permission/session: macOS Screen Recording, Linux must be a logged-in X11/XWayland desktop session (not a root/SSH shell) |
| Mouse moves but clicks/keys do nothing | macOS Accessibility permission; Windows: target window is elevated and the host isn't |
| Laggy on slow links | Lower **Quality**/**FPS** in the viewer toolbar (applies live); latency itself does not snowball — stale frames are dropped by design |
| Works on Wi-Fi at home, not from outside | You're using a LAN IP / CGNAT — use the server's public IP/domain everywhere (Option C check) |

## FAQ

- **Does the controlled machine need a public IP or port forwarding?**
  No. It only dials out to the relay. Any NAT/firewall is fine.
- **How many machines per server?** Many — each host gets its own ID. One
  viewer controls one host per session; the host is free again afterwards.
- **Two hosts with the same `--id`?** The newest registration replaces the
  old one. Keep IDs unique.
- **Can I control from a phone?** Yes — the viewer supports touch
  (tap = click, long-press = right-click, two-finger scroll) and has an
  on-screen extra-keys bar + soft-keyboard support.
