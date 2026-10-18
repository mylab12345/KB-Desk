# KB-Desk

A self-hosted remote desktop tool: view and control another machine's screen
over the network. Built from scratch in Rust. **All traffic is encrypted**:
TLS on every connection, plus an end-to-end encrypted viewer↔host session
(the relay and web bridge only ever forward ciphertext) — see
[`docs/encryption-and-certificates.md`](docs/encryption-and-certificates.md).

> **KB-Desk is an independent, clean-room implementation.**
> It is **not** derived from RustDesk, AnyDesk, TeamViewer, VNC, or any other
> remote-desktop product. No third-party application source code was copied.
> The wire protocol, capture pipeline, relay, and GUI are original. KB-Desk is
> released under the MIT license (see `LICENSE`).

---

## Quick start (Windows · macOS · Linux)

Clone the repo, then run **one command**. It builds on first use, then starts a
relay, the host (sharing this machine) and the browser viewer:

```bash
# Linux / macOS
./run.sh                 # relay + host + web viewer  (viewers need only an ID)
./run.sh web             # host + web viewer, no relay
./run.sh host            # just share this screen

# Windows (PowerShell)
.\run.ps1                # same modes as above
.\run.cmd web            # double-clickable wrapper for PowerShell
```

Then, from another machine, open the printed `http://<this-machine>:8080/` in any
browser and enter the **ID** and **password** from the banner.

`run.sh` / `run.ps1` only build the project and forward to the `kbdesk` launcher,
so the same command works on every OS. A Rust toolchain is required
(<https://rustup.rs>).

## Control any machine from just a browser (relay mode)

Browsers cannot open raw TCP connections, so a browser can never talk to the
relay directly. `kbdesk-web` is the bridge that fixes that: it serves the viewer
page over HTTPS and pipes the browser's Secure WebSocket to the relay's TLS
port. It is deliberately *blind* — the page itself performs the encrypted
handshake with the host, so the bridge (like the relay) only forwards
ciphertext and never sees screen, input, or the password. Run the relay and
the bridge together on one reachable server (LAN box, VPS, …) and the person
*controlling* needs nothing but a browser:

```bash
# On the server (stays running):
./run.sh serve            # = kbdesk serve: relay :21118 + browser viewer :8080

# On each machine to be controlled (after cargo build --release there).
# Copy ca.pem from the server's kbdesk-tls/ first (printed by `serve`), or
# omit --tls-ca when the relay uses a publicly trusted certificate:
target/release/kbdesk-host --server <server-ip>:21118 --password <its-password> --tls-ca ca.pem
# → prints:  KB-Desk ID: 544228382      (stays registered, reconnects itself)

# On the controlling side: open https://<server-ip>:8080/ in any browser,
# enter 544 228 382 + that machine's password → full control.
```

```
┌─────────┐  WSS (TLS)  ┌────────────────────────────┐   TLS    ┌────────────┐
│ Browser │◄────────────►│ kbdesk-web ─► kbdesk-server│◄────────►│kbdesk-host │
│ (only a │   :8080      │ blind bridge   relay :21118│ registers│ (controlled│
│ browser)│              │        `kbdesk serve`      │  by ID   │  machine)  │
└─────────┘              └────────────────────────────┘          └────────────┘
 ╰──────── end-to-end encrypted session (page ↔ host, inside the pipe) ──────╯
```

The browser viewer is a complete controller, not a view-only page:

- mouse (incl. middle/back/forward buttons, scroll), full keyboard with
  left/right modifiers, numpad, F1–F24, PrintScreen, media/browser keys;
- touch: tap = click, long-press = right-click, drag = move, two-finger
  drag = scroll, plus an on-screen extra-keys bar and soft-keyboard typing;
- **Send keys** menu for combinations browsers swallow (Ctrl+Alt+Del,
  Ctrl+Shift+Esc, Alt+F4, Win+D, …), and **Paste text** to type a string
  (e.g. a long password) into the remote machine;
- live quality/FPS controls, Fit / Actual-size / Stretch scaling, fullscreen
  (with keyboard lock where the browser supports it), view-only toggle,
  resolution/FPS/latency stats;
- auto-reconnect, and released keys/buttons can never get stuck on the
  controlled machine (focus loss / tab close / network drop all release
  every held key and button on the host);
- latency stays flat on slow links: frames and mouse-moves are
  latest-wins at every hop instead of queueing up.

> 🌍 **Controlling machines over the internet, by ID + password?**
> See **[docs/internet-deployment.md](docs/internet-deployment.md)** — the
> complete guide: putting `kbdesk serve` on a VPS (or a VPN, or a home PC),
> fixed "userid" IDs, per-machine passwords, HTTPS, auto-start, and the
> security checklist to read before exposing anything publicly.

## What it does

- **Screen sharing** — the host captures its display and streams it as JPEG.
- **Remote control** — the viewer sends mouse and keyboard events that the host
  injects into the local session.
- **Two ways to connect**
  - *Direct*: the viewer connects straight to the host's `ip:port`.
  - *Relay*: the host registers with a rendezvous server under a short numeric
    ID; the viewer connects to the server and is paired with that ID. The server
    then becomes a transparent byte pump.
- **Encryption everywhere** — TLS (rustls) on every leg, mandatory by
  default; plus a true end-to-end encrypted viewer↔host session: ephemeral
  X25519 + a password-bound HKDF key schedule + ChaCha20-Poly1305 per
  frame. The password is never transmitted (mutual key confirmation proves
  it), and the relay/web bridge see only ciphertext. The launcher
  auto-generates a local CA so one-command modes need no setup; bring
  Let's Encrypt / corporate certs when you have them. Details:
  [`docs/encryption-and-certificates.md`](docs/encryption-and-certificates.md).

## Architecture

```
┌──────────────┐        ┌───────────────┐        ┌──────────────┐
│ kbdesk-client│◄──────►│ kbdesk-server │◄──────►│  kbdesk-host │
│   (viewer)   │ relay  │ (rendezvous + │ relay  │   (agent)    │
│  egui GUI    │        │    relay)     │        │ capture+input│
└──────────────┘        └───────────────┘        └──────────────┘
        │                                                 ▲
        └──────────── direct ip:port ────────────────────┘
```

| Crate | Binary | Role |
|-------|--------|------|
| `crates/kbdesk-core`   | —               | Wire protocol + framing (shared) |
| `crates/kbdesk-server` | `kbdesk-server` | Rendezvous + relay |
| `crates/kbdesk-host`   | `kbdesk-host`   | Screen capture + input injection |
| `crates/kbdesk-client` | `kbdesk-client` | Native viewer GUI (egui/eframe) |
| `crates/kbdesk-web`    | `kbdesk-web`    | Browser viewer (HTTP + WebSocket) |
| `crates/kbdesk-launcher` | `kbdesk`      | One-command launcher for the above |

The **web viewer** replaces the native client: it serves a page that speaks the
same protocol over a WebSocket, so a viewer only needs a browser — nothing to
install.


## Build

Requires a recent stable Rust toolchain.

```bash
cargo build --release
```

Binaries land in `target/release/`.

CI (GitHub Actions, `.github/workflows/ci.yml`) checks the workspace, runs the
unit tests, builds release binaries, cross-checks Windows/macOS, and runs an
end-to-end smoke test of the browser path (`tests/e2e/`): a WebSocket client
drives `kbdesk-web` → relay → a fake host and asserts frames, input, and
session teardown all arrive intact.

### Rebuilding after code changes

Use `update.sh` instead of calling `cargo` by hand:

```bash
./update.sh                 # rebuild (release) once
./update.sh --debug         # fast debug rebuild
./update.sh --test          # rebuild, then run the test suite
./update.sh --watch         # rebuild automatically on every source change
./update.sh --watch --debug # watch with fast debug builds
./update.sh --clean         # cargo clean, then rebuild
./update.sh --run client    # rebuild, then launch a binary
./update.sh --package       # rebuild, then build packages into dist/
```

In `--watch` mode the script fingerprints every `*.rs` / `Cargo.toml` /
`Cargo.lock` file and rebuilds the moment one changes, so you can leave it
running in a terminal while you edit. It survives build failures (fix and save
again) and stops with Ctrl-C.

On Linux the host uses the pure-Rust X11 client (`x11rb`) for capture, so no C
libraries are needed to build. On Windows and macOS the host captures through
`xcap` (GDI / CoreGraphics). `enigo` provides input injection on X11, Wayland,
Windows, and macOS.

## Run it

The fastest path is the `kbdesk` launcher (see **Quick start**). The sections
below describe the underlying pieces and their flags, which the launcher simply
wires together.

```bash
target/release/kbdesk up     # relay + host + web viewer on this machine
target/release/kbdesk web    # host + web viewer, no relay
target/release/kbdesk serve  # relay + web viewer only (server for browser control)
target/release/kbdesk host   # share this screen (direct)
target/release/kbdesk relay  # relay server only
target/release/kbdesk viewer # native desktop viewer
```

Common options: `--password <p>`, `--id <id>`, `--bind 0.0.0.0`,
`--web-port 8080`, `--relay-port 21118`, `--host-port 21119`, `--fps 15`,
`--quality 70`. TLS options (all binaries): `--tls-cert/--tls-key` for
listeners, `--tls-ca`/`--tls-server-name` for outbound verification; the
launcher generates a local CA in `./kbdesk-tls/` so the commands above are
fully encrypted out of the box (`--tls-host name` adds certificate names,
`--allow-plaintext` is a development-only escape hatch).

### 1. Relay server (needed only for relay mode)

> ⚠️ The `kbdesk-*` binaries are **not** installed system-wide by a plain
> `cargo build` — typing `kbdesk-server` right after cloning gives
> `command not found`. Build first and run them from `target/release/`
> (as below), use the `kbdesk` launcher / `./run.sh` (which builds for you),
> or install them onto your PATH once:
> `cargo install --path crates/kbdesk-server --locked` (same pattern for the
> other crates). The `.deb` package (see *Packaging*) also puts them in
> `/usr/bin`, after which the bare names work.

```bash
cargo build --release   # once (also done for you by ./run.sh)
target/release/kbdesk-server --bind 0.0.0.0 --port 21118 \
    --tls-cert cert.pem --tls-key key.pem
```

TLS is mandatory: a listener started without `--tls-cert/--tls-key` refuses
to run (use the launcher, which generates a local CA into `./kbdesk-tls/`,
or `--allow-plaintext` for local development only).

### 2. Host (the machine being controlled)

Relay mode — register and print a numeric ID:

```bash
# --tls-ca verifies the relay (copy ca.pem from the relay's kbdesk-tls/;
# unnecessary when the relay has a publicly trusted certificate)
KB_DESK_PASSWORD=mysecret target/release/kbdesk-host --server 203.0.113.5:21118 --tls-ca ca.pem
# → KB-Desk ID: 544228382
```

Direct mode — listen for viewers on a port (TLS; needs a certificate —
the launcher's `./kbdesk-tls/` files work):

```bash
KB_DESK_PASSWORD=mysecret target/release/kbdesk-host --listen --bind 0.0.0.0 --port 21118 \
    --tls-cert kbdesk-tls/cert.pem --tls-key kbdesk-tls/key.pem
```

Useful flags: `--id <id>`, `--fps 15`, `--quality 70`, `--monitor 0`.

### 3. Viewer

Launch the GUI and fill in the address, optional ID, and password:

```bash
target/release/kbdesk-client
```

Fields can be pre-filled from the environment:
`KB_DESK_SERVER`, `KB_DESK_ID`, `KB_DESK_PASSWORD`. TLS is verified against
the built-in WebPKI roots plus `KB_DESK_TLS_CA=/path/ca.pem` when set (use
it with launcher-generated CAs; `kbdesk viewer` sets it for you).

- **Direct** connection → put `host:port` in *Address*, leave *ID* empty.
- **Relay** connection → put `relay:port` in *Address* and the host's numeric
  ID in *ID*.

### 4. Viewer (web mode) — nothing to install

Serve a browser-based viewer. This is what lets *anyone* connect with just a
browser:

```bash
target/release/kbdesk-web --listen 0.0.0.0:8080 --relay relay.example.com:21118 \
    --tls-cert cert.pem --tls-key key.pem [--tls-ca ca.pem]
```

Then open `https://<server>:8080/` in any browser, enter the **ID** and
**password**, and press **Connect**.

- With `--relay`, visitors only need an **ID + password**.
- Without `--relay`, visitors must supply a **direct host address** (safer to
  leave unset on a public deployment).

The page is a full viewer in the browser: it performs the protocol-v2 key
exchange with the host itself (`web/crypto.js`) and encrypts every control
and video frame end-to-end. `kbdesk-web` is a blind WebSocket↔TLS byte
bridge — it never receives the password and cannot see screen or input data.

## Packaging

Build installable packages into `dist/`:

```bash
./packaging/build-packages.sh          # or: ./update.sh --package
```

Produces:

| Artifact | For |
|----------|-----|
| `dist/kbdesk_<ver>_<arch>.deb` | Debian / Ubuntu |
| `dist/kbdesk-<ver>-linux-<arch>.tar.gz` | any Linux (includes `install.sh`) |
| `dist/kbdesk-<ver>.<arch>.rpm` | Fedora / RHEL / openSUSE (needs `rpm-build` installed) |

The `.deb` installs the four binaries into `/usr/bin`, a desktop entry and icon,
and three systemd units:

| Unit | Type | Purpose |
|------|------|---------|
| `kbdesk-server.service` | system | relay / rendezvous |
| `kbdesk-web.service`    | system | browser viewer (config in `/etc/kbdesk/kbdesk-web.env`) |
| `kbdesk-host.service`   | **user** | shares a desktop session (`~/.config/kbdesk/host.env`) |

```bash
sudo apt install ./dist/kbdesk_0.1.0_amd64.deb
sudo systemctl enable --now kbdesk-server kbdesk-web
systemctl --user enable --now kbdesk-host   # after editing ~/.config/kbdesk/host.env
```


## Protocol

Every frame on the wire is:

```
┌────────────┬──────┬─────────────────────────┐
│ u32 length │ kind │ payload (length-1 bytes)│
│ big-endian │ u8   │                         │
└────────────┴──────┴─────────────────────────┘
```

- `kind = 0x01` — control message, JSON.
- `kind = 0x02` — video frame: `u16 width | u16 height | u8 monitor | jpeg…`.

Control messages: `Hello`, `AssignedId`, `Connect`, `KeyExchangeInit`,
`KeyExchangeReply`, `KeyExchangeFinish`, `AuthResult`, `StartStream`,
`StopStream`, `Input`, `Ping`, `Pong`, `Error`.

Every hop runs over TLS. On top of that, the viewer↔host session is
end-to-end encrypted (protocol v2). Handshake (viewer speaks first);
`🔒` frames have AEAD-encrypted payloads:

```
viewer → host : Hello(v2, Viewer)
host   → viewer: Hello(v2, Host, id)
viewer → host : KeyExchangeInit(X25519 pubkey, nonce)
host   → viewer: KeyExchangeReply(pubkey, nonce, key-confirmation)
viewer → host : KeyExchangeFinish(key-confirmation)
host   → viewer: 🔒 AuthResult(ok)     ← first encrypted frame
viewer → host : 🔒 StartStream(monitor, quality, fps)
host   → viewer: 🔒 VideoFrame… (repeated)
viewer → host : 🔒 Input(MouseMove | MouseButton | MouseScroll | Key)…
```

Session keys come from ephemeral X25519 + HKDF-SHA256, with the password
mixed into the key schedule and proven via the key-confirmation values —
the password itself is never sent. Each frame is sealed with
ChaCha20-Poly1305 and a strict per-direction counter (replay-safe). The
construction is implemented identically in Rust (`crates/kbdesk-core`),
the browser page (`crypto.js`), and a Python reference under `tests/`,
all pinned to one test vector; see
[`docs/encryption-and-certificates.md`](docs/encryption-and-certificates.md).

In relay mode the viewer first sends `Connect { target }` to the server
(inside its TLS leg), which pairs it with the host and then forwards bytes
untouched — i.e., ciphertext.

## Platform support

| Platform | Capture | Input | Status |
|----------|---------|-------|--------|
| Linux / X11     | ✅ `x11rb` (pure Rust) | ✅ `enigo` | Fully implemented |
| Linux / Wayland | via XWayland only | ✅ `enigo` | Native Wayland capture not wired up |
| Windows         | ✅ `xcap` (GDI) | ✅ `enigo` | Implemented; builds cross-checked |
| macOS           | ✅ `xcap` (CoreGraphics) | ✅ `enigo` | Implemented; builds cross-checked |

The whole workspace compiles for all three platforms (`cargo check` passes for
`x86_64-pc-windows-gnu` and `x86_64-apple-darwin`). Linux/X11 is the
continuously exercised backend; the Windows and macOS backends are implemented
but have not been run on those operating systems yet.

### Permissions

- **macOS** — the first run must be granted **Screen Recording** (to capture)
  and **Accessibility** (to send input) in *System Settings → Privacy &
  Security*. Without Screen Recording you will see a black screen; without
  Accessibility, clicks and keys are ignored.
- **Windows** — capture and input work without special permission, but an
  unelevated host cannot control windows that are running elevated (UAC).
- **Linux / Wayland** — run under an X11 session, or ensure XWayland is present;
  native Wayland capture is not yet implemented.

## 🔒 Security

All KB-Desk traffic is encrypted, in two independent layers:

- **TLS (rustls) on every leg** — browser↔bridge (HTTPS/WSS), bridge↔relay,
  host↔relay, viewer↔host. Mandatory by default: listeners refuse to start
  without `--tls-cert/--tls-key`; the launcher generates a local CA into
  `./kbdesk-tls/` for one-command modes, or you can supply Let's Encrypt /
  corporate certificates. This authenticates servers and shields IDs and
  routing metadata.
- **End-to-end viewer↔host encryption** — ephemeral X25519 + HKDF-SHA256
  with the password bound into the key schedule, ChaCha20-Poly1305 AEAD on
  every screen/input frame. The password is **never transmitted** (mutual
  key confirmation proves knowledge of it); the relay and web bridge see
  only ciphertext; a compromised relay trying to impersonate a host gets
  one online password guess per attempt and is detected by the viewer.

Certificate management (generated CA, Let's Encrypt, corporate PKI,
rotation, the full flag/env reference, and the threat model) is documented
in **[`docs/encryption-and-certificates.md`](docs/encryption-and-certificates.md)**.

What encryption does **not** give you (read this before internet exposure):
there are still no per-user accounts/SSO, MFA, or session auditing — access
is "ID + that machine's password", so use a strong, unique password per
machine. The relay can see pairing metadata (IDs, timing, sizes) though
never content. Whoever serves the web page controls its code, so run
`kbdesk-web` on infrastructure you trust (the native client needs no web
server). For public deployments prefer real certificates, keep `--relay`
set on `kbdesk-web` (so browsers can't ask the bridge to dial arbitrary
addresses), and consider IP allowlists / an authenticating reverse proxy in
front. `--allow-plaintext` and `--tls-insecure` exist for local development
only and must never be used on a network you don't fully control.

## Limitations / roadmap

- Single host per ID; a viewer claims a host and the pairing ends when the
  session closes (the host re-registers automatically for the next viewer;
  dead registrations are reaped by the relay within ~10 s).
- JPEG-only, full-frame capture (no damage regions or adaptive codecs yet).
- No file transfer or two-way clipboard sync yet — the browser viewer's
  **Paste text** types text into the host, which covers the common case.
- Capture is the primary display (X11: the whole root window); the protocol
  carries a monitor index, but the backends don't switch monitors yet.
- In a browser, a few shortcuts are always taken by the browser/OS itself
  (e.g. Ctrl+W, Ctrl+N); use fullscreen + the **Send keys** menu for those.
  On Windows, a true secure-attention Ctrl+Alt+Del additionally requires the
  host to run elevated/as a service — synthetic input cannot reach the
  secure desktop otherwise (an OS restriction, same for every such tool).

## License

MIT — see [`LICENSE`](LICENSE).
