# KB-Desk

A self-hosted remote desktop tool: view and control another machine's screen
over the network. Built from scratch in Rust.

> **KB-Desk is an independent, clean-room implementation.**
> It is **not** derived from RustDesk, AnyDesk, TeamViewer, VNC, or any other
> remote-desktop product. No third-party application source code was copied.
> The wire protocol, capture pipeline, relay, and GUI are original. KB-Desk is
> released under the MIT license (see `LICENSE`).

---

## What it does

- **Screen sharing** — the host captures its display and streams it as JPEG.
- **Remote control** — the viewer sends mouse and keyboard events that the host
  injects into the local session.
- **Two ways to connect**
  - *Direct*: the viewer connects straight to the host's `ip:port`.
  - *Relay*: the host registers with a rendezvous server under a short numeric
    ID; the viewer connects to the server and is paired with that ID. The server
    then becomes a transparent byte pump.

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

The **web viewer** replaces the native client: it serves a page that speaks the
same protocol over a WebSocket, so a viewer only needs a browser — nothing to
install.


## Build

Requires a recent stable Rust toolchain.

```bash
cargo build --release
```

Binaries land in `target/release/`.

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
libraries are needed to build. `enigo` provides input injection on X11, Wayland,
Windows, and macOS.

## Run it

### 1. Relay server (needed only for relay mode)

```bash
kbdesk-server --bind 0.0.0.0 --port 21118
```

### 2. Host (the machine being controlled)

Relay mode — register and print a numeric ID:

```bash
KB_DESK_PASSWORD=mysecret kbdesk-host --server 203.0.113.5:21118
# → KB-Desk ID: 544228382
```

Direct mode — listen for viewers on a port:

```bash
KB_DESK_PASSWORD=mysecret kbdesk-host --listen --bind 0.0.0.0 --port 21118
```

Useful flags: `--id <id>`, `--fps 15`, `--quality 70`, `--monitor 0`.

### 3. Viewer

Launch the GUI and fill in the address, optional ID, and password:

```bash
kbdesk-client
```

Fields can be pre-filled from the environment:
`KB_DESK_SERVER`, `KB_DESK_ID`, `KB_DESK_PASSWORD`.

- **Direct** connection → put `host:port` in *Address*, leave *ID* empty.
- **Relay** connection → put `relay:port` in *Address* and the host's numeric
  ID in *ID*.

### 4. Viewer (web mode) — nothing to install

Serve a browser-based viewer. This is what lets *anyone* connect with just a
browser:

```bash
kbdesk-web --listen 0.0.0.0:8080 --relay relay.example.com:21118
```

Then open `http://<server>:8080/` in any browser, enter the **ID** and
**password**, and press **Connect**.

- With `--relay`, visitors only need an **ID + password**.
- Without `--relay`, visitors must supply a **direct host address** (safer to
  leave unset on a public deployment).

The web viewer streams JPEG frames as binary WebSocket messages and returns
mouse/keyboard events as JSON, using the exact same wire protocol.

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

Control messages: `Hello`, `AssignedId`, `Connect`, `Auth`, `AuthResult`,
`StartStream`, `StopStream`, `Input`, `Ping`, `Pong`, `Error`.

Handshake (viewer speaks first):

```
viewer → host : Hello(Viewer)
host   → viewer: Hello(Host, id)
viewer → host : Auth(password)
host   → viewer: AuthResult(ok)
viewer → host : StartStream(monitor, quality, fps)
host   → viewer: VideoFrame… (repeated)
viewer → host : Input(MouseMove | MouseButton | MouseScroll | Key)…
```

In relay mode the viewer first sends `Connect { target }` to the server, which
pairs it with the host and then forwards bytes untouched.

## Platform support

| Platform | Capture | Input | Status |
|----------|---------|-------|--------|
| Linux / X11     | ✅ `x11rb` (pure Rust) | ✅ `enigo` | **Reference backend** |
| Linux / Wayland | via XWayland only | ✅ `enigo` | Capture on native Wayland not yet wired up |
| Windows | stub (builds) | ✅ `enigo` | Capture backend to be added |
| macOS   | stub (builds) | ✅ `enigo` | Capture backend to be added |

The workspace builds on all three platforms; only Linux/X11 capture is fully
implemented. Adding a capture backend is a matter of implementing
`Capture::capture_jpeg` in `crates/kbdesk-host/src/capture.rs`.

## ⚠️ Security

This first version is deliberately minimal and is **safe only on trusted
networks (e.g. a LAN or VPN)**:

- The password travels over the connection **in plaintext** (no TLS yet).
- Video frames are **not encrypted**.
- There is one password per host and no per-user accounts.

Do **not** expose the relay or host ports to the public internet as-is.
Planned hardening: TLS transport, password challenge/response, per-connection
session keys, and IP allow-listing.

**Web mode specifically:** `kbdesk-web` serves plain HTTP and an unauthenticated
WebSocket. Anyone who can reach the port can attempt connections. Put it behind
a reverse proxy with HTTPS and access control (e.g. Caddy, nginx + auth), or
restrict it to a private network. If you omit `--relay`, a visitor may ask the
server to connect to an arbitrary host address — set `--relay` on public
deployments to constrain that.

## Limitations / roadmap

- Single host per ID; a viewer claims a host and the pairing ends when the
  session closes.
- JPEG-only, full-frame capture (no damage regions or adaptive codecs yet).
- No file transfer, clipboard sync, or multi-monitor selection in the UI yet.
- Stale registrations are only cleaned up when a viewer next connects.

## License

MIT — see [`LICENSE`](LICENSE).
