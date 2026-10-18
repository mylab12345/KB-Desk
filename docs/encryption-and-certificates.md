# Encryption & certificate management

Every KB-Desk connection is encrypted — twice. This document explains what
protects what, how certificates are managed in each deployment style, and
the limits you should understand before rolling KB-Desk out in a company.

## The two layers

```
browser / native viewer ──① TLS──▶ web bridge ──① TLS──▶ relay ──① TLS──▶ host
        └──────────────── ② end-to-end encrypted session ────────────────┘
                    (screen, input, auth — relay & bridge see ciphertext)
```

### ① Transport TLS (every leg)

* rustls (TLS 1.2/1.3, `ring` provider) on **every** connection: host↔relay,
  viewer↔relay, viewer↔host (direct), browser↔web bridge (HTTPS/WSS),
  bridge↔relay/host.
* Authenticates the server side of each leg and also protects things the
  E2E layer intentionally doesn't: host IDs, pairing/routing metadata, the
  web page itself.
* **Mandatory by default.** A listener without `--tls-cert/--tls-key`
  refuses to start; `--allow-plaintext` exists for local development only
  and logs a loud warning.

### ② End-to-end session encryption (viewer ↔ host)

Runs *inside* the relay/bridge byte pipe, so infrastructure never sees
screen contents, input, or credentials:

* Per-session **ephemeral X25519** key agreement (forward secrecy).
* Keys derived with **HKDF-SHA256** over the shared secret mixed with a hash
  of the **session password**. The password is **never transmitted** — both
  sides prove knowledge of it through key-confirmation values.
* Every frame (video and control) is sealed with **ChaCha20-Poly1305**
  (AEAD), with strict per-direction counters — replay/reorder/tampering is
  detected and aborts the session.
* Security properties: a passive observer cannot dictionary-attack the
  password (they never see password-derived material without doing the
  X25519 themselves); an active MITM — including a malicious or compromised
  relay — must guess the password online, gets exactly one guess per
  connection attempt, and the failure is visible to the viewer
  ("host authentication failed"). **Use a real password**: the strength of
  this layer is the strength of the password. The launcher generates a
  16-character random one by default.

Protocol v2 note: encryption is mandatory, so v1 components are rejected.
Upgrade every binary together (they are one release set).

## Certificates: the three ways

### A. Launcher-generated local CA (default for one-command modes)

`kbdesk up | web | serve | relay | host` generate (once, then reuse) a
small CA in `./kbdesk-tls/`:

| File | Purpose | Keep private? |
| --- | --- | --- |
| `ca.pem` | CA certificate — give to anything that must verify this machine | no |
| `ca-key.pem` | CA key (signs the leaf) | **yes** |
| `cert.pem` | leaf + CA chain presented by listeners | no |
| `key.pem` | leaf private key (0600 on Unix) | **yes** |

The leaf covers `localhost`, `127.0.0.1`, `::1`, this machine's LAN IP, the
`--bind` address, plus any `--tls-host NAME` you add (repeatable). Use
`--tls-host` when clients refer to this machine by a name
(e.g. `--tls-host kb.internal.example`).

Who needs `ca.pem`?

* **Browsers** opening the web viewer: you'll get the usual self-signed-CA
  warning unless you import `ca.pem` into the browser/OS trust store
  (fine on a LAN; use real certificates for public deployments, below).
  In managed fleets, push the CA via your MDM/GPO like any internal CA.
* **Other machines' `kbdesk-host`** connecting to your relay:
  `kbdesk-host --server relay.corp:21118 --password … --tls-ca ca.pem`
* **Native viewers**: `KB_DESK_TLS_CA=/path/ca.pem kbdesk viewer`
  (or `--tls-ca` on the launcher).

Rotation/revocation: delete `./kbdesk-tls/` (or `--tls-dir`) and restart —
a fresh CA is minted. Redistribute the new `ca.pem`; old-CA clients can no
longer connect (that *is* the revocation story for a local CA; there is no
CRL/OCSP in the generated-CA flow).

### B. Publicly trusted certificates (Let's Encrypt & friends)

For anything internet-facing, use a real certificate so browsers and
clients verify without distributing a CA file:

```sh
# once: certbot certonly --standalone -d kb.example.com

kbdesk serve --tls-cert /etc/letsencrypt/live/kb.example.com/fullchain.pem \
             --tls-key  /etc/letsencrypt/live/kb.example.com/privkey.pem
# or individual binaries with the same flags / KB_DESK_TLS_CERT/KEY env
```

With public certs, hosts/viewers need *no* `--tls-ca` (WebPKI roots are
built in). Renewed certificates are picked up on process restart — run
under systemd and restart the units after renewal (a `deploy-hook` for
certbot). Clients connecting by a different name than the certificate
contains can pass `--tls-server-name kb.example.com`.

### C. Corporate PKI

Same as B, with your internal CA: listeners take `--tls-cert/--tls-key`
(issue the cert for the machine's DNS name); clients take
`--tls-ca corp-ca.pem` (can be pre-provisioned by your config management;
`KB_DESK_TLS_CA` also supported). If your fleet already trusts the
corporate CA in the OS store, note KB-Desk verifies against WebPKI roots
plus `--tls-ca` — so pass the corporate CA explicitly.

### Reverse proxy option (web leg only)

You may put Caddy/nginx/Traefik in front of `kbdesk-web` for HTTPS
termination: run `kbdesk-web --listen 127.0.0.1:8080 --allow-plaintext`
behind the proxy (WSS via the proxy's WebSocket support). This protects the
browser leg but the web bridge itself must still reach the relay over TLS,
and `--allow-plaintext` on `kbdesk-web` would also disable TLS on *its*
outbound leg — so only do this when the bridge↔relay hop is on the same
trusted host/namespace. Serving HTTPS directly from `kbdesk-web` is
simpler and preferred.

## Configuration reference

Same flags everywhere (clap names; env equivalents in parentheses):

| Setting | Where | Meaning |
| --- | --- | --- |
| `--tls-cert FILE` (`KB_DESK_TLS_CERT`) | server, host `--listen`, web, launcher | PEM chain to present |
| `--tls-key FILE` (`KB_DESK_TLS_KEY`) | same | PEM private key |
| `--tls-ca FILE` (`KB_DESK_TLS_CA`) | host (relay leg), web (dial leg), client (env), launcher | extra CA(s) to trust |
| `--tls-server-name NAME` (`KB_DESK_TLS_SERVER_NAME`) | host, web, client (env) | expected cert name when not the dialled host |
| `--tls-insecure` (`KB_DESK_TLS_INSECURE=1` for client) | host, web, client | 🚨 skip verification — dev only |
| `--allow-plaintext` (`KB_DESK_ALLOW_PLAINTEXT=1` for client) | all | 🚨 no transport TLS — dev only |
| `--tls-host NAME` (repeatable), `--tls-dir DIR` | launcher | generated-cert SANs / storage |

Components refuse to start without TLS material unless
`--allow-plaintext` is explicit, and print exactly how to fix it.

## What the relay can and cannot see

Can see (inside its TLS legs): that a host registered ID `X` at time `T`
from some IP, that a viewer asked for `X`, session durations, byte counts.
Cannot see: passwords, screen content, keystrokes, clipboard-typed text,
file names — that is E2E-encrypted between viewer and host. The web bridge
is equally blind (it cannot even construct protocol messages), **but**
whoever controls what the web server serves controls the page's code, and
the page handles the password: run `kbdesk-web` on infrastructure you
trust, over HTTPS. The native client avoids that trust entirely.

## Honest limits (enterprise readiness)

KB-Desk now provides *encryption in transit* everywhere, which is what
compliance regimes (PCI DSS, HIPAA, SOC 2, ISO 27001) require for network
traffic. It does **not** by itself provide: SSO/OIDC login, per-user
accounts, session auditing/recording, MFA, or centralized policy — access
is "ID + that machine's password". Typical compliant deployments add
those around KB-Desk: private network/VPN or IP allowlists in front of the
relay, an authenticating reverse proxy (e.g. OAuth2 Proxy) in front of
the web UI, unique strong passwords per machine, and OS-level auditing on
the endpoints. Do not expose a relay to the public internet without
weighing this.

Also note: encryption is *in transit* only — screen data lives in memory
on host and viewer; protect endpoints accordingly. Certificates for the
TLS legs should be rotated on your normal schedule (replace files + restart).
