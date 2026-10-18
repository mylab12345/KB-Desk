"""Fake kbdesk-host for the E2E test: registers with the relay over TLS,
performs the protocol-v2 end-to-end encrypted handshake (X25519 + password
key confirmation), streams an encrypted 1x1 JPEG, and records every Input
it decrypts to a JSON-lines log. Proves the browser -> kbdesk-web (HTTPS,
blind bridge) -> relay -> host path works with only ciphertext in between.

Env: FAKE_HOST_TLS=0 to dial the relay without TLS (not used by CI).
"""
import json, os, socket, ssl, struct, sys, threading, time, base64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kb_crypto

RELAY = ("127.0.0.1", 21118)
HOST_ID = "544228382"
PASSWORD = "testpw"
LOG = open("/tmp/fake_host_log.jsonl", "a", buffering=1)

JPEG_1X1 = base64.b64decode(
    "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////"
    "2wBDAf//////////////////////////////////////////////////////////////////////////////////////wAAR"
    "CAABAAEDASIAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/xAAUAQEAAAAAAAAAAAAAAAAAAAAA"
    "/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8AvwH/2Q=="
)

SEND_LOCK = threading.Lock()


def send(sock, kind, payload: bytes):
    with SEND_LOCK:
        sock.sendall(struct.pack(">I", len(payload) + 1) + bytes([kind]) + payload)


def send_ctl(sock, obj):
    send(sock, 1, json.dumps(obj).encode())


def send_secure(sock, cipher, kind, payload: bytes):
    with SEND_LOCK:
        wire = cipher.encrypt(kind, payload)
        sock.sendall(struct.pack(">I", len(wire) + 1) + bytes([kind]) + wire)


def send_ctl_secure(sock, session, obj):
    send_secure(sock, session.send, 1, json.dumps(obj).encode())


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def recv_packet(sock):
    (ln,) = struct.unpack(">I", recv_exact(sock, 4))
    kind = recv_exact(sock, 1)[0]
    return kind, recv_exact(sock, ln - 1)


def log(*a):
    LOG.write(json.dumps(a) + "\n")
    print("[fake-host]", *a, flush=True)


def main():
    # Like the real host in relay mode: after every session (or failed
    # handshake — e.g. the wrong-password phase), re-register the same id.
    while True:
        try:
            serve_once()
        except Exception as e:
            log("serve-loop", repr(e))
            time.sleep(0.3)


def serve_once():
    raw = socket.create_connection(RELAY, timeout=10)
    if os.environ.get("FAKE_HOST_TLS", "1") == "1":
        ctx = ssl._create_unverified_context()
        s = ctx.wrap_socket(raw, server_hostname="localhost")
    else:
        s = raw

    # --- register with the relay (this metadata lives inside the TLS leg) ---
    send_ctl(s, {"Hello": {"version": 2, "role": "Host", "id": HOST_ID}})
    kind, payload = recv_packet(s)
    log("assigned", json.loads(payload))

    # Parked at the relay now: a viewer may take a while to arrive.
    s.settimeout(120)

    # --- v2 end-to-end handshake (we are the host side) ---
    kind, payload = recv_packet(s)
    hello = json.loads(payload)["Hello"]
    log("viewer-hello", hello)
    assert hello["version"] == 2 and hello["role"] == "Viewer", hello
    send_ctl(s, {"Hello": {"version": 2, "role": "Host", "id": HOST_ID}})

    kind, payload = recv_packet(s)
    init = json.loads(payload)["KeyExchangeInit"]
    log("kex-init", True)
    client_pub = bytes.fromhex(init["pubkey"])
    client_nonce = bytes.fromhex(init["nonce"])

    secret, my_pub = kb_crypto.generate_keypair()
    host_nonce = os.urandom(16)
    session = kb_crypto.derive_session(
        secret, client_pub, client_pub, my_pub, client_nonce, host_nonce,
        HOST_ID, PASSWORD, i_am_viewer=False,
    )
    send_ctl(s, {"KeyExchangeReply": {
        "pubkey": my_pub.hex(), "nonce": host_nonce.hex(),
        "confirm": session.my_confirm.hex(),
    }})

    kind, payload = recv_packet(s)
    finish = json.loads(payload)["KeyExchangeFinish"]
    ok = kb_crypto.ct_eq(bytes.fromhex(finish["confirm"]), session.peer_confirm)
    log("auth", ok)
    if not ok:
        send_ctl(s, {"Error": "authentication failed"})
        return
    # First encrypted frame: AuthResult(ok).
    send_ctl_secure(s, session, {"AuthResult": {"ok": True, "reason": "ok"}})

    # --- encrypted session ---
    kind, payload = recv_packet(s)
    start = json.loads(session.recv.decrypt(kind, payload))
    log("startstream", start)

    stop = threading.Event()

    def frames():
        while not stop.is_set():
            vf = struct.pack(">HHB", 1, 1, 0) + JPEG_1X1
            try:
                send_secure(s, session.send, 2, vf)
            except OSError:
                return
            time.sleep(0.1)

    threading.Thread(target=frames, daemon=True).start()

    s.settimeout(30)
    try:
        while True:
            kind, payload = recv_packet(s)
            plain = session.recv.decrypt(kind, payload)
            msg = json.loads(plain) if kind == 1 else {"video": len(plain)}
            log("recv", msg)
            if isinstance(msg, dict) and "Ping" in msg:
                send_ctl_secure(s, session, {"Pong": msg["Ping"]})
            if msg == "StopStream":
                break
    except Exception as e:
        log("host-loop-end", repr(e))
    stop.set()
    try:
        s.close()
    except OSError:
        pass


if __name__ == "__main__":
    main()
