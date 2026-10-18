"""Fake kbdesk-host: registers with the relay, authenticates, streams a 1x1
JPEG, records every Input it receives to a JSON-lines log. Used to prove the
browser -> kbdesk-web -> relay -> host path end to end."""
import json, socket, struct, sys, threading, time, base64

RELAY = ("127.0.0.1", 21118)
PASSWORD = "testpw"
LOG = open("/tmp/fake_host_log.jsonl", "a", buffering=1)

JPEG_1X1 = base64.b64decode(
    "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////"
    "2wBDAf//////////////////////////////////////////////////////////////////////////////////////wAAR"
    "CAABAAEDASIAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/xAAUAQEAAAAAAAAAAAAAAAAAAAAA"
    "/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8AvwH/2Q=="
)

def send(sock, kind, payload: bytes):
    sock.sendall(struct.pack(">I", len(payload) + 1) + bytes([kind]) + payload)

def send_ctl(sock, obj):
    send(sock, 1, json.dumps(obj).encode())

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
    LOG.write(json.dumps(a) + "\n"); print("[fake-host]", *a, flush=True)

def main():
    s = socket.create_connection(RELAY, timeout=10)
    send_ctl(s, {"Hello": {"version": 1, "role": "Host", "id": "544228382"}})
    kind, payload = recv_packet(s)
    assigned = json.loads(payload)
    log("assigned", assigned)

    # Parked at the relay now: a viewer may take a while to arrive.
    s.settimeout(120)
    # Viewer hello (after pairing through relay)
    kind, payload = recv_packet(s)
    log("viewer-hello", json.loads(payload))
    send_ctl(s, {"Hello": {"version": 1, "role": "Host", "id": "544228382"}})

    kind, payload = recv_packet(s)
    auth = json.loads(payload)
    ok = auth.get("Auth", {}).get("password") == PASSWORD
    log("auth", ok)
    send_ctl(s, {"AuthResult": {"ok": ok, "reason": "ok" if ok else "incorrect password"}})
    if not ok:
        return

    kind, payload = recv_packet(s)
    log("startstream", json.loads(payload))

    stop = threading.Event()
    def frames():
        while not stop.is_set():
            vf = struct.pack(">HHB", 1, 1, 0) + JPEG_1X1
            try:
                send(s, 2, vf)
            except OSError:
                return
            time.sleep(0.1)
    threading.Thread(target=frames, daemon=True).start()

    s.settimeout(30)
    try:
        while True:
            kind, payload = recv_packet(s)
            msg = json.loads(payload) if kind == 1 else {"video": len(payload)}
            log("recv", msg)
            if isinstance(msg, dict) and "Ping" in msg:
                send_ctl(s, {"Pong": msg["Ping"]})
    except Exception as e:
        log("host-loop-end", repr(e))
        stop.set()

if __name__ == "__main__":
    main()
