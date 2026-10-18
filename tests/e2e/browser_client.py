"""Acts as the browser page: talks to kbdesk-web over WSS exactly like
web/index.html + crypto.js do. The bridge is a blind byte pipe, so this
client performs the whole protocol-v2 handshake itself (X25519, password
key confirmation, AEAD frames) and asserts the relay path works — plus the
security invariants: wrong password is caught by key confirmation, and an
unknown ID fails cleanly. CI additionally greps the tap-proxy capture to
prove no plaintext crosses the relay boundary.
"""
import asyncio, json, os, ssl, struct, sys, time
import websockets

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kb_crypto

HOST_ID = "544228382"
WS = "wss://127.0.0.1:8080/ws"


def frame(kind: int, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload) + 1) + bytes([kind]) + payload


def ctl_frame(obj) -> bytes:
    return frame(1, json.dumps(obj).encode())


class Framer:
    """Reassembles KB-Desk frames from arbitrary WebSocket binary chunks."""

    def __init__(self):
        self.buf = b""

    def feed(self, data: bytes):
        self.buf += data
        out = []
        while len(self.buf) >= 4:
            (ln,) = struct.unpack(">I", self.buf[:4])
            if len(self.buf) < 4 + ln:
                break
            out.append((self.buf[4], self.buf[5:4 + ln]))
            self.buf = self.buf[4 + ln:]
        return out


class ViewerSession:
    """Viewer-side protocol v2 state machine, mirroring web/index.html."""

    def __init__(self, ws, password):
        self.ws = ws
        self.password = password
        self.framer = Framer()
        self.state = "waitReady"
        self.host_id = ""
        self.session = None
        self.error = None
        self.video = []       # decrypted video payloads
        self.controls = []    # decrypted control messages
        self.ended = False

    async def start(self):
        secret, self.my_pub = kb_crypto.generate_keypair()
        self.secret = secret
        self.my_nonce = os.urandom(16)
        await self.ws.send(ctl_frame({"Hello": {"version": 2, "role": "Viewer", "id": ""}}))
        self.state = "waitHello"

    async def on_text(self, text):
        m = json.loads(text)
        t = m.get("type")
        if t == "ready" and self.state == "waitReady":
            await self.start()
        elif t == "error":
            self.error = "bridge error: " + str(m.get("message"))
        elif t == "ended":
            self.ended = True

    async def on_bytes(self, data: bytes):
        for kind, payload in self.framer.feed(data):
            await self.on_frame(kind, payload)

    async def on_frame(self, kind, payload):
        if self.state == "live":
            plain = self.session.recv.decrypt(kind, payload)
            if kind == 2:
                self.video.append(plain)
            else:
                self.controls.append(json.loads(plain))
            return
        if kind != 1:
            return
        if self.state == "waitAuth":
            try:
                plain = self.session.recv.decrypt(kind, payload)
            except Exception:
                try:
                    msg = json.loads(payload)
                    if "Error" in msg:
                        self.error = "host rejected: " + str(msg["Error"])
                        return
                except Exception:
                    pass
                raise
            msg = json.loads(plain)
            if msg.get("AuthResult", {}).get("ok"):
                self.state = "live"
            else:
                self.error = "auth failed: " + str(msg)
            return
        msg = json.loads(payload)
        if "Error" in msg:
            self.error = str(msg["Error"])
        elif "Hello" in msg and self.state == "waitHello":
            hello = msg["Hello"]
            assert hello["version"] == 2 and hello["role"] == "Host", hello
            self.host_id = hello["id"]
            await self.ws.send(ctl_frame({"KeyExchangeInit": {
                "pubkey": self.my_pub.hex(), "nonce": self.my_nonce.hex(),
            }}))
            self.state = "waitReply"
        elif "KeyExchangeReply" in msg and self.state == "waitReply":
            reply = msg["KeyExchangeReply"]
            host_pub = bytes.fromhex(reply["pubkey"])
            host_nonce = bytes.fromhex(reply["nonce"])
            session = kb_crypto.derive_session(
                self.secret, host_pub, self.my_pub, host_pub, self.my_nonce,
                host_nonce, self.host_id, self.password, i_am_viewer=True,
            )
            if not kb_crypto.ct_eq(bytes.fromhex(reply["confirm"]), session.peer_confirm):
                self.error = "host authentication failed (wrong password or MITM)"
                return
            self.session = session
            await self.ws.send(ctl_frame({"KeyExchangeFinish": {
                "confirm": session.my_confirm.hex(),
            }}))
            self.state = "waitAuth"

    async def send_ctl(self, obj):
        wire = self.session.send.encrypt(1, json.dumps(obj).encode())
        await self.ws.send(frame(1, wire))

    async def pump_until(self, predicate, timeout=15.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate(self):
                return True
            if self.error:
                return False
            try:
                msg = await asyncio.wait_for(self.ws.recv(), timeout=deadline - time.time())
            except (asyncio.TimeoutError, websockets.ConnectionClosed):
                return False
            if isinstance(msg, bytes):
                await self.on_bytes(msg)
            else:
                await self.on_text(msg)
        return predicate(self)


async def dial(password, host_id="544 228 382"):
    ctx = ssl._create_unverified_context()
    ws = await websockets.connect(WS, max_size=2**24, ssl=ctx)
    sess = ViewerSession(ws, password)
    await ws.send(json.dumps({"type": "dial", "id": host_id, "address": None}))
    return ws, sess


async def main():
    failures = []

    def check(cond, label):
        print(("PASS " if cond else "FAIL ") + label, flush=True)
        if not cond:
            failures.append(label)

    # ---- phase A: unknown ID fails cleanly ----
    ws, sess = await dial("testpw", host_id="111222333")
    await sess.pump_until(lambda s: s.error is not None, timeout=10)
    check(sess.error is not None and "no host" in sess.error,
          f"unknown id rejected (got: {sess.error})")
    await ws.close()

    # ---- phase B: wrong password caught by key confirmation ----
    ws, sess = await dial("WRONG-password")
    await sess.pump_until(lambda s: s.error is not None, timeout=10)
    check(sess.state != "live" and sess.error is not None and "authentication failed" in sess.error,
          f"wrong password detected by viewer-side key confirmation (got: {sess.error})")
    await ws.close()
    # That consumed the host registration; give it a moment to re-register.
    await asyncio.sleep(1.5)

    # ---- phase C: full session (ID typed with spaces, as humans see it) ----
    ws, sess = await dial("testpw")
    ok_live = await sess.pump_until(lambda s: s.state == "live", timeout=8)
    if not ok_live and sess.error and "no host" in sess.error:
        await ws.close()
        await asyncio.sleep(2)
        ws, sess = await dial("testpw")
        ok_live = await sess.pump_until(lambda s: s.state == "live")
    check(ok_live and sess.host_id == HOST_ID,
          f"encrypted session established with host (state={sess.state}, id={sess.host_id}, err={sess.error})")

    if ok_live:
        await sess.send_ctl({"StartStream": {"monitor": 0, "quality": 70, "fps": 15}})
        await sess.send_ctl({"Input": {"MouseMove": {"x": 10, "y": 20}}})
        for ev in [
            {"Key": {"key": {"Named": "ControlLeft"}, "down": True}},
            {"Key": {"key": {"Char": "c"}, "down": True}},
            {"Key": {"key": {"Char": "c"}, "down": False}},
            {"Key": {"key": {"Named": "ControlLeft"}, "down": False}},
            {"Text": "hello remote"},
            "ReleaseAll",
        ]:
            await sess.send_ctl({"Input": ev})
        await sess.send_ctl({"StartStream": {"monitor": 0, "quality": 50, "fps": 24}})
        await sess.send_ctl({"Ping": 424242})

        def done(s):
            has_video = len(s.video) > 0
            has_pong = any(c.get("Pong") == 424242 for c in s.controls if isinstance(c, dict))
            return has_video and has_pong

        ok = await sess.pump_until(done)
        check(len(sess.video) > 0, "encrypted video frame received and decrypted")
        if sess.video:
            v = sess.video[0]
            hdr = (int.from_bytes(v[0:2], "big"), int.from_bytes(v[2:4], "big"), v[4], v[5:7])
            check(hdr == (1, 1, 0, b"\xff\xd8"), f"frame header is 1x1 jpeg (got {hdr})")
        check(any(c.get("Pong") == 424242 for c in sess.controls if isinstance(c, dict)),
              "pong echo for latency probe (encrypted)")
        check(ok, "all session traffic completed")

        await sess.send_ctl("StopStream")
        await ws.send(json.dumps({"type": "disconnect"}))
        ended = await sess.pump_until(lambda s: s.ended, timeout=5)
        check(ended, "'ended' after disconnect")
    await ws.close()

    print("RESULT:", "FAIL " + str(failures) if failures else "ALL PASS")
    sys.exit(1 if failures else 0)


asyncio.run(main())
