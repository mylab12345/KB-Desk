"""Acts as the browser page: talks to kbdesk-web over WebSocket exactly like
web/index.html does, and asserts the whole relay path works."""
import asyncio, json, sys, time
import websockets

WS = "ws://127.0.0.1:8080/ws"

async def main():
    failures = []
    def check(cond, label):
        print(("PASS " if cond else "FAIL ") + label, flush=True)
        if not cond:
            failures.append(label)

    async with websockets.connect(WS, max_size=2**24) as ws:
        # ID typed the way humans see it (with spaces) must still connect.
        await ws.send(json.dumps({
            "type": "connect", "id": "544 228 382", "address": None,
            "password": "testpw", "monitor": 0, "quality": 70, "fps": 15,
        }))

        got_connected = got_frame = got_pong = False
        frame_hdr = None
        deadline = time.time() + 15
        await ws.send(json.dumps({"type": "input", "event": {"MouseMove": {"x": 10, "y": 20}}}))
        await ws.send(json.dumps({"type": "inputs", "events": [
            {"Key": {"key": {"Named": "ControlLeft"}, "down": True}},
            {"Key": {"key": {"Char": "c"}, "down": True}},
            {"Key": {"key": {"Char": "c"}, "down": False}},
            {"Key": {"key": {"Named": "ControlLeft"}, "down": False}},
            {"Text": "hello remote"},
            "ReleaseAll",
        ]}))
        await ws.send(json.dumps({"type": "stream", "monitor": 0, "quality": 50, "fps": 24}))
        ping_t = 424242
        await ws.send(json.dumps({"type": "ping", "t": ping_t}))

        while time.time() < deadline and not (got_connected and got_frame and got_pong):
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=5)
            except asyncio.TimeoutError:
                break
            if isinstance(msg, bytes):
                got_frame = True
                frame_hdr = (int.from_bytes(msg[0:2], "big"), int.from_bytes(msg[2:4], "big"), msg[4], msg[5:7])
            else:
                m = json.loads(msg)
                print("[browser] text:", m, flush=True)
                if m.get("type") == "status" and str(m.get("message", "")).startswith("connected"):
                    got_connected = True
                if m.get("type") == "pong" and m.get("t") == ping_t:
                    got_pong = True
                if m.get("type") == "error":
                    check(False, "no error from bridge: " + str(m))
                    break

        check(got_connected, "status 'connected; streaming' received")
        check(got_frame, "binary video frame received")
        check(frame_hdr == (1, 1, 0, b"\xff\xd8"), f"frame header is 1x1 jpeg (got {frame_hdr})")
        check(got_pong, "pong echo for latency probe")

        await ws.send(json.dumps({"type": "disconnect"}))
        try:
            while True:
                msg = await asyncio.wait_for(ws.recv(), timeout=3)
                if isinstance(msg, str) and json.loads(msg).get("type") == "ended":
                    check(True, "'ended' after disconnect")
                    break
        except asyncio.TimeoutError:
            check(False, "'ended' after disconnect")

    print("RESULT:", "FAIL " + str(failures) if failures else "ALL PASS")
    sys.exit(1 if failures else 0)

asyncio.run(main())
