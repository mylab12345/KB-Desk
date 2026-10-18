"""Assert the tap-proxy capture contains no plaintext and is TLS."""
import sys

data = open("/tmp/tap.bin", "rb").read()
failures = []


def check(cond, label):
    print(("PASS " if cond else "FAIL ") + label, flush=True)
    if not cond:
        failures.append(label)


check(len(data) > 2000, f"tap captured real traffic ({len(data)} bytes)")
check(data[:2] == b"\x16\x03", "bridge->relay leg starts with a TLS ClientHello")

for needle, label in [
    (b"testpw", "password never on the wire"),
    (b"WRONG-password", "wrong password never on the wire either"),
    (b"hello remote", "typed text never on the wire"),
    (b"StartStream", "control JSON never on the wire"),
    (b"KeyExchangeFinish", "handshake JSON never on the wire"),
    (b"MouseMove", "input JSON never on the wire"),
    (b"\xff\xd8\xff", "raw JPEG never on the wire"),
]:
    check(needle not in data, f"{label} ({needle!r} absent)")

print("RESULT:", "FAIL " + str(failures) if failures else "ALL PASS")
sys.exit(1 if failures else 0)
