"""TCP tap used by the E2E test to prove nothing sensitive crosses the
bridge->relay wire in plaintext.

kbdesk-web is pointed at this proxy as its "relay"; the proxy forwards to
the real relay and appends every byte (both directions) to /tmp/tap.bin.
CI then asserts the capture:
  * begins with a TLS ClientHello (0x16 0x03 ...) — the leg is TLS;
  * contains no session plaintext: no password ("testpw"), no typed text
    ("hello remote"), no JSON control ("StartStream", "KeyExchangeFinish");
  * contains no raw JPEG (FF D8 FF) — screen data is encrypted too.
"""
import os, socket, threading

LISTEN = ("127.0.0.1", 21119)
TARGET = ("127.0.0.1", 21118)
CAPTURE = open("/tmp/tap.bin", "ab", buffering=0)
LOCK = threading.Lock()


def pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            with LOCK:
                CAPTURE.write(data)
            dst.sendall(data)
    except OSError:
        pass
    try:
        dst.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(LISTEN)
    server.listen(8)
    print("[tap] listening", LISTEN, "->", TARGET, "capture", os.path.abspath("/tmp/tap.bin"), flush=True)
    while True:
        client, _ = server.accept()
        upstream = socket.create_connection(TARGET, timeout=10)
        threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client), daemon=True).start()


if __name__ == "__main__":
    main()
