"""Reference implementation of the KB-Desk v2 session encryption.

This is the *specification by example* for the viewer<->host end-to-end
encryption used by the Rust code (crates/kbdesk-core/src/crypto.rs) and the
browser page (crates/kbdesk-web/web/crypto.js). All three implementations
are verified against the same fixed test vector.

Construction (all hashes SHA-256, HKDF per RFC 5869, X25519 per RFC 7748,
AEAD = ChaCha20-Poly1305 IETF per RFC 8439):

    transcript T = SHA256("KBDesk-v2-transcript" || client_pub || host_pub
                          || client_nonce || host_nonce || host_id_utf8)
    password_key P = SHA256(password_utf8)
    shared S = X25519(my_secret, peer_pub)          (all-zero S rejected)
    PRK = HKDF-Extract(salt=T, IKM=S || P)
    expand labels:
        "kbdesk v2 host confirm"            -> 32-byte key-confirmation value
        "kbdesk v2 viewer confirm"          -> 32-byte key-confirmation value
        "kbdesk v2 viewer-to-host key"      -> AEAD key   (viewer -> host)
        "kbdesk v2 viewer-to-host nonce"    -> 4-byte nonce prefix
        "kbdesk v2 host-to-viewer key"      -> AEAD key   (host -> viewer)
        "kbdesk v2 host-to-viewer nonce"    -> 4-byte nonce prefix
    frame AEAD: nonce = prefix(4) || counter_u64_be
                aad   = "KBDesk-v2-frame" || kind_byte || counter_u64_be
                wire payload = counter_u64_be || ciphertext||tag
    counters are per-direction, start at 0, strictly sequential.
"""
import hashlib
import hmac as hmac_mod
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac_mod.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac_mod.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def ct_eq(a: bytes, b: bytes) -> bool:
    """Constant-time equality for confirmation values."""
    return hmac_mod.compare_digest(a, b)


def generate_keypair(secret_bytes: bytes = None):
    """Return (secret_bytes32, public_bytes32)."""
    if secret_bytes is None:
        secret_bytes = os.urandom(32)
    priv = X25519PrivateKey.from_private_bytes(secret_bytes)
    # Normalise via serialization so callers get the exact raw scalar bytes.
    raw_secret = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw_secret, pub


def x25519(secret_bytes: bytes, peer_pub: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(secret_bytes)
    shared = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    if shared == b"\x00" * 32:
        raise ValueError("all-zero X25519 shared secret (small-order peer key)")
    return shared


class DirectionCipher:
    """One direction of the encrypted frame stream."""

    def __init__(self, key: bytes, nonce_prefix: bytes):
        self._aead = ChaCha20Poly1305(key)
        self._prefix = nonce_prefix
        self._tx_counter = 0
        self._rx_expected = 0

    def encrypt(self, kind: int, payload: bytes) -> bytes:
        counter_bytes = self._tx_counter.to_bytes(8, "big")
        self._tx_counter += 1
        nonce = self._prefix + counter_bytes
        aad = b"KBDesk-v2-frame" + bytes([kind]) + counter_bytes
        return counter_bytes + self._aead.encrypt(nonce, payload, aad)

    def decrypt(self, kind: int, wire: bytes) -> bytes:
        if len(wire) < 8 + 16:
            raise ValueError("encrypted payload too short")
        counter_bytes, ct = wire[:8], wire[8:]
        counter = int.from_bytes(counter_bytes, "big")
        if counter != self._rx_expected:
            raise ValueError(f"frame counter out of order: got {counter}, want {self._rx_expected}")
        self._rx_expected += 1
        nonce = self._prefix + counter_bytes
        aad = b"KBDesk-v2-frame" + bytes([kind]) + counter_bytes
        return self._aead.decrypt(nonce, ct, aad)


class Session:
    """Derived session material for one side (viewer or host)."""

    def __init__(self, send: DirectionCipher, recv: DirectionCipher,
                 my_confirm: bytes, peer_confirm: bytes):
        self.send = send
        self.recv = recv
        self.my_confirm = my_confirm
        self.peer_confirm = peer_confirm


def derive_session(my_secret: bytes, peer_pub: bytes, client_pub: bytes,
                   host_pub: bytes, client_nonce: bytes, host_nonce: bytes,
                   host_id: str, password: str, i_am_viewer: bool) -> Session:
    transcript = sha256(
        b"KBDesk-v2-transcript" + client_pub + host_pub
        + client_nonce + host_nonce + host_id.encode("utf-8")
    )
    password_key = sha256(password.encode("utf-8"))
    shared = x25519(my_secret, peer_pub)
    prk = hkdf_extract(transcript, shared + password_key)

    def expand(label: bytes, n: int) -> bytes:
        return hkdf_expand(prk, label, n)

    confirm_host = expand(b"kbdesk v2 host confirm", 32)
    confirm_viewer = expand(b"kbdesk v2 viewer confirm", 32)
    v2h = DirectionCipher(expand(b"kbdesk v2 viewer-to-host key", 32),
                          expand(b"kbdesk v2 viewer-to-host nonce", 4))
    h2v = DirectionCipher(expand(b"kbdesk v2 host-to-viewer key", 32),
                          expand(b"kbdesk v2 host-to-viewer nonce", 4))
    if i_am_viewer:
        return Session(send=v2h, recv=h2v, my_confirm=confirm_viewer, peer_confirm=confirm_host)
    return Session(send=h2v, recv=v2h, my_confirm=confirm_host, peer_confirm=confirm_viewer)
