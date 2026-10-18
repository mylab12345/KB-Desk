/*
 * KB-Desk v2 end-to-end session crypto for the browser viewer.
 *
 * Pure-JS implementations of SHA-256, HKDF (RFC 5869), X25519 (RFC 7748,
 * BigInt), and ChaCha20-Poly1305 AEAD (RFC 8439). Written from the RFCs so
 * the browser can hold the password and the session keys itself: the
 * password never leaves this page, and the web bridge + relay only ever
 * forward ciphertext. Interop with the Rust implementation
 * (crates/kbdesk-core/src/crypto.rs) and the Python reference
 * (tests/e2e/kb_crypto.py) is pinned by tests/js/crypto.test.cjs.
 *
 * Construction (identical in all three implementations):
 *   T  = SHA256("KBDesk-v2-transcript" || client_pub || host_pub
 *               || client_nonce || host_nonce || host_id_utf8)
 *   P  = SHA256(password_utf8)
 *   S  = X25519(my_secret, peer_pub)            (all-zero rejected)
 *   PRK = HKDF-Extract(salt=T, IKM=S || P)
 *   labels: "<dir> confirm" / "... key" / "... nonce" via HKDF-Expand
 *   frame AEAD nonce = 4-byte prefix || u64be counter (per direction, from 0)
 *   frame AEAD aad   = "KBDesk-v2-frame" || kind_byte || u64be counter
 *   wire payload     = u64be counter || ciphertext||tag
 */
"use strict";

const KBCrypto = (() => {
  // ---------------- small utilities ----------------
  const utf8 = (s) => new TextEncoder().encode(s);
  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const unhex = (h) => {
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  };
  const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out;
  };
  const ctEq = (a, b) => {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  };
  const randomBytes = (n) => {
    const out = new Uint8Array(n);
    const c = (typeof window !== "undefined" ? window.crypto : globalThis.crypto);
    if (!c || !c.getRandomValues) {
      throw new Error("secure randomness unavailable — open this page over HTTPS or localhost");
    }
    c.getRandomValues(out);
    return out;
  };

  // ---------------- SHA-256 ----------------
  const SHA_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) | 0;

  function sha256(msg) {
    const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const bitLen = msg.length * 8;
    const padded = new Uint8Array((((msg.length + 8) >> 6) + 1) << 6);
    padded.set(msg);
    padded[msg.length] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 4, bitLen >>> 0);
    dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
    const w = new Uint32Array(64);
    for (let block = 0; block < padded.length; block += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(block + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + SHA_K[i] + w[i]) | 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i] >>> 0);
    return out;
  }

  // ---------------- HMAC / HKDF (RFC 5869) ----------------
  function hmacSha256(key, msg) {
    let k = key.length > 64 ? sha256(key) : key;
    const block = new Uint8Array(64);
    block.set(k);
    const ipad = new Uint8Array(64), opad = new Uint8Array(64);
    for (let i = 0; i < 64; i++) { ipad[i] = block[i] ^ 0x36; opad[i] = block[i] ^ 0x5c; }
    return sha256(concat(opad, sha256(concat(ipad, msg))));
  }
  const hkdfExtract = (salt, ikm) => hmacSha256(salt, ikm);
  function hkdfExpand(prk, info, length) {
    const out = new Uint8Array(length);
    let t = new Uint8Array(0), off = 0, counter = 1;
    while (off < length) {
      t = hmacSha256(prk, concat(t, info, new Uint8Array([counter++])));
      out.set(t.subarray(0, Math.min(32, length - off)), off);
      off += 32;
    }
    return out;
  }

  // ---------------- X25519 (RFC 7748, BigInt) ----------------
  const P = (1n << 255n) - 19n;
  const leToBig = (bytes) => {
    let x = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(bytes[i]);
    return x;
  };
  const bigToLe = (x, len = 32) => {
    const out = new Uint8Array(len);
    let v = x;
    for (let i = 0; i < len; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
    return out;
  };
  const modPow = (base, exp) => {
    let result = 1n, b = ((base % P) + P) % P, e = exp;
    while (e > 0n) {
      if (e & 1n) result = (result * b) % P;
      b = (b * b) % P;
      e >>= 1n;
    }
    return result;
  };
  function x25519(scalarBytes, uBytes) {
    const k = new Uint8Array(scalarBytes);
    k[0] &= 248; k[31] &= 127; k[31] |= 64;                      // clamp
    const scalar = leToBig(k);
    const u = leToBig(uBytes) & ((1n << 255n) - 1n);            // mask top bit
    const a24 = 121665n;
    let x1 = u, x2 = 1n, z2 = 0n, x3 = u, z3 = 1n, swap = 0n;
    const m = (v) => ((v % P) + P) % P;
    const cswap = (doSwap, a, b) => (doSwap ? [b, a] : [a, b]);
    for (let t = 254n; t >= 0n; t--) {
      const bit = (scalar >> t) & 1n;
      swap ^= bit;
      [x2, x3] = cswap(swap === 1n, x2, x3);
      [z2, z3] = cswap(swap === 1n, z2, z3);
      swap = bit;
      const A = m(x2 + z2), AA = m(A * A), B = m(x2 - z2), BB = m(B * B);
      const E = m(AA - BB);
      const C = m(x3 + z3), D = m(x3 - z3), DA = m(D * A), CB = m(C * B);
      x3 = m((DA + CB) * (DA + CB));
      z3 = m(x1 * m((DA - CB) * (DA - CB)));
      x2 = m(AA * BB);
      z2 = m(E * m(AA + m(a24 * E)));
    }
    [x2, x3] = cswap(swap === 1n, x2, x3);
    [z2, z3] = cswap(swap === 1n, z2, z3);
    return bigToLe(m(x2 * modPow(z2, P - 2n)));
  }
  const BASEPOINT = (() => { const b = new Uint8Array(32); b[0] = 9; return b; })();
  const publicFromSecret = (secret) => x25519(secret, BASEPOINT);
  const generateKeypair = () => {
    const secret = randomBytes(32);
    return { secret, publicKey: publicFromSecret(secret) };
  };

  // ---------------- ChaCha20-Poly1305 AEAD (RFC 8439) ----------------
  const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) | 0;
  function chachaBlock(key, counter, nonce) {
    const constants = utf8("expand 32-byte k");
    const st = new Uint32Array(16);
    const read = (bytes, i) =>
      (bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24)) | 0;
    for (let i = 0; i < 4; i++) st[i] = read(constants, i * 4);
    for (let i = 0; i < 8; i++) st[4 + i] = read(key, i * 4);
    st[12] = counter | 0;
    for (let i = 0; i < 3; i++) st[13 + i] = read(nonce, i * 4);
    const w = new Uint32Array(st);
    const qr = (a, b, c, d) => {
      w[a] = (w[a] + w[b]) | 0; w[d] = rotl(w[d] ^ w[a], 16);
      w[c] = (w[c] + w[d]) | 0; w[b] = rotl(w[b] ^ w[c], 12);
      w[a] = (w[a] + w[b]) | 0; w[d] = rotl(w[d] ^ w[a], 8);
      w[c] = (w[c] + w[d]) | 0; w[b] = rotl(w[b] ^ w[c], 7);
    };
    for (let i = 0; i < 10; i++) {
      qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
      qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
    }
    const out = new Uint8Array(64);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 16; i++) dv.setUint32(i * 4, (w[i] + st[i]) >>> 0, true);
    return out;
  }
  function chachaCrypt(key, nonce, data, initialCounter = 1) {
    const out = new Uint8Array(data.length);
    let counter = initialCounter;
    for (let off = 0; off < data.length; off += 64) {
      const block = chachaBlock(key, counter++, nonce);
      const n = Math.min(64, data.length - off);
      for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ block[i];
    }
    return out;
  }
  const POLY_P = (1n << 130n) - 5n;
  function poly1305Mac(key32, data) {
    const rBytes = new Uint8Array(key32.subarray(0, 16));
    rBytes[3] &= 15; rBytes[7] &= 15; rBytes[11] &= 15; rBytes[15] &= 15;
    rBytes[4] &= 252; rBytes[8] &= 252; rBytes[12] &= 252;       // clamp r
    const r = leToBig(rBytes), s = leToBig(key32.subarray(16, 32));
    let acc = 0n;
    for (let off = 0; off < data.length; off += 16) {
      const chunk = data.subarray(off, Math.min(off + 16, data.length));
      const n = leToBig(chunk) + (1n << BigInt(8 * chunk.length));
      acc = ((acc + n) * r) % POLY_P;
    }
    return bigToLe((acc + s) & ((1n << 128n) - 1n), 16);
  }
  const polyMacData = (aad, ct) => {
    const pad = (n) => new Uint8Array((16 - (n % 16)) % 16);
    const lens = new Uint8Array(16);
    const dv = new DataView(lens.buffer);
    dv.setBigUint64(0, BigInt(aad.length), true);
    dv.setBigUint64(8, BigInt(ct.length), true);
    return concat(aad, pad(aad.length), ct, pad(ct.length), lens);
  };
  function aeadEncrypt(key, nonce, plaintext, aad) {
    const polyKey = chachaBlock(key, 0, nonce).subarray(0, 32);
    const ct = chachaCrypt(key, nonce, plaintext, 1);
    const tag = poly1305Mac(polyKey, polyMacData(aad, ct));
    return concat(ct, tag);
  }
  function aeadDecrypt(key, nonce, ctAndTag, aad) {
    if (ctAndTag.length < 16) throw new Error("ciphertext too short");
    const ct = ctAndTag.subarray(0, ctAndTag.length - 16);
    const tag = ctAndTag.subarray(ctAndTag.length - 16);
    const polyKey = chachaBlock(key, 0, nonce).subarray(0, 32);
    const expected = poly1305Mac(polyKey, polyMacData(aad, ct));
    if (!ctEq(tag, expected)) throw new Error("AEAD authentication failed");
    return chachaCrypt(key, nonce, ct, 1);
  }

  // ---------------- KB-Desk v2 session ----------------
  const u64be = (n) => {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, BigInt(n));
    return out;
  };
  function directionCipher(key, noncePrefix) {
    let txCounter = 0, rxExpected = 0;
    const frameAad = (kind, counterBytes) =>
      concat(utf8("KBDesk-v2-frame"), new Uint8Array([kind]), counterBytes);
    return {
      encrypt(kind, payload) {
        const counterBytes = u64be(txCounter++);
        const nonce = concat(noncePrefix, counterBytes);
        return concat(counterBytes, aeadEncrypt(key, nonce, payload, frameAad(kind, counterBytes)));
      },
      decrypt(kind, wire) {
        if (wire.length < 8 + 16) throw new Error("encrypted payload too short");
        const counterBytes = wire.subarray(0, 8);
        const counter = new DataView(wire.buffer, wire.byteOffset, 8).getBigUint64(0);
        if (counter !== BigInt(rxExpected)) {
          throw new Error(`frame counter out of order: got ${counter}, want ${rxExpected}`);
        }
        rxExpected++;
        const nonce = concat(noncePrefix, counterBytes);
        return aeadDecrypt(key, nonce, wire.subarray(8), frameAad(kind, counterBytes));
      },
    };
  }

  function deriveSession({ mySecret, peerPublic, clientPublic, hostPublic,
                           clientNonce, hostNonce, hostId, password, iAmViewer }) {
    const transcript = sha256(concat(
      utf8("KBDesk-v2-transcript"), clientPublic, hostPublic,
      clientNonce, hostNonce, utf8(hostId)));
    const passwordKey = sha256(utf8(password));
    const shared = x25519(mySecret, peerPublic);
    if (shared.every((b) => b === 0)) throw new Error("all-zero X25519 shared secret");
    const prk = hkdfExtract(transcript, concat(shared, passwordKey));
    const expand = (label, n) => hkdfExpand(prk, utf8(label), n);
    const confirmHost = expand("kbdesk v2 host confirm", 32);
    const confirmViewer = expand("kbdesk v2 viewer confirm", 32);
    const v2h = directionCipher(expand("kbdesk v2 viewer-to-host key", 32),
                                 expand("kbdesk v2 viewer-to-host nonce", 4));
    const h2v = directionCipher(expand("kbdesk v2 host-to-viewer key", 32),
                                 expand("kbdesk v2 host-to-viewer nonce", 4));
    return iAmViewer
      ? { send: v2h, recv: h2v, myConfirm: confirmViewer, peerConfirm: confirmHost }
      : { send: h2v, recv: v2h, myConfirm: confirmHost, peerConfirm: confirmViewer };
  }

  return {
    utf8, hex, unhex, concat, ctEq, randomBytes,
    sha256, hmacSha256, hkdfExtract, hkdfExpand,
    x25519, publicFromSecret, generateKeypair,
    aeadEncrypt, aeadDecrypt, deriveSession,
  };
})();

if (typeof module !== "undefined" && module.exports) module.exports = KBCrypto;
