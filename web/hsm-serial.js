// hsm-serial.js — Web Serial client for the ESP32-S3 HSM.
// Wire protocol mirrors firmware/main/frame.* exactly (verified byte-identical).
//
//   [0xA5 0x5A] SOF | CMD | FLAGS | LEN(uint16 LE) | PAYLOAD | CRC16(LE)
//   CRC-16/CCITT-FALSE over CMD..PAYLOAD (SOF excluded).

export const CMD = {
  GET_PUBKEY: 0x01,
  DERIVE_SESSION: 0x02,
  ENCRYPT: 0x03,
  DECRYPT: 0x04,
  RATCHET_ADVANCE: 0x05,
  SIGN_CHALLENGE: 0x06,
  ERROR: 0xff,
};

export const STATUS = {
  0x00: "OK", 0x01: "BAD_LENGTH", 0x02: "BAD_CMD", 0x03: "NO_SESSION",
  0x04: "DECRYPT_FAIL", 0x05: "NOT_PROVISIONED", 0x06: "INTERNAL", 0x07: "CRYPTO_FAIL",
};

const SOF0 = 0xa5, SOF1 = 0x5a;
const MAX_PAYLOAD = 2048;

// ---- CRC-16/CCITT-FALSE ----
function crc16(bytes) {
  let crc = 0xffff;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++)
      crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
}

function encodeFrame(cmd, flags, payload = new Uint8Array(0)) {
  if (payload.length > MAX_PAYLOAD) throw new Error("payload too large");
  const body = new Uint8Array(4 + payload.length);
  body[0] = cmd; body[1] = flags;
  body[2] = payload.length & 0xff; body[3] = (payload.length >> 8) & 0xff;
  body.set(payload, 4);
  const crc = crc16(body);
  const out = new Uint8Array(2 + body.length + 2);
  out[0] = SOF0; out[1] = SOF1;
  out.set(body, 2);
  out[out.length - 2] = crc & 0xff;
  out[out.length - 1] = (crc >> 8) & 0xff;
  return out;
}

// Streaming decoder, same state machine as the firmware (resyncs on SOF).
class FrameDecoder {
  constructor(onFrame) {
    this.onFrame = onFrame;
    this.reset(); this.state = "SOF0";
  }
  reset() { this.hdr = []; this.payload = []; this.crc = []; this.state = "SOF0"; }
  push(chunk) {
    for (const c of chunk) {
      switch (this.state) {
        case "SOF0": if (c === SOF0) this.state = "SOF1"; break;
        case "SOF1":
          if (c === SOF1) { this.hdr = []; this.state = "HEADER"; }
          else if (c === SOF0) this.state = "SOF1";
          else this.state = "SOF0";
          break;
        case "HEADER":
          this.hdr.push(c);
          if (this.hdr.length === 4) {
            this.cmd = this.hdr[0]; this.flags = this.hdr[1];
            this.len = this.hdr[2] | (this.hdr[3] << 8);
            if (this.len > MAX_PAYLOAD) { this.reset(); break; }
            this.payload = [];
            this.state = this.len === 0 ? "CRC" : "PAYLOAD";
          }
          break;
        case "PAYLOAD":
          this.payload.push(c);
          if (this.payload.length === this.len) { this.crc = []; this.state = "CRC"; }
          break;
        case "CRC":
          this.crc.push(c);
          if (this.crc.length === 2) {
            const rx = this.crc[0] | (this.crc[1] << 8);
            const calc = crc16([...this.hdr, ...this.payload]);
            if (rx === calc) this.onFrame(this.cmd, this.flags, new Uint8Array(this.payload));
            this.reset();
          }
          break;
      }
    }
  }
}

export class HsmSerial {
  constructor({ baudRate = 115200, timeoutMs = 3000 } = {}) {
    this.baudRate = baudRate;
    this.timeoutMs = timeoutMs;
    this.port = null;
    this.writer = null;
    this._pending = null;       // { resolve, reject, timer }
    this._chain = Promise.resolve(); // single-flight serializer
    this._onDisconnect = null;
    this.decoder = new FrameDecoder((cmd, flags, payload) => this._handleFrame(cmd, flags, payload));
  }

  async connect() {
    this.port = await navigator.serial.requestPort();
    await this.port.open({ baudRate: this.baudRate });
    this.writer = this.port.writable.getWriter();
    this._readLoop();
    navigator.serial.addEventListener("disconnect", (e) => {
      if (e.target === this.port && this._onDisconnect) this._onDisconnect();
    });
  }

  onDisconnect(cb) { this._onDisconnect = cb; }

  async disconnect() {
    try { await this.reader?.cancel(); } catch {}
    try { this.writer?.releaseLock(); } catch {}
    try { await this.port?.close(); } catch {}
  }

  async _readLoop() {
    this.reader = this.port.readable.getReader();
    try {
      for (;;) {
        const { value, done } = await this.reader.read();
        if (done) break;
        if (value) this.decoder.push(value);
      }
    } catch (e) {
      if (this._onDisconnect) this._onDisconnect();
    } finally {
      try { this.reader.releaseLock(); } catch {}
    }
  }

  _handleFrame(cmd, flags, payload) {
    if (!this._pending) return; // unsolicited frame, ignore
    const p = this._pending; this._pending = null;
    clearTimeout(p.timer);
    if (cmd === CMD.ERROR) p.reject(new Error("HSM error: " + (STATUS[flags] || flags)));
    else p.resolve({ cmd, flags, payload });
  }

  // Serialized request/response (single-flight).
  _command(cmd, flags, payload) {
    const run = () => new Promise((resolve, reject) => {
      this._pending = {
        resolve, reject,
        timer: setTimeout(() => { this._pending = null; reject(new Error("HSM timeout")); }, this.timeoutMs),
      };
      this.writer.write(encodeFrame(cmd, flags, payload)).catch(reject);
    });
    const next = this._chain.then(run, run);
    this._chain = next.catch(() => {});
    return next;
  }

  // ---- high-level commands ----
  async getPubkeys() {
    const { payload } = await this._command(CMD.GET_PUBKEY, 0);
    return { x25519: payload.slice(0, 32), ed25519: payload.slice(32, 64) };
  }

  // peerX25519Pub: Uint8Array(32). Returns { sendKey, recvKey } raw bytes.
  async deriveSession(peerX25519Pub) {
    const { payload } = await this._command(CMD.DERIVE_SESSION, 0, peerX25519Pub);
    return { sendKey: payload.slice(0, 32), recvKey: payload.slice(32, 64) };
  }

  // Diseño A: device-side AEAD. Returns { nonce, ciphertext, tag }.
  async encrypt(plaintext) {
    const { payload } = await this._command(CMD.ENCRYPT, 0, plaintext);
    return {
      nonce: payload.slice(0, 12),
      ciphertext: payload.slice(12, payload.length - 16),
      tag: payload.slice(payload.length - 16),
    };
  }

  async decrypt(nonce, ciphertext, tag) {
    const body = new Uint8Array(12 + ciphertext.length + 16);
    body.set(nonce, 0); body.set(ciphertext, 12); body.set(tag, 12 + ciphertext.length);
    const { payload } = await this._command(CMD.DECRYPT, 0, body);
    return payload;
  }

  async ratchetAdvance() {
    const { payload } = await this._command(CMD.RATCHET_ADVANCE, 0);
    return payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24);
  }

  async signChallenge(challenge) {
    const { payload } = await this._command(CMD.SIGN_CHALLENGE, 0, challenge);
    return payload; // 64-byte Ed25519 signature
  }
}

// ---- WebCrypto helpers (Diseño B: browser-side AEAD) ----
// Import a 32-byte key as a NON-EXTRACTABLE AES-256-GCM CryptoKey.
export async function importSessionKey(raw32) {
  return crypto.subtle.importKey("raw", raw32, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

// nonce = gen(4 LE) || counter(8 LE), mirroring the firmware layout.
export function makeNonce(gen, counter) {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setUint32(0, gen >>> 0, true);
  // counter as 64-bit LE
  let c = BigInt(counter);
  for (let i = 0; i < 8; i++) { n[4 + i] = Number(c & 0xffn); c >>= 8n; }
  return n;
}

export async function aeadEncrypt(cryptoKey, nonce, plaintext) {
  const buf = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, cryptoKey, plaintext);
  return new Uint8Array(buf); // ciphertext || tag(16)
}

export async function aeadDecrypt(cryptoKey, nonce, ctPlusTag) {
  const buf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, cryptoKey, ctPlusTag);
  return new Uint8Array(buf);
}

export const _internal = { crc16, encodeFrame, FrameDecoder };
