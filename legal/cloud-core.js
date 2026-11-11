/**
 * LifeOS account sync — crypto and transport (no app state; runs in browsers
 * and in Node 20+, so the sync service can be tested without a UI).
 *
 * Keys: PBKDF2-SHA256(password, salt, 310k) → 64 bytes. The first half is the
 * password proof sent to the server (authKey, hex); the second half (KEK)
 * wraps a random 32-byte data key (DEK) with AES-GCM. Only the wrapped DEK is
 * stored on the server, so the server cannot read anything, and changing the
 * password only re-wraps the DEK.
 *
 * Payloads: gzip → AES-GCM(DEK, random 12-byte IV) → iv|ciphertext → base64,
 * split into pieces the server stores as text.
 */
export const PIECE = 1_500_000; // base64 chars per stored piece (server cap 1.9M)

const enc = new TextEncoder();
export const toHex = (b) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('');
export function randomBytes(n) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536))); // 64 KB per call max
  return out;
}

export function bytesToB64(bytes) {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = '';
  for (let i = 0; i < u.length; i += 0x8000) out += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  return btoa(out);
}
export function b64ToBytes(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function pipeBytes(bytes, stream) {
  const res = new Response(new Blob([bytes]).stream().pipeThrough(stream));
  return new Uint8Array(await res.arrayBuffer());
}
const gzip = (b) => pipeBytes(b, new CompressionStream('gzip'));
const gunzip = (b) => pipeBytes(b, new DecompressionStream('gzip'));

/** { authKey: hex, kek: CryptoKey } from a password and the account's salt (hex). */
export async function deriveKeys(password, saltHex, iterations = 310000) {
  const base = await crypto.subtle.importKey('raw', enc.encode(String(password).normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  const salt = new Uint8Array(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, 512));
  const kek = await crypto.subtle.importKey('raw', bits.slice(32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  return { authKey: toHex(bits.slice(0, 32)), kek };
}

async function aesKey(raw) {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/** Wrap / unwrap the data key with the password key. */
export async function wrapKey(kek, dek) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, dek));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  return bytesToB64(out);
}
export async function unwrapKey(kek, wrappedB64) {
  const b = b64ToBytes(wrappedB64);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.subarray(0, 12) }, kek, b.subarray(12)));
  } catch {
    throw new Error('That password could not unlock this account’s data.');
  }
}

/** bytes → base64 ciphertext. */
export async function seal(dek, bytes) {
  const key = await aesKey(dek);
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, await gzip(bytes)));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  return bytesToB64(out);
}
/** base64 ciphertext → bytes. */
export async function open(dek, b64) {
  const key = await aesKey(dek);
  const b = b64ToBytes(b64);
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.subarray(0, 12) }, key, b.subarray(12));
  } catch {
    throw new Error('Synced data could not be decrypted (wrong key or damaged copy).');
  }
  return gunzip(new Uint8Array(plain));
}

export async function sha256Hex(bytes) {
  return toHex(await crypto.subtle.digest('SHA-256', bytes));
}

export const pieces = (s) => {
  const out = [];
  for (let i = 0; i < s.length; i += PIECE) out.push(s.slice(i, i + PIECE));
  return out.length ? out : [''];
};

/* --------------------------------- transport -------------------------------- */

export class CloudError extends Error {
  constructor(status, code, message, extra = {}) { super(message); this.status = status; this.code = code; Object.assign(this, extra); }
}

/** A small client for the sync worker. `base` like https://lifeos-sync.example.workers.dev */
export function client(base, getToken = () => '') {
  async function call(method, path, { json, text, timeout = 30000 } = {}) {
    const ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = ctl ? setTimeout(() => ctl.abort(), timeout) : null;
    let res;
    try {
      const token = getToken();
      res = await fetch(base.replace(/\/+$/, '') + path, {
        method,
        headers: {
          ...(token ? { authorization: `Bearer ${token}` } : {}),
          ...(json !== undefined ? { 'content-type': 'application/json' } : text !== undefined ? { 'content-type': 'text/plain' } : {}),
        },
        body: json !== undefined ? JSON.stringify(json) : text,
        signal: ctl?.signal,
      });
    } catch (err) {
      throw new CloudError(0, 'offline', 'Can’t reach the LifeOS sync service — check your internet connection.');
    } finally {
      if (timer) clearTimeout(timer);
    }
    const ct = res.headers.get('content-type') || '';
    if (!res.ok) {
      let e = {};
      try { e = (await res.json()).error || {}; } catch { /* not JSON */ }
      throw new CloudError(res.status, e.code || 'error', e.message || `Sync request failed (${res.status}).`, e);
    }
    return ct.includes('application/json') ? res.json() : res.text();
  }
  return {
    call,
    prelogin: (email) => call('POST', '/v1/prelogin', { json: { email } }),
    signup: (b) => call('POST', '/v1/signup', { json: b }),
    login: (b) => call('POST', '/v1/login', { json: b }),
    logout: () => call('POST', '/v1/logout', { json: {} }),
    head: () => call('GET', '/v1/head', { timeout: 8000 }),
    password: (b) => call('POST', '/v1/password', { json: b }),
    remove: (b) => call('POST', '/v1/delete', { json: b }),
    listFiles: () => call('GET', '/v1/files'),

    /** Upload sealed text as a snapshot on top of version `base`. */
    async putSnapshot(sealed, base) {
      const upload = toHex(randomBytes(12));
      const parts = pieces(sealed);
      for (let i = 0; i < parts.length; i++) await call('PUT', `/v1/snapshot/${upload}/${i}`, { text: parts[i], timeout: 120000 });
      return call('POST', '/v1/snapshot/commit', { json: { upload, chunks: parts.length, bytes: sealed.length, base } });
    },
    async getSnapshot(head) {
      let out = '';
      for (let i = 0; i < head.chunks; i++) out += await call('GET', `/v1/snapshot/${head.upload}/${i}`, { timeout: 120000 });
      return out;
    },
    async putFile(name, sealed) {
      const parts = pieces(sealed);
      const n = encodeURIComponent(name);
      for (let i = 0; i < parts.length; i++) await call('PUT', `/v1/files/${n}/${i}`, { text: parts[i], timeout: 120000 });
      return call('POST', `/v1/files/${n}/commit`, { json: { chunks: parts.length, bytes: sealed.length } });
    },
    async getFile(name, chunks = 1) {
      const n = encodeURIComponent(name);
      let out = '';
      for (let i = 0; i < chunks; i++) out += await call('GET', `/v1/files/${n}/${i}`, { timeout: 120000 });
      return out;
    },
  };
}
