"use strict";
/* Wire protocol between the web process and zehnox-maild (DESIGN.md section 5.3).

   Frame: one ASCII line  v1.<kid>.<b64url(payloadJSON)>.<hex HMAC-SHA256>\n
   MAC:   HMAC-SHA256(key[kid], "zehnox-mail/v1/req\n" + b64payload)   requests
          HMAC-SHA256(key[kid], "zehnox-mail/v1/res\n" + b64payload)   responses
   The two prefixes are domain separation: a response can never be replayed as a request.

   Verification order is the security property: frame shape -> kid known -> constant-time
   MAC compare -> only then base64-decode and JSON.parse. Nothing an unauthenticated peer
   sends is ever parsed. Pure: node:crypto only. */

const crypto = require("crypto");
const C = require("./constants.js");
const V = require("./validate.js");
const { CoreError } = C;

const PREFIX = Object.freeze({ req: "zehnox-mail/v1/req\n", res: "zehnox-mail/v1/res\n" });
const FRAME_RE = /^v1\.([a-z0-9]{1,16})\.([A-Za-z0-9_-]{2,})\.([0-9a-f]{64})$/;
const KID_RE = /^[a-z0-9]{1,16}$/;
const NONCE_RE = /^[0-9a-f]{32}$/;
const TS_WINDOW_MS = 30 * 1000;
const START_SLACK_MS = 1000;
const NONCE_TTL_MS = 60 * 1000;
const NONCE_CAP = 10000;

function mac(key, dir, b64) {
  return crypto.createHmac("sha256", key).update(PREFIX[dir] + b64, "latin1").digest();
}

function checkKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new TypeError("mail protocol key must be a 32-byte Buffer");
}

/* dir: 'req' | 'res'. Returns the frame including the trailing LF. */
function encodeFrame(dir, kid, key, obj) {
  if (!V.hasOwn(PREFIX, dir) || !KID_RE.test(String(kid))) throw new TypeError("bad frame parameters");
  checkKey(key);
  const b64 = Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
  const frame = "v1." + kid + "." + b64 + "." + mac(key, dir, b64).toString("hex") + "\n";
  const max = dir === "req" ? C.LIMITS.frameMax : C.LIMITS.responseMax;
  if (Buffer.byteLength(frame) > max) throw new CoreError(dir === "req" ? "bad_request" : "backend_failed");
  return frame;
}

/* keyFor(kid) -> Buffer | null. Every failure before a verified MAC is the same
   'unauthorized' (the daemon answers all of them identically and closes the socket).
   onParse is a test hook to prove JSON.parse is never reached for an invalid frame. */
function decodeFrame(dir, line, keyFor, onParse) {
  if (typeof line !== "string") throw new CoreError("unauthorized");
  const max = dir === "req" ? C.LIMITS.frameMax : C.LIMITS.responseMax;
  if (Buffer.byteLength(line) > max) throw new CoreError("unauthorized");
  const text = line.endsWith("\n") ? line.slice(0, -1) : line;
  const m = text.match(FRAME_RE);
  if (!m) throw new CoreError("unauthorized");
  const kid = m[1];
  const key = typeof keyFor === "function" ? keyFor(kid) : null;
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new CoreError("unauthorized");
  const want = mac(key, dir, m[2]);
  const got = Buffer.from(m[3], "hex");
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) throw new CoreError("unauthorized");
  let payload;
  try {
    if (onParse) onParse();
    payload = JSON.parse(Buffer.from(m[2], "base64url").toString("utf8"));
  } catch (_) {
    throw new CoreError("unauthorized");
  }
  if (!V.isPlainObject(payload)) throw new CoreError("unauthorized");
  return { kid, payload };
}

const newNonce = () => crypto.randomBytes(16).toString("hex");

/* ---------- replay protection ---------- */

/* Nonces are remembered until ts + 60 s, which covers the whole ±30 s acceptance window.
   When the cache is full of live nonces the daemon answers busy instead of evicting:
   evicting would reopen a replay window, and a full cache means a flood anyway. */
class NonceCache {
  constructor(opts) {
    const o = opts || {};
    this.cap = o.cap || NONCE_CAP;
    this.ttl = o.ttlMs || NONCE_TTL_MS;
    this.map = new Map();
  }
  prune(nowMs) {
    for (const [n, exp] of this.map) if (exp <= nowMs) this.map.delete(n);
  }
  /* -> 'ok' | 'replay' | 'busy' */
  add(nonce, ts, nowMs) {
    const known = this.map.get(nonce);
    if (known !== undefined && known > nowMs) return "replay";
    if (this.map.size >= this.cap) this.prune(nowMs);
    if (this.map.size >= this.cap) return "busy";
    this.map.set(nonce, ts + this.ttl);
    return "ok";
  }
  get size() { return this.map.size; }
}

/* ---------- request payload ---------- */

const ACTOR_SPEC = { type: "object", props: { user: { type: "string", re: C.ACTOR_USER_RE }, ip: { type: "string", re: C.ACTOR_IP_RE } } };
const PAYLOAD_KEYS = new Set(["ts", "nonce", "verb", "idem", "ifRev", "args", "actor"]);

/* Builds a request payload. idem/ifRev are included only for mutating verbs. */
function buildRequest(p) {
  const kind = V.hasOwn(C.VERBS, p.verb) ? C.VERBS[p.verb].kind : null;
  if (!kind) throw new CoreError("unknown_verb");
  const out = { ts: p.nowMs, nonce: p.nonce || newNonce(), verb: p.verb };
  if (kind === "mutate") { out.idem = p.idem; out.ifRev = p.ifRev; }
  out.args = p.args || {};
  out.actor = { user: p.actor.user, ip: p.actor.ip };
  return out;
}

/* Daemon-side checks after the MAC verified, in the documented order:
   ts window -> start floor -> nonce -> schema. opts: { nowMs, startedAtMs, nonces }. */
function checkRequest(payload, opts) {
  if (!V.isPlainObject(payload)) throw new CoreError("bad_request");
  if (!Number.isSafeInteger(payload.ts) || typeof payload.nonce !== "string" || !NONCE_RE.test(payload.nonce)) throw new CoreError("bad_request");
  if (Math.abs(opts.nowMs - payload.ts) > TS_WINDOW_MS) throw new CoreError("stale");
  // A request signed before a restart cannot be replayed into the fresh nonce cache.
  if (payload.ts < opts.startedAtMs - START_SLACK_MS) throw new CoreError("stale");
  const seen = opts.nonces.add(payload.nonce, payload.ts, opts.nowMs);
  if (seen === "replay") throw new CoreError("replay");
  if (seen === "busy") throw new CoreError("busy");
  for (const k of Object.keys(payload)) if (!PAYLOAD_KEYS.has(k)) throw new CoreError("bad_request");
  if (typeof payload.verb !== "string" || !V.hasOwn(C.VERBS, payload.verb)) throw new CoreError("unknown_verb");
  const mutating = C.VERBS[payload.verb].kind === "mutate";
  if (mutating) {
    if (typeof payload.idem !== "string" || !C.UUID_V4_RE.test(payload.idem)) throw new CoreError("bad_request");
    if (!Number.isSafeInteger(payload.ifRev) || payload.ifRev < 0) throw new CoreError("bad_request");
  } else if (V.hasOwn(payload, "idem") || V.hasOwn(payload, "ifRev")) {
    throw new CoreError("bad_request");
  }
  V.schema(payload.actor, ACTOR_SPEC, { unknownCode: "bad_request", typeCode: "bad_request" });
  V.checkVerbArgs(payload.verb, payload.args);
  return payload;
}

/* ---------- responses ---------- */

function encodeResponse(kid, key, body) {
  const out = { nonce: body.nonce, ok: body.ok === true };
  if (out.ok) out.result = body.result === undefined ? null : body.result;
  else out.error = body.error && Array.isArray(body.error.refs) ? { code: String(body.error.code), refs: body.error.refs.slice() } : { code: String(body.error && body.error.code) };
  return encodeFrame("res", kid, key, out);
}

/* Web side. Any failure (MAC, kid, nonce echo, shape) is bad_response: the answer cannot
   be trusted, so neither success nor a specific error is reported. */
function verifyResponse(line, kid, key, expectedNonce) {
  let d;
  try {
    d = decodeFrame("res", line, (k) => (k === kid ? key : null));
  } catch (_) {
    throw new CoreError("bad_response");
  }
  const b = d.payload;
  if (d.kid !== kid || b.nonce !== expectedNonce || typeof b.ok !== "boolean") throw new CoreError("bad_response");
  for (const k of Object.keys(b)) if (!["nonce", "ok", "result", "error"].includes(k)) throw new CoreError("bad_response");
  if (b.ok) {
    if (!V.hasOwn(b, "result") || V.hasOwn(b, "error")) throw new CoreError("bad_response");
    return { ok: true, result: b.result };
  }
  const e = b.error;
  if (!V.isPlainObject(e) || typeof e.code !== "string" || V.hasOwn(b, "result")) throw new CoreError("bad_response");
  const refs = Array.isArray(e.refs) ? e.refs.filter((r) => V.isValidLocal(r)).slice(0, 50) : undefined;
  return { ok: false, error: refs ? { code: e.code, refs } : { code: e.code } };
}

module.exports = {
  PREFIX, TS_WINDOW_MS, NONCE_TTL_MS, NONCE_CAP,
  encodeFrame, decodeFrame, newNonce, NonceCache, buildRequest, checkRequest, encodeResponse, verifyResponse,
};
