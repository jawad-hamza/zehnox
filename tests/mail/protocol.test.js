"use strict";
/* Wire protocol between the web process and zehnox-maild (lib/mail/core/protocol.js),
   DESIGN.md section 5.3: frame shape, HMAC with domain separation, verification before
   parsing, the timestamp window, the restart floor, nonce replay and the size limits. */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const crypto = require("crypto");
const { CORE } = require("./helpers/common.js");

const protocol = require(path.join(CORE, "protocol.js"));
const C = require(path.join(CORE, "constants.js"));

const codeOf = (fn) => { try { fn(); return null; } catch (e) { return e.code; } };
const KEY = crypto.randomBytes(32);
const keyFor = (kid) => (kid === "k1" ? KEY : null);
const actor = { user: "admin", ip: "127.0.0.1" };

function req(verb, args, extra) {
  const e = extra || {};
  return protocol.buildRequest({ verb, args, idem: e.idem, ifRev: e.ifRev, actor, nowMs: e.nowMs || Date.now(), nonce: e.nonce });
}

test("frames: sign then verify round-trips; the frame is one ASCII line", () => {
  const p = req("createAddress", { local: "info", forwards: ["a@example.com"], mailbox: null, reuseDeleted: false }, { idem: crypto.randomUUID(), ifRev: 3 });
  const frame = protocol.encodeFrame("req", "k1", KEY, p);
  assert.match(frame, /^v1\.k1\.[A-Za-z0-9_-]+\.[0-9a-f]{64}\n$/);
  assert.equal(frame.indexOf("\n"), frame.length - 1);
  const d = protocol.decodeFrame("req", frame, keyFor);
  assert.equal(d.kid, "k1");
  assert.deepEqual(d.payload, p);
});

test("frames: a flipped payload byte, a wrong key, an unknown kid, a bad MAC are all 'unauthorized'", () => {
  const p = req("listAddresses", {});
  const frame = protocol.encodeFrame("req", "k1", KEY, p);
  const [v, kid, b64, mac] = frame.trim().split(".");
  const flip = (s, i) => s.slice(0, i) + (s[i] === "A" ? "B" : "A") + s.slice(i + 1);
  const bad = [
    [v, kid, flip(b64, 5), mac].join("."),
    // change the first MAC character to a different hex digit (a fixed "0" would be a
    // no-op, and a flaky test, whenever the random MAC already starts with "0")
    [v, kid, b64, (mac[0] === "0" ? "1" : "0") + mac.slice(1)].join("."),
    [v, kid, b64, mac.slice(0, 63)].join("."),
    [v, kid, b64, mac.toUpperCase()].join("."),
    [v, kid, b64, "z".repeat(64)].join("."),
    ["v1", "k9", b64, mac].join("."),
    ["v2", kid, b64, mac].join("."),
    "garbage",
    "",
    "v1.k1.." + mac,
    frame.trim() + ".extra",
  ];
  for (const f of bad) assert.equal(codeOf(() => protocol.decodeFrame("req", f + "\n", keyFor)), "unauthorized", f.slice(0, 30));
  const other = crypto.randomBytes(32);
  const forged = protocol.encodeFrame("req", "k1", other, p);
  assert.equal(codeOf(() => protocol.decodeFrame("req", forged, keyFor)), "unauthorized");
  assert.equal(codeOf(() => protocol.decodeFrame("req", 42, keyFor)), "unauthorized");
});

test("frames: the MAC is checked before any base64 decode or JSON.parse", () => {
  let parsed = 0;
  const onParse = () => { parsed++; };
  const p = req("listAddresses", {});
  const frame = protocol.encodeFrame("req", "k1", KEY, p);
  const tampered = frame.replace(/\.([A-Za-z0-9_-]+)\./, (m, b) => "." + b.slice(0, -2) + "__.");
  assert.equal(codeOf(() => protocol.decodeFrame("req", tampered, keyFor, onParse)), "unauthorized");
  assert.equal(codeOf(() => protocol.decodeFrame("req", protocol.encodeFrame("req", "k1", crypto.randomBytes(32), p), keyFor, onParse)), "unauthorized");
  assert.equal(parsed, 0, "JSON.parse was never reached for an unauthenticated frame");
  protocol.decodeFrame("req", frame, keyFor, onParse);
  assert.equal(parsed, 1);
  // A validly signed frame whose payload is not JSON is still refused uniformly.
  const b64 = Buffer.from("not json{", "utf8").toString("base64url");
  const mac = crypto.createHmac("sha256", KEY).update(protocol.PREFIX.req + b64, "latin1").digest("hex");
  assert.equal(codeOf(() => protocol.decodeFrame("req", "v1.k1." + b64 + "." + mac + "\n", keyFor)), "unauthorized");
});

test("domain separation: a response frame cannot be verified as a request, nor the reverse", () => {
  const p = req("listAddresses", {});
  const res = protocol.encodeResponse("k1", KEY, { nonce: p.nonce, ok: true, result: { rev: 1 } });
  assert.equal(codeOf(() => protocol.decodeFrame("req", res, keyFor)), "unauthorized");
  const reqFrame = protocol.encodeFrame("req", "k1", KEY, { nonce: p.nonce, ok: true, result: {} });
  assert.equal(codeOf(() => protocol.verifyResponse(reqFrame, "k1", KEY, p.nonce)), "bad_response");
});

test("responses: nonce echo, kid, key and shape must all match or it is bad_response", () => {
  const nonce = protocol.newNonce();
  const good = protocol.encodeResponse("k1", KEY, { nonce, ok: true, result: { rev: 2 } });
  assert.deepEqual(protocol.verifyResponse(good, "k1", KEY, nonce), { ok: true, result: { rev: 2 } });
  assert.equal(codeOf(() => protocol.verifyResponse(good, "k1", KEY, protocol.newNonce())), "bad_response", "wrong nonce echo");
  assert.equal(codeOf(() => protocol.verifyResponse(good, "k2", KEY, nonce)), "bad_response", "wrong kid");
  assert.equal(codeOf(() => protocol.verifyResponse(good, "k1", crypto.randomBytes(32), nonce)), "bad_response", "wrong key");
  assert.equal(codeOf(() => protocol.verifyResponse('{"ok":false,"error":{"code":"unauthorized"}}\n', "k1", KEY, nonce)), "bad_response", "unsigned line");
  const extra = protocol.encodeFrame("res", "k1", KEY, { nonce, ok: true, result: {}, debug: "x" });
  assert.equal(codeOf(() => protocol.verifyResponse(extra, "k1", KEY, nonce)), "bad_response", "unknown field");
  const both = protocol.encodeFrame("res", "k1", KEY, { nonce, ok: false, error: { code: "x" }, result: {} });
  assert.equal(codeOf(() => protocol.verifyResponse(both, "k1", KEY, nonce)), "bad_response");
  // refs are filtered to valid local parts: a daemon cannot smuggle text into a message.
  const refs = protocol.encodeResponse("k1", KEY, { nonce, ok: false, error: { code: "in_use", refs: ["info", "<script>", "a@strategicbhm.com"] } });
  assert.deepEqual(protocol.verifyResponse(refs, "k1", KEY, nonce), { ok: false, error: { code: "in_use", refs: ["info"] } });
});

test("size limits: a request frame over 16 KiB cannot be built and is refused unread", () => {
  const big = req("createAddress", { local: "info", forwards: ["a".repeat(C.LIMITS.frameMax) + "@example.com"], mailbox: null, reuseDeleted: false }, { idem: crypto.randomUUID(), ifRev: 0 });
  assert.equal(codeOf(() => protocol.encodeFrame("req", "k1", KEY, big)), "bad_request");
  let parsed = 0;
  const line = "v1.k1." + "A".repeat(C.LIMITS.frameMax) + "." + "0".repeat(64) + "\n";
  assert.equal(codeOf(() => protocol.decodeFrame("req", line, keyFor, () => { parsed++; })), "unauthorized");
  assert.equal(parsed, 0);
});

test("replay protection: ts window of 30 s, the restart floor, and nonces", () => {
  const now = Date.now();
  const nonces = new protocol.NonceCache();
  const check = (p, o) => codeOf(() => protocol.checkRequest(p, Object.assign({ nowMs: now, startedAtMs: now - 60000, nonces }, o || {})));
  assert.equal(check(req("listAddresses", {}, { nowMs: now })), null);
  assert.equal(check(req("listAddresses", {}, { nowMs: now - 31000 })), "stale", "31 s old");
  assert.equal(check(req("listAddresses", {}, { nowMs: now + 31000 })), "stale", "31 s in the future");
  assert.equal(check(req("listAddresses", {}, { nowMs: now - 29000 })), null, "29 s is inside the window");
  // Signed before the daemon (re)started: refused even though inside the window.
  assert.equal(check(req("listAddresses", {}, { nowMs: now - 5000 }), { startedAtMs: now }), "stale");
  const p = req("listAddresses", {}, { nowMs: now });
  assert.equal(check(p), null);
  assert.equal(check(p), "replay", "the same nonce twice");
  assert.equal(check(Object.assign({}, p, { ts: now + 1 })), "replay", "a new ts does not refresh a seen nonce");
});

test("replay protection: a full nonce cache answers busy instead of evicting", () => {
  const now = Date.now();
  const nonces = new protocol.NonceCache({ cap: 3 });
  for (let i = 0; i < 3; i++) assert.equal(nonces.add(protocol.newNonce(), now, now), "ok");
  assert.equal(nonces.add(protocol.newNonce(), now, now), "busy");
  // Expired entries are pruned when room is needed.
  assert.equal(nonces.add(protocol.newNonce(), now, now + 61000), "ok");
});

test("request payload: strict keys; idem/ifRev required on mutations and forbidden on reads; unknown verbs refused", () => {
  const now = Date.now();
  const opts = () => ({ nowMs: now, startedAtMs: now - 1000, nonces: new protocol.NonceCache() });
  const base = { ts: now, nonce: protocol.newNonce(), actor };
  const cases = [
    [Object.assign({}, base, { verb: "listAddresses", args: {}, idem: crypto.randomUUID() }), "bad_request"],
    [Object.assign({}, base, { verb: "listAddresses", args: {}, ifRev: 1 }), "bad_request"],
    [Object.assign({}, base, { verb: "removeForwarding", args: { local: "info" }, ifRev: 1 }), "bad_request"],
    [Object.assign({}, base, { verb: "removeForwarding", args: { local: "info" }, idem: "not-a-uuid", ifRev: 1 }), "bad_request"],
    [Object.assign({}, base, { verb: "removeForwarding", args: { local: "info" }, idem: crypto.randomUUID(), ifRev: -1 }), "bad_request"],
    [Object.assign({}, base, { verb: "listAddresses", args: {}, domain: "strategicbhm.com" }), "bad_request"],
    [Object.assign({}, base, { verb: "listAddresses", args: {}, actor: { user: "admin; rm -rf /", ip: "127.0.0.1" } }), "bad_request"],
    [Object.assign({}, base, { verb: "listAddresses", args: {}, actor: { user: "admin", ip: "127.0.0.1", role: "root" } }), "bad_request"],
    [Object.assign({}, base, { verb: "exec", args: { cmd: "id" } }), "unknown_verb"],
    [Object.assign({}, base, { verb: "__proto__", args: {} }), "unknown_verb"],
    [Object.assign({}, base, { verb: "toString", args: {} }), "unknown_verb"],
    [Object.assign({}, base, { verb: "constructor", args: {} }), "unknown_verb"],
    [Object.assign({}, base, { verb: "hasOwnProperty", args: {} }), "unknown_verb"],
    [Object.assign({}, base, { nonce: "XYZ", verb: "listAddresses", args: {} }), "bad_request"],
    [Object.assign({}, base, { ts: "now", verb: "listAddresses", args: {} }), "bad_request"],
  ];
  for (const [p, want] of cases) assert.equal(codeOf(() => protocol.checkRequest(p, opts())), want, JSON.stringify(p).slice(0, 90));
  assert.equal(codeOf(() => protocol.buildRequest({ verb: "exec", args: {}, actor, nowMs: now })), "unknown_verb");
});

test("keys: only 32-byte Buffers are accepted", () => {
  for (const k of [crypto.randomBytes(16), crypto.randomBytes(33), "a".repeat(64), null]) {
    assert.throws(() => protocol.encodeFrame("req", "k1", k, {}), TypeError);
  }
  assert.throws(() => protocol.encodeFrame("req", "K1", KEY, {}), TypeError, "kid is lowercase alnum");
  assert.throws(() => protocol.encodeFrame("sideways", "k1", KEY, {}), TypeError);
});
