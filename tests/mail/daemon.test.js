"use strict";
/* zehnox-maild (mail-daemon/zehnox-maild.js), DESIGN.md sections 5.3-5.6: the
   protocol as the daemon enforces it (bad HMAC, stale timestamp, replayed nonce, oversized
   frame, unknown verbs) and the apply/rollback path with a fake postmap run through the
   daemon's real execFile. Sandbox mode only: temporary state directory, key generated now,
   no Postfix, Dovecot, systemd or system path involved. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const net = require("net");
const path = require("path");
const crypto = require("crypto");
const { CORE, fakeHash, CRYPT6 } = require("./helpers/common.js");
const { maild, protocol, C, FAKE_POSTMAP, recordingExecutor, newDaemon, client, currentRev, listenTarget } = require("./helpers/daemon.js");

const R = require(path.join(CORE, "render.js"));
const live = (d) => Object.fromEntries(R.FILES.map((n) => [n, fs.readFileSync(d.filePaths[n], "utf8")]));
const decode = (line) => { try { return Buffer.from(line.split(".")[2] || "", "base64url").toString("utf8"); } catch (_) { return ""; } };
const createArgs = (local, forwards, hash) => ({ local, forwards: forwards || [], mailbox: hash ? { passwordHash: hash } : null, reuseDeleted: false });

/* ---------- protocol, as enforced by the daemon ---------- */

test("unauthenticated frames: bad HMAC, unknown kid and garbage get one identical unsigned line", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  try {
    const p = protocol.buildRequest({ verb: "listAddresses", args: {}, actor: { user: "admin", ip: "127.0.0.1" }, nowMs: Date.now() });
    const forged = protocol.encodeFrame("req", "k1", crypto.randomBytes(32), p);
    const unknownKid = protocol.encodeFrame("req", "k9", t.key, p);
    const good = protocol.encodeFrame("req", "k1", t.key, p);
    const flipped = good.replace(/\.[0-9a-f]{64}\n$/, (m) => "." + (m[1] === "0" ? "1" : "0") + m.slice(2));
    const answers = [];
    for (const line of [forged, unknownKid, flipped, "garbage\n", "\n", "v1.k1.e30." + "0".repeat(64) + "\n", good.toUpperCase()]) answers.push(await t.d.handleLine(line));
    for (const a of answers) assert.equal(a, maild.UNAUTHORIZED_LINE);
    assert.equal(maild.UNAUTHORIZED_LINE, '{"ok":false,"error":{"code":"unauthorized"}}\n');
    // The good frame still works (the failures above consumed no nonce).
    assert.equal(protocol.verifyResponse(await t.d.handleLine(good), "k1", t.key, p.nonce).ok, true);
  } finally { await t.d.close(); }
});

test("stale timestamps, pre-start timestamps and replayed nonces are refused (signed answers)", async () => {
  let now = Date.now();
  const t = await newDaemon({ extra: { executor: recordingExecutor(), now: () => now } });
  try {
    const c = client(t.key);
    assert.deepEqual(await c.call(t.d, "listAddresses", {}, { nowMs: now - 31000 }), { ok: false, error: { code: "stale" } });
    assert.deepEqual(await c.call(t.d, "listAddresses", {}, { nowMs: now + 31000 }), { ok: false, error: { code: "stale" } });
    const nonce = protocol.newNonce();
    assert.equal((await c.call(t.d, "listAddresses", {}, { nonce, nowMs: now })).ok, true);
    assert.deepEqual(await c.call(t.d, "listAddresses", {}, { nonce, nowMs: now }), { ok: false, error: { code: "replay" } });
    // A mutation replayed byte for byte is refused before it can apply twice.
    const r0 = await currentRev(t.d, c);
    const payload = protocol.buildRequest({ verb: "createAddress", args: createArgs("info", ["a@example.com"]), idem: crypto.randomUUID(), ifRev: r0, actor: { user: "admin", ip: "127.0.0.1" }, nowMs: now });
    const frame = protocol.encodeFrame("req", "k1", t.key, payload);
    assert.equal(protocol.verifyResponse(await t.d.handleLine(frame), "k1", t.key, payload.nonce).ok, true);
    assert.deepEqual(protocol.verifyResponse(await t.d.handleLine(frame), "k1", t.key, payload.nonce), { ok: false, error: { code: "replay" } });
    assert.equal(await currentRev(t.d, c), r0 + 1);
    // A request signed before this daemon started cannot be replayed into its fresh cache.
    // (5 s old: inside the 30 s window, but more than 1 s before the restart.)
    now += 10000;
    await t.d.close();
    const t2 = await newDaemon({ made: t.made, dir: t.dir, extra: { executor: recordingExecutor(), now: () => now } });
    try {
      assert.deepEqual(await client(t.key).call(t2.d, "listAddresses", {}, { nowMs: now - 5000 }), { ok: false, error: { code: "stale" } });
      assert.equal((await client(t.key).call(t2.d, "listAddresses", {}, { nowMs: now })).ok, true);
    } finally { await t2.d.close(); }
  } finally { await t.d.close(); }
});

test("unknown verbs, extra payload fields and foreign domains are refused; nothing is dispatched generically", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  try {
    assert.deepEqual(t.d.HANDLERS_KEYS, C.VERB_NAMES);
    const send = async (payload) => protocol.verifyResponse(await t.d.handleLine(protocol.encodeFrame("req", "k1", t.key, payload)), "k1", t.key, payload.nonce);
    const base = () => ({ ts: Date.now(), nonce: protocol.newNonce(), actor: { user: "admin", ip: "127.0.0.1" } });
    for (const verb of ["exec", "spawn", "reload", "postmap", "__proto__", "constructor", "toString", "hasOwnProperty", "GETMAILSTATUS"]) {
      assert.deepEqual(await send(Object.assign(base(), { verb, args: {} })), { ok: false, error: { code: "unknown_verb" } }, verb);
    }
    const r0 = await currentRev(t.d, client(t.key));
    const mut = (args, extra) => Object.assign(base(), { verb: "createAddress", idem: crypto.randomUUID(), ifRev: r0, args }, extra || {});
    assert.deepEqual(await send(mut(createArgs("info", ["a@example.com"]), { domain: "strategicbhm.com" })), { ok: false, error: { code: "bad_request" } });
    assert.deepEqual(await send(mut(Object.assign(createArgs("info", ["a@example.com"]), { domain: "strategicbhm.com" }))), { ok: false, error: { code: "bad_request" } });
    assert.deepEqual(await send(mut(Object.assign(createArgs("info", ["a@example.com"]), { path: "/etc/postfix/main.cf" }))), { ok: false, error: { code: "bad_request" } });
    assert.deepEqual(await send(mut(createArgs("info@strategicbhm.com", ["a@example.com"]))), { ok: false, error: { code: "invalid_local" } });
    assert.deepEqual(await send(mut(createArgs("INFO", ["a@example.com"]))), { ok: false, error: { code: "invalid_local" } });
    assert.deepEqual(await send(mut(createArgs("info", ["|/bin/sh -c id@x.com"]))), { ok: false, error: { code: "invalid_destination" } });
    assert.deepEqual(await send(mut(createArgs("info", ["x@zehnox.com"]))), { ok: false, error: { code: "destination_not_mailbox" } });
    assert.deepEqual(await send(mut(createArgs("box", [], fakeHash(1000)))), { ok: false, error: { code: "weak_rounds" } }, "the daemon's 50,000-round floor");
    assert.deepEqual(await send(Object.assign(base(), { verb: "listAddresses", args: {}, idem: crypto.randomUUID() })), { ok: false, error: { code: "bad_request" } });
    assert.equal(await currentRev(t.d, client(t.key)), r0, "nothing was applied");
  } finally { await t.d.close(); }
});

test("the socket: an oversized frame is cut off unanswered; one frame per connection", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  const target = listenTarget(t.dir);
  await t.d.listen(target);
  const talk = (data) => new Promise((resolve) => {
    const s = net.createConnection({ path: target });
    let got = "";
    s.on("data", (c) => { got += c; });
    s.on("close", () => resolve(got));
    s.on("error", () => resolve(got));
    s.on("connect", () => s.write(data));
  });
  try {
    assert.equal(await talk("v1.k1." + "A".repeat(C.LIMITS.frameMax + 1)), "", "no newline within 16 KiB: closed, no answer");
    assert.equal(await talk("v1.k1." + "A".repeat(C.LIMITS.frameMax) + "\n"), "", "a newline past 16 KiB: closed, no answer");
    assert.equal(await talk("garbage\n"), maild.UNAUTHORIZED_LINE);
    const p = protocol.buildRequest({ verb: "getMailStatus", args: {}, actor: { user: "admin", ip: "127.0.0.1" }, nowMs: Date.now() });
    const p2 = protocol.buildRequest({ verb: "listAddresses", args: {}, actor: { user: "admin", ip: "127.0.0.1" }, nowMs: Date.now() });
    const both = await talk(protocol.encodeFrame("req", "k1", t.key, p) + protocol.encodeFrame("req", "k1", t.key, p2));
    assert.equal(both.split("\n").filter(Boolean).length, 1, "only the first frame is answered");
    const st = protocol.verifyResponse(both, "k1", t.key, p.nonce);
    assert.equal(st.result.domain, "zehnox.com");
  } finally { await t.d.close(); }
});

/* ---------- apply and rollback with the fake postmap (real execFile) ---------- */

test("apply: files rendered, indexes built through the frozen argv; indexer output never reaches a response", async () => {
  const t = await newDaemon({});
  try {
    const c = client(t.key);
    const h = fakeHash(50000);
    const r = await c.call(t.d, "createAddress", createArgs("contact", ["m@example.com"], h), { ifRev: await currentRev(t.d, c) });
    assert.equal(r.ok, true);
    const files = live(t.d);
    assert.match(files.virtual, /^contact@zehnox\.com contact@zehnox\.com, m@example\.com$/m);
    assert.match(files.passwd, /^contact@zehnox\.com:\{SHA512-CRYPT\}/m);
    for (const m of ["virtual", "vmailbox", "sender_login", "sasl_access"]) assert.equal(fs.readFileSync(t.d.filePaths[m] + ".db", "utf8"), files[m], m + ".db");
    const calls = fs.readFileSync(path.join(t.cfg.stateDir, "fake-postmap.log"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    const allowed = Object.values(t.d.POSTMAP_ARGV).map((a) => JSON.stringify(a.slice(1)));
    for (const call of calls) assert.ok(allowed.includes(JSON.stringify(call.argv)), JSON.stringify(call.argv));
    for (const line of c.lines) {
      const text = line + decode(line);
      assert.ok(!text.includes("TESTS-FAKE-POSTMAP") && !text.includes(h) && !text.includes(CRYPT6));
    }
    assert.ok(!fs.readFileSync(t.d.paths.state, "utf8").includes(CRYPT6), "state.json never holds a hash");
    // The journal lines hold no hash and no key; the indexer's output is scrubbed and capped.
    const journal = t.logs.join("\n");
    for (const s of [h, CRYPT6, t.key.toString("hex"), t.key.toString("base64")]) assert.ok(!journal.includes(s));
    for (const l of t.logs.filter((x) => x.startsWith("event=postmap_output"))) assert.ok(l.length <= 600, "capped");
    assert.ok(!fs.readFileSync(path.join(t.d.paths.root, "audit.jsonl"), "utf8").includes(CRYPT6), "nor does the service audit");
  } finally { await t.d.close(); }
});

test("rollback: a failing postmap restores every live file byte for byte; nothing is committed; the retry applies once", async () => {
  const t = await newDaemon({});
  try {
    const c = client(t.key);
    const r0 = await currentRev(t.d, c);
    const before = live(t.d);
    const stateBefore = fs.readFileSync(t.d.paths.state, "utf8");
    const hashesBefore = fs.readFileSync(t.d.paths.hashes, "utf8");
    fs.writeFileSync(path.join(t.cfg.stateDir, "fake-postmap.json"), JSON.stringify({ fail: ["sasl_access"], once: true }));
    const idem = crypto.randomUUID();
    const args = createArgs("contact", ["m@example.com"], fakeHash(50000));
    const r = await c.call(t.d, "createAddress", args, { ifRev: r0, idem });
    assert.deepEqual(r, { ok: false, error: { code: "backend_failed" } });
    assert.deepEqual(live(t.d), before, "the maps and passwd are back to their old bytes");
    assert.equal(fs.readFileSync(t.d.paths.state, "utf8"), stateBefore);
    assert.equal(fs.readFileSync(t.d.paths.hashes, "utf8"), hashesBefore);
    for (const f of [t.d.paths.state, t.d.paths.hashes]) assert.equal(fs.existsSync(f + ".tmp"), false);
    for (const m of ["virtual", "vmailbox", "sender_login", "sasl_access"]) assert.equal(fs.readFileSync(t.d.filePaths[m] + ".db", "utf8"), before[m], m + " re-indexed from the restored source");
    assert.equal(t.d.ready, true, "a clean restore leaves the daemon ready");
    assert.ok(t.logs.some((l) => l.includes("event=postmap_failed file=sasl_access")));
    // The failure was not remembered under the idempotency key: the same request now applies, once.
    const ok = await c.call(t.d, "createAddress", args, { ifRev: r0, idem });
    assert.equal(ok.ok, true);
    assert.equal(ok.result.rev, r0 + 1);
    const again = await c.call(t.d, "createAddress", args, { ifRev: r0, idem });
    assert.deepEqual(again, ok, "a replayed idempotency key returns the original result");
    assert.equal(await currentRev(t.d, c), r0 + 1);
    for (const line of c.lines) assert.ok(!(line + decode(line)).includes("TESTS-FAKE-POSTMAP"));
  } finally { await t.d.close(); }
});

test("a failing restore: not_ready for every mutation until a reconcile succeeds", async () => {
  const t = await newDaemon({});
  try {
    const c = client(t.key);
    const r0 = await currentRev(t.d, c);
    fs.writeFileSync(path.join(t.cfg.stateDir, "fake-postmap.json"), JSON.stringify({ fail: "all" }));
    const r = await c.call(t.d, "createAddress", createArgs("info", ["a@example.com"]), { ifRev: r0 });
    assert.deepEqual(r, { ok: false, error: { code: "not_ready" } });
    assert.equal(t.d.mapsInSync, false);
    assert.deepEqual(await c.call(t.d, "createAddress", createArgs("sales", ["a@example.com"]), { ifRev: r0 }), { ok: false, error: { code: "not_ready" } });
    const st = await c.call(t.d, "getMailStatus", {});
    assert.equal(st.result.service.mapsInSync, false);
    await t.d.pending;
    fs.unlinkSync(path.join(t.cfg.stateDir, "fake-postmap.json"));
    assert.equal((await t.d.reconcile()).ok, true);
    assert.equal(t.d.mapsInSync, true);
    assert.equal((await c.call(t.d, "createAddress", createArgs("info", ["a@example.com"]), { ifRev: r0 })).ok, true);
  } finally { await t.d.close(); }
});

test("ifRev and idempotency: a stale rev is conflict_rev; the idempotency check runs first", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  try {
    const c = client(t.key);
    const r0 = await currentRev(t.d, c);
    const idem = crypto.randomUUID();
    const first = await c.call(t.d, "createAddress", createArgs("info", ["a@example.com"]), { ifRev: r0, idem });
    assert.equal(first.ok, true);
    // Same key, same args, old rev: the stored success, not conflict_rev.
    assert.deepEqual(await c.call(t.d, "createAddress", createArgs("info", ["a@example.com"]), { ifRev: r0, idem }), first);
    assert.deepEqual(await c.call(t.d, "createAddress", createArgs("info", ["b@example.com"]), { ifRev: r0 + 1, idem }), { ok: false, error: { code: "idempotency_mismatch" } });
    assert.deepEqual(await c.call(t.d, "createAddress", createArgs("sales", ["a@example.com"]), { ifRev: r0 }), { ok: false, error: { code: "conflict_rev" } });
  } finally { await t.d.close(); }
});

test("executor: every indexer call uses a frozen argv entry by identity, frozen options, no shell", async () => {
  const exec = recordingExecutor();
  const t = await newDaemon({ extra: { executor: exec } });
  try {
    const c = client(t.key);
    await c.call(t.d, "createAddress", createArgs("info", ["a@example.com"]), { ifRev: await currentRev(t.d, c) });
    assert.ok(exec.calls.length >= 4);
    assert.ok(Object.isFrozen(t.d.POSTMAP_ARGV) && Object.isFrozen(t.d.POSTMAP_OPTIONS) && Object.isFrozen(t.d.POSTMAP_OPTIONS.env));
    const allowed = Object.values(t.d.POSTMAP_ARGV);
    for (const call of exec.calls) {
      assert.equal(call.file, process.execPath);
      assert.ok(allowed.includes(call.argv));
      assert.equal(call.options, t.d.POSTMAP_OPTIONS);
      assert.equal(call.options.shell, undefined);
      assert.deepEqual(call.options.env, { PATH: "/usr/sbin:/usr/bin", LANG: "C" });
    }
    assert.deepEqual(Object.keys(t.d.POSTMAP_ARGV).sort(), ["sasl_access", "sender_login", "virtual", "vmailbox"]);
    for (const [m, argv] of Object.entries(t.d.POSTMAP_ARGV)) assert.deepEqual(argv, [FAKE_POSTMAP, "hash:" + t.d.filePaths[m]]);
  } finally { await t.d.close(); }
});

test("production config: the indexer path, state dir and domain are pinned; sandbox-only options are refused", () => {
  const { makeConfig } = require("./helpers/daemon.js");
  const { mkTmp } = require("./helpers/common.js");
  const { cfg } = makeConfig(mkTmp("cfg"));
  const prod = Object.assign({}, cfg, { stateDir: "/var/lib/zehnox-mail", postmapPath: "/usr/sbin/postmap", keys: { k1: "/etc/zehnox-mail/keys/k1.key" } });
  delete prod.postmapPreArgs;
  assert.doesNotThrow(() => maild.validateConfig(prod, { sandbox: false }));
  for (const bad of [{ domain: "strategicbhm.com" }, { postmapPath: "/bin/sh" }, { postmapPreArgs: ["-c"] }, { stateDir: "/tmp/x" }, { mapType: "btree" }, { exec: "id" }]) {
    assert.throws(() => maild.validateConfig(Object.assign({}, prod, bad), { sandbox: false }), maild.ConfigError, JSON.stringify(bad));
  }
  assert.throws(() => maild.createDaemon({ config: prod, sandbox: false, noPostmap: true }), maild.ConfigError);
  assert.throws(() => maild.createDaemon({ config: prod, sandbox: false, keys: new Map() }), maild.ConfigError);
});
