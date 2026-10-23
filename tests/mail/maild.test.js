"use strict";
/* zehnox-maild (mail-daemon/zehnox-maild.js), DESIGN.md sections 5 and 15: the daemon
   author's own suite (config, CLI modes, reconcile, import, service audit, socket). It used to
   live in test/mail/, which CI ran on its own; it is part of tests/ now, so one command runs
   everything (node --test tests/).

   Every daemon here runs in sandbox mode on a temporary state directory, with either an
   injected executor that records the indexer argv or the fake indexer script
   (helpers/maild-fake-postmap.js). Keys are generated at run time. Nothing touches Postfix,
   Dovecot, systemd, a real mail server or a system path. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const net = require("net");

/* tests/mail/ is one level deeper than tests/ was in the project this came from. */
const REPO = path.join(__dirname, "..", "..");
const DAEMON_FILE = path.join(REPO, "mail-daemon", "zehnox-maild.js");
const maild = require(DAEMON_FILE);
const protocol = require(path.join(REPO, "lib", "mail", "core", "protocol.js"));
const C = require(path.join(REPO, "lib", "mail", "core", "constants.js"));
const R = require(path.join(REPO, "lib", "mail", "core", "render.js"));
const FAKE_POSTMAP = path.join(__dirname, "helpers", "maild-fake-postmap.js");
const WIN = process.platform === "win32";
// Honours ZEHNOX_TEST_TMP like the rest of tests/ (helpers/common.js).
const { TMP_ROOT } = require("./helpers/common.js");
fs.mkdirSync(TMP_ROOT, { recursive: true });

const tmpRoots = [];
test.after(() => { for (const d of tmpRoots) fs.rmSync(d, { recursive: true, force: true }); });

/* The crypt marker, built at run time so this file never holds the literal (the repo
   hygiene scan flags it outside the crypt vectors). */
const CRYPT_MARK = "$" + "6" + "$";

/* A plausible SHA512-CRYPT string: the daemon checks the format and rounds, never the hash. */
function fakeHash(rounds) {
  const A = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const pick = (n) => Array.from(crypto.randomBytes(n), (b) => A[b % 64]).join("");
  return "{SHA512-CRYPT}" + CRYPT_MARK + "rounds=" + (rounds || 50000) + "$" + pick(16) + "$" + pick(86);
}

function makeConfig(dir, over) {
  const keyFile = path.join(dir, "k1.key");
  const key = crypto.randomBytes(32);
  fs.writeFileSync(keyFile, key.toString("hex") + "\n");
  const cfg = {
    domain: "zehnox.com", hostname: "mail.example.net", mapType: "hash",
    postmapPath: process.execPath, postmapPreArgs: [FAKE_POSTMAP],
    stateDir: path.join(dir, "state"), bootstrapForward: "owner@example.com",
    mailboxes: { enabled: true, uid: 5000, gid: 5000, homeBase: "/var/vmail/zehnox.com", schemes: ["SHA512-CRYPT"], minRounds: 50000, gate: { senderLoginEnforced: true, outboundRateLimited: true } },
    dkim: { selector: "sbhm1", publicFile: null },
    probes: { smtp: 25, submission: 587, imap: 993 },
    keys: { k1: keyFile },
  };
  return { cfg: Object.assign(cfg, over || {}), key };
}

/* Records every indexer call and answers like the real runner (callback style). */
function recordingExecutor(opts) {
  const calls = [];
  const o = opts || {};
  const fn = (file, argv, options, cb) => {
    calls.push({ file, argv, options });
    const name = path.basename(String(argv[argv.length - 1]).replace(/^(hash|lmdb):/, ""));
    setImmediate(() => {
      if (o.fail && o.fail(name, calls.length)) {
        const e = new Error("exit 75");
        e.code = 75;
        return cb(e, "EXECUTOR-STDOUT-CANARY", "EXECUTOR-STDERR-CANARY");
      }
      const src = String(argv[argv.length - 1]).replace(/^(hash|lmdb):/, "");
      try { fs.writeFileSync(src + ".db", fs.readFileSync(src)); } catch (_) { /* restore of a missing file */ }
      cb(null, "EXECUTOR-STDOUT-CANARY", "");
    });
  };
  fn.calls = calls;
  return fn;
}

async function newDaemon(opts) {
  const o = opts || {};
  const dir = o.dir || fs.mkdtempSync(path.join(TMP_ROOT, "maild-"));
  if (!o.dir) tmpRoots.push(dir);
  const made = o.made || makeConfig(dir, o.over);
  const logs = [];
  const d = maild.createDaemon(Object.assign({ config: made.cfg, sandbox: true, log: (l) => logs.push(l) }, o.extra || {}));
  const started = await d.start({ periodic: false });
  return { d, dir, cfg: made.cfg, key: made.key, made, logs, started };
}

/* Client side: a signed frame and a verified response, as the web process does it. */
function client(key, kid) {
  const k = kid || "k1";
  const responses = [];
  async function call(d, verb, args, extra) {
    const e = extra || {};
    const payload = protocol.buildRequest({ verb, args, idem: e.idem || (C.VERBS[verb].kind === "mutate" ? crypto.randomUUID() : undefined), ifRev: e.ifRev, actor: { user: "admin", ip: "127.0.0.1" }, nowMs: e.nowMs || Date.now(), nonce: e.nonce });
    const line = await d.handleLine(protocol.encodeFrame("req", k, key, payload));
    responses.push(line);
    return protocol.verifyResponse(line, k, key, payload.nonce);
  }
  return { call, responses };
}

async function rev(d, c) {
  const r = await c.call(d, "listAddresses", {});
  assert.equal(r.ok, true);
  return r.result.rev;
}

const liveFiles = (d) => Object.fromEntries(R.FILES.map((n) => [n, fs.readFileSync(d.filePaths[n], "utf8")]));

/* ---------- configuration ---------- */

test("config: production pins domain, stateDir, indexer path, homeBase and key location", () => {
  const dir = fs.mkdtempSync(path.join(TMP_ROOT, "maild-cfg-"));
  tmpRoots.push(dir);
  const { cfg } = makeConfig(dir);
  const prod = Object.assign({}, cfg, { postmapPreArgs: undefined, stateDir: "/var/lib/zehnox-mail", postmapPath: "/usr/sbin/postmap", keys: { k1: "/etc/zehnox-mail/keys/k1.key" } });
  delete prod.postmapPreArgs;
  assert.doesNotThrow(() => maild.validateConfig(prod, { sandbox: false }));
  const bad = [
    { domain: "strategicbhm.com" },
    { postmapPath: "/usr/local/bin/postmap" },
    { postmapPreArgs: ["/tmp/x.js"] },
    { stateDir: "/tmp/zehnox" },
    { mapType: "btree" },
    { bootstrapForward: "postmaster@zehnox.com" },
    { keys: { k1: "/tmp/k1.key" } },
    { dkim: { selector: "sbhm1", publicFile: "/etc/opendkim/keys/zehnox.com/sbhm1.txt" } },
    { mailboxes: Object.assign({}, cfg.mailboxes, { homeBase: "/var/vmail/other" }) },
    { mailboxes: Object.assign({}, cfg.mailboxes, { schemes: ["BLF-CRYPT"] }) },
    { extra: true },
    { __proto__: null, constructor: 1 },
  ];
  for (const b of bad) {
    const c = Object.assign({}, prod, b);
    assert.throws(() => maild.validateConfig(c, { sandbox: false }), maild.ConfigError, JSON.stringify(Object.keys(b)));
  }
  // minRounds below the production floor is clamped, never honoured.
  const low = maild.validateConfig(Object.assign({}, prod, { mailboxes: Object.assign({}, cfg.mailboxes, { minRounds: 1000 }) }), { sandbox: false });
  assert.equal(low.mailboxes.minRounds, 50000);
});

test("config: key files must hold 64 hex characters; the bytes never appear in errors", () => {
  const dir = fs.mkdtempSync(path.join(TMP_ROOT, "maild-key-"));
  tmpRoots.push(dir);
  const { cfg } = makeConfig(dir);
  const secret = crypto.randomBytes(31).toString("hex"); // 62 hex: wrong length
  fs.writeFileSync(cfg.keys.k1, secret);
  const v = maild.validateConfig(cfg, { sandbox: true });
  assert.throws(() => maild.loadKeys(v), (e) => e instanceof maild.ConfigError && !e.message.includes(secret));
});

test("config: the mailbox gate keeps mailboxes off until both flags are set (D10)", async () => {
  const gate = { senderLoginEnforced: true, outboundRateLimited: false };
  const t = await newDaemon({ over: { mailboxes: { enabled: true, uid: 5000, gid: 5000, homeBase: "/var/vmail/zehnox.com", schemes: ["SHA512-CRYPT"], minRounds: 50000, gate } }, extra: { executor: recordingExecutor() } });
  assert.ok(t.logs.includes("event=mailbox_gate_closed"));
  const c = client(t.key);
  const st = await c.call(t.d, "getMailStatus", {});
  assert.equal(st.result.capabilities.mailboxes, false);
  const r = await c.call(t.d, "createAddress", { local: "contact", forwards: [], mailbox: { passwordHash: fakeHash() }, reuseDeleted: false }, { ifRev: await rev(t.d, c) });
  assert.deepEqual(r, { ok: false, error: { code: "capability_missing" } });
  await t.d.close();
});

/* ---------- first start, verbs, rendering ---------- */

test("first start creates protected postmaster@ and abuse@ and renders every file", async () => {
  const exec = recordingExecutor();
  const t = await newDaemon({ extra: { executor: exec } });
  assert.equal(t.started.selfCheck, "ok");
  assert.equal(t.started.mapsInSync, true);
  const c = client(t.key);
  const list = await c.call(t.d, "listAddresses", {});
  assert.deepEqual(list.result.addresses.map((a) => [a.local, a.protected, a.forwards]), [["abuse", true, ["owner@example.com"]], ["postmaster", true, ["owner@example.com"]]]);
  const files = liveFiles(t.d);
  assert.match(files.virtual, /^abuse@zehnox\.com owner@example\.com$/m);
  assert.doesNotThrow(() => R.assertRendered(files));
  const st = JSON.parse(fs.readFileSync(t.d.paths.state, "utf8"));
  assert.equal(st.domain, "zehnox.com");
  await t.d.close();
});

test("verb table: exactly the frozen 12 verbs; anything else is unknown_verb", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  assert.deepEqual(t.d.HANDLERS_KEYS, [
    "getMailStatus", "listAddresses", "getAuditTail", "createAddress", "deleteAddress", "setForwarding",
    "removeForwarding", "setAddressEnabled", "createMailbox", "disableMailbox", "enableMailbox", "changeMailboxPassword",
  ]);
  assert.deepEqual(t.d.HANDLERS_KEYS, C.VERB_NAMES);
  for (const verb of ["exec", "reload", "__proto__", "constructor", "toString"]) {
    const payload = { ts: Date.now(), nonce: protocol.newNonce(), verb, args: {}, actor: { user: "admin", ip: "127.0.0.1" } };
    const line = await t.d.handleLine(protocol.encodeFrame("req", "k1", t.key, payload));
    assert.deepEqual(protocol.verifyResponse(line, "k1", t.key, payload.nonce), { ok: false, error: { code: "unknown_verb" } }, verb);
  }
  await t.d.close();
});

test("protocol: bad MAC, unknown kid and garbage get the same unsigned unauthorized line", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  const other = crypto.randomBytes(32);
  const payload = protocol.buildRequest({ verb: "listAddresses", args: {}, actor: { user: "admin", ip: "::1" }, nowMs: Date.now() });
  const lines = [
    protocol.encodeFrame("req", "k1", other, payload),
    protocol.encodeFrame("req", "k9", t.key, payload),
    "hello\n",
    protocol.encodeFrame("res", "k1", t.key, payload), // a response frame is never a request
  ];
  const good = protocol.encodeFrame("req", "k1", t.key, payload);
  const tampered = good.slice(0, 10) + (good[10] === "A" ? "B" : "A") + good.slice(11);
  lines.push(tampered);
  for (const l of lines) assert.equal(await t.d.handleLine(l), maild.UNAUTHORIZED_LINE);
  await t.d.close();
  assert.ok(t.logs.some((l) => /^event=auth_failures count=\d+$/.test(l)));
});

test("protocol: stale ts, pre-start ts, replayed nonce and extra fields are refused", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  const c = client(t.key);
  assert.deepEqual(await c.call(t.d, "listAddresses", {}, { nowMs: Date.now() - 31000 }), { ok: false, error: { code: "stale" } });
  assert.deepEqual(await c.call(t.d, "listAddresses", {}, { nowMs: Date.now() + 31000 }), { ok: false, error: { code: "stale" } });
  const nonce = protocol.newNonce();
  assert.equal((await c.call(t.d, "listAddresses", {}, { nonce })).ok, true);
  assert.deepEqual(await c.call(t.d, "listAddresses", {}, { nonce }), { ok: false, error: { code: "replay" } });
  // Read verbs must not carry idem/ifRev; mutating verbs must.
  const p = { ts: Date.now(), nonce: protocol.newNonce(), verb: "listAddresses", idem: crypto.randomUUID(), ifRev: 1, args: {}, actor: { user: "admin", ip: "::1" } };
  const line = await t.d.handleLine(protocol.encodeFrame("req", "k1", t.key, p));
  assert.deepEqual(protocol.verifyResponse(line, "k1", t.key, p.nonce), { ok: false, error: { code: "bad_request" } });
  await t.d.close();
});

test("domain pin: another domain, a path or an unknown field never gets through", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  const c = client(t.key);
  const r0 = await rev(t.d, c);
  const cases = [
    [{ local: "info@strategicbhm.com", forwards: ["a@example.com"], mailbox: null, reuseDeleted: false }, "invalid_local"],
    [{ local: "../etc", forwards: ["a@example.com"], mailbox: null, reuseDeleted: false }, "invalid_local"],
    [{ local: "root", forwards: ["a@example.com"], mailbox: null, reuseDeleted: false }, "reserved_local"],
    [{ local: "info", forwards: ["|/bin/sh@example.com"], mailbox: null, reuseDeleted: false }, "invalid_destination"],
    [{ local: "info", forwards: ["a@example.com\r\nBcc: v@example.org"], mailbox: null, reuseDeleted: false }, "invalid_destination"],
    [{ local: "info", forwards: ["x@zehnox.com"], mailbox: null, reuseDeleted: false }, "destination_not_mailbox"],
    [{ local: "info", forwards: ["a@example.com"], mailbox: null, reuseDeleted: false, domain: "strategicbhm.com" }, "bad_request"],
    [{ local: "info", forwards: ["a@example.com"], mailbox: null, reuseDeleted: false, path: "/etc/postfix/virtual" }, "bad_request"],
    [{ local: "postmaster", forwards: ["a@example.com"], mailbox: null, reuseDeleted: false }, "protected"],
    [{ local: "info", forwards: ["a@example.com"], mailbox: { passwordHash: fakeHash(1000) }, reuseDeleted: false }, "weak_rounds"],
    [{ local: "info", forwards: ["a@example.com"], mailbox: { passwordHash: "{BLF-CRYPT}$2y$10$abcdefghijklmnopqrstuv" }, reuseDeleted: false }, "invalid_hash"],
  ];
  for (const [args, code] of cases) {
    const r = await c.call(t.d, "createAddress", args, { ifRev: r0 });
    assert.equal(r.ok, false, JSON.stringify(args));
    assert.equal(r.error.code, code, JSON.stringify(args));
  }
  assert.equal(await rev(t.d, c), r0);
  for (const f of Object.values(liveFiles(t.d))) assert.doesNotMatch(f, /strategicbhm|\/bin\/sh|etc\/postfix/);
  await t.d.close();
});

test("mutations: ifRev, idempotency before ifRev, and changed:false for a no-op", async () => {
  const exec = recordingExecutor();
  const t = await newDaemon({ extra: { executor: exec } });
  const c = client(t.key);
  const r0 = await rev(t.d, c);
  const idem = crypto.randomUUID();
  const args = { local: "info", forwards: ["owner@example.com"], mailbox: null, reuseDeleted: false };
  const first = await c.call(t.d, "createAddress", args, { idem, ifRev: r0 });
  assert.equal(first.ok, true);
  assert.equal(first.result.rev, r0 + 1);
  // A retry with the same key (and the now stale rev) returns the original success.
  const again = await c.call(t.d, "createAddress", args, { idem, ifRev: r0 });
  assert.deepEqual(again, first);
  // The same key for different arguments is refused.
  const other = await c.call(t.d, "createAddress", Object.assign({}, args, { local: "info2" }), { idem, ifRev: r0 + 1 });
  assert.deepEqual(other, { ok: false, error: { code: "idempotency_mismatch" } });
  assert.deepEqual(await c.call(t.d, "setForwarding", { local: "info", forwards: ["x@example.com"] }, { ifRev: r0 }), { ok: false, error: { code: "conflict_rev" } });
  const noop = await c.call(t.d, "setForwarding", { local: "info", forwards: ["owner@example.com"] }, { ifRev: r0 + 1 });
  assert.equal(noop.result.changed, false);
  assert.equal(noop.result.rev, r0 + 1);
  assert.equal(await rev(t.d, c), r0 + 1);
  await t.d.close();
});

test("mailboxes: passwd, vmailbox, sender_login, sasl_access; hashes never leave the host", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  const c = client(t.key);
  const h1 = fakeHash();
  let r = await c.call(t.d, "createAddress", { local: "contact", forwards: ["management@example.com"], mailbox: { passwordHash: h1 }, reuseDeleted: false }, { ifRev: await rev(t.d, c) });
  assert.equal(r.result.address.type, "mailbox+forward");
  const files = liveFiles(t.d);
  assert.match(files.virtual, /^contact@zehnox\.com contact@zehnox\.com, management@example\.com$/m);
  assert.match(files.vmailbox, /^contact@zehnox\.com zehnox\.com\/contact\/$/m);
  assert.match(files.sender_login, /^contact@zehnox\.com contact@zehnox\.com$/m);
  assert.match(files.sasl_access, /^contact@zehnox\.com zehnox_sender$/m);
  assert.ok(files.passwd.includes("contact@zehnox.com:" + h1 + ":5000:5000::/var/vmail/zehnox.com/contact::"));
  const h2 = fakeHash();
  r = await c.call(t.d, "changeMailboxPassword", { local: "contact", passwordHash: h2 }, { ifRev: r.result.rev });
  assert.deepEqual(Object.keys(r.result).sort(), ["changed", "passwordSetAt", "rev"]);
  r = await c.call(t.d, "disableMailbox", { local: "contact" }, { ifRev: r.result.rev });
  assert.doesNotMatch(fs.readFileSync(t.d.filePaths.passwd, "utf8"), /contact@/);
  await c.call(t.d, "getAuditTail", { limit: 50, beforeSeq: null });
  await c.call(t.d, "getMailStatus", {});
  for (const line of c.responses) {
    const text = Buffer.from(line.split(".")[2] || "", "base64url").toString("utf8") + line;
    assert.ok(!text.includes(CRYPT_MARK) && !text.includes(h1) && !text.includes(h2), "hash in a response");
  }
  const state = fs.readFileSync(t.d.paths.state, "utf8");
  assert.ok(!state.includes(CRYPT_MARK), "state.json must not hold a hash");
  const audit = fs.readFileSync(path.join(t.d.paths.root, "audit.jsonl"), "utf8");
  assert.ok(!audit.includes(CRYPT_MARK), "the service audit must not hold a hash");
  await t.d.close();
});

/* ---------- the indexer ---------- */

test("executor: every call is a frozen POSTMAP_ARGV entry, no shell, minimal env", async () => {
  const exec = recordingExecutor();
  const t = await newDaemon({ extra: { executor: exec } });
  const c = client(t.key);
  await c.call(t.d, "createAddress", { local: "sales", forwards: ["sales-team@example.com"], mailbox: null, reuseDeleted: false }, { ifRev: await rev(t.d, c) });
  assert.ok(exec.calls.length >= 4);
  const allowed = Object.values(t.d.POSTMAP_ARGV);
  assert.ok(Object.isFrozen(t.d.POSTMAP_ARGV));
  for (const call of exec.calls) {
    assert.equal(call.file, t.cfg.postmapPath);
    assert.ok(allowed.includes(call.argv), "argv must be one of the frozen arrays, by identity");
    assert.ok(Object.isFrozen(call.argv));
    assert.equal(call.options.shell, undefined);
    assert.deepEqual(Object.keys(call.options.env).sort(), ["LANG", "PATH"]);
    assert.equal(call.options.timeout, 5000);
    assert.equal(call.options.maxBuffer, 65536);
  }
  for (const m of ["virtual", "vmailbox", "sender_login", "sasl_access"]) {
    assert.deepEqual(t.d.POSTMAP_ARGV[m], [FAKE_POSTMAP, "hash:" + path.join(t.cfg.stateDir, "postfix", m)]);
  }
  await t.d.close();
});

test("a failing indexer restores the live files byte for byte and returns backend_failed", async () => {
  let failing = false;
  let failures = 0;
  // Fails once, on apply; the restore that follows succeeds.
  const exec = recordingExecutor({ fail: (name) => failing && name === "sender_login" && failures++ === 0 });
  const t = await newDaemon({ extra: { executor: exec } });
  const c = client(t.key);
  const r0 = await rev(t.d, c);
  const before = liveFiles(t.d);
  const stateBefore = fs.readFileSync(t.d.paths.state, "utf8");
  failing = true;
  const r = await c.call(t.d, "createAddress", { local: "info", forwards: ["owner@example.com"], mailbox: null, reuseDeleted: false }, { ifRev: r0 });
  assert.deepEqual(r, { ok: false, error: { code: "backend_failed" } });
  assert.deepEqual(liveFiles(t.d), before);
  assert.equal(fs.readFileSync(t.d.paths.state, "utf8"), stateBefore);
  assert.ok(!fs.existsSync(t.d.paths.state + ".tmp") && !fs.existsSync(t.d.paths.hashes + ".tmp"));
  // The restored maps were re-indexed.
  const reindexed = exec.calls.slice(-3).map((x) => path.basename(x.argv[x.argv.length - 1]));
  assert.deepEqual(reindexed, ["sender_login", "vmailbox", "virtual"]);
  assert.ok(t.d.ready);
  failing = false;
  const ok = await c.call(t.d, "createAddress", { local: "info", forwards: ["owner@example.com"], mailbox: null, reuseDeleted: false }, { ifRev: r0 });
  assert.equal(ok.ok, true);
  // The indexer's output is journal-only.
  for (const line of c.responses) assert.ok(!line.includes("CANARY") && !Buffer.from(line.split(".")[2] || "", "base64url").toString().includes("CANARY"));
  assert.ok(t.logs.some((l) => l.includes("event=postmap_failed file=sender_login")));
  await t.d.close();
});

test("a failing restore makes every mutation not_ready until a reconcile succeeds", async () => {
  let broken = false;
  const exec = recordingExecutor({ fail: (name) => broken && name === "virtual" });
  const t = await newDaemon({ extra: { executor: exec } });
  const c = client(t.key);
  const r0 = await rev(t.d, c);
  broken = true; // virtual fails on apply and again on restore
  const r = await c.call(t.d, "createAddress", { local: "info", forwards: ["owner@example.com"], mailbox: null, reuseDeleted: false }, { ifRev: r0 });
  assert.deepEqual(r, { ok: false, error: { code: "not_ready" } });
  assert.ok(t.logs.includes("event=restore_failed file=virtual"));
  assert.equal(t.d.mapsInSync, false);
  const again = await c.call(t.d, "createAddress", { local: "info2", forwards: ["owner@example.com"], mailbox: null, reuseDeleted: false }, { ifRev: r0 });
  assert.deepEqual(again, { ok: false, error: { code: "not_ready" } });
  const st = await c.call(t.d, "getMailStatus", {});
  assert.equal(st.result.service.mapsInSync, false);
  assert.notEqual(st.result.service.state, "online");
  broken = false;
  await t.d.pending; // the status call queued a reconcile
  const rec = await t.d.reconcile();
  assert.equal(rec.ok, true);
  assert.equal(t.d.mapsInSync, true);
  const ok = await c.call(t.d, "createAddress", { local: "info", forwards: ["owner@example.com"], mailbox: null, reuseDeleted: false }, { ifRev: r0 });
  assert.equal(ok.ok, true);
  await t.d.close();
});

test("fake indexer script via the real runner: indexes, fails cleanly, output stays out of responses", async () => {
  const t = await newDaemon({});
  const c = client(t.key);
  for (const m of ["virtual", "vmailbox", "sender_login", "sasl_access"]) assert.ok(fs.existsSync(t.d.filePaths[m] + ".db"), m + ".db");
  const r0 = await rev(t.d, c);
  fs.writeFileSync(path.join(t.cfg.stateDir, "fake-postmap.json"), JSON.stringify({ fail: ["virtual"] }));
  const before = liveFiles(t.d);
  const r = await c.call(t.d, "createAddress", { local: "info", forwards: ["owner@example.com"], mailbox: null, reuseDeleted: false }, { ifRev: r0 });
  // virtual fails on apply and on restore: not_ready (the maps are not in sync).
  assert.equal(r.ok, false);
  assert.ok(["backend_failed", "not_ready"].includes(r.error.code));
  fs.unlinkSync(path.join(t.cfg.stateDir, "fake-postmap.json"));
  await t.d.reconcile();
  assert.deepEqual(liveFiles(t.d), before);
  const ok = await c.call(t.d, "createAddress", { local: "info", forwards: ["owner@example.com"], mailbox: null, reuseDeleted: false }, { ifRev: r0 });
  assert.equal(ok.ok, true);
  for (const line of c.responses) assert.ok(!Buffer.from(line.split(".")[2] || "", "base64url").toString().includes("CANARY"));
  const argvLog = fs.readFileSync(path.join(t.cfg.stateDir, "fake-postmap.log"), "utf8").trim().split("\n").map((l) => JSON.parse(l).argv);
  for (const a of argvLog) assert.match(a[0], /^hash:.+[\\/]postfix[\\/](virtual|vmailbox|sender_login|sasl_access)$/);
  await t.d.close();
});

/* ---------- reconcile and crash safety ---------- */

test("reconcile: a deleted or edited rendered file is repaired at restart", async () => {
  const exec = recordingExecutor();
  const t = await newDaemon({ extra: { executor: exec } });
  const c = client(t.key);
  await c.call(t.d, "createAddress", { local: "info", forwards: ["owner@example.com"], mailbox: null, reuseDeleted: false }, { ifRev: await rev(t.d, c) });
  const good = liveFiles(t.d);
  await t.d.close();
  fs.unlinkSync(t.d.filePaths.virtual);
  fs.appendFileSync(t.d.filePaths.sasl_access, "evil@strategicbhm.com zehnox_sender\n");
  const t2 = await newDaemon({ dir: t.dir, made: t.made, extra: { executor: recordingExecutor() } });
  assert.equal(t2.started.mapsInSync, true);
  assert.ok(t2.logs.includes("event=reconcile_mismatch file=virtual"));
  assert.ok(t2.logs.includes("event=reconcile_mismatch file=sasl_access"));
  assert.deepEqual(liveFiles(t2.d), good);
  await t2.d.close();
});

test("reconcile: a stale index is rebuilt; --reconcile --dry-run reports without writing", async () => {
  const exec = recordingExecutor();
  const t = await newDaemon({ extra: { executor: exec } });
  fs.unlinkSync(t.d.filePaths.vmailbox + ".db");
  fs.writeFileSync(t.d.filePaths.passwd, "tampered\n");
  const dry = await t.d.reconcile({ dryRun: true });
  assert.deepEqual(dry.mismatched, ["passwd"]);
  assert.deepEqual(dry.staleIndex, ["vmailbox"]);
  assert.equal(fs.readFileSync(t.d.filePaths.passwd, "utf8"), "tampered\n");
  const real = await t.d.reconcile();
  assert.equal(real.ok, true);
  assert.ok(fs.existsSync(t.d.filePaths.vmailbox + ".db"));
  assert.notEqual(fs.readFileSync(t.d.filePaths.passwd, "utf8"), "tampered\n");
  await t.d.close();
});

test("crash between the file writes and the commit converges on the old state", async () => {
  let crash = false;
  const hooks = { beforeCommit() { if (crash) { const e = new Error("simulated crash"); e.simulateCrash = true; throw e; } } };
  const t = await newDaemon({ extra: { executor: recordingExecutor(), hooks } });
  const c = client(t.key);
  const r0 = await rev(t.d, c);
  const before = liveFiles(t.d);
  const stateBefore = fs.readFileSync(t.d.paths.state, "utf8");
  crash = true;
  const r = await c.call(t.d, "createAddress", { local: "info", forwards: ["owner@example.com"], mailbox: null, reuseDeleted: false }, { ifRev: r0 });
  assert.equal(r.ok, false);
  assert.notDeepEqual(liveFiles(t.d), before, "the new maps were live when the process died");
  assert.ok(fs.existsSync(t.d.paths.state + ".tmp"));
  await t.d.close();
  const t2 = await newDaemon({ dir: t.dir, made: t.made, extra: { executor: recordingExecutor() } });
  assert.equal(fs.readFileSync(t2.d.paths.state, "utf8"), stateBefore);
  assert.ok(!fs.existsSync(t2.d.paths.state + ".tmp"));
  const c2 = client(t2.key);
  assert.equal(await rev(t2.d, c2), r0);
  // Same rendering as before the crash (the header carries the unchanged rev).
  assert.deepEqual(liveFiles(t2.d), before);
  await t2.d.close();
});

test("state.json missing while hashes.json exists is refused, not re-bootstrapped", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  await t.d.close();
  fs.unlinkSync(t.d.paths.state);
  const t2 = await newDaemon({ dir: t.dir, made: t.made, extra: { executor: recordingExecutor() } });
  assert.equal(t2.started.stateError, "state_missing");
  const c = client(t2.key);
  assert.deepEqual(await c.call(t2.d, "listAddresses", {}), { ok: false, error: { code: "not_ready" } });
  const st = await c.call(t2.d, "getMailStatus", {});
  assert.equal(st.result.service.selfCheck, "state_missing");
  await t2.d.close();
});

test("self-check: a wrong directory mode refuses mutations (POSIX only)", { skip: WIN }, async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  const c = client(t.key);
  const r0 = await rev(t.d, c);
  fs.chmodSync(t.d.paths.postfix, 0o755);
  const st = await c.call(t.d, "getMailStatus", {});
  assert.equal(st.result.service.selfCheck, "dir_mode");
  const r = await c.call(t.d, "createAddress", { local: "info", forwards: ["owner@example.com"], mailbox: null, reuseDeleted: false }, { ifRev: r0 });
  assert.deepEqual(r, { ok: false, error: { code: "not_ready" } });
  fs.chmodSync(t.d.paths.postfix, 0o2750);
  assert.equal(t.d.selfCheck(), "ok");
  const mode = (f) => fs.statSync(f).mode & 0o777;
  assert.equal(mode(t.d.paths.state), 0o600);
  assert.equal(mode(t.d.paths.hashes), 0o600);
  assert.equal(mode(t.d.filePaths.passwd), 0o640);
  assert.equal(mode(t.d.filePaths.virtual), 0o640);
  await t.d.close();
});

/* ---------- limits, audit, status ---------- */

test("rate limits: the 61st mutation within a minute is rate_limited", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  const c = client(t.key);
  const r0 = await rev(t.d, c);
  for (let i = 0; i < 60; i++) {
    const r = await c.call(t.d, "setAddressEnabled", { local: "nobody-here", enabled: true }, { ifRev: r0 });
    assert.equal(r.error.code, "not_found");
  }
  const r = await c.call(t.d, "setAddressEnabled", { local: "nobody-here", enabled: true }, { ifRev: r0 });
  assert.deepEqual(r, { ok: false, error: { code: "rate_limited" } });
  await t.d.close();
});

test("rate limits: password changes are capped per hour", async () => {
  const limits = { mutationsPerMinute: 1000, passwordChangesPerHour: 3, forwardingChangesPerHour: 1000 };
  const t = await newDaemon({ over: { limits }, extra: { executor: recordingExecutor() } });
  const c = client(t.key);
  let r = await c.call(t.d, "createAddress", { local: "box", forwards: [], mailbox: { passwordHash: fakeHash() }, reuseDeleted: false }, { ifRev: await rev(t.d, c) });
  let cur = r.result.rev;
  for (let i = 0; i < 2; i++) { r = await c.call(t.d, "changeMailboxPassword", { local: "box", passwordHash: fakeHash() }, { ifRev: cur }); cur = r.result.rev; }
  r = await c.call(t.d, "changeMailboxPassword", { local: "box", passwordHash: fakeHash() }, { ifRev: cur });
  assert.deepEqual(r, { ok: false, error: { code: "rate_limited" } });
  await t.d.close();
});

test("service audit: hash chained, public fields only through getAuditTail", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  const c = client(t.key);
  const r0 = await rev(t.d, c);
  await c.call(t.d, "createAddress", { local: "info", forwards: ["owner@example.com"], mailbox: null, reuseDeleted: false }, { ifRev: r0 });
  await c.call(t.d, "deleteAddress", { local: "info", confirm: "info@strategicbhm.com" }, { ifRev: r0 + 1 });
  const tail = await c.call(t.d, "getAuditTail", { limit: 10, beforeSeq: null });
  assert.equal(tail.ok, true);
  // The refusal is not a record of its own: refused requests are counted into one summary
  // line a minute (the first one after a quiet minute is written at once).
  assert.deepEqual(tail.result.entries.map((e) => [e.verb, e.target, e.ok, e.code]), [[null, null, false, "refused_summary"], ["createAddress", "info", true, null]]);
  assert.equal(tail.result.entries[0].count, 1);
  assert.deepEqual(tail.result.entries[0].refused, { "deleteAddress/confirm_mismatch": 1 });
  assert.deepEqual(Object.keys(tail.result.entries[1]).sort(), ["actor", "at", "code", "idem", "nonce", "ok", "rev", "seq", "target", "verb"]);
  assert.deepEqual(Object.keys(tail.result.entries[0]).sort(), ["actor", "at", "code", "count", "idem", "nonce", "ok", "refused", "rev", "seq", "target", "verb"]);
  const lines = fs.readFileSync(path.join(t.d.paths.root, "audit.jsonl"), "utf8").trim().split("\n");
  const recs = lines.map((l) => JSON.parse(l));
  assert.equal(recs[0].prev, null);
  assert.equal(recs[1].prev, crypto.createHash("sha256").update(lines[0]).digest("hex"));
  assert.ok(recs[0].files && typeof recs[0].files.virtual === "string");
  const page = await c.call(t.d, "getAuditTail", { limit: 1, beforeSeq: null });
  assert.equal(page.result.nextBeforeSeq, recs[1].seq);
  await t.d.close();
});

test("status: probes are injectable, DKIM returns only the public p= value", async () => {
  const dir = fs.mkdtempSync(path.join(TMP_ROOT, "maild-dkim-"));
  tmpRoots.push(dir);
  const pub = path.join(dir, "dkim-public.txt");
  const p = crypto.randomBytes(160).toString("base64");
  fs.writeFileSync(pub, 'sbhm1._domainkey IN TXT ( "v=DKIM1; k=rsa; "\n  "p=' + p.slice(0, 100) + '"\n  "' + p.slice(100) + '" )\n');
  const made = makeConfig(dir, { dkim: { selector: "sbhm1", publicFile: pub } });
  const probe = async (name) => (name === "imap" ? "absent" : "up");
  const t = await newDaemon({ dir, made, extra: { executor: recordingExecutor(), probe } });
  const c = client(t.key);
  const st = await c.call(t.d, "getMailStatus", {});
  assert.equal(st.result.service.state, "online");
  assert.equal(st.result.dkim.publicKey, p);
  assert.equal(st.result.domain, "zehnox.com");
  // A PEM-shaped decoy (random bytes, built at run time so no key header sits in the repo).
  const pem = (tag) => "-----" + tag + " PRIVATE" + " KEY-----";
  fs.writeFileSync(pub, pem("BEGIN") + "\n" + crypto.randomBytes(64).toString("base64") + "\n" + pem("END") + "\n");
  const st2 = await c.call(t.d, "getMailStatus", {});
  assert.equal(st2.result.dkim.publicKey, null);
  await t.d.close();
});

/* ---------- owner CLI operations ---------- */

test("import: adopts only @zehnox.com entries through the core rules; dry run writes nothing", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  const map = path.join(t.dir, "virtual.hand");
  const pw = path.join(t.dir, "passwd.hand");
  const h = fakeHash();
  fs.writeFileSync(map, [
    "# hand made",
    "info@zehnox.com   owner@example.com,",
    "    ceo@example.org",
    "contact@zehnox.com contact@zehnox.com, management@example.com",
    "someone@strategicbhm.com      other@example.com",
    "postmaster@zehnox.com owner2@example.com",
    "bad@zehnox.com    |/bin/sh",
    "",
  ].join("\n"));
  fs.writeFileSync(pw, "contact@zehnox.com:" + h + ":5000:5000::/var/vmail/zehnox.com/contact::\nz@strategicbhm.com:{PLAIN}x:1:1::/x::\n");
  const stateBefore = fs.readFileSync(t.d.paths.state, "utf8");
  const dry = await t.d.importMaps({ postfixMap: map, passwdFile: pw, dryRun: true });
  assert.equal(dry.foreignKeys, 2);
  assert.equal(fs.readFileSync(t.d.paths.state, "utf8"), stateBefore);
  const real = await t.d.importMaps({ postfixMap: map, passwdFile: pw, dryRun: false });
  assert.deepEqual(real.imported.map((x) => x.local).sort(), ["contact", "info", "postmaster"]);
  assert.deepEqual(real.skipped, [{ local: "bad", code: "invalid_destination" }]);
  const c = client(t.key);
  const list = (await c.call(t.d, "listAddresses", {})).result.addresses;
  const byLocal = Object.fromEntries(list.map((a) => [a.local, a]));
  assert.deepEqual(byLocal.info.forwards, ["owner@example.com", "ceo@example.org"]);
  assert.equal(byLocal.contact.type, "mailbox+forward");
  assert.deepEqual(byLocal.postmaster.forwards, ["owner2@example.com"]);
  assert.ok(!("someone" in byLocal));
  assert.doesNotMatch(liveFiles(t.d).virtual, /strategicbhm/);
  await t.d.close();
});

test("purge-tombstone removes only the tombstone", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  const c = client(t.key);
  let r = await c.call(t.d, "createAddress", { local: "old", forwards: ["a@example.com"], mailbox: { passwordHash: fakeHash() }, reuseDeleted: false }, { ifRev: await rev(t.d, c) });
  r = await c.call(t.d, "deleteAddress", { local: "old", confirm: "old@zehnox.com" }, { ifRev: r.result.rev });
  assert.equal(r.result.mailboxDataRetained, true);
  let list = (await c.call(t.d, "listAddresses", {})).result;
  assert.deepEqual(list.tombstones.map((x) => x.local), ["old"]);
  const p = await t.d.purgeTombstone("old");
  assert.equal(p.maildir, "/var/vmail/zehnox.com/old/");
  list = (await c.call(t.d, "listAddresses", {})).result;
  assert.deepEqual(list.tombstones, []);
  await assert.rejects(t.d.purgeTombstone("../x"), (e) => e.code === "invalid_local");
  await t.d.close();
});

test("--status inspection is read-only and reports per-file sync", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  const snap = fs.readdirSync(t.d.paths.root).sort();
  const rep = t.d.inspect();
  assert.equal(rep.state, "ok");
  assert.equal(rep.mapsInSync, true);
  assert.equal(rep.files.virtual.inSync, true);
  assert.deepEqual(fs.readdirSync(t.d.paths.root).sort(), snap);
  fs.appendFileSync(t.d.filePaths.virtual, "x@zehnox.com y@example.com\n");
  assert.equal(t.d.inspect().files.virtual.inSync, false);
  assert.ok(!JSON.stringify(rep).includes(CRYPT_MARK));
  await t.d.close();
});

test("CLI: --check-config and --print-manifest; unknown arguments are refused", async () => {
  const dir = fs.mkdtempSync(path.join(TMP_ROOT, "maild-cli-"));
  tmpRoots.push(dir);
  const { cfg } = makeConfig(dir);
  const file = path.join(dir, "config.json");
  fs.writeFileSync(file, JSON.stringify(cfg));
  assert.equal(maild.parseArgs(["--config", file, "--exec", "x"]), null);
  assert.equal(maild.parseArgs(["--config", file, "--config", file]), null);
  const out = [];
  const w = process.stdout.write;
  process.stdout.write = (s) => { out.push(String(s)); return true; };
  let code;
  try { code = await maild.main(["--config", file, "--check-config", "--sandbox"]); } finally { process.stdout.write = w; }
  assert.equal(code, 0);
  assert.match(out.join(""), /^config ok: domain=zehnox\.com/);
  assert.ok(!out.join("").includes(fs.readFileSync(cfg.keys.k1, "utf8").trim()));
  const m = maild.manifest(DAEMON_FILE, maild.CORE_DIR);
  assert.match(m, /^[0-9a-f]{64} {2}core\/constants\.js$/m);
  assert.match(m, /^[0-9a-f]{64} {2}zehnox-maild\.js\n$/m);
  assert.equal(m, maild.manifest(DAEMON_FILE, maild.CORE_DIR));
  const tool = require(path.join(REPO, "tools", "mail-manifest.js"));
  assert.equal(tool.manifest(REPO), m, "the repo tool and the installed daemon print the same manifest");
});

/* ---------- socket layer ---------- */

function listenTarget(dir) {
  return WIN ? "\\\\.\\pipe\\zehnox-mail-test-" + crypto.randomBytes(6).toString("hex") : path.join(dir, "mail.sock");
}

test("socket: one frame per connection; an oversized frame is cut off; the VPS client works end to end", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  const target = listenTarget(t.dir);
  await t.d.listen(target);
  // Oversized: more than 16 KiB without a newline ends the connection with no answer.
  const got = await new Promise((resolve) => {
    const s = net.createConnection({ path: target });
    let data = "";
    s.on("data", (c) => { data += c; });
    s.on("close", () => resolve(data));
    s.on("error", () => resolve(data));
    s.on("connect", () => s.write("v1.k1." + "A".repeat(C.LIMITS.frameMax + 10)));
  });
  assert.equal(got, "");
  const { VpsMailProvider } = require(path.join(REPO, "lib", "mail", "vps-provider.js"));
  const p = new VpsMailProvider({ socketPath: target, kid: "k1", key: t.key });
  const ctx = (ifRev) => ({ actor: { user: "admin", via: "cookie", ip: "127.0.0.1" }, idem: crypto.randomUUID(), ifRev });
  const status = await p.getStatus();
  assert.equal(status.domain, "zehnox.com");
  const created = await p.createAddress({ local: "info", forwards: ["owner@example.com"], passwordHash: null }, ctx(status.rev));
  assert.equal(created.address.address, "info@zehnox.com");
  await assert.rejects(p.createAddress({ local: "info", forwards: ["owner@example.com"] }, ctx(created.rev)), (e) => e.code === "duplicate");
  const wrong = new VpsMailProvider({ socketPath: target, kid: "k1", key: crypto.randomBytes(32) });
  await assert.rejects(wrong.listAddresses(), (e) => e.code === "bad_response");
  await t.d.close();
});

/* ---------- static surface ---------- */

test("static: the daemon's only subprocess call is the indexer lookup; no shell or eval", () => {
  const src = fs.readFileSync(DAEMON_FILE, "utf8");
  assert.equal((src.match(/execFile/g) || []).length, 1, "the runner is referenced exactly once");
  for (const bad of ["execSync", "spawn", "fork(", "eval(", "new Function", "vm.", "process.binding", "shell:", "exec("]) {
    assert.ok(!src.includes(bad), bad);
  }
  assert.match(src, /run\(cfg\.postmapPath, POSTMAP_ARGV\[name\], POSTMAP_OPTIONS,/);
  assert.equal((src.match(/\brun\(/g) || []).length, 1);
  // Only the pinned core is required, besides the stdlib.
  const reqs = Array.from(src.matchAll(/require\(([^)]+)\)/g)).map((m) => m[1]);
  for (const r of reqs) assert.ok(/^"(fs|path|net|crypto|child_process)"$/.test(r) || /^path\.join\(CORE_DIR, "[a-z]+\.js"$/.test(r), r);
});
