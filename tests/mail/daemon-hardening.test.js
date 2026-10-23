"use strict";
/* zehnox-maild hardening (review fixes), as regression tests. Each test is a scenario a
   key holder (a compromised web container) or any local user who can reach the socket
   could run, and checks the daemon now resists it:

   - a flood of refused mutations cannot push applied changes out of the service audit,
     and rotated files holding applied changes are never deleted;
   - a retry of an applied change returns its original success even at the rate limit;
   - getMailStatus cannot turn into a flood of connections to the shared MTA;
   - idle connections cannot hold every slot for the full read timeout;
   - dovecot/passwd.prev never keeps a replaced or deleted mailbox's hash;
   - forwards cannot target the mail host, a denied co-hosted domain, or use a "%" route;
   - a huge tombstone list cannot make listAddresses fail;
   - a password cannot be planted while the mailbox gate is closed.

   Sandbox mode only (temporary state directory, keys generated now, a recording executor
   or the fake postmap), no Postfix, Dovecot, systemd, real mail server or system path. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const net = require("net");
const path = require("path");
const crypto = require("crypto");
const { fakeHash, sleep } = require("./helpers/common.js");
const { maild, protocol, recordingExecutor, makeConfig, newDaemon, client, currentRev, listenTarget } = require("./helpers/daemon.js");
const { mkTmp } = require("./helpers/common.js");

const createArgs = (local, forwards, hash) => ({ local, forwards: forwards || [], mailbox: hash ? { passwordHash: hash } : null, reuseDeleted: false });
const auditLines = (d) => {
  const out = [];
  for (const n of fs.readdirSync(d.paths.root).filter((x) => /^audit(-\d{12}(-\d+)?)?\.jsonl$/.test(x))) {
    for (const l of fs.readFileSync(path.join(d.paths.root, n), "utf8").split("\n").filter(Boolean)) out.push(JSON.parse(l));
  }
  return out.sort((a, b) => a.seq - b.seq);
};
const rotatedFiles = (d) => fs.readdirSync(d.paths.root).filter((x) => /^audit-\d{12}(-\d+)?\.jsonl$/.test(x));

/* ---------- the service audit survives a flood of refusals ---------- */

test("a flood of refused mutations is summarized, and the attacker's applied change stays in the audit", async () => {
  let now = Date.now(); // the helpers sign some reads with the real clock
  // A small rotation size: without the fix, a few hundred refusals would rotate the audit
  // more than AUDIT_KEEP times and delete the file holding the applied change.
  const t = await newDaemon({ extra: { executor: recordingExecutor(), now: () => now, auditMaxBytes: 2048 } });
  try {
    const c = client(t.key);
    const call = (verb, args, extra) => { now += 7; return c.call(t.d, verb, args, Object.assign({ nowMs: now }, extra)); };
    const r0 = await currentRev(t.d, c);
    const evil = await call("setForwarding", { local: "postmaster", forwards: ["attacker@example.org"] }, { ifRev: r0 });
    assert.equal(evil.ok, true);
    const evilSeq = auditLines(t.d).find((r) => r.verb === "setForwarding" && r.ok === true).seq;
    const codes = {};
    for (let i = 0; i < 3000; i++) {
      // A stale rev, like the review's script: conflict_rev first, rate_limited once the
      // forwarding budget (20 an hour) is spent.
      const r = await call("setForwarding", { local: "postmaster", forwards: ["x" + i + "@example.org"] }, { ifRev: r0 });
      codes[r.error.code] = (codes[r.error.code] || 0) + 1;
    }
    assert.ok(codes.rate_limited > 2000 && codes.conflict_rev > 0, JSON.stringify(codes));
    await t.d.close(); // flushes the pending summary
    const recs = auditLines(t.d);
    assert.ok(recs.some((r) => r.seq === evilSeq && r.verb === "setForwarding" && r.ok === true), "the applied change is still on disk");
    const summaries = recs.filter((r) => r.code === "refused_summary");
    assert.ok(summaries.length >= 1 && summaries.length <= 3, "one line a minute (21 simulated seconds): " + summaries.length);
    assert.equal(summaries.reduce((n, r) => n + r.count, 0), 3000, "every refusal is counted");
    assert.equal(recs.filter((r) => r.ok === false && r.code !== "refused_summary").length, 0, "no per-refusal records");
    assert.ok(rotatedFiles(t.d).length <= 1, "3000 refusals barely grow the audit");
    assert.ok(t.logs.some((l) => l.startsWith("event=mutations_refused count=")));
    assert.ok(!t.logs.some((l) => l.startsWith("event=mutation ") && l.includes("ok=false")), "the journal is summarized too");
    // The hash chain runs through the summary lines like any other record.
    const raw = [];
    for (const n of fs.readdirSync(t.d.paths.root).filter((x) => /^audit(-\d{12}(-\d+)?)?\.jsonl$/.test(x))) {
      raw.push(...fs.readFileSync(path.join(t.d.paths.root, n), "utf8").split("\n").filter(Boolean));
    }
    raw.sort((a, b) => JSON.parse(a).seq - JSON.parse(b).seq);
    for (let i = 1; i < raw.length; i++) {
      assert.equal(JSON.parse(raw[i]).seq, JSON.parse(raw[i - 1]).seq + 1);
      assert.equal(JSON.parse(raw[i]).prev, crypto.createHash("sha256").update(raw[i - 1]).digest("hex"), "chain at " + i);
    }
  } finally { await t.d.close(); }
});

test("rotation never deletes a file holding an applied change; summary-only files age out; fast rotation is reported", async () => {
  let now = Date.now(); // the helpers sign some reads with the real clock
  const t = await newDaemon({ over: { limits: { mutationsPerMinute: 10000, passwordChangesPerHour: 20, forwardingChangesPerHour: 10000 } }, extra: { executor: recordingExecutor(), now: () => now, auditMaxBytes: 700 } });
  try {
    const c = client(t.key);
    const call = (verb, args, extra) => c.call(t.d, verb, args, Object.assign({ nowMs: now }, extra));
    let rev = await currentRev(t.d, c);
    // 30 applied changes, a couple per 700-byte file: many more rotations than AUDIT_KEEP.
    for (let i = 0; i < 30; i++) {
      now += 1000;
      const r = await call("setForwarding", { local: "abuse", forwards: ["owner" + i + "@example.com"] }, { ifRev: rev });
      assert.equal(r.ok, true);
      rev = r.result.rev;
    }
    const applied = auditLines(t.d).filter((r) => r.ok === true).length;
    assert.equal(applied, 30, "all 30 applied changes are on disk");
    assert.ok(rotatedFiles(t.d).length > maild.LIMITS.auditKeep, "more files than AUDIT_KEEP were kept");
    assert.ok(t.logs.some((l) => l.startsWith("event=audit_rotation_pressure")), "rotations minutes apart are reported");
    // Then 90 minutes of refusals: one summary line a minute, files with only those age out.
    const withChanges = rotatedFiles(t.d).length;
    for (let m = 0; m < 90; m++) {
      now += 61000;
      await call("setForwarding", { local: "abuse", forwards: ["z@example.com"] }, { ifRev: 0 });
    }
    const written = t.logs.filter((l) => l.startsWith("event=mutations_refused count=1")).length;
    assert.equal(written, 90, "a summary line each minute");
    const onDisk = auditLines(t.d).filter((r) => r.code === "refused_summary").length;
    assert.ok(onDisk < written, "the oldest summary-only files were deleted: " + onDisk + " of " + written + " left");
    assert.ok(rotatedFiles(t.d).length <= withChanges + maild.LIMITS.auditKeep + 1, "summary-only files age out: " + rotatedFiles(t.d).length);
    assert.equal(auditLines(t.d).filter((r) => r.ok === true).length, 30, "and the applied changes are all still there");
    // getAuditTail pages back to the oldest applied change.
    let before = null;
    const seen = [];
    for (let i = 0; i < 20; i++) {
      const page = await call("getAuditTail", { limit: 200, beforeSeq: before });
      seen.push(...page.result.entries);
      if (page.result.nextBeforeSeq === null) break;
      before = page.result.nextBeforeSeq;
    }
    assert.equal(seen.filter((e) => e.ok === true && e.verb === "setForwarding").length, 30);
  } finally { await t.d.close(); }
});

/* ---------- idempotency before the rate limit ---------- */

test("a retry of an applied change returns its original success at the rate limit and is not charged", async () => {
  const t = await newDaemon({ over: { limits: { mutationsPerMinute: 60, passwordChangesPerHour: 20, forwardingChangesPerHour: 1 } }, extra: { executor: recordingExecutor() } });
  try {
    const c = client(t.key);
    const r0 = await currentRev(t.d, c);
    const idem = crypto.randomUUID();
    const args = { local: "postmaster", forwards: ["owner@example.org"] };
    const first = await c.call(t.d, "setForwarding", args, { ifRev: r0, idem });
    assert.equal(first.ok, true);
    // The web retried after a timeout (same idem, fresh nonce): the stored success, not rate_limited.
    assert.deepEqual(await c.call(t.d, "setForwarding", args, { ifRev: r0, idem }), first);
    assert.deepEqual(await c.call(t.d, "setForwarding", args, { ifRev: r0, idem }), first);
    // A different change under the same key is still a mismatch, and a new change is limited.
    assert.deepEqual(await c.call(t.d, "setForwarding", { local: "postmaster", forwards: ["b@example.org"] }, { ifRev: r0 + 1, idem }), { ok: false, error: { code: "idempotency_mismatch" } });
    assert.deepEqual(await c.call(t.d, "setForwarding", { local: "abuse", forwards: ["b@example.org"] }, { ifRev: r0 + 1 }), { ok: false, error: { code: "rate_limited" } });
  } finally { await t.d.close(); }
});

/* ---------- status probes are cached ---------- */

test("getMailStatus probes the MTA at most once per cache period, one round at a time", async () => {
  let now = Date.now(); // the helpers sign some reads with the real clock
  const probes = [];
  const probe = async (name, port) => { probes.push(name + ":" + port); await sleep(5); return "up"; };
  const t = await newDaemon({ extra: { executor: recordingExecutor(), now: () => now, probe } });
  try {
    const c = client(t.key);
    const all = await Promise.all(Array.from({ length: 50 }, () => c.call(t.d, "getMailStatus", {}, { nowMs: now })));
    for (const r of all) assert.equal(r.result.service.smtp, "up");
    assert.equal(probes.length, 3, "50 concurrent calls share one round: " + probes.length);
    for (let i = 0; i < 20; i++) await c.call(t.d, "getMailStatus", {}, { nowMs: now });
    assert.equal(probes.length, 3, "served from the cache");
    now += maild.LIMITS.probeCacheMs + 1;
    await c.call(t.d, "getMailStatus", {}, { nowMs: now });
    assert.equal(probes.length, 6, "a new round once the cache is stale");
  } finally { await t.d.close(); }
});

/* ---------- idle connections ---------- */

test("idle connections are closed after the first-byte timeout, so they cannot keep the daemon unreachable", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  const target = listenTarget(t.dir);
  await t.d.listen(target);
  const idle = [];
  try {
    const started = Date.now();
    const closed = [];
    for (let i = 0; i < maild.LIMITS.maxConnections; i++) {
      await new Promise((resolve) => {
        const s = net.createConnection({ path: target });
        s.on("error", () => {});
        s.on("close", () => closed.push(Date.now() - started));
        s.on("connect", resolve);
        idle.push(s);
      });
    }
    // Every slot is held by a silent peer. Within about FIRST_BYTE_MS they are all closed.
    const deadline = Date.now() + maild.LIMITS.readTimeoutMs - 500;
    while (closed.length < idle.length && Date.now() < deadline) await sleep(25);
    assert.equal(closed.length, idle.length, "all idle connections were closed before the read timeout");
    assert.ok(Math.max(...closed) < maild.LIMITS.readTimeoutMs, "closed at " + Math.max(...closed) + " ms");
    // A signed request is answered right away.
    const p = protocol.buildRequest({ verb: "getMailStatus", args: {}, actor: { user: "admin", ip: "127.0.0.1" }, nowMs: Date.now() });
    const got = await new Promise((resolve) => {
      const s = net.createConnection({ path: target });
      let buf = "";
      s.on("data", (d) => { buf += d; });
      s.on("close", () => resolve(buf));
      s.on("error", () => resolve(buf));
      s.on("connect", () => s.write(protocol.encodeFrame("req", "k1", t.key, p)));
    });
    assert.equal(protocol.verifyResponse(got, "k1", t.key, p.nonce).ok, true);
    assert.ok(maild.LIMITS.maxConnections >= 32);
  } finally {
    for (const s of idle) s.destroy();
    await t.d.close();
  }
});

/* ---------- passwd.prev ---------- */

test("dovecot/passwd.prev never keeps a replaced or deleted mailbox's hash", async () => {
  let failNext = false;
  const exec = recordingExecutor({ fail: () => { if (failNext) { failNext = false; return true; } return false; } });
  const t = await newDaemon({ extra: { executor: exec } });
  try {
    const c = client(t.key);
    const prev = t.d.filePaths.passwd + ".prev";
    const h1 = fakeHash(50000);
    const h2 = fakeHash(50000);
    let r = await c.call(t.d, "createAddress", createArgs("contact", ["m@example.com"], h1), { ifRev: await currentRev(t.d, c) });
    assert.equal(r.ok, true);
    assert.equal(fs.existsSync(prev), false, "no rollback copy after a create");
    r = await c.call(t.d, "changeMailboxPassword", { local: "contact", passwordHash: h2 }, { ifRev: r.result.rev });
    assert.equal(r.ok, true);
    assert.equal(fs.existsSync(prev), false, "no rollback copy after a password change");
    const dovecotDir = path.dirname(t.d.filePaths.passwd);
    for (const n of fs.readdirSync(dovecotDir)) assert.ok(!fs.readFileSync(path.join(dovecotDir, n), "utf8").includes(h1), n + " holds the old hash");
    // A failed change is restored, and its rollback copy is removed too.
    failNext = true;
    const h3 = fakeHash(50000);
    const bad = await c.call(t.d, "createAddress", createArgs("sales", ["m@example.com"], h3), { ifRev: r.result.rev });
    assert.deepEqual(bad, { ok: false, error: { code: "backend_failed" } });
    assert.equal(fs.existsSync(prev), false, "no rollback copy after a restore");
    r = await c.call(t.d, "deleteAddress", { local: "contact", confirm: "contact@zehnox.com" }, { ifRev: r.result.rev });
    assert.equal(r.ok, true);
    assert.equal(fs.existsSync(prev), false, "no rollback copy after a delete");
    for (const n of fs.readdirSync(dovecotDir)) assert.ok(!fs.readFileSync(path.join(dovecotDir, n), "utf8").includes(h2), n + " holds the deleted mailbox's hash");
    // A leftover from a crash is removed at the next start.
    await t.d.close();
    fs.writeFileSync(prev, "contact@zehnox.com:" + h2 + ":5000:5000::/var/vmail/zehnox.com/contact::\n");
    const t2 = await newDaemon({ made: t.made, dir: t.dir, extra: { executor: recordingExecutor() } });
    assert.equal(fs.existsSync(prev), false, "removed at start");
    await t2.d.close();
  } finally { await t.d.close(); }
});

/* ---------- forwarding destinations ---------- */

test("forwards to the mail host, a denied co-hosted domain or a percent route are refused by the daemon", async () => {
  const t = await newDaemon({ over: { forwardDenyDomains: ["cohosted.example"] }, extra: { executor: recordingExecutor() } });
  try {
    const c = client(t.key);
    const r0 = await currentRev(t.d, c);
    // cfg.hostname is mail.example.net in the test config.
    for (const d of ["root@mail.example.net", "a@sub.mail.example.net", "postmaster@cohosted.example", "x%y.example@mail.example.org"]) {
      assert.deepEqual(await c.call(t.d, "createAddress", createArgs("relay", [d]), { ifRev: r0 }), { ok: false, error: { code: "invalid_destination" } }, d);
      assert.deepEqual(await c.call(t.d, "setForwarding", { local: "postmaster", forwards: [d] }, { ifRev: r0 }), { ok: false, error: { code: "invalid_destination" } }, d);
    }
    assert.equal(await currentRev(t.d, c), r0, "nothing applied");
    assert.equal((await c.call(t.d, "createAddress", createArgs("relay", ["someone@example.org"]), { ifRev: r0 })).ok, true);
    assert.ok(!fs.readFileSync(t.d.filePaths.virtual, "utf8").includes("%"));
    // The config refuses denying the pinned domain, a parent of it, or a malformed name.
    const { cfg } = makeConfig(mkTmp("deny"));
    for (const bad of [["zehnox.com"], ["com"], ["Bad_Name"], ["a"]]) {
      assert.throws(() => maild.validateConfig(Object.assign({}, cfg, { forwardDenyDomains: bad }), { sandbox: true }), maild.ConfigError, JSON.stringify(bad));
    }
    assert.deepEqual(maild.validateConfig(Object.assign({}, cfg, { forwardDenyDomains: ["cohosted.example"] }), { sandbox: true }).forwardDeny, ["mail.example.net", "cohosted.example"]);
  } finally { await t.d.close(); }
});

/* ---------- tombstones ---------- */

test("a state with a huge tombstone list still answers listAddresses (newest markers only)", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  await t.d.close();
  // As if 1500 create/delete cycles had run before the cap existed.
  const s = JSON.parse(fs.readFileSync(t.d.paths.state, "utf8"));
  for (let i = 0; i < 1500; i++) s.tombstones[("t" + i).padEnd(64, "x")] = { deletedAt: new Date(Date.UTC(2026, 0, 1) + i * 1000).toISOString(), hadMailbox: false };
  fs.writeFileSync(t.d.paths.state, JSON.stringify(s));
  const t2 = await newDaemon({ made: t.made, dir: t.dir, extra: { executor: recordingExecutor() } });
  try {
    const r = await client(t.key).call(t2.d, "listAddresses", {});
    assert.equal(r.ok, true, JSON.stringify(r.error || {}));
    assert.equal(r.result.tombstones.length, 200);
    // The next delete trims the stored list back to the cap.
    const c = client(t.key);
    const rev = r.result.rev;
    const a = await c.call(t2.d, "createAddress", createArgs("gone", ["a@example.com"]), { ifRev: rev });
    const d = await c.call(t2.d, "deleteAddress", { local: "gone", confirm: "gone@zehnox.com" }, { ifRev: a.result.rev });
    assert.equal(d.ok, true);
    assert.equal(Object.keys(JSON.parse(fs.readFileSync(t2.d.paths.state, "utf8")).tombstones).length, 200);
  } finally { await t2.d.close(); }
});

/* ---------- the mailbox gate covers password changes ---------- */

test("with the mailbox gate closed, changeMailboxPassword is refused and passwd is untouched", async () => {
  const t = await newDaemon({ extra: { executor: recordingExecutor() } });
  const c = client(t.key);
  const h1 = fakeHash(50000);
  const r = await c.call(t.d, "createAddress", createArgs("contact", ["m@example.com"], h1), { ifRev: await currentRev(t.d, c) });
  assert.equal(r.ok, true);
  await t.d.close();
  // Phase B rollback: the owner closes the gate and restarts the daemon.
  const closedCfg = Object.assign({}, t.made.cfg, { mailboxes: Object.assign({}, t.made.cfg.mailboxes, { gate: { senderLoginEnforced: true, outboundRateLimited: false } }) });
  const t2 = await newDaemon({ made: { cfg: closedCfg, key: t.key }, dir: t.dir, extra: { executor: recordingExecutor() } });
  try {
    const passwdBefore = fs.readFileSync(t2.d.filePaths.passwd, "utf8");
    const hashesBefore = fs.readFileSync(t2.d.paths.hashes, "utf8");
    const planted = fakeHash(50000);
    assert.deepEqual(await c.call(t2.d, "changeMailboxPassword", { local: "contact", passwordHash: planted }, { ifRev: r.result.rev }), { ok: false, error: { code: "capability_missing" } });
    assert.equal(fs.readFileSync(t2.d.filePaths.passwd, "utf8"), passwdBefore);
    assert.equal(fs.readFileSync(t2.d.paths.hashes, "utf8"), hashesBefore);
    assert.ok(!hashesBefore.includes(planted));
  } finally { await t2.d.close(); }
});
