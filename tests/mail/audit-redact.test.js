"use strict";
/* Audit logs and redaction (lib/mail/audit.js, redact.js), DESIGN.md sections 13.5 and 14.
   The audit is hash-chained so an edited, deleted or truncated line is detectable; every
   detail is allowlisted per action and then redacted, so a password or hash can never be
   written to it even by a caller that passes the wrong object. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { LIB, mkTmp, canary, forms, authPlain, fakeHash, CRYPT6 } = require("./helpers/common.js");

const { createChainLog, createAppAudit, sanitizeDetail, ACTIONS } = require(path.join(LIB, "audit.js"));
const { redactDeep, scrubString, MASK } = require(path.join(LIB, "redact.js"));

const actor = { user: "admin", via: "cookie", ip: "203.0.113.9" };

test("chain log: append, tail newest-first, verify intact", async () => {
  const dir = mkTmp("audit");
  const log = createChainLog({ file: path.join(dir, "a.jsonl") });
  for (let i = 0; i < 5; i++) await log.append((seq, prev) => ({ seq, n: i, prev }));
  const t = await log.tail({ limit: 3 });
  assert.deepEqual(t.entries.map((e) => e.seq), [5, 4, 3]);
  assert.equal(t.next, 3);
  const older = await log.tail({ limit: 3, before: t.next });
  assert.deepEqual(older.entries.map((e) => e.seq), [2, 1]);
  assert.deepEqual(await log.verify(), { ok: true, firstBrokenSeq: null, count: 5 });
  // A fresh instance on the same file continues the chain.
  const again = createChainLog({ file: path.join(dir, "a.jsonl") });
  const rec = await again.append((seq, prev) => ({ seq, prev }));
  assert.equal(rec.seq, 6);
  assert.equal((await again.verify()).ok, true);
});

test("chain log: an edited, deleted or truncated line is found at the right seq", async () => {
  const dir = mkTmp("audit-tamper");
  const file = path.join(dir, "a.jsonl");
  const log = createChainLog({ file });
  for (let i = 0; i < 6; i++) await log.append((seq, prev) => ({ seq, v: "x" + i, prev }));
  const orig = fs.readFileSync(file, "utf8");
  const lines = orig.split("\n").filter(Boolean);

  fs.writeFileSync(file, lines.map((l, i) => (i === 2 ? l.replace('"x2"', '"EDITED"') : l)).join("\n") + "\n");
  assert.deepEqual(pick(await createChainLog({ file }).verify()), { ok: false, firstBrokenSeq: 3 });

  fs.writeFileSync(file, lines.filter((_, i) => i !== 3).join("\n") + "\n");
  assert.deepEqual(pick(await createChainLog({ file }).verify()), { ok: false, firstBrokenSeq: 4 });

  fs.writeFileSync(file, orig.slice(0, -20));
  assert.equal((await createChainLog({ file }).verify()).ok, false);

  fs.writeFileSync(file, orig);
  assert.equal((await createChainLog({ file }).verify()).ok, true);
});
const pick = (v) => ({ ok: v.ok, firstBrokenSeq: v.firstBrokenSeq });

test("chain log: rotation keeps the chain (the new file's first prev is the old file's last line)", async () => {
  const dir = mkTmp("audit-rot");
  const file = path.join(dir, "audit.jsonl");
  const log = createChainLog({ file, maxBytes: 300, keep: 3 });
  for (let i = 0; i < 20; i++) await log.append((seq, prev) => ({ seq, pad: "p".repeat(40), prev }));
  const rotated = fs.readdirSync(dir).filter((n) => /^audit-\d{12}(-\d+)?\.jsonl$/.test(n));
  assert.ok(rotated.length >= 1 && rotated.length <= 3, "old files are pruned to `keep`");
  assert.equal((await log.verify()).ok, true);
  const live = fs.readFileSync(file, "utf8").split("\n").filter(Boolean);
  // Several rotations land in the same minute here (names -<stamp>.jsonl, -<stamp>-1, ...,
  // -<stamp>-10): the newest is the one with the highest seq, whatever its name sorts as.
  const lastSeqOf = (n) => { const ls = fs.readFileSync(path.join(dir, n), "utf8").split("\n").filter(Boolean); return { n, ls, seq: JSON.parse(ls[ls.length - 1]).seq }; };
  const byAge = rotated.map(lastSeqOf).sort((a, b) => a.seq - b.seq);
  const newest = byAge[byAge.length - 1];
  assert.equal(newest.seq + 1, JSON.parse(live[0]).seq, "the kept rotated files are the newest ones");
  assert.equal(JSON.parse(live[0]).prev, crypto.createHash("sha256").update(newest.ls[newest.ls.length - 1]).digest("hex"));
  // tail() walks the live file and then the rotated files newest first, with no gaps.
  const all = await log.tail({ limit: 200 });
  assert.equal(all.entries[0].seq, 20);
  all.entries.forEach((e, i) => assert.equal(e.seq, 20 - i));
  // A fresh instance whose live file is empty finds the chain head in the newest rotated file.
  fs.renameSync(file, path.join(dir, "moved.bak"));
  const fresh = createChainLog({ file, maxBytes: 300, keep: 3 });
  const rec = await fresh.append((seq, prev) => ({ seq, prev }));
  assert.equal(rec.seq, newest.seq + 1);
  assert.equal(rec.prev, crypto.createHash("sha256").update(newest.ls[newest.ls.length - 1]).digest("hex"));
});

test("app audit: details are allowlisted per action; unknown actions and keys are dropped with a log line", async () => {
  const dir = mkTmp("app-audit");
  const errs = [];
  const audit = createAppAudit({ file: path.join(dir, "audit.jsonl"), provider: () => "mock", logErr: (m) => errs.push(m) });
  const pw = canary("aud");
  const h = fakeHash(50000);
  assert.equal(await audit.record({ actor, action: "mailbox.password_change", target: "info@zehnox.com", result: "ok", detail: { password: pw } }), null);
  assert.equal(await audit.record({ actor, action: "mailbox.password_change", target: "info@zehnox.com", result: "ok", detail: { generated: true, hash: h } }), null);
  assert.equal(await audit.record({ actor, action: "shell.exec", detail: {} }), null);
  assert.equal(await audit.record({ actor, action: "forwarding.set", detail: { before: "not-a-list" } }), null);
  assert.equal(errs.length, 4);
  for (const e of errs) assert.equal(e, "mail: audit detail rejected");
  const ok = await audit.record({ actor, action: "mailbox.password_change", target: "info@zehnox.com", result: "ok", detail: { generated: false }, idem: crypto.randomUUID(), rev: 4 });
  assert.equal(ok.seq, 1);
  assert.deepEqual(ok.detail, { generated: false });
  const text = fs.readFileSync(path.join(dir, "audit.jsonl"), "utf8");
  for (const f of forms(pw).concat([h, CRYPT6])) assert.ok(!text.includes(f));
});

test("app audit: values are redacted, targets outside the pinned domain are dropped, fields are bounded", async () => {
  const dir = mkTmp("app-audit2");
  const audit = createAppAudit({ file: path.join(dir, "audit.jsonl"), provider: () => "vps" });
  const h = fakeHash(50000);
  const b64 = crypto.randomBytes(60).toString("base64");
  const rec = await audit.record({ actor: { user: "x".repeat(200), via: "evil", ip: "1.2.3.4".repeat(20) }, action: "forwarding.set", target: "info@strategicbhm.com", result: "weird", code: "Not A Code!", detail: { before: [h], after: ["ok@example.com", b64] }, idem: "nope", serviceNonce: "zz", rev: "7" });
  assert.equal(rec.target, null, "a foreign-domain target is never recorded as such");
  assert.equal(rec.result, "error");
  assert.equal(rec.code, null);
  assert.equal(rec.idem, null);
  assert.equal(rec.serviceNonce, null);
  assert.equal(rec.rev, null);
  assert.equal(rec.actor.via, null);
  assert.ok(rec.actor.user.length <= 80 && rec.actor.ip.length <= 45);
  assert.deepEqual(rec.detail.before, [MASK]);
  assert.equal(rec.detail.after[0], "ok@example.com");
  assert.ok(!JSON.stringify(rec).includes(b64));
  assert.equal(rec.provider, "vps");
});

test("app audit: rate-limit rejections are summarised once per limiter per minute", async () => {
  const dir = mkTmp("app-audit3");
  let t = Date.parse("2026-09-27T10:00:00Z");
  const audit = createAppAudit({ file: path.join(dir, "audit.jsonl"), provider: () => "mock", now: () => new Date(t) });
  const first = await audit.rateLimited("mailWrite", actor);
  assert.equal(first.detail.count, 1);
  for (let i = 0; i < 5; i++) assert.equal(await audit.rateLimited("mailWrite", actor), null);
  t += 61000;
  const next = await audit.rateLimited("mailWrite", actor);
  assert.equal(next.detail.count, 6);
  assert.equal(next.action, "rate_limit.summary");
});

test("sanitizeDetail: every action has a closed shape", () => {
  assert.ok(Object.isFrozen(ACTIONS));
  assert.throws(() => sanitizeDetail("smtp.settings_update", { values: { password: "x" } }), TypeError);
  assert.throws(() => sanitizeDetail("smtp.settings_update", { changed: ["password", "secret"] }), TypeError);
  assert.deepEqual(sanitizeDetail("smtp.settings_update", { changed: ["password", "host"], values: { host: "mail.example.net" }, passwordRemovedByRebind: false }),
    { changed: ["password", "host"], values: { host: "mail.example.net" }, passwordRemovedByRebind: false });
  assert.throws(() => sanitizeDetail("smtp.test", { to: "a@example.com", message: "535 pw=x" }), TypeError);
  assert.throws(() => sanitizeDetail("request.refused", { route: "GET /etc/passwd", code: "x" }), TypeError);
  assert.throws(() => sanitizeDetail("smtp.password_set", { password: "x" }), TypeError);
});

test("redactDeep: drops secret-looking keys, masks crypt hashes and long base64 runs", () => {
  const h = fakeHash(50000);
  const b64 = crypto.randomBytes(40).toString("base64");
  const input = {
    local: "info", password: "p", newPassword: "p", passwordHash: h, hash: h, secret: "s", apiKey: "k", token: "t",
    Authorization: "Bearer x", cookie: "c", signature: "sig", nested: { list: [h, "plain", b64, { pass: "x", ok: 1 }] },
    note: "argon {ARGON2ID}$argon2id$v=19$m=1", blob: CRYPT6 + "abc",
  };
  input.self = input; // cycles are cut, not followed
  const out = redactDeep(input);
  assert.deepEqual(Object.keys(out).sort(), ["blob", "local", "nested", "note", "self"].sort());
  assert.equal(out.nested.list[0], MASK);
  assert.equal(out.nested.list[1], "plain");
  assert.equal(out.nested.list[2], MASK);
  assert.deepEqual(out.nested.list[3], { ok: 1 });
  assert.equal(out.note, MASK);
  assert.equal(out.blob, MASK);
  assert.ok(!JSON.stringify(out).includes(h));
  const proto = redactDeep(JSON.parse('{"__proto__":{"polluted":1},"a":1}'));
  assert.deepEqual(proto, { a: 1 });
  assert.equal({}.polluted, undefined);
});

test("scrubString: removes every form of each secret, collapses CR/LF, printable ASCII, capped", () => {
  const user = "contact@zehnox.com";
  const pass = canary("scrub");
  const blob = authPlain(user, pass);
  const hostile = "535 5.7.8 auth failed for " + blob + " user=" + user + " pass=" + pass + " b64=" + Buffer.from(pass).toString("base64") +
    " url=" + Buffer.from(pass).toString("base64url") + "\r\nX-Injected: yes\u0000é";
  const out = scrubString(hostile, [pass, user, "\0" + user + "\0" + pass]);
  for (const f of forms(pass).concat(forms(user), [blob])) assert.ok(!out.includes(f), "leaked " + f.slice(0, 8));
  assert.ok(!/[\r\n\0]/.test(out));
  assert.match(out, /^[\x20-\x7e]*$/);
  assert.ok(out.includes("X-Injected"), "the line is collapsed, not dropped");
  assert.ok(scrubString("x".repeat(1000), []).length <= 200);
  assert.equal(scrubString(null, null), "");
});
