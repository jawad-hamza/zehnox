"use strict";
/* handleMail in-process (lib/mail/routes.js), DESIGN.md sections 6.1 and 9.1: the order of
   the transport checks, what gets audited, and that an unexpected error is logged as a
   code only (never a message, body or stack) and answered with a constant. The full HTTP
   stack, with the admin gate in front, is covered by api.test.js. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { LIB, mkTmp, canary, forms } = require("./helpers/common.js");

const { createMailModule } = require(path.join(LIB, "index.js"));
const { createMailRoutes } = require(path.join(LIB, "routes.js"));

/* A harness: a mock-provider mail module on a temp dir, fake req/res, recorded logs. */
function harness(over) {
  const dir = mkTmp("routes");
  const logs = [];
  const mail = createMailModule({ env: { NODE_ENV: "test", MAIL_PROVIDER: "mock", MAIL_HASH_ROUNDS: "1000", MAIL_BOOTSTRAP_FORWARD: "owner@example.com" }, dataDir: dir, log: (...a) => logs.push(a.join(" ")), logErr: (...a) => logs.push(a.join(" ")) });
  const m = Object.assign({}, mail, over || {});
  const { handleMail } = createMailRoutes(m);
  let reads = 0;
  const blocked = new Set();
  const limiter = (name) => ({ blocked: (k) => blocked.has(name), hit: () => 1 });
  const h = {
    readJson: async (req, limit) => {
      reads++;
      if (Buffer.byteLength(req.body || "") > limit) throw Object.assign(new Error("too large"), { status: 413 });
      if (!req.body) throw Object.assign(new Error("empty"), { status: 400 });
      return JSON.parse(req.body);
    },
    sendJson: (res, status, body, headers) => { res.status = status; res.body = body; res.headers = headers || {}; },
    fail: () => { throw new Error("handleMail must answer through sendJson"); },
    clientIp: () => "203.0.113.9",
    log: (...a) => logs.push(a.join(" ")),
    logErr: (...a) => logs.push(a.join(" ")),
    limits: { mailWrite: limiter("mailWrite"), mailSecret: limiter("mailSecret"), smtpTest: limiter("smtpTest"), smtpTestGlobal: limiter("smtpTestGlobal"), healthRefresh: limiter("healthRefresh") },
    inquiryRecipient: () => "inbox@example.com",
  };
  const session = { username: "admin", via: "cookie" };
  async function call(method, p, o) {
    const opts = o || {};
    const headers = {};
    if (opts.ctype !== null && method !== "GET") headers["content-type"] = opts.ctype || "application/json";
    if (opts.idem) headers["idempotency-key"] = opts.idem === true ? crypto.randomUUID() : opts.idem;
    const req = { method, headers, body: opts.raw != null ? opts.raw : opts.body !== undefined ? JSON.stringify(opts.body) : "" };
    const res = {};
    await handleMail(req, res, new URL("http://127.0.0.1" + p), session, h);
    return res;
  }
  return { call, logs, dir, mail, block: (n) => blocked.add(n), get reads() { return reads; } };
}

test("check order for mutations: Content-Type, then Idempotency-Key, then limiters, then the body", async () => {
  const x = harness();
  let r = await x.call("POST", "/api/mail/addresses", { ctype: "text/plain", raw: "{}" });
  assert.equal(r.status, 415);
  r = await x.call("POST", "/api/mail/addresses", { body: { rev: 1, local: "a", type: "forward", forwards: ["a@example.com"] } });
  assert.equal(r.status, 400);
  assert.equal(r.body.code, "missing_idempotency_key");
  r = await x.call("POST", "/api/mail/addresses", { idem: "not-a-uuid", body: {} });
  assert.equal(r.body.code, "missing_idempotency_key");
  r = await x.call("POST", "/api/mail/addresses", { idem: crypto.randomUUID().replace(/^(.{14})4/, "$11"), body: {} });
  assert.equal(r.body.code, "missing_idempotency_key", "a uuid that is not v4");
  assert.equal(x.reads, 0, "no body was read for any of these");
  x.block("mailWrite");
  r = await x.call("POST", "/api/mail/addresses", { idem: true, body: {} });
  assert.equal(r.status, 429);
  assert.equal(r.headers["Retry-After"], "60");
  assert.equal(x.reads, 0, "a rate-limited request is refused before its body is read");
  const y = harness();
  r = await y.call("POST", "/api/mail/addresses", { idem: true, raw: "x".repeat(17 * 1024) });
  assert.equal(r.status, 413);
  r = await y.call("POST", "/api/mail/addresses", { idem: true, raw: "[1,2]" });
  assert.equal(r.body.code, "invalid_body");
  r = await y.call("POST", "/api/mail/addresses", { idem: true, ctype: "application/json; charset=utf-8", body: { rev: 1, local: "ok", type: "forward", forwards: ["a@example.com"] } });
  assert.equal(r.status, 201, "the charset suffix is allowed");
  r = await y.call("POST", "/api/mail/addresses", { idem: true, ctype: "application/json; charset=latin1", body: {} });
  assert.equal(r.status, 415);
});

test("methods and paths: 405 with Allow, 404 for unknown paths and for anything that is not a plain local part", async () => {
  const x = harness();
  let r = await x.call("PUT", "/api/mail/addresses", { body: {} });
  assert.equal(r.status, 405);
  assert.equal(r.headers.Allow, "GET, POST");
  for (const p of ["/api/mail", "/api/mail/", "/api/mail/exec", "/api/mail/addresses/info%40strategicbhm.com", "/api/mail/addresses/INFO",
    "/api/mail/addresses/..%2Fetc", "/api/mail/addresses/info/../../etc", "/api/mail/addresses/" + "a".repeat(65), "/api/mail/addresses/a%00b",
    "/api/mail/status/", "/api/mail/addresses/info/extra"]) {
    r = await x.call("GET", p);
    assert.equal(r.status, 404, p);
  }
  // Matched by the pattern but refused by the full validation (reserved, bad separators): 404 too.
  for (const p of ["/api/mail/addresses/root", "/api/mail/addresses/a..b", "/api/mail/addresses/-a"]) {
    r = await x.call("PATCH", p, { idem: true, body: { rev: 1, enabled: false } });
    assert.equal(r.status, 404, p);
  }
});

test("an unexpected error is logged as a code only and answered with a constant 500", async () => {
  const secret = canary("boom");
  const evil = {
    kind: "mock",
    async listAddresses() { const e = new Error("db password=" + secret); e.stack = "at secret " + secret; throw e; },
    async info() { return { kind: "mock", connected: true, mock: true, reason: null }; },
  };
  const x = harness({ getProvider: () => evil });
  const r = await x.call("GET", "/api/mail/addresses");
  assert.equal(r.status, 500);
  assert.deepEqual(r.body, { ok: false, error: "Something went wrong on the server.", code: "internal" });
  assert.ok(x.logs.includes("mail: internal error"));
  for (const f of forms(secret)) assert.ok(!x.logs.join("\n").includes(f) && !JSON.stringify(r).includes(f));
});

test("refusals on mutating routes are audited as refused; passwords never reach the audit or the log", async () => {
  const x = harness();
  const pw = canary("rt");
  const rev = (await x.call("GET", "/api/mail/addresses")).body.rev;
  let r = await x.call("POST", "/api/mail/addresses", { idem: true, body: { rev, local: "info@strategicbhm.com", type: "forward", forwards: ["a@example.com"] } });
  assert.equal(r.body.code, "invalid_local");
  r = await x.call("POST", "/api/mail/addresses", { idem: true, body: { rev, local: "box", type: "mailbox", forwards: [], password: "short" } });
  assert.equal(r.body.code, "weak_password");
  r = await x.call("POST", "/api/mail/addresses", { idem: true, body: { rev, local: "box", type: "mailbox", forwards: [], password: pw, domain: "strategicbhm.com" } });
  assert.equal(r.body.code, "unknown_field");
  r = await x.call("POST", "/api/mail/addresses", { idem: true, body: { rev, local: "box", type: "mailbox", forwards: [], password: pw } });
  assert.equal(r.status, 201);
  const audit = fs.readFileSync(path.join(x.dir, "mail", "audit.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.deepEqual(audit.map((a) => [a.action, a.result, a.code]), [
    ["address.create", "refused", "invalid_local"],
    ["address.create", "refused", "weak_password"],
    ["request.refused", "refused", "unknown_field"],
    ["address.create", "ok", null],
  ]);
  const all = fs.readFileSync(path.join(x.dir, "mail", "audit.jsonl"), "utf8") + x.logs.join("\n");
  for (const f of forms(pw)) assert.ok(!all.includes(f));
  assert.ok(!all.includes("strategicbhm.com") || !/"target":"[^"]*strategicbhm/.test(all), "a foreign target is never recorded as a target");
});
