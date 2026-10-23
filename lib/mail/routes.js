"use strict";
/* /api/mail/* routes (DESIGN.md sections 6.1, 7 and 9.1).

   handleMail(req, res, url, session, h) is called by server.js AFTER its admin gate: the
   session is already verified, cookie writes are already same-origin, foreign Origins are
   already refused. There is no second login. On top of that, as defense in depth:
   - every non-GET needs Content-Type: application/json (415): a cross-site form cannot
     send it and a cross-site fetch would need a CORS preflight the server never grants;
   - every mutation needs an Idempotency-Key header (uuid v4) and the list's `rev`;
   - methods are enforced per route (405); bodies are strict (unknown keys are refused;
     "domain" and "address" are never keys);
   - :local must match ^[a-z0-9._-]{1,64}$ in the raw path, so "%40" or "@" is a 404.
   Order for mutating routes: Content-Type -> Idempotency-Key -> limiters -> readJson ->
   strict schema -> handler.

   h = { readJson, sendJson, fail, clientIp, log, logErr, limits, inquiryRecipient }
   Responses never contain a password, a hash or a key: they are built from the
   allowlist serializers in provider.js and website-smtp.js. */

const C = require("./core/constants.js");
const V = require("./core/validate.js");
const P = require("./provider.js");
const { checkPassword } = require("./password-policy.js");
const { isEmail } = require("../../smtp.js");

const { mailError, fromCoreError, META } = P;
const BODY_LIMIT = 16 * 1024;
const JSON_TYPE_RE = /^application\/json\s*(;\s*charset=utf-8\s*)?$/i;
const LOCAL_SEG = "([a-z0-9._-]{1,64})";
const RETRY_AFTER = { mailWrite: 60, mailSecret: 900, smtpTest: 600, smtpTestGlobal: 3600, healthRefresh: 60 };

/* ---------- body specs (strict) ---------- */
const S = (props, required) => ({ type: "object", props, required: required || [] });
const REV = { type: "int", min: 0 };
const PW = { type: "string", max: 1024 };
const FWD = { type: "array", max: 50, items: { type: "string", max: 320 } };
const SPECS = {
  create: S({ rev: REV, local: { type: "string", max: 320 }, type: { type: "string", max: 20 }, forwards: FWD, password: PW, reuseDeleted: { type: "bool" }, generated: { type: "bool" } }, ["rev", "local", "type"]),
  patch: S({ rev: REV, forwards: FWD, enabled: { type: "bool" }, mailboxEnabled: { type: "bool" } }, ["rev"]),
  mailbox: S({ rev: REV, password: PW, generated: { type: "bool" } }, ["rev", "password"]),
  password: S({ rev: REV, password: PW, generated: { type: "bool" } }, ["rev", "password"]),
  del: S({ rev: REV, confirm: { type: "string", max: 320 } }, ["rev", "confirm"]),
  empty: S({}),
  test: S({ to: { type: "string", max: 320 } }),
  rotate: S({ rev: REV }, ["rev"]),
};

function checkBody(body, spec) {
  try {
    V.schema(body, spec, { unknownCode: "unknown_field", typeCode: "invalid_body" });
  } catch (e) {
    const err = mailError(e.code === "unknown_field" ? "unknown_field" : "invalid_body", { field: e.field });
    err.shape = true; // audited as request.refused (an unknown shape), not as the action
    throw err;
  }
  return body;
}

/* Node-side normalisation of forwarding input (section 3.2): trim, lowercase the domain,
   smtp.js isEmail AND the shared DEST_RE, de-duplicate, at most 10. */
function normalizeForwards(list) {
  const out = [];
  for (const raw of list || []) {
    const d = V.normalizeDestination(raw);
    if (!isEmail(d)) throw mailError("invalid_destination", { field: "forwards" });
    out.push(d);
  }
  return V.cleanForwards(out, { min: 0, max: C.LIMITS.maxForwardsPerAddress });
}

function passwordOrThrow(pw, local) {
  const weak = checkPassword(pw, { local });
  if (weak) throw mailError("weak_password", { field: "password", reason: weak.reason });
  return pw;
}

function deletePreview(a) {
  const out = ["Stops accepting mail at " + a.address + " (senders get 'user unknown')"];
  if (a.forwards.length) out.push("Forwarding to " + a.forwards.join(", ") + " stops");
  if (a.mailbox) {
    if (a.mailbox.enabled) out.push("Mailbox login is disabled");
    out.push("Stored mail stays on the server until the owner removes it");
  }
  return out;
}

const nonceOf = (r) => (r && r[META] && r[META].nonce) || null;

/* ---------- the handler factory ---------- */

function createMailRoutes(mail) {
  async function localFromPath(m) {
    try { return V.checkLocal(m[1]); } catch (_) { throw mailError("not_found"); }
  }

  async function hashFor(provider, password) {
    let caps = null;
    if (mail.cfg.passwordScheme === "ARGON2ID") { try { caps = (await provider.getStatus()).capabilities; } catch (_) { caps = null; } }
    return mail.getHashPool().hash(password, mail.hashOptions(caps));
  }

  /* Each handler: (x) -> { status?, body, audits?: [{action, target, detail, result?, rev?, serviceNonce?}] }
     x = { req, url, m, body, provider, ctx, actor, r (per-request audit state), h } */
  const H = {
    async status(x) {
      const info = await x.provider.info();
      let s;
      try { s = await x.provider.getStatus(); } catch (_) { s = null; }
      const svc = s ? s.service : { state: "not_connected", smtp: "absent", submission: "absent", imap: "absent", mapsInSync: false, selfCheck: info.reason || "unavailable", checkedAt: new Date().toISOString() };
      return { body: {
        ok: true, domain: C.PINNED_DOMAIN, provider: x.provider.kind, mock: info.mock === true, connected: !!(s && info.connected),
        reason: s ? info.reason : info.reason || "unavailable", service: svc,
        capabilities: s ? s.capabilities : { mailboxes: false, schemes: ["SHA512-CRYPT"], maxForwards: C.LIMITS.maxForwardsPerAddress, maxAddresses: C.LIMITS.maxAddresses, maxExternalDestinations: C.LIMITS.maxExternalDestinationsTotal },
        rev: s ? s.rev : null,
      } };
    },

    async list(x) {
      const l = await x.provider.listAddresses();
      return { body: { ok: true, rev: l.rev, addresses: l.addresses, tombstones: l.tombstones } };
    },

    async getOne(x) {
      const local = await localFromPath(x.m);
      const l = await x.provider.listAddresses();
      const a = l.addresses.find((y) => y.local === local);
      if (!a) throw mailError("not_found");
      return { body: { ok: true, rev: l.rev, address: a, deletePreview: deletePreview(a) } };
    },

    async create(x) {
      const b = checkBody(x.body, SPECS.create);
      x.r.action = "address.create";
      if (typeof b.local === "string" && b.local.includes("@")) throw mailError("invalid_local", { field: "local" });
      const local = V.normalizeLocal(b.local);
      x.r.target = V.addressOf(local);
      const type = b.type;
      if (type !== "forward" && type !== "mailbox" && type !== "mailbox+forward") throw mailError("invalid_body", { field: "type" });
      const forwards = normalizeForwards(b.forwards || []);
      const hasPw = typeof b.password === "string" && b.password.length > 0;
      if (type === "forward") {
        if (!forwards.length) throw mailError("no_destination", { field: "forwards" });
        if (hasPw) throw mailError("invalid_body", { field: "password" });
      } else {
        if (type === "mailbox" && forwards.length) throw mailError("invalid_body", { field: "forwards" });
        if (type === "mailbox+forward" && !forwards.length) throw mailError("no_destination", { field: "forwards" });
        if (!hasPw) throw mailError("invalid_body", { field: "password" });
      }
      let passwordHash = null;
      if (hasPw) {
        let pw = passwordOrThrow(b.password, local);
        b.password = null;
        passwordHash = await hashFor(x.provider, pw);
        pw = null;
      }
      const res = await x.provider.createAddress({ local, forwards, passwordHash, reuseDeleted: b.reuseDeleted === true }, x.ctx);
      return {
        status: 201,
        body: { ok: true, rev: res.rev, address: res.address, resumesExistingMaildir: res.resumesExistingMaildir },
        audits: [{ action: "address.create", target: x.r.target, detail: { type: res.address.type, forwards: res.address.forwards }, rev: res.rev, serviceNonce: nonceOf(res) }],
      };
    },

    async patch(x) {
      const local = await localFromPath(x.m);
      x.r.target = V.addressOf(local);
      const b = checkBody(x.body, SPECS.patch);
      const present = ["forwards", "enabled", "mailboxEnabled"].filter((k) => V.hasOwn(b, k));
      if (present.length !== 1) { const e = mailError("invalid_body"); e.shape = true; throw e; }
      if (present[0] === "forwards") {
        const forwards = normalizeForwards(b.forwards);
        x.r.action = forwards.length ? "forwarding.set" : "forwarding.remove";
        const before = (await x.provider.getAddress(local)).forwards;
        const res = await x.provider.updateForwarding({ local, forwards }, x.ctx);
        const detail = forwards.length ? { before, after: res.address.forwards } : { before };
        return { body: { ok: true, rev: res.rev, address: res.address }, audits: [{ action: x.r.action, target: x.r.target, detail, rev: res.rev, serviceNonce: nonceOf(res) }] };
      }
      if (present[0] === "enabled") {
        x.r.action = b.enabled ? "address.enable" : "address.disable";
        const res = await x.provider.setAddressEnabled({ local, enabled: b.enabled }, x.ctx);
        return { body: { ok: true, rev: res.rev, address: res.address }, audits: [{ action: x.r.action, target: x.r.target, detail: {}, rev: res.rev, serviceNonce: nonceOf(res) }] };
      }
      x.r.action = b.mailboxEnabled ? "mailbox.enable" : "mailbox.disable";
      const res = await x.provider.setMailboxEnabled({ local, enabled: b.mailboxEnabled }, x.ctx);
      return { body: { ok: true, rev: res.rev, address: res.address }, audits: [{ action: x.r.action, target: x.r.target, detail: {}, rev: res.rev, serviceNonce: nonceOf(res) }] };
    },

    async addMailbox(x) {
      const local = await localFromPath(x.m);
      x.r.action = "mailbox.create";
      x.r.target = V.addressOf(local);
      const b = checkBody(x.body, SPECS.mailbox);
      let pw = passwordOrThrow(b.password, local);
      b.password = null;
      const passwordHash = await hashFor(x.provider, pw);
      pw = null;
      const res = await x.provider.createMailbox({ local, passwordHash }, x.ctx);
      return { body: { ok: true, rev: res.rev, address: res.address }, audits: [{ action: "mailbox.create", target: x.r.target, detail: { generated: b.generated === true }, rev: res.rev, serviceNonce: nonceOf(res) }] };
    },

    async changePassword(x) {
      const local = await localFromPath(x.m);
      x.r.action = "mailbox.password_change";
      x.r.target = V.addressOf(local);
      const b = checkBody(x.body, SPECS.password);
      let pw = passwordOrThrow(b.password, local);
      b.password = null;
      const passwordHash = await hashFor(x.provider, pw);
      pw = null;
      const res = await x.provider.changeMailboxPassword({ local, passwordHash }, x.ctx);
      return { body: { ok: true, rev: res.rev, passwordSetAt: res.passwordSetAt }, audits: [{ action: "mailbox.password_change", target: x.r.target, detail: { generated: b.generated === true }, rev: res.rev, serviceNonce: nonceOf(res) }] };
    },

    async del(x) {
      const local = await localFromPath(x.m);
      x.r.action = "address.delete";
      x.r.target = V.addressOf(local);
      const b = checkBody(x.body, SPECS.del);
      if (b.confirm !== V.addressOf(local)) throw mailError("confirm_mismatch", { field: "confirm" });
      const before = await x.provider.getAddress(local);
      const res = await x.provider.deleteAddress({ local, confirm: b.confirm }, x.ctx);
      return { body: { ok: true, rev: res.rev, mailboxDataRetained: res.mailboxDataRetained }, audits: [{ action: "address.delete", target: x.r.target, detail: { type: before.type, mailboxDataRetained: res.mailboxDataRetained }, rev: res.rev, serviceNonce: nonceOf(res) }] };
    },

    async health(x) {
      return { body: Object.assign({ ok: true }, await x.provider.getDomainHealth({ refresh: false })) };
    },

    async healthRefresh(x) {
      checkBody(x.body, SPECS.empty);
      return { body: Object.assign({ ok: true }, await x.provider.getDomainHealth({ refresh: true })) };
    },

    async smtpGet(x) {
      const smtp = mail.getSmtp();
      const view = smtp.publicView();
      let rotateAvailable = false;
      const cand = smtp.rotateCandidate();
      if (cand && view.secretsKeyPresent && !view.locked) {
        try { const a = await x.provider.getAddress(cand); rotateAvailable = !!(a.enabled && a.mailbox && a.mailbox.enabled); } catch (_) { rotateAvailable = false; }
      }
      return { body: Object.assign({ ok: true }, view, { rotateAvailable }) };
    },

    async smtpPut(x) {
      x.r.action = "smtp.settings_update";
      const out = await mail.getSmtp().update(x.body, { actor: x.actor, listAddresses: () => x.provider.listAddresses() });
      const audits = [{ action: "smtp.settings_update", target: null, detail: { changed: out.audit.changed, values: out.audit.values, passwordRemovedByRebind: out.audit.passwordRemovedByRebind } }];
      if (out.audit.passwordSet) audits.push({ action: "smtp.password_set", target: null, detail: {} });
      if (out.audit.passwordCleared) audits.push({ action: "smtp.password_clear", target: null, detail: {} });
      return { body: Object.assign({ ok: true }, out.view, { warnings: out.warnings }), audits };
    },

    async smtpTest(x) {
      x.r.action = "smtp.test";
      const b = checkBody(x.body, SPECS.test);
      const to = typeof b.to === "string" ? b.to.trim() : undefined;
      const t = await x.provider.testSmtp({ to, inquiryRecipient: typeof x.h.inquiryRecipient === "function" ? x.h.inquiryRecipient() : "" }, x.ctx);
      x.h.log("mail: smtp test stage=" + t.stage + " code=" + (t.smtpCode == null ? "-" : t.smtpCode));
      return {
        body: { ok: true, test: { passed: t.passed, stage: t.stage, smtpCode: t.smtpCode, ms: t.ms, message: t.message, hint: t.hint } },
        audits: [{ action: "smtp.test", target: null, detail: { to: t.to, passed: t.passed, stage: t.stage, smtpCode: t.smtpCode }, result: t.passed ? "ok" : "error" }],
        quiet: true, // the one-line log above is the only log line for a test
      };
    },

    async smtpRotate(x) {
      x.r.action = "smtp.password_rotate";
      checkBody(x.body, SPECS.rotate);
      const out = await mail.getSmtp().rotate({ provider: x.provider, hashPool: mail.getHashPool(), ctx: x.ctx, hashOpts: mail.hashOptions(null) });
      return { body: { ok: true, passwordUpdatedAt: out.passwordUpdatedAt }, audits: [{ action: "smtp.password_rotate", target: null, detail: {}, rev: out.result && out.result.rev, serviceNonce: nonceOf(out.result) }] };
    },

    async auditGet(x) {
      const q = x.url.searchParams;
      for (const k of q.keys()) if (!["source", "limit", "before", "verify", "target"].includes(k)) throw mailError("unknown_field", { field: k });
      const source = q.get("source") || "app";
      if (source !== "app" && source !== "service") throw mailError("invalid_body", { field: "source" });
      const limit = q.has("limit") ? Number(q.get("limit")) : 50;
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw mailError("invalid_body", { field: "limit" });
      const before = q.has("before") ? Number(q.get("before")) : null;
      if (before !== null && (!Number.isSafeInteger(before) || before < 1)) throw mailError("invalid_body", { field: "before" });
      const verify = q.get("verify") === "1";
      let target = null;
      if (q.has("target")) { try { target = V.addressOf(V.checkLocal(q.get("target"))); } catch (_) { throw mailError("invalid_body", { field: "target" }); } }
      if (source === "service") {
        const t = await x.provider.auditTail({ limit, beforeSeq: before });
        return { body: { ok: true, source, entries: t.entries, next: t.nextBeforeSeq } };
      }
      const audit = mail.getAudit();
      const t = await audit.tail({ limit, before: before == null ? undefined : before, target });
      const body = { ok: true, source, entries: t.entries, next: t.next };
      if (verify) { const v = await audit.verify(); body.chain = { ok: v.ok, firstBrokenSeq: v.firstBrokenSeq }; }
      return { body };
    },
  };

  const A = "/api/mail";
  const ADDR = A + "/addresses/" + LOCAL_SEG;
  const ROUTES = [
    { method: "GET", re: new RegExp("^" + A + "/status$"), label: "GET /api/mail/status", fn: H.status },
    { method: "GET", re: new RegExp("^" + A + "/addresses$"), label: "GET /api/mail/addresses", fn: H.list },
    { method: "POST", re: new RegExp("^" + A + "/addresses$"), label: "POST /api/mail/addresses", fn: H.create, mutating: true, limiters: ["mailWrite"], secretIfPassword: true },
    { method: "GET", re: new RegExp("^" + ADDR + "$"), label: "GET /api/mail/addresses/:local", fn: H.getOne },
    { method: "PATCH", re: new RegExp("^" + ADDR + "$"), label: "PATCH /api/mail/addresses/:local", fn: H.patch, mutating: true, limiters: ["mailWrite"] },
    { method: "DELETE", re: new RegExp("^" + ADDR + "$"), label: "DELETE /api/mail/addresses/:local", fn: H.del, mutating: true, limiters: ["mailWrite"] },
    { method: "POST", re: new RegExp("^" + ADDR + "/mailbox$"), label: "POST /api/mail/addresses/:local/mailbox", fn: H.addMailbox, mutating: true, limiters: ["mailWrite", "mailSecret"] },
    { method: "POST", re: new RegExp("^" + ADDR + "/password$"), label: "POST /api/mail/addresses/:local/password", fn: H.changePassword, mutating: true, limiters: ["mailSecret"] },
    { method: "GET", re: new RegExp("^" + A + "/health$"), label: "GET /api/mail/health", fn: H.health },
    { method: "POST", re: new RegExp("^" + A + "/health/refresh$"), label: "POST /api/mail/health/refresh", fn: H.healthRefresh, limiters: ["healthRefresh"] },
    { method: "GET", re: new RegExp("^" + A + "/smtp$"), label: "GET /api/mail/smtp", fn: H.smtpGet },
    { method: "PUT", re: new RegExp("^" + A + "/smtp$"), label: "PUT /api/mail/smtp", fn: H.smtpPut, mutating: true, limiters: ["mailWrite"], secretIfPassword: true },
    { method: "POST", re: new RegExp("^" + A + "/smtp/test$"), label: "POST /api/mail/smtp/test", fn: H.smtpTest, limiters: ["smtpTest", "smtpTestGlobal"] },
    { method: "POST", re: new RegExp("^" + A + "/smtp/rotate$"), label: "POST /api/mail/smtp/rotate", fn: H.smtpRotate, mutating: true, limiters: ["mailSecret"] },
    { method: "GET", re: new RegExp("^" + A + "/audit$"), label: "GET /api/mail/audit", fn: H.auditGet },
  ];

  function send(h, res, status, body, headers) {
    return h.sendJson(res, status, body, headers);
  }
  function sendError(h, res, e) {
    const body = { ok: false, error: e.message, code: e.code };
    if (e.field) body.field = e.field;
    if (e.refs && e.refs.length) body.refs = e.refs;
    const headers = e.status === 429 ? { "Retry-After": String(e.retryAfter || 60) } : e.status === 405 && e.allow ? { Allow: e.allow } : undefined;
    return send(h, res, e.status, body, headers);
  }

  /* Checks a limiter; on rejection audits a (rate-capped) summary and throws 429. */
  function applyLimiter(h, name, session, ip, actor) {
    const lim = h.limits && h.limits[name];
    if (!lim) return;
    const key = name === "smtpTestGlobal" ? "global" : session.username + "|" + ip;
    if (lim.blocked(key)) {
      mail.getAudit().rateLimited(name, actor);
      throw mailError("rate_limited", { retryAfter: RETRY_AFTER[name] || 60 });
    }
    lim.hit(key);
  }

  async function handleMail(req, res, url, session, h) {
    const p = url.pathname;
    const method = req.method;
    const candidates = ROUTES.filter((r) => r.re.test(p));
    if (!candidates.length) return send(h, res, 404, { ok: false, error: "Not found.", code: "not_found" });
    const route = candidates.find((r) => r.method === method);
    if (!route) {
      const e = mailError("method_not_allowed");
      e.allow = candidates.map((r) => r.method).join(", ");
      return sendError(h, res, e);
    }

    const ip = h.clientIp(req);
    const actor = { user: session.username, via: session.via, ip };
    const r = { action: null, target: null }; // what the handler got to, for failure audits
    const audit = route.mutating || route.fn === H.smtpTest ? mail.getAudit() : null;
    let stage = "pre"; // pre -> handler
    let idem = null;

    try {
      if (method !== "GET") {
        if (!JSON_TYPE_RE.test(String(req.headers["content-type"] || "").trim())) throw mailError("unsupported_media_type");
        if (route.mutating) {
          idem = String(req.headers["idempotency-key"] || "").trim().toLowerCase();
          if (!C.UUID_V4_RE.test(idem)) { idem = null; throw mailError("missing_idempotency_key"); }
        }
        for (const name of route.limiters || []) applyLimiter(h, name, session, ip, actor);
      }

      let body = null;
      if (method !== "GET") {
        try {
          body = await h.readJson(req, BODY_LIMIT);
        } catch (e) {
          throw mailError(e && e.status === 413 ? "body_too_large" : "invalid_body");
        }
        if (!V.isPlainObject(body)) throw mailError("invalid_body");
        if (route.secretIfPassword && typeof body.password === "string" && body.password.length) applyLimiter(h, "mailSecret", session, ip, actor);
      }

      const provider = mail.getProvider();
      const ctx = { actor, idem, ifRev: body && Number.isSafeInteger(body.rev) ? body.rev : undefined };
      stage = "handler";
      const out = await route.fn({ req, url, m: p.match(route.re), body, provider, ctx, actor, r, h });

      for (const a of out.audits || []) {
        await audit.record({ actor, action: a.action, target: a.target, result: a.result || "ok", code: null, detail: a.detail, idem, serviceNonce: a.serviceNonce, rev: a.rev });
        if (!out.quiet) h.log("mail: " + a.action + " " + (a.target ? a.target.slice(0, a.target.indexOf("@") + 1) + " " : "") + "by " + session.username + " result=ok");
      }
      return send(h, res, out.status || 200, out.body);
    } catch (err) {
      let e = err;
      if (!(e instanceof P.MailError)) {
        if (e && e.name === "CoreError") {
          e = fromCoreError(e); // validation from lib/mail/core: codes are already public
        } else {
          // A bug, not a refusal: log a code only, never a message, body or stack.
          h.logErr("mail: internal " + (e && typeof e.code === "string" ? e.code.replace(/[^A-Za-z0-9_]/g, "").slice(0, 40) : "error"));
          e = mailError("internal");
        }
      }
      if (audit && e.status !== 429) {
        const result = e.status >= 500 ? "error" : "refused";
        if (stage === "pre" || e.shape || !r.action) {
          if (e.status < 500) await audit.record({ actor, action: "request.refused", target: null, result: "refused", code: e.code, detail: { route: route.label, code: e.code }, idem });
        } else {
          await audit.record({ actor, action: r.action, target: r.target, result, code: e.code, detail: {}, idem });
        }
        h.log("mail: " + (r.action || "request") + " " + (r.target ? r.target.slice(0, r.target.indexOf("@") + 1) + " " : "") + "by " + session.username + " result=" + result + " code=" + e.code);
      }
      return sendError(h, res, e);
    }
  }

  return { handleMail, ROUTES, deletePreview };
}

/* The process-wide handler, bound to the lib/mail singleton. */
let bound = null;
function handleMail(req, res, url, session, h) {
  if (!bound) bound = createMailRoutes(require("./index.js"));
  return bound.handleMail(req, res, url, session, h);
}

module.exports = { handleMail, createMailRoutes, deletePreview, SPECS };
