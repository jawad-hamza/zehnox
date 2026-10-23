"use strict";
/* MailProvider interface, MailError, NullProvider and the public serializers
   (DESIGN.md section 4).

   Every provider method is async and either resolves with plain data built by an
   allowlist serializer below, or throws MailError. A MailError's message is always the
   constant public string for its code: nothing from the daemon, SMTP or DNS is ever
   interpolated into it, so handleMail can send it to the browser as is. */

const C = require("./core/constants.js");
const V = require("./core/validate.js");

/* Results carry the daemon's nonce for the audit cross-link under this symbol, so it can
   never be serialized into a response by accident (JSON.stringify skips symbol keys). */
const META = Symbol("mail.meta");

class MailError extends Error {
  constructor(code, status, publicMessage, extra) {
    super(publicMessage);
    this.name = "MailError";
    this.code = code;
    this.status = status;
    if (extra && extra.field) this.field = extra.field;
    if (extra && Array.isArray(extra.refs)) this.refs = extra.refs.slice();
    if (extra && Number.isSafeInteger(extra.retryAfter)) this.retryAfter = extra.retryAfter;
  }
}

/* The usual way to build one: status and message come from the closed table. */
function mailError(code, extra) {
  const def = C.ERROR_CODES[code] || C.ERROR_CODES.backend_failed;
  const known = C.ERROR_CODES[code] ? code : "backend_failed";
  let message = def.message;
  if (known === "weak_password" && extra && typeof extra.reason === "string") message = "That password is too weak: " + extra.reason + ".";
  if (known === "in_use" && extra && Array.isArray(extra.refs) && extra.refs.length) {
    // refs are validated local parts (never raw input), so they are safe to show.
    const refs = extra.refs.filter(V.isValidLocal).slice(0, 10);
    if (refs.length) message = "Other addresses forward here: " + refs.join(", ") + ". Change them first.";
  }
  return new MailError(known, def.status, message, extra);
}

/* Maps a CoreError (from the core, the protocol, or a daemon error code) onto the public
   set. Core rule codes map 1:1; daemon-internal codes (unauthorized, bad_request, replay,
   invalid_hash, ...) mean the web side sent something wrong, which is backend_failed. */
const PUBLIC_FROM_CORE = new Set([
  "invalid_local", "reserved_local", "invalid_destination", "self_destination", "destination_not_mailbox",
  "too_many_destinations", "domain_destination_cap", "confirm_mismatch", "protected", "not_found",
  "duplicate", "tombstoned", "no_destination", "in_use", "conflict_rev", "idempotency_mismatch",
  "capability_missing", "limit_addresses", "limit_tombstones", "rate_limited", "busy", "backend_failed", "not_ready",
  "domain_mismatch", "bad_response", "unavailable", "not_connected", "invalid_body", "unknown_field",
]);
function fromCoreError(e) {
  if (e instanceof MailError) return e;
  const code = e && typeof e.code === "string" && PUBLIC_FROM_CORE.has(e.code) ? e.code : "backend_failed";
  return mailError(code, { field: e && e.field, refs: e && e.refs });
}

/* ---------- allowlist serializers ---------- */

const iso = (v) => (typeof v === "string" && v.length <= 40 ? v : null);
const TYPES = new Set(["forward", "mailbox", "mailbox+forward"]);

/* Copies fields one by one from a daemon/mock record. Never copies a hash: there is no
   field here that could hold one, and passwordSetAt must look like a date. */
function toPublicAddress(a) {
  if (!V.isPlainObject(a) || !V.isValidLocal(a.local)) throw mailError("bad_response");
  const forwards = Array.isArray(a.forwards) ? a.forwards.filter(V.isDestination).slice(0, C.LIMITS.maxForwardsPerAddress) : [];
  return {
    local: a.local,
    address: V.addressOf(a.local),
    type: TYPES.has(a.type) ? a.type : "forward",
    enabled: a.enabled === true,
    protected: a.protected === true,
    forwards,
    mailbox: V.isPlainObject(a.mailbox) ? { enabled: a.mailbox.enabled === true, passwordSetAt: iso(a.mailbox.passwordSetAt) } : null,
    createdAt: iso(a.createdAt),
    updatedAt: iso(a.updatedAt),
  };
}

function toPublicTombstone(t) {
  if (!V.isPlainObject(t) || !V.isValidLocal(t.local)) throw mailError("bad_response");
  return { local: t.local, deletedAt: iso(t.deletedAt), hadMailbox: t.hadMailbox === true };
}

const UPDOWN = new Set(["up", "down", "absent"]);
const STATES = new Set(["online", "degraded", "offline", "not_connected"]);
const pick = (v, set, dflt) => (set.has(v) ? v : dflt);

/* Status (section 4). `kind` and `connected` come from the provider, not the payload. */
function toPublicStatus(s, kind, connected) {
  const svc = V.isPlainObject(s && s.service) ? s.service : {};
  const caps = V.isPlainObject(s && s.capabilities) ? s.capabilities : {};
  const dkim = V.isPlainObject(s && s.dkim) ? s.dkim : {};
  const daemon = V.isPlainObject(s && s.daemon) ? s.daemon : null;
  const selfCheck = typeof svc.selfCheck === "string" && /^[a-z0-9_]{1,40}$/.test(svc.selfCheck) ? svc.selfCheck : "unknown";
  return {
    domain: typeof (s && s.domain) === "string" && s.domain.length <= 253 ? s.domain : null,
    kind,
    connected: connected === true,
    rev: Number.isSafeInteger(s && s.rev) ? s.rev : null,
    service: {
      state: pick(svc.state, STATES, "offline"),
      smtp: pick(svc.smtp, UPDOWN, "absent"),
      submission: pick(svc.submission, UPDOWN, "absent"),
      imap: pick(svc.imap, UPDOWN, "absent"),
      mapsInSync: svc.mapsInSync === true,
      selfCheck,
      checkedAt: iso(svc.checkedAt),
    },
    capabilities: {
      mailboxes: caps.mailboxes === true,
      schemes: Array.isArray(caps.schemes) ? caps.schemes.filter((x) => x === "SHA512-CRYPT" || x === "ARGON2ID") : ["SHA512-CRYPT"],
      maxForwards: C.LIMITS.maxForwardsPerAddress,
      maxAddresses: C.LIMITS.maxAddresses,
      maxExternalDestinations: C.LIMITS.maxExternalDestinationsTotal,
    },
    // DKIM: the public p= value only, and only if it looks like base64.
    dkim: {
      selector: typeof dkim.selector === "string" && /^[a-z0-9._-]{1,63}$/i.test(dkim.selector) ? dkim.selector : null,
      publicKey: typeof dkim.publicKey === "string" && /^[A-Za-z0-9+/=]{1,4096}$/.test(dkim.publicKey) ? dkim.publicKey : null,
    },
    daemon: daemon ? { version: typeof daemon.version === "string" ? daemon.version.slice(0, 20) : null, startedAt: iso(daemon.startedAt) } : null,
  };
}

/* Service audit entries (getAuditTail): fields copied one by one. The daemon writes refused
   requests as one summary line a minute (code "refused_summary"); that line also carries
   its total and the counts per "<verb>/<code>", each key and value checked here. */
const REFUSED_KEY_RE = /^([A-Za-z]{1,40})\/([a-z_]{1,40})$/;
function toPublicServiceEntry(e) {
  if (!V.isPlainObject(e)) return null;
  const actor = V.isPlainObject(e.actor) ? e.actor : {};
  const out = {
    seq: Number.isSafeInteger(e.seq) ? e.seq : null,
    at: iso(e.at),
    verb: typeof e.verb === "string" && V.hasOwn(C.VERBS, e.verb) ? e.verb : null,
    target: V.isValidLocal(e.target) ? e.target : null,
    actor: { user: typeof actor.user === "string" && C.ACTOR_USER_RE.test(actor.user) ? actor.user : null, ip: typeof actor.ip === "string" && C.ACTOR_IP_RE.test(actor.ip) ? actor.ip : null },
    nonce: typeof e.nonce === "string" && /^[0-9a-f]{32}$/.test(e.nonce) ? e.nonce : null,
    idem: typeof e.idem === "string" && C.UUID_V4_RE.test(e.idem) ? e.idem : null,
    ok: e.ok === true,
    code: typeof e.code === "string" && /^[a-z_]{1,40}$/.test(e.code) ? e.code : null,
    rev: Number.isSafeInteger(e.rev) ? e.rev : null,
  };
  if (out.code === "refused_summary" && Number.isSafeInteger(e.count) && e.count >= 0) {
    out.count = e.count;
    const refused = {};
    if (V.isPlainObject(e.refused)) {
      for (const k of Object.keys(e.refused).slice(0, 100)) {
        const m = REFUSED_KEY_RE.exec(k);
        const n = e.refused[k];
        if (m && V.hasOwn(C.VERBS, m[1]) && Number.isSafeInteger(n) && n >= 0) refused[k] = n;
      }
    }
    out.refused = refused;
  }
  return out;
}

/* ---------- base class ---------- */

class MailProvider {
  /* deps (optional, wired by index.js): { health: HealthChecker, smtpTester: { run(opts) } } */
  constructor(deps) {
    this._deps = deps || {};
  }
  get kind() { return "none"; }
  async info() { throw mailError("not_connected"); }
  async getStatus() { throw mailError("not_connected"); }
  async listAddresses() { throw mailError("not_connected"); }
  async getAddress() { throw mailError("not_connected"); }
  async createAddress() { throw mailError("not_connected"); }
  async deleteAddress() { throw mailError("not_connected"); }
  async updateForwarding() { throw mailError("not_connected"); }
  async setAddressEnabled() { throw mailError("not_connected"); }
  async createMailbox() { throw mailError("not_connected"); }
  async setMailboxEnabled() { throw mailError("not_connected"); }
  async changeMailboxPassword() { throw mailError("not_connected"); }
  async auditTail() { throw mailError("not_connected"); }

  /* Backend-agnostic: DNS keeps working even with no mail service connected. The status is
     best effort (it feeds the DKIM key, the service row and the domain row). */
  async getDomainHealth(opts) {
    const health = this._deps.health;
    if (!health) throw mailError("unavailable");
    let status = null;
    try { status = await this.getStatus(); } catch (_) { status = null; }
    return health.check({ refresh: !!(opts && opts.refresh), status });
  }

  /* SMTP test (section 10.4). opts: { to?, inquiryRecipient: string, user: admin username }.
     The recipient allowlist needs the enabled domain addresses; when the provider is down
     only the inquiry recipient and the From address remain allowed. */
  async testSmtp(opts, ctx) {
    const tester = this._deps.smtpTester;
    if (!tester) throw mailError("unavailable");
    let enabled = [];
    try {
      const list = await this.listAddresses();
      enabled = list.addresses.filter((a) => a.enabled).map((a) => a.address);
    } catch (_) { enabled = []; }
    return tester.run({ to: opts && opts.to, inquiryRecipient: opts && opts.inquiryRecipient, enabledAddresses: enabled, user: ctx && ctx.actor && ctx.actor.user });
  }
}

/* The kill switch and the production default (D12). Every list or mutation throws; the
   status says not_connected; DNS health still runs. */
class NullProvider extends MailProvider {
  constructor(opts, deps) {
    super(deps);
    const reason = opts && opts.reason;
    this.reason = reason === "domain_mismatch" || reason === "unavailable" ? reason : "not_connected";
  }
  get kind() { return "none"; }
  _err() { return mailError(this.reason === "domain_mismatch" ? "domain_mismatch" : "not_connected"); }
  async info() { return { kind: "none", domain: C.PINNED_DOMAIN, connected: false, mock: false, reason: this.reason }; }
  async getStatus() {
    return toPublicStatus({
      domain: this.reason === "domain_mismatch" ? null : C.PINNED_DOMAIN,
      rev: null,
      service: { state: "not_connected", smtp: "absent", submission: "absent", imap: "absent", mapsInSync: false, selfCheck: "not_connected", checkedAt: new Date().toISOString() },
      capabilities: { mailboxes: false, schemes: ["SHA512-CRYPT"] },
      dkim: { selector: process.env.MAIL_DKIM_SELECTOR || null, publicKey: null },
      daemon: null,
    }, "none", false);
  }
  async listAddresses() { throw this._err(); }
  async getAddress() { throw this._err(); }
  async createAddress() { throw this._err(); }
  async deleteAddress() { throw this._err(); }
  async updateForwarding() { throw this._err(); }
  async setAddressEnabled() { throw this._err(); }
  async createMailbox() { throw this._err(); }
  async setMailboxEnabled() { throw this._err(); }
  async changeMailboxPassword() { throw this._err(); }
  async auditTail() { throw this._err(); }
}

module.exports = {
  MailError, mailError, fromCoreError, META,
  MailProvider, NullProvider,
  toPublicAddress, toPublicTombstone, toPublicStatus, toPublicServiceEntry,
};
