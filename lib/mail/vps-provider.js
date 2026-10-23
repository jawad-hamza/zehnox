"use strict";
/* VpsMailProvider: the client side of the zehnox-maild socket (DESIGN.md section 4.4).

   One request per connection over a Unix socket (a named pipe on Windows, for tests):
   exactly one signed frame is written and one frame line is read back. There is no TCP
   anywhere (D1).

   Timeouts: connect 1 s; total 5 s for reads, 8 s for mutations; the socket is destroyed
   on expiry. A response over 256 KiB is refused.
   Verification: response MAC (response domain-separation prefix), nonce echo and kid must
   all match, or the call fails with bad_response (502) and nothing from it is used.
   Retry (mutations only): at most once, and only after a timeout or ECONNRESET that
   happened once the connection was established, i.e. when the request may have reached
   the daemon. The retry reuses the same idem with a fresh nonce and ts, so the daemon
   returns its stored result instead of applying twice. ECONNREFUSED / ENOENT mean nothing
   was sent: unavailable, no retry.
   Domain check: getMailStatus is cached for 10 s; if the daemon reports a domain other
   than the pinned one, every call throws domain_mismatch.
   Key: a Buffer handed in by index.js and kept on a closure, never on `this`. */

const net = require("net");
const C = require("./core/constants.js");
const V = require("./core/validate.js");
const protocol = require("./core/protocol.js");
const P = require("./provider.js");
const { sanitizeActor } = require("./mock-provider.js");

const { mailError, META } = P;
const STATUS_TTL_MS = 10 * 1000;
const DEFAULTS = Object.freeze({ connectMs: 1000, readMs: 5000, mutateMs: 8000, responseMax: C.LIMITS.responseMax });

/* Daemon codes that surface unchanged; everything else in (or outside) its enum becomes
   backend_failed (section 4.4). */
const PASS_THROUGH = new Set([
  "invalid_local", "reserved_local", "invalid_destination", "self_destination", "destination_not_mailbox",
  "too_many_destinations", "domain_destination_cap", "confirm_mismatch", "protected", "not_found",
  "duplicate", "tombstoned", "no_destination", "in_use", "conflict_rev", "idempotency_mismatch",
  "capability_missing", "limit_addresses", "limit_tombstones", "rate_limited", "busy", "backend_failed", "not_ready", "domain_mismatch",
]);

function tagged(code, afterConnect) {
  const e = new Error("mail socket " + code);
  e.sockCode = code;
  e.afterConnect = afterConnect;
  return e;
}

/* One connection, one frame out, one line back. Rejects with a tagged Error (no daemon
   text is ever attached). */
function roundTrip(socketPath, frame, totalMs, t) {
  return new Promise((resolve, reject) => {
    let connected = false;
    let done = false;
    let size = 0;
    const chunks = [];
    const sock = net.createConnection({ path: socketPath });
    const finish = (err, line) => {
      if (done) return;
      done = true;
      clearTimeout(connectTimer);
      clearTimeout(totalTimer);
      sock.destroy();
      if (err) reject(err); else resolve(line);
    };
    const connectTimer = setTimeout(() => finish(tagged("connect_timeout", false)), t.connectMs);
    const totalTimer = setTimeout(() => finish(tagged("timeout", connected)), totalMs);
    sock.on("connect", () => { connected = true; clearTimeout(connectTimer); sock.write(frame); });
    sock.on("data", (chunk) => {
      size += chunk.length;
      if (size > t.responseMax) return finish(tagged("too_large", true));
      chunks.push(chunk);
      const all = Buffer.concat(chunks);
      const nl = all.indexOf(10);
      if (nl >= 0) finish(null, all.subarray(0, nl + 1).toString("utf8"));
    });
    sock.on("error", (e) => finish(tagged(e && e.code ? e.code : "error", connected)));
    sock.on("close", () => finish(tagged("closed", connected)));
  });
}

class VpsMailProvider extends P.MailProvider {
  /* opts: { socketPath, kid, key: Buffer(32), timeouts?: {connectMs, readMs, mutateMs, responseMax}, now?: () => number } */
  constructor(opts, deps) {
    super(deps);
    const key = opts.key;
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new TypeError("mail service key must be 32 bytes");
    const kid = opts.kid;
    const socketPath = opts.socketPath;
    const t = Object.assign({}, DEFAULTS, opts.timeouts || {});
    const nowMs = opts.now || (() => Date.now());
    let statusCache = null; // { at, status }
    this.lastConnected = false;

    /* The key never leaves this closure. */
    const call = async (verb, args, ctx) => {
      const mutating = C.VERBS[verb].kind === "mutate";
      const actor = sanitizeActor(ctx && ctx.actor);
      let attempt = 0;
      for (;;) {
        attempt++;
        const payload = protocol.buildRequest({ verb, args, idem: ctx && ctx.idem, ifRev: ctx && ctx.ifRev, actor, nowMs: nowMs() });
        let frame;
        try { frame = protocol.encodeFrame("req", kid, key, payload); } catch (_) { throw mailError("backend_failed"); }
        let line;
        try {
          line = await roundTrip(socketPath, frame, mutating ? t.mutateMs : t.readMs, t);
        } catch (e) {
          const retryable = mutating && attempt === 1 && e.afterConnect && (e.sockCode === "timeout" || e.sockCode === "ECONNRESET" || e.sockCode === "EPIPE");
          if (retryable) continue;
          this.lastConnected = false;
          if (e.sockCode === "too_large") throw mailError("bad_response");
          throw mailError("unavailable");
        }
        let res;
        try { res = protocol.verifyResponse(line, kid, key, payload.nonce); } catch (_) { throw mailError("bad_response"); }
        this.lastConnected = true;
        if (!res.ok) {
          const code = PASS_THROUGH.has(res.error.code) ? res.error.code : "backend_failed";
          throw mailError(code, { refs: res.error.refs });
        }
        if (res.result !== null && typeof res.result === "object") Object.defineProperty(res.result, META, { value: { nonce: payload.nonce }, enumerable: false });
        return res.result;
      }
    };

    const status = async (force) => {
      const now = nowMs();
      if (!force && statusCache && now - statusCache.at < STATUS_TTL_MS) return statusCache.status;
      const s = await call("getMailStatus", {}, { actor: { user: "system", ip: "::" } });
      if (!V.isPlainObject(s)) throw mailError("bad_response");
      statusCache = { at: now, status: s };
      return s;
    };

    /* Every call except getMailStatus first checks the daemon's pinned domain. */
    const checked = async (verb, args, ctx) => {
      const s = await status(false);
      if (s.domain !== C.PINNED_DOMAIN) throw mailError("domain_mismatch");
      return call(verb, args, ctx);
    };

    Object.defineProperty(this, "_status", { value: status, enumerable: false });
    Object.defineProperty(this, "_call", { value: checked, enumerable: false });
    Object.defineProperty(this, "_invalidate", { value: () => { statusCache = null; }, enumerable: false });
  }

  get kind() { return "vps"; }

  async info() {
    try {
      const s = await this._status(false);
      if (s.domain !== C.PINNED_DOMAIN) return { kind: "vps", domain: C.PINNED_DOMAIN, connected: false, mock: false, reason: "domain_mismatch" };
      return { kind: "vps", domain: C.PINNED_DOMAIN, connected: true, mock: false, reason: null };
    } catch (_) {
      return { kind: "vps", domain: C.PINNED_DOMAIN, connected: false, mock: false, reason: "unavailable" };
    }
  }

  async getStatus() {
    const s = await this._status(true);
    if (s.domain !== C.PINNED_DOMAIN) throw mailError("domain_mismatch");
    return P.toPublicStatus(s, "vps", true);
  }

  async listAddresses() {
    const r = await this._call("listAddresses", {}, { actor: { user: "system", ip: "::" } });
    if (!V.isPlainObject(r) || !Array.isArray(r.addresses)) throw mailError("bad_response");
    return {
      rev: Number.isSafeInteger(r.rev) ? r.rev : null,
      addresses: r.addresses.map(P.toPublicAddress),
      tombstones: Array.isArray(r.tombstones) ? r.tombstones.map(P.toPublicTombstone) : [],
    };
  }

  async getAddress(local) {
    if (!V.isValidLocal(local)) throw mailError("not_found");
    const list = await this.listAddresses();
    const a = list.addresses.find((x) => x.local === local);
    if (!a) throw mailError("not_found");
    return a;
  }

  async _mut(verb, args, ctx) {
    if (!ctx || typeof ctx.idem !== "string" || !C.UUID_V4_RE.test(ctx.idem)) throw mailError("missing_idempotency_key");
    if (!Number.isSafeInteger(ctx.ifRev) || ctx.ifRev < 0) throw mailError("invalid_body", { field: "rev" });
    const r = await this._call(verb, args, ctx);
    if (!V.isPlainObject(r) || !Number.isSafeInteger(r.rev)) throw mailError("bad_response");
    return r;
  }

  async createAddress(p, ctx) {
    const r = await this._mut("createAddress", {
      local: p.local, forwards: p.forwards || [], mailbox: p.passwordHash ? { passwordHash: p.passwordHash } : null, reuseDeleted: p.reuseDeleted === true,
    }, ctx);
    return keepMeta(r, { rev: r.rev, changed: r.changed !== false, address: P.toPublicAddress(r.address), resumesExistingMaildir: r.resumesExistingMaildir === true });
  }

  async deleteAddress(p, ctx) {
    const r = await this._mut("deleteAddress", { local: p.local, confirm: typeof p.confirm === "string" ? p.confirm : "" }, ctx);
    return keepMeta(r, { rev: r.rev, changed: r.changed !== false, mailboxDataRetained: r.mailboxDataRetained === true });
  }

  async updateForwarding(p, ctx) {
    const forwards = p.forwards || [];
    const r = forwards.length
      ? await this._mut("setForwarding", { local: p.local, forwards }, ctx)
      : await this._mut("removeForwarding", { local: p.local }, ctx);
    return addressResult(r);
  }

  async setAddressEnabled(p, ctx) {
    return addressResult(await this._mut("setAddressEnabled", { local: p.local, enabled: p.enabled === true }, ctx));
  }

  async createMailbox(p, ctx) {
    return addressResult(await this._mut("createMailbox", { local: p.local, passwordHash: p.passwordHash }, ctx));
  }

  async setMailboxEnabled(p, ctx) {
    return addressResult(await this._mut(p.enabled === true ? "enableMailbox" : "disableMailbox", { local: p.local }, ctx));
  }

  async changeMailboxPassword(p, ctx) {
    const r = await this._mut("changeMailboxPassword", { local: p.local, passwordHash: p.passwordHash }, ctx);
    return keepMeta(r, { rev: r.rev, changed: r.changed !== false, passwordSetAt: typeof r.passwordSetAt === "string" && r.passwordSetAt.length <= 40 ? r.passwordSetAt : null });
  }

  async auditTail(p) {
    const limit = Math.max(1, Math.min(C.LIMITS.auditTailMax, (p && p.limit) || 50));
    const beforeSeq = p && Number.isSafeInteger(p.beforeSeq) && p.beforeSeq > 0 ? p.beforeSeq : null;
    const r = await this._call("getAuditTail", { limit, beforeSeq }, { actor: { user: "system", ip: "::" } });
    if (!V.isPlainObject(r) || !Array.isArray(r.entries)) throw mailError("bad_response");
    return { entries: r.entries.map(P.toPublicServiceEntry).filter(Boolean), nextBeforeSeq: Number.isSafeInteger(r.nextBeforeSeq) ? r.nextBeforeSeq : null };
  }
}

function keepMeta(src, out) {
  Object.defineProperty(out, META, { value: src[META] || { nonce: null }, enumerable: false });
  return out;
}
function addressResult(r) {
  return keepMeta(r, { rev: r.rev, changed: r.changed !== false, address: P.toPublicAddress(r.address) });
}

module.exports = { VpsMailProvider, roundTrip, DEFAULTS };
