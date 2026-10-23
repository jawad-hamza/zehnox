"use strict";
/* MockMailProvider (DESIGN.md section 4.3).

   The same engine as the daemon: core.apply, render and assertRendered from lib/mail/core,
   the same ifRev, idempotency, tombstone, in_use and limit rules. Only the applier differs:
   instead of running postmap it writes the rendered files under DATA/mail/mock/render/ so
   a developer can read exactly the bytes the VPS would receive. It never starts a process
   and never opens a socket.

   Files (all 0600, written atomically):
     DATA/mail/mock/state.json     same schema as the daemon's (no hashes)
     DATA/mail/mock/hashes.json    development hashes only
     DATA/mail/mock/idem.json      idempotency records (10 min, last 1000)
     DATA/mail/mock/audit.jsonl    the "service" audit in mock mode (hash chained)
     DATA/mail/mock/render/{virtual,vmailbox,sender_login,sasl_access,passwd}

   State is re-read from disk on every call (the files are small), so two instances on the
   same DATA dir agree, and a hand edit is picked up (and re-validated) immediately. */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { writeFileAtomic } = require("../../write-file.js");
const C = require("./core/constants.js");
const V = require("./core/validate.js");
const S = require("./core/state.js");
const core = require("./core/core.js");
const R = require("./core/render.js");
const { createChainLog } = require("./audit.js");
const crypt = require("./crypt.js");
const P = require("./provider.js");

const { mailError, fromCoreError, META } = P;
const MOCK_DKIM = "MOCKMOCKMOCKMOCKMOCKMOCKMOCKMOCKMOCKMOCKMOCKMOCK";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class MockMailProvider extends P.MailProvider {
  /* opts: { dir: DATA/mail/mock, cfg: loadMailConfig().cfg, now?: () => Date } */
  constructor(opts, deps) {
    super(deps);
    this.dir = opts.dir;
    this.cfg = opts.cfg;
    this.now = opts.now || (() => new Date());
    this.startedAt = this.now().toISOString();
    this.lock = Promise.resolve();
    this.audit = createChainLog({ file: path.join(this.dir, "audit.jsonl"), now: this.now });
    this.caps = { mailboxes: this.cfg.mock.caps !== "forward-only" };
    this.hashPolicy = {
      schemes: this.cfg.passwordScheme === "ARGON2ID" ? ["SHA512-CRYPT", "ARGON2ID"] : ["SHA512-CRYPT"],
      minRounds: this.cfg.nodeEnv === "test" ? 1000 : C.LIMITS.minRounds,
    };
    /* The daemon refuses forwards to its own mail host (local delivery through
       /etc/aliases); the mock rehearses the same rule with MAIL_HOSTNAME when it is set. */
    this.forwardDeny = Object.freeze(this.cfg.hostname ? [this.cfg.hostname] : []);
  }

  get kind() { return "mock"; }

  /* Fault injection is honoured only outside production (section 4.3). */
  _fault() { return this.cfg.production ? "" : this.cfg.mock.fail; }
  async _faults(mutating) {
    const f = this._fault();
    if (f === "slow") await sleep(3000);
    if (f === "unavailable") throw mailError("unavailable");
    if (f === "backend_failed" && mutating) throw mailError("backend_failed");
  }

  _file(name) { return path.join(this.dir, name); }
  _readJson(name) {
    try { return JSON.parse(fs.readFileSync(this._file(name), "utf8")); } catch (e) { if (e.code === "ENOENT") return undefined; throw mailError("not_ready"); }
  }
  _write(name, text) {
    writeFileAtomic(this._file(name), text, { mode: 0o600 });
  }

  _bootstrapForward() {
    const f = this.cfg.bootstrapForward;
    return f && V.isDestination(f) && !V.isSameDomain(f.toLowerCase()) ? f : "owner@example.invalid";
  }

  /* First run only (no state.json): protected postmaster@ and abuse@, plus the optional
     development seed. Seeding never happens in production, whatever MAIL_MOCK_SEED says. */
  _bootstrap() {
    const nowIso = this.now().toISOString();
    let state = S.bootstrapState(this._bootstrapForward(), nowIso);
    let hashes = S.emptyHashes();
    if (this.cfg.mock.seed && !this.cfg.production) {
      const ctx = { now: nowIso, capabilities: { mailboxes: true }, hashPolicy: { minRounds: 1000 } };
      // Throwaway hashes of random passwords nobody ever sees: the seed mailboxes exist to
      // render the UI, not to be signed in to.
      const devHash = () => crypt.sha512Crypt(crypto.randomBytes(18).toString("base64url"), { rounds: 1000, minRounds: 1000 });
      const seeds = [
        { local: "info", forwards: ["owner@example.com"], mailbox: null, reuseDeleted: false },
        { local: "contact", forwards: ["management@example.com"], mailbox: { passwordHash: devHash() }, reuseDeleted: false },
        { local: "careers", forwards: [], mailbox: { passwordHash: devHash() }, reuseDeleted: false },
      ];
      for (const args of seeds) { const r = core.apply(state, hashes, "createAddress", args, ctx); state = r.state; hashes = r.hashes; }
    }
    this._commit(state, hashes);
    return { state, hashes };
  }

  _load() {
    fs.mkdirSync(path.join(this.dir, "render"), { recursive: true, mode: 0o700 });
    const state = this._readJson("state.json");
    if (state === undefined) return this._bootstrap();
    const hashes = this._readJson("hashes.json") || S.emptyHashes();
    try {
      S.checkState(state);
      S.checkHashes(hashes);
    } catch (_) {
      throw mailError("not_ready");
    }
    return { state, hashes };
  }

  _render(state, hashes) {
    return R.assertRendered(R.render(state, hashes, { mailboxes: this.caps.mailboxes }));
  }

  /* Same order as the daemon's commit: rendered files, then hashes, then state (state.json
     carries rev, so it is the last thing to change). */
  _commit(state, hashes) {
    const files = this._render(state, hashes);
    /* The real bytes are asserted above; the inspection copy of passwd masks the hash so
       that hashes.json stays the only file under DATA holding one (the canary sweep in
       the API tests relies on that). Every other file is byte-identical to the VPS's. */
    const inspect = Object.assign({}, files, { passwd: files.passwd.replace(/:\{(SHA512-CRYPT|ARGON2ID)\}[^:]+:/g, ":{$1}<see hashes.json>:") });
    for (const f of R.FILES) writeFileAtomic(path.join(this.dir, "render", f), inspect[f], { mode: 0o600 });
    this._write("hashes.json", JSON.stringify(hashes, null, 2) + "\n");
    this._write("state.json", JSON.stringify(state, null, 2) + "\n");
    return files;
  }

  _serialize(fn) {
    const run = this.lock.then(fn);
    this.lock = run.catch(() => {});
    return run;
  }

  async _mutate(verb, args, ctx) {
    await this._faults(true);
    if (!ctx || typeof ctx.idem !== "string" || !C.UUID_V4_RE.test(ctx.idem)) throw mailError("missing_idempotency_key");
    if (!Number.isSafeInteger(ctx.ifRev) || ctx.ifRev < 0) throw mailError("invalid_body", { field: "rev" });
    const actor = sanitizeActor(ctx.actor);
    return this._serialize(async () => {
      const nowDate = this.now();
      const nowMs = nowDate.getTime();
      const nonce = crypto.randomBytes(16).toString("hex");
      const { state, hashes } = this._load();
      const idemFile = this._readJson("idem.json");
      const idemEntries = idemFile && Array.isArray(idemFile.entries) ? idemFile.entries : [];
      let out;
      try {
        const sha = core.argsSha256(verb, args);
        const cached = core.idemLookup(idemEntries, ctx.idem, verb, sha, nowMs);
        if (cached) return withMeta(S.clone(cached), null);
        if (ctx.ifRev !== state.rev) throw new C.CoreError("conflict_rev");
        const r = core.apply(state, hashes, verb, args, { now: nowDate.toISOString(), capabilities: this.caps, hashPolicy: this.hashPolicy, forwardDeny: this.forwardDeny });
        let files = null;
        if (r.changed) files = this._commit(r.state, r.hashes);
        else this._render(state, hashes); // assert even on a no-op, as the daemon does
        out = r.result;
        await this._auditService({ nowDate, verb, target: args.local, actor, nonce, idem: ctx.idem, ok: true, code: null, rev: out.rev, files });
        const nextIdem = core.idemRemember(idemEntries, { idem: ctx.idem, argsSha256: sha, verb, response: out }, nowMs);
        this._write("idem.json", JSON.stringify({ v: 1, entries: nextIdem }) + "\n");
      } catch (e) {
        const err = e instanceof P.MailError ? e : fromCoreError(e);
        await this._auditService({ nowDate, verb, target: args && V.isValidLocal(args.local) ? args.local : null, actor, nonce, idem: ctx.idem, ok: false, code: err.code, rev: state.rev, files: null });
        throw err;
      }
      return withMeta(S.clone(out), nonce);
    });
  }

  async _auditService(e) {
    const hashesOf = e.files ? Object.fromEntries(R.FILES.map((f) => [f, crypto.createHash("sha256").update(e.files[f]).digest("hex")])) : null;
    try {
      await this.audit.append((seq, prev) => ({
        seq, at: e.nowDate.toISOString(), verb: e.verb, target: e.target, actor: e.actor, nonce: e.nonce,
        idem: e.idem, ok: e.ok, code: e.code, rev: e.rev, files: hashesOf, prev,
      }));
    } catch (_) { /* the service audit is best effort in the mock; the change stands */ }
  }

  /* ---------- MailProvider interface ---------- */

  async info() {
    const down = this._fault() === "unavailable";
    return { kind: "mock", domain: C.PINNED_DOMAIN, connected: !down, mock: true, reason: down ? "unavailable" : null };
  }

  async getStatus() {
    await this._faults(false);
    const { state } = await this._serialize(() => this._load());
    const st = this.cfg.production ? "online" : this.cfg.mock.status;
    const up = st === "online";
    return P.toPublicStatus({
      domain: C.PINNED_DOMAIN,
      rev: state.rev,
      service: {
        state: st,
        smtp: st === "offline" ? "down" : "up",
        submission: up ? "up" : "down",
        imap: st === "offline" ? "down" : this.caps.mailboxes ? "up" : "absent",
        mapsInSync: up,
        selfCheck: up ? "ok" : "mock_" + st,
        checkedAt: this.now().toISOString(),
      },
      capabilities: { mailboxes: this.caps.mailboxes, schemes: this.hashPolicy.schemes },
      dkim: { selector: this.cfg.dkimSelector || "sbhm1", publicKey: MOCK_DKIM },
      daemon: { version: "mock", startedAt: this.startedAt },
    }, "mock", true);
  }

  async listAddresses() {
    await this._faults(false);
    const { state, hashes } = await this._serialize(() => this._load());
    const view = S.listView(state, hashes);
    return { rev: view.rev, addresses: view.addresses.map(P.toPublicAddress), tombstones: view.tombstones.map(P.toPublicTombstone) };
  }

  async getAddress(local) {
    if (!V.isValidLocal(local)) throw mailError("not_found");
    const list = await this.listAddresses();
    const a = list.addresses.find((x) => x.local === local);
    if (!a) throw mailError("not_found");
    return a;
  }

  async createAddress(p, ctx) {
    const r = await this._mutate("createAddress", {
      local: p.local, forwards: p.forwards || [], mailbox: p.passwordHash ? { passwordHash: p.passwordHash } : null, reuseDeleted: p.reuseDeleted === true,
    }, ctx);
    return withMeta({ rev: r.rev, changed: r.changed, address: P.toPublicAddress(r.address), resumesExistingMaildir: r.resumesExistingMaildir === true }, r[META]);
  }

  async deleteAddress(p, ctx) {
    const r = await this._mutate("deleteAddress", { local: p.local, confirm: typeof p.confirm === "string" ? p.confirm : "" }, ctx);
    return withMeta({ rev: r.rev, changed: r.changed, mailboxDataRetained: r.mailboxDataRetained === true }, r[META]);
  }

  async updateForwarding(p, ctx) {
    const forwards = p.forwards || [];
    const r = forwards.length
      ? await this._mutate("setForwarding", { local: p.local, forwards }, ctx)
      : await this._mutate("removeForwarding", { local: p.local }, ctx);
    return addressResult(r);
  }

  async setAddressEnabled(p, ctx) {
    return addressResult(await this._mutate("setAddressEnabled", { local: p.local, enabled: p.enabled === true }, ctx));
  }

  async createMailbox(p, ctx) {
    return addressResult(await this._mutate("createMailbox", { local: p.local, passwordHash: p.passwordHash }, ctx));
  }

  async setMailboxEnabled(p, ctx) {
    return addressResult(await this._mutate(p.enabled === true ? "enableMailbox" : "disableMailbox", { local: p.local }, ctx));
  }

  async changeMailboxPassword(p, ctx) {
    const r = await this._mutate("changeMailboxPassword", { local: p.local, passwordHash: p.passwordHash }, ctx);
    return withMeta({ rev: r.rev, changed: r.changed, passwordSetAt: typeof r.passwordSetAt === "string" ? r.passwordSetAt : null }, r[META]);
  }

  async auditTail(p) {
    await this._faults(false);
    const limit = Math.max(1, Math.min(C.LIMITS.auditTailMax, (p && p.limit) || 50));
    const t = await this.audit.tail({ limit, before: p && Number.isSafeInteger(p.beforeSeq) ? p.beforeSeq : undefined });
    return { entries: t.entries.map(P.toPublicServiceEntry).filter(Boolean), nextBeforeSeq: t.next };
  }
}

function withMeta(obj, nonce) {
  Object.defineProperty(obj, META, { value: { nonce }, enumerable: false });
  return obj;
}
function addressResult(r) {
  return withMeta({ rev: r.rev, changed: r.changed, address: P.toPublicAddress(r.address) }, r[META]);
}
/* The same actor rules as the wire protocol, so mock audit lines look like the daemon's. */
function sanitizeActor(a) {
  const user = String((a && a.user) || "unknown").replace(/[^A-Za-z0-9._@-]/g, "_").slice(0, 64) || "unknown";
  const ip = a && typeof a.ip === "string" && C.ACTOR_IP_RE.test(a.ip) ? a.ip : "::";
  return { user, ip };
}

module.exports = { MockMailProvider, sanitizeActor, MOCK_DKIM };
