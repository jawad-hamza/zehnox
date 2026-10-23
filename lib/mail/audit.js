"use strict";
/* Audit logs (DESIGN.md section 14).

   createChainLog: a generic append-only, hash-chained JSONL file. Each line carries `seq`
     and `prev` = sha256 of the previous line's exact bytes, so an edited, deleted or
     truncated line is detectable by verify(). Writes go through one in-process promise
     queue, so lines never interleave. At maxBytes the file is renamed to
     <name>-YYYYMMDDHHmm.jsonl (newest `keep` kept) and the chain continues: the first line
     of the new file carries the hash of the old file's last line.
   createAppAudit: the admin-panel audit (DATA/mail/audit.jsonl) on top of it, with the
     per-action detail allowlist and redaction. record() never throws: an audit failure is
     logged and the mail change it describes is not reverted.

   The mock provider also uses createChainLog for its "service" audit (mock/audit.jsonl). */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { redactDeep } = require("./redact.js");
const V = require("./core/validate.js");
const C = require("./core/constants.js");

const sha256 = (s) => crypto.createHash("sha256").update(s, "utf8").digest("hex");
const MAX_BYTES = 5 * 1024 * 1024;
const KEEP = 10;

function stamp(d) {
  const p = (n) => String(n).padStart(2, "0");
  return d.getUTCFullYear() + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) + p(d.getUTCHours()) + p(d.getUTCMinutes());
}

function readText(file) {
  try { return fs.readFileSync(file, "utf8"); } catch (e) { if (e.code === "ENOENT") return ""; throw e; }
}
const splitLines = (text) => text.split("\n").filter((l) => l.length);

function createChainLog(opts) {
  const file = opts.file;
  const dir = path.dirname(file);
  const base = path.basename(file, ".jsonl");
  const maxBytes = opts.maxBytes || MAX_BYTES;
  const keep = opts.keep || KEEP;
  const now = opts.now || (() => new Date());
  let loaded = false;
  let lastSeq = 0;
  let lastHash = null;
  let size = 0;
  let chain = Promise.resolve();

  const ROTATED_RE = new RegExp("^" + base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "-(\\d{12})(?:-(\\d+))?\\.jsonl$");
  const rotKey = (n) => { const m = n.match(ROTATED_RE); return [m[1], m[2] ? parseInt(m[2], 10) : 0]; };
  /* Oldest first. Sorted by (stamp, counter) rather than by name: for rotations in the
     same minute a plain string sort puts "-1" before the unsuffixed (older) file and "-10"
     before "-2", which would prune the wrong file and misplace the chain head. */
  const rotatedFiles = () => {
    let names = [];
    try { names = fs.readdirSync(dir); } catch (_) { return []; }
    return names.filter((n) => ROTATED_RE.test(n))
      .sort((a, b) => { const x = rotKey(a); const y = rotKey(b); return x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : x[1] - y[1]; })
      .map((n) => path.join(dir, n));
  };

  /* Finds the chain head: the live file's last line, or the newest rotated file's. */
  function load() {
    if (loaded) return;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tryFile = (f) => {
      const lines = splitLines(readText(f));
      for (let i = lines.length - 1; i >= 0; i--) {
        try {
          const rec = JSON.parse(lines[i]);
          if (Number.isSafeInteger(rec.seq)) { lastSeq = rec.seq; lastHash = sha256(lines[i]); return true; }
        } catch (_) { /* a torn last line: keep looking backwards */ }
      }
      return false;
    };
    try { size = fs.statSync(file).size; } catch (_) { size = 0; }
    if (!tryFile(file)) { const r = rotatedFiles(); if (r.length) tryFile(r[r.length - 1]); }
    loaded = true;
  }

  function rotate() {
    /* The counter continues after the newest file of the same minute, so a name freed by
       pruning is never reused (a reused, lower name would sort as older than it is). */
    const st = stamp(now());
    const same = rotatedFiles().map((f) => rotKey(path.basename(f))).filter((k) => k[0] === st);
    const n = same.length ? Math.max(...same.map((k) => k[1])) + 1 : 0;
    const target = path.join(dir, base + "-" + st + (n ? "-" + n : "") + ".jsonl");
    fs.renameSync(file, target);
    size = 0;
    const all = rotatedFiles();
    for (const old of all.slice(0, Math.max(0, all.length - keep))) { try { fs.unlinkSync(old); } catch (_) { /* best effort */ } }
  }

  /* build(seq, prev) -> the record object. Returns a promise of the written record. */
  function append(build) {
    const job = chain.then(async () => {
      load();
      const rec = build(lastSeq + 1, lastHash);
      const line = JSON.stringify(rec);
      const bytes = Buffer.byteLength(line) + 1;
      if (size > 0 && size + bytes > maxBytes) rotate();
      await fs.promises.appendFile(file, line + "\n", { flag: "a", mode: 0o600 });
      size += bytes;
      lastSeq = rec.seq;
      lastHash = sha256(line);
      return rec;
    });
    chain = job.catch(() => {});
    return job;
  }

  /* Newest first. before: return entries with seq < before. filter: optional predicate.
     Reads the live file and, if needed, rotated files from newest to oldest. */
  async function tail(o) {
    const limit = Math.max(1, Math.min(200, (o && o.limit) || 50));
    const before = o && Number.isSafeInteger(o.before) ? o.before : Infinity;
    const filter = o && typeof o.filter === "function" ? o.filter : null;
    await chain;
    const files = [file].concat(rotatedFiles().reverse());
    const out = [];
    for (const f of files) {
      let text = "";
      try { text = await fs.promises.readFile(f, "utf8"); } catch (_) { continue; }
      const lines = splitLines(text);
      for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
        let rec;
        try { rec = JSON.parse(lines[i]); } catch (_) { continue; }
        if (!rec || !Number.isSafeInteger(rec.seq) || rec.seq >= before) continue;
        if (filter && !filter(rec)) continue;
        out.push(rec);
      }
      if (out.length >= limit) break;
    }
    return { entries: out, next: out.length === limit ? out[out.length - 1].seq : null };
  }

  /* Recomputes the chain across the live file. The first line's prev is the anchor (it
     points into the rotated file or is null for a brand-new log). */
  async function verify() {
    await chain;
    let text = "";
    try { text = await fs.promises.readFile(file, "utf8"); } catch (e) { if (e.code !== "ENOENT") throw e; }
    const lines = text.split("\n");
    const torn = lines[lines.length - 1] !== "";
    if (!torn) lines.pop();
    const recs = lines.map((l) => { try { const r = JSON.parse(l); return r && Number.isSafeInteger(r.seq) ? r : null; } catch (_) { return null; } });
    let prevSeq = null;
    for (let i = 0; i < lines.length; i++) {
      const r = recs[i];
      if (!r || (i === lines.length - 1 && torn)) return { ok: false, firstBrokenSeq: prevSeq == null ? 1 : prevSeq + 1, count: i };
      if (prevSeq != null && r.seq !== prevSeq + 1) return { ok: false, firstBrokenSeq: prevSeq + 1, count: i };
      if (i > 0 && r.prev !== sha256(lines[i - 1])) {
        /* Either line i-1 was edited (only line i disagrees), or line i itself was edited
           in its prev field (then line i+1 disagrees with line i as well). */
        const next = recs[i + 1];
        const alsoNext = next && next.prev !== sha256(lines[i]);
        return { ok: false, firstBrokenSeq: alsoNext ? r.seq : recs[i - 1].seq, count: i };
      }
      prevSeq = r.seq;
    }
    return { ok: true, firstBrokenSeq: null, count: lines.length };
  }

  return { append, tail, verify, file, get head() { return { seq: lastSeq, hash: lastHash }; } };
}

/* ---------- the app audit ---------- */

const ACTIONS = Object.freeze({
  "address.create": { type: "type", forwards: "strings" },
  "address.delete": { type: "type", mailboxDataRetained: "bool" },
  "address.enable": {},
  "address.disable": {},
  "forwarding.set": { before: "strings", after: "strings" },
  "forwarding.remove": { before: "strings" },
  "mailbox.create": { generated: "bool" },
  "mailbox.enable": {},
  "mailbox.disable": {},
  "mailbox.password_change": { generated: "bool" },
  "smtp.settings_update": { changed: "fields", values: "values", passwordRemovedByRebind: "bool" },
  "smtp.password_set": {},
  "smtp.password_clear": {},
  "smtp.password_rotate": {},
  "smtp.test": { to: "email", passed: "bool", stage: "token", smtpCode: "code" },
  "request.refused": { route: "route", code: "token" },
  "rate_limit.summary": { limiter: "token", count: "int" },
});
const SMTP_FIELDS = new Set(["host", "port", "tlsMode", "username", "fromLocal", "fromName", "password"]);
const VALUE_FIELDS = new Set(["host", "port", "tlsMode", "username", "fromLocal"]);
const TYPES = new Set(["forward", "mailbox", "mailbox+forward"]);

function detailError() { return new TypeError("audit: detail not allowed for this action"); }

/* Throws on an unknown action, an unknown key or a value of the wrong kind. Keys are all
   optional (a refused request may know only part of the detail). */
function sanitizeDetail(action, detail) {
  if (!V.hasOwn(ACTIONS, action)) throw new TypeError("audit: unknown action");
  const spec = ACTIONS[action];
  const d = detail == null ? {} : detail;
  if (!V.isPlainObject(d)) throw detailError();
  const out = {};
  for (const k of Object.keys(d)) {
    if (!V.hasOwn(spec, k)) throw detailError();
    const v = d[k];
    switch (spec[k]) {
      case "bool": if (typeof v !== "boolean") throw detailError(); out[k] = v; break;
      case "int": if (!Number.isSafeInteger(v)) throw detailError(); out[k] = v; break;
      case "code": if (v !== null && !Number.isSafeInteger(v)) throw detailError(); out[k] = v; break;
      case "type": if (!TYPES.has(v)) throw detailError(); out[k] = v; break;
      case "token": if (typeof v !== "string" || !/^[A-Za-z0-9_.]{1,40}$/.test(v)) throw detailError(); out[k] = v; break;
      case "route": if (typeof v !== "string" || !/^[A-Z]{3,6} \/api\/mail[a-z0-9/_:.-]{0,80}$/.test(v)) throw detailError(); out[k] = v; break;
      case "email": if (typeof v !== "string" || v.length > 254) throw detailError(); out[k] = v; break;
      case "strings":
        if (!Array.isArray(v) || v.length > 10 || v.some((x) => typeof x !== "string" || x.length > 254)) throw detailError();
        out[k] = v.slice(); break;
      case "fields":
        if (!Array.isArray(v) || v.some((x) => !SMTP_FIELDS.has(x))) throw detailError();
        out[k] = v.slice(); break;
      case "values": {
        if (!V.isPlainObject(v)) throw detailError();
        const vals = {};
        for (const f of Object.keys(v)) {
          if (!VALUE_FIELDS.has(f)) throw detailError();
          const x = v[f];
          if (!(typeof x === "string" && x.length <= 254) && !Number.isSafeInteger(x)) throw detailError();
          vals[f] = x;
        }
        out[k] = vals; break;
      }
      default: throw detailError();
    }
  }
  return out;
}

const RESULTS = new Set(["ok", "error", "refused"]);

/* opts: { file, provider: () => 'mock'|'vps'|'none', logErr, now, maxBytes, keep } */
function createAppAudit(opts) {
  const log = createChainLog(opts);
  const logErr = opts.logErr || (() => {});
  const providerKind = typeof opts.provider === "function" ? opts.provider : () => opts.provider || null;
  const now = opts.now || (() => new Date());
  const rateSeen = new Map(); // limiter -> { lastWritten, pending }

  /* entry: { actor:{user,via,ip}, action, target, result, code, detail, idem, serviceNonce, rev }
     -> Promise<record|null>. Never rejects. */
  function record(entry) {
    let detail;
    try {
      /* The allowlist vouches for the top-level keys (so "passwordRemovedByRebind" is kept
         although it matches the sensitive-key pattern); values still go through redactDeep
         so a hash-like or long base64 string is masked wherever it appears. */
      const clean = sanitizeDetail(entry.action, entry.detail);
      detail = {};
      for (const k of Object.keys(clean)) detail[k] = typeof clean[k] === "object" && clean[k] !== null ? redactDeep(clean[k]) : typeof clean[k] === "string" ? redactDeep(clean[k]) : clean[k];
    } catch (_) {
      logErr("mail: audit detail rejected");
      return Promise.resolve(null);
    }
    const a = entry.actor || {};
    const at = now();
    return log.append((seq, prev) => ({
      v: 1,
      seq,
      id: at.getTime().toString(36) + "-" + crypto.randomBytes(4).toString("hex"),
      at: at.toISOString(),
      actor: { user: typeof a.user === "string" ? a.user.slice(0, 80) : null, via: a.via === "bearer" ? "bearer" : a.via === "cookie" ? "cookie" : null, ip: typeof a.ip === "string" ? a.ip.slice(0, 45) : null },
      action: entry.action,
      target: typeof entry.target === "string" && C.KEY_RE.test(entry.target) ? entry.target : null,
      result: RESULTS.has(entry.result) ? entry.result : "error",
      code: typeof entry.code === "string" && /^[a-z_]{1,40}$/.test(entry.code) ? entry.code : null,
      detail,
      provider: providerKind(),
      idem: typeof entry.idem === "string" && C.UUID_V4_RE.test(entry.idem) ? entry.idem : null,
      serviceNonce: typeof entry.serviceNonce === "string" && /^[0-9a-f]{32}$/.test(entry.serviceNonce) ? entry.serviceNonce : null,
      rev: Number.isSafeInteger(entry.rev) ? entry.rev : null,
      prev,
    })).catch(() => { logErr("mail: audit append failed"); return null; });
  }

  /* 429s are summarised: at most one rate_limit.summary line per limiter per minute, with
     the count of rejections since the last line. */
  function rateLimited(limiter, actor) {
    const t = now().getTime();
    const s = rateSeen.get(limiter) || { lastWritten: 0, pending: 0 };
    s.pending++;
    rateSeen.set(limiter, s);
    if (t - s.lastWritten < 60 * 1000) return Promise.resolve(null);
    const count = s.pending;
    s.pending = 0;
    s.lastWritten = t;
    return record({ actor, action: "rate_limit.summary", target: null, result: "refused", code: "rate_limited", detail: { limiter, count } });
  }

  /* opts: { limit 1..100, before, target } -> { entries, next } */
  function tail(o) {
    const target = o && typeof o.target === "string" ? o.target : null;
    return log.tail({ limit: Math.min(100, (o && o.limit) || 50), before: o && o.before, filter: target ? (r) => r.target === target : null });
  }

  return { record, rateLimited, tail, verify: log.verify, file: log.file };
}

module.exports = { createChainLog, createAppAudit, sanitizeDetail, ACTIONS, sha256 };
