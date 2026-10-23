#!/usr/bin/env node
"use strict";
/* zehnox-maild: the privileged mail-management service (docs/mail/DESIGN.md section 5).

   Trust chain (D1): web container -> HMAC-signed frame over a Unix socket -> this process,
   running as the unprivileged user zehnox-mail -> files it owns under
   /var/lib/zehnox-mail, which Postfix and Dovecot read. It needs no root at runtime (D2).

   What it does:
   - Serves exactly the frozen 12-verb table (lib/mail/core/constants.js VERBS). There is no
     generic dispatch: HANDLERS below is asserted equal to that list at load time.
   - Verifies every frame (shape -> kid -> constant-time MAC -> only then parse), then the
     timestamp window, the start floor, the nonce cache and the strict schema.
   - Keeps state.json as the single source of truth (D3) and renders the four Postfix maps
     and the Dovecot passwd-file in full from it, through the same pure core the web side
     and the mock use. assertRendered() is the last gate before anything is written.
   - Applies changes atomically with a *.prev copy of every live file it touches, restores
     them on any failure, and reconciles live files against state at startup and every 60 s.
   - Its only subprocess is the Postfix map indexer, with an argv table built once at
     startup from the config (POSTMAP_ARGV). No request data can reach argv, no shell is
     involved, and its output goes to journald truncated, never into a response.

   What it never does (section 5.8): accept a domain, path, command or unknown field; use a
   shell or evaluate code; read or write Postfix/Dovecot/OpenDKIM config; write anything
   outside its state directory; reload or restart any service; delete a maildir; see a
   plaintext password; listen on TCP or resolve DNS; return a hash, a key or subprocess output.

   Layout: installed as /usr/local/lib/zehnox-mail/zehnox-maild.js with the core copied
   to ./core next to it. In the repository (tests), the core is loaded from ../lib/mail/core.
   Runs on Node 18 or later, stdlib only.

   Modes (owner CLI, section 5.7; none of them is reachable through the socket):
     --config <file>                      serve (systemd socket activation: fd 3, or --listen <path>)
     --status                             read-only diagnosis as JSON (no socket needed)
     --check-config                       validate the config and the key files, then exit
     --reconcile [--dry-run]              one self-check + reconcile (dry run: report only)
     --import --postfix-map <f> [--passwd-file <f>] [--dry-run]
                                          adopt hand-made @zehnox.com entries
     --purge-tombstone <local>            forget a deleted address (the maildir stays; rm -r it by hand)
     --print-manifest                     sha256 of this file and core/*.js
   Sandbox (tests and local rehearsal only, never on the VPS):
     --sandbox                            any absolute stateDir, a fake indexer binary
                                          (postmapPath + postmapPreArgs), no owner/group checks
     --no-postmap                         with --sandbox: render and write, but run no indexer */

const fs = require("fs");
const path = require("path");
const net = require("net");
const crypto = require("crypto");
const cp = require("child_process");

const WIN = process.platform === "win32";
const VERSION = "1.0.0";

/* ---------- core resolution (section 5.1) ---------- */

const CORE_DIR = (() => {
  const installed = path.join(__dirname, "core");
  return fs.existsSync(path.join(installed, "constants.js")) ? installed : path.join(__dirname, "..", "lib", "mail", "core");
})();
const C = require(path.join(CORE_DIR, "constants.js"));
const V = require(path.join(CORE_DIR, "validate.js"));
const S = require(path.join(CORE_DIR, "state.js"));
const core = require(path.join(CORE_DIR, "core.js"));
const R = require(path.join(CORE_DIR, "render.js"));
const protocol = require(path.join(CORE_DIR, "protocol.js"));
const { CoreError } = C;

/* ---------- constants ---------- */

const PROD_STATE_DIR = "/var/lib/zehnox-mail";
const PROD_POSTMAP = "/usr/sbin/postmap";
const PROD_HOME_BASE = "/var/vmail/" + C.PINNED_DOMAIN;
const PROD_ETC = "/etc/zehnox-mail/";
const MAPS = Object.freeze(["virtual", "vmailbox", "sender_login", "sasl_access"]);
const INDEX_EXT = Object.freeze({ hash: ".db", lmdb: ".lmdb" });
const RESTRICTION_CLASS = "zehnox_sender";
/* Concurrent connections. Each costs a few KB, so the cap is generous: anyone who can open
   the socket (no key needed) could otherwise fill a small table with idle connections. */
const MAX_CONNECTIONS = 32;
const READ_TIMEOUT_MS = 3000;
/* A real client writes its frame right after connecting. A connection that has sent nothing
   by then is closed, so idle connections cannot hold the slots for the full read timeout. */
const FIRST_BYTE_MS = 500;
/* getMailStatus opens three connections to the shared MTA per call (25, 587, 993 on
   localhost, which is usually exempt from anvil/postscreen limits). The results are cached
   and only one probe round runs at a time, so a flood of status calls cannot turn into a
   flood of connections to the strategicbhm.com mail server. */
const PROBE_CACHE_MS = 10 * 1000;
const PERIOD_MS = 60 * 1000;
const PROBE_TIMEOUT_MS = 2000;
const AUDIT_MAX_BYTES = 5 * 1024 * 1024;
const AUDIT_KEEP = 10;
/* Two rotations less than this apart means something is writing far more than normal use
   ever would: say so in the journal (event=audit_rotation_pressure). */
const AUDIT_PRESSURE_MS = 60 * 60 * 1000;
const OUTPUT_LOG_MAX = 500;
const KID_RE = /^[a-z0-9]{1,16}$/;
const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const SELECTOR_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const NONCE_RE = /^[0-9a-f]{32}$/;
/* Sent, unsigned, for every frame that fails before a verified MAC: an unknown kid, a bad
   MAC and a malformed frame are indistinguishable to the peer (section 5.3). The client
   cannot verify it and reports bad_response, which is the honest outcome. */
const UNAUTHORIZED_LINE = JSON.stringify({ ok: false, error: { code: "unauthorized" } }) + "\n";
/* The code of the once-a-minute line that stands in for refused requests in the service
   audit (see createServiceAudit). */
const REFUSED_SUMMARY = "refused_summary";
const DEFAULT_LIMITS = Object.freeze({ mutationsPerMinute: 60, passwordChangesPerHour: 20, forwardingChangesPerHour: 20 });

const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
const isAbs = (p) => typeof p === "string" && (path.isAbsolute(p) || path.posix.isAbsolute(p));
const hasDotDot = (p) => String(p).split(/[\\/]+/).includes("..");

class ConfigError extends Error {
  constructor(field, reason) {
    super("config: " + field + " " + reason);
    this.name = "ConfigError";
    this.field = field;
  }
}

/* ---------- configuration (section 5.2) ---------- */

const str = (o) => Object.assign({ type: "string", min: 1, max: 4096 }, o || {});
const int = (min, max, nullable) => ({ type: "int", min, max, nullable: !!nullable });
const bool = { type: "bool" };
const obj = (props, required) => ({ type: "object", props, required: required || Object.keys(props) });

const CONFIG_SPEC = obj({
  domain: str({ max: 253 }),
  hostname: str({ max: 253 }),
  mapType: str({ max: 8 }),
  postmapPath: str(),
  postmapPreArgs: { type: "array", items: str(), min: 0, max: 4 },
  stateDir: str(),
  bootstrapForward: str({ max: C.LIMITS.destMax }),
  mailboxes: obj({
    enabled: bool,
    uid: int(1, 4294967294),
    gid: int(1, 4294967294),
    homeBase: str(),
    schemes: { type: "array", items: str({ max: 20 }), min: 1, max: 2 },
    minRounds: int(1000, C.LIMITS.maxRounds),
    gate: obj({ senderLoginEnforced: bool, outboundRateLimited: bool }),
  }),
  dkim: obj({ selector: str({ max: 63 }), publicFile: str({ nullable: true }) }),
  probes: obj({ smtp: int(1, 65535, true), submission: int(1, 65535, true), imap: int(1, 65535, true) }),
  keys: { type: "any" },
  limits: obj({ mutationsPerMinute: int(1, 10000), passwordChangesPerHour: int(1, 10000), forwardingChangesPerHour: int(1, 10000) }),
  forwardDenyDomains: { type: "array", items: str({ max: 253 }), min: 0, max: 20 },
}, ["domain", "hostname", "mapType", "postmapPath", "stateDir", "bootstrapForward", "mailboxes", "dkim", "probes", "keys"]);

/* Validates a parsed config document. Returns a frozen, non-secret config plus the list of
   key files; the key bytes are read separately (loadKeys) and never stored on this object.
   The daemon refuses to start on any failure (it exits non-zero), so a typo can never run
   with a half-understood config. */
function validateConfig(raw, opts) {
  const sandbox = !!(opts && opts.sandbox);
  try {
    V.schema(raw, CONFIG_SPEC, { unknownCode: "unknown_field", typeCode: "invalid_value" });
  } catch (e) {
    throw new ConfigError(e.field || "document", e.code === "unknown_field" ? "is not a known setting" : "has the wrong type or range");
  }
  if (raw.domain !== C.PINNED_DOMAIN) throw new ConfigError("domain", "must be " + C.PINNED_DOMAIN);
  if (!HOST_RE.test(raw.hostname)) throw new ConfigError("hostname", "is not a lowercase host name");
  if (!V.hasOwn(INDEX_EXT, raw.mapType)) throw new ConfigError("mapType", "must be hash or lmdb");

  if (sandbox) {
    if (!isAbs(raw.postmapPath) || hasDotDot(raw.postmapPath)) throw new ConfigError("postmapPath", "must be an absolute path");
  } else {
    if (raw.postmapPath !== PROD_POSTMAP) throw new ConfigError("postmapPath", "must be exactly " + PROD_POSTMAP);
    if (raw.postmapPreArgs !== undefined) throw new ConfigError("postmapPreArgs", "is only allowed in sandbox mode");
  }
  const preArgs = raw.postmapPreArgs || [];
  for (const a of preArgs) if (!isAbs(a) || hasDotDot(a)) throw new ConfigError("postmapPreArgs", "entries must be absolute paths");

  let stateDir;
  if (sandbox) {
    if (!isAbs(raw.stateDir) || hasDotDot(raw.stateDir)) throw new ConfigError("stateDir", "must be an absolute path without ..");
    stateDir = path.resolve(raw.stateDir);
    if (stateDir === path.parse(stateDir).root) throw new ConfigError("stateDir", "cannot be a filesystem root");
  } else {
    if (raw.stateDir !== PROD_STATE_DIR) throw new ConfigError("stateDir", "must be exactly " + PROD_STATE_DIR);
    stateDir = PROD_STATE_DIR;
  }

  if (!V.isDestination(raw.bootstrapForward) || V.isSameDomain(raw.bootstrapForward.toLowerCase())) {
    throw new ConfigError("bootstrapForward", "must be an external email address");
  }

  const mb = raw.mailboxes;
  /* The design allows any /var/vmail/ path, but render.assertRendered pins the passwd home
     to /var/vmail/zehnox.com, so anything else could only ever fail closed. Refusing
     it here turns that into a clear startup error instead of failing every mutation. */
  if (mb.homeBase !== PROD_HOME_BASE) throw new ConfigError("mailboxes.homeBase", "must be exactly " + PROD_HOME_BASE);
  const schemes = [];
  for (const s of mb.schemes) {
    if (s !== "SHA512-CRYPT" && s !== "ARGON2ID") throw new ConfigError("mailboxes.schemes", "may list only SHA512-CRYPT and ARGON2ID");
    if (!schemes.includes(s)) schemes.push(s);
  }
  // The daemon never accepts fewer rounds than the production floor, whatever the file says.
  const minRounds = Math.max(mb.minRounds, C.LIMITS.minRounds);

  /* D10: mailboxes stay off until scoped sender-login enforcement and the per-login rate
     limit are both live. A config that asks for mailboxes with the gate closed runs with
     mailboxes disabled, and says so in the journal. */
  const gateOpen = mb.gate.senderLoginEnforced === true && mb.gate.outboundRateLimited === true;
  const mailboxesEffective = mb.enabled === true && gateOpen;

  if (!SELECTOR_RE.test(raw.dkim.selector)) throw new ConfigError("dkim.selector", "is not a valid selector");
  const pub = raw.dkim.publicFile;
  if (pub !== null) {
    if (!isAbs(pub) || hasDotDot(pub)) throw new ConfigError("dkim.publicFile", "must be an absolute path");
    // The daemon has no business near the private key (section 13.3).
    if (/opendkim/i.test(pub)) throw new ConfigError("dkim.publicFile", "must be the copied public value, not a path under OpenDKIM");
    if (!sandbox && !pub.startsWith(PROD_ETC)) throw new ConfigError("dkim.publicFile", "must be under " + PROD_ETC);
  }

  const keyFiles = {};
  const k = raw.keys;
  if (!V.isPlainObject(k) || !Object.keys(k).length || Object.keys(k).length > 4) throw new ConfigError("keys", "must list 1 to 4 key files");
  for (const kid of Object.keys(k)) {
    if (!KID_RE.test(kid)) throw new ConfigError("keys", "ids must match [a-z0-9]{1,16}");
    const f = k[kid];
    if (typeof f !== "string" || !isAbs(f) || hasDotDot(f)) throw new ConfigError("keys." + kid, "must be an absolute path");
    if (!sandbox && !f.startsWith(PROD_ETC + "keys/")) throw new ConfigError("keys." + kid, "must be under " + PROD_ETC + "keys/");
    keyFiles[kid] = f;
  }

  const limits = Object.assign({}, DEFAULT_LIMITS, raw.limits || {});

  /* Domains no forward may target, on top of the mail host name itself (always denied):
     typically the other domains hosted on the same MTA (e.g. strategicbhm.com), so a compromised
     web process cannot route zehnox.com mail into their mailboxes. Subdomains are
     covered too. The pinned domain cannot be listed: its own forwards follow the
     mailbox-only rule instead. */
  const deny = [raw.hostname];
  for (const d of raw.forwardDenyDomains || []) {
    if (!HOST_RE.test(d)) throw new ConfigError("forwardDenyDomains", "entries must be lowercase host names");
    if (d === C.PINNED_DOMAIN || C.PINNED_DOMAIN.endsWith("." + d)) throw new ConfigError("forwardDenyDomains", "cannot include " + C.PINNED_DOMAIN + " or a parent of it");
    if (!deny.includes(d)) deny.push(d);
  }

  return Object.freeze({
    sandbox,
    domain: C.PINNED_DOMAIN,
    hostname: raw.hostname,
    mapType: raw.mapType,
    postmapPath: sandbox ? path.resolve(raw.postmapPath) : PROD_POSTMAP,
    postmapPreArgs: Object.freeze(preArgs.slice()),
    stateDir,
    bootstrapForward: raw.bootstrapForward,
    mailboxes: Object.freeze({
      configured: mb.enabled === true,
      gateOpen,
      effective: mailboxesEffective,
      uid: mb.uid,
      gid: mb.gid,
      homeBase: mb.homeBase,
      schemes: Object.freeze(schemes),
      minRounds,
    }),
    dkim: Object.freeze({ selector: raw.dkim.selector, publicFile: pub }),
    probes: Object.freeze({ smtp: raw.probes.smtp, submission: raw.probes.submission, imap: raw.probes.imap }),
    keyFiles: Object.freeze(keyFiles),
    limits: Object.freeze(limits),
    forwardDeny: Object.freeze(deny),
  });
}

function readConfigFile(file, opts) {
  const sandbox = !!(opts && opts.sandbox);
  if (!isAbs(file)) throw new ConfigError("--config", "must be an absolute path");
  let st;
  try { st = fs.statSync(file); } catch (_) { throw new ConfigError("--config", "cannot be read"); }
  if (!st.isFile() || st.size > 65536) throw new ConfigError("--config", "is not a small regular file");
  if (!WIN && !sandbox && (st.mode & 0o002)) throw new ConfigError("--config", "is world-writable");
  let raw;
  try { raw = JSON.parse(fs.readFileSync(file, "utf8")); } catch (_) { throw new ConfigError("--config", "is not valid JSON"); }
  return validateConfig(raw, opts);
}

/* Reads each key file into a Buffer. The bytes live only in the Map the caller keeps in
   its closure; they are never logged, never put in an error and never written anywhere. */
function loadKeys(cfg) {
  const keys = new Map();
  for (const kid of Object.keys(cfg.keyFiles)) {
    const f = cfg.keyFiles[kid];
    let st;
    try { st = fs.statSync(f); } catch (_) { throw new ConfigError("keys." + kid, "cannot be read"); }
    if (!st.isFile() || st.size > 256) throw new ConfigError("keys." + kid, "is not a small regular file");
    if (!WIN && !cfg.sandbox && (st.mode & 0o007)) throw new ConfigError("keys." + kid, "must not be accessible to other users");
    let text;
    try { text = fs.readFileSync(f, "latin1").trim(); } catch (_) { throw new ConfigError("keys." + kid, "cannot be read"); }
    if (!/^[0-9a-fA-F]{64}$/.test(text)) throw new ConfigError("keys." + kid, "must hold exactly 64 hex characters");
    keys.set(kid, Buffer.from(text, "hex"));
    text = null;
  }
  return keys;
}

/* ---------- small durable-file helpers ---------- */

/* Writes, fsyncs and closes. The mode is forced with fchmod because the process umask
   could otherwise leave a file wider or narrower than section 5.5 requires. */
function writeDurable(file, text, mode) {
  const fd = fs.openSync(file, "w", mode);
  try {
    if (!WIN) fs.fchmodSync(fd, mode);
    fs.writeFileSync(fd, text);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/* A rename is durable only once the directory entry is on disk. Windows cannot open a
   directory for fsync; there it is skipped (Windows is a test platform only). */
function fsyncDir(dir) {
  if (WIN) return;
  let fd = null;
  try { fd = fs.openSync(dir, "r"); fs.fsyncSync(fd); } catch (_) { /* best effort */ } finally { if (fd !== null) try { fs.closeSync(fd); } catch (_) { /* ignore */ } }
}

function readOrNull(file) {
  try { return fs.readFileSync(file, "utf8"); } catch (e) { if (e.code === "ENOENT") return null; throw e; }
}
function unlinkQuiet(file) {
  try { fs.unlinkSync(file); } catch (_) { /* already gone */ }
}

/* Journal-safe: printable ASCII only, one line, capped. Used for the indexer's output. */
function scrubOutput(s) {
  return String(s || "").replace(/[^\x20-\x7e]+/g, " ").trim().slice(0, OUTPUT_LOG_MAX);
}

/* Group ids by name, from /etc/group (read-only). The self-check needs them to confirm the
   setgid directories carry the postfix and dovecot groups. */
function groupIds() {
  const out = new Map();
  let text = "";
  try { text = fs.readFileSync("/etc/group", "utf8"); } catch (_) { return out; }
  for (const line of text.split("\n")) {
    const f = line.split(":");
    if (f.length >= 3 && /^\d+$/.test(f[2])) out.set(f[0], parseInt(f[2], 10));
  }
  return out;
}

/* ---------- service audit (section 14.2) ----------
   Hash-chained JSONL written only by this process. Same scheme as the app audit: each line
   carries seq and prev = sha256 of the previous line's exact bytes; at 5 MB the file is
   rotated to audit-YYYYMMDDHHmm.jsonl and the chain continues into the new file.

   This is the record to trust if the web container is compromised (section 18), and the
   key holder is exactly who could try to flush it. Two rules keep it:
   - Refused requests that changed nothing are not written one by one: the daemon counts
     them and writes one summary line per minute (see noteRefused below). Refusals cost the
     sender nothing, so one line each would let a flood push real records off the disk.
   - Rotated files that hold an applied change (ok:true) are never deleted. Only files with
     nothing but refusals, summaries and failures age out past the newest AUDIT_KEEP. The
     daemon's own rate limits bound how fast applied changes can arrive, and rotations less
     than an hour apart are reported as event=audit_rotation_pressure. */

function stamp(d) {
  const p = (n) => String(n).padStart(2, "0");
  return d.getUTCFullYear() + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) + p(d.getUTCHours()) + p(d.getUTCMinutes());
}
/* The time a rotated file was cut, from its name (minute precision, UTC), or null. */
function stampMs(name) {
  const m = String(name).match(/^audit-(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/);
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]) : null;
}

function createServiceAudit(dir, nowMs, log, maxBytes) {
  const limit = Number.isSafeInteger(maxBytes) && maxBytes > 0 ? maxBytes : AUDIT_MAX_BYTES;
  const file = path.join(dir, "audit.jsonl");
  const ROT_RE = /^audit-\d{12}(?:-\d+)?\.jsonl$/;
  const note = typeof log === "function" ? log : () => {};
  let seq = 0;
  let prev = null;
  let size = 0;
  let lastRotationMs = null;
  /* Rotated files never change, so whether one holds an applied change is computed once. */
  const holdsChangeMemo = new Map();

  const rotated = () => {
    let names = [];
    try { names = fs.readdirSync(dir); } catch (_) { return []; }
    return names.filter((n) => ROT_RE.test(n)).sort().map((n) => path.join(dir, n));
  };
  const lastOf = (f) => {
    const text = readOrNull(f) || "";
    const lines = text.split("\n").filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i--) {
      try { const r = JSON.parse(lines[i]); if (Number.isSafeInteger(r.seq)) return { seq: r.seq, hash: sha256(lines[i]) }; } catch (_) { /* torn line */ }
    }
    return null;
  };
  /* True if any record in the file is an applied change. A file that cannot be read or
     parsed is treated as holding one: when in doubt, keep it. */
  const holdsChange = (f) => {
    if (holdsChangeMemo.has(f)) return holdsChangeMemo.get(f);
    let found = false;
    let text = null;
    try { text = fs.readFileSync(f, "utf8"); } catch (_) { found = true; }
    if (text !== null) {
      for (const line of text.split("\n")) {
        if (!line) continue;
        let r;
        try { r = JSON.parse(line); } catch (_) { found = true; break; }
        if (r && r.ok === true) { found = true; break; }
      }
    }
    holdsChangeMemo.set(f, found);
    return found;
  };
  (function load() {
    try { size = fs.statSync(file).size; } catch (_) { size = 0; }
    const r = rotated();
    if (r.length) lastRotationMs = stampMs(path.basename(r[r.length - 1]));
    let head = lastOf(file);
    if (!head && r.length) head = lastOf(r[r.length - 1]);
    if (head) { seq = head.seq; prev = head.hash; }
  })();

  function rotate() {
    const now = nowMs();
    let target = path.join(dir, "audit-" + stamp(new Date(now)) + ".jsonl");
    for (let n = 1; fs.existsSync(target); n++) target = path.join(dir, "audit-" + stamp(new Date(now)) + "-" + n + ".jsonl");
    fs.renameSync(file, target);
    size = 0;
    const all = rotated();
    let deleted = 0;
    for (const old of all.slice(0, Math.max(0, all.length - AUDIT_KEEP))) {
      if (holdsChange(old)) continue; // an applied change is never aged out
      unlinkQuiet(old);
      holdsChangeMemo.delete(old);
      deleted++;
    }
    const retained = all.length - deleted;
    if (lastRotationMs !== null && now - lastRotationMs < AUDIT_PRESSURE_MS) {
      note("event=audit_rotation_pressure retained=" + retained + " minutes_since_last=" + Math.max(0, Math.floor((now - lastRotationMs) / 60000)));
    } else {
      note("event=audit_rotated retained=" + retained);
    }
    lastRotationMs = now;
  }

  function append(rec) {
    const full = Object.assign({ seq: seq + 1 }, rec, { prev });
    const line = JSON.stringify(full);
    const bytes = Buffer.byteLength(line) + 1;
    if (size > 0 && size + bytes > limit) rotate();
    const created = size === 0 && !fs.existsSync(file);
    fs.appendFileSync(file, line + "\n", { mode: 0o640 });
    if (created && !WIN) try { fs.chmodSync(file, 0o640); } catch (_) { /* self-check reports it */ }
    size += bytes;
    seq = full.seq;
    prev = sha256(line);
    return full;
  }

  /* Public fields only, newest first. The files map and prev never leave the host. A
     refusal summary also carries its total and the per verb/code counts. */
  const publicEntry = (r) => {
    const out = {
      seq: r.seq, at: r.at, verb: r.verb, target: r.target, actor: r.actor,
      nonce: r.nonce, idem: r.idem, ok: r.ok, code: r.code, rev: r.rev,
    };
    if (r.code === REFUSED_SUMMARY && Number.isSafeInteger(r.count)) {
      out.count = r.count;
      if (V.isPlainObject(r.refused)) out.refused = r.refused;
    }
    return out;
  };

  function tail(limit, beforeSeq) {
    const before = Number.isSafeInteger(beforeSeq) ? beforeSeq : Infinity;
    const out = [];
    for (const f of [file].concat(rotated().reverse())) {
      const lines = (readOrNull(f) || "").split("\n").filter(Boolean);
      for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
        let r;
        try { r = JSON.parse(lines[i]); } catch (_) { continue; }
        if (!r || !Number.isSafeInteger(r.seq) || r.seq >= before) continue;
        out.push(publicEntry(r));
      }
      if (out.length >= limit) break;
    }
    return { entries: out, nextBeforeSeq: out.length === limit ? out[out.length - 1].seq : null };
  }

  return { append, tail, file, get seq() { return seq; } };
}

/* ---------- status probes (section 5.6) ----------
   Connect to 127.0.0.1 only and read the banner line; nothing is ever sent. For IMAPS a
   successful connect is enough. The unit's IPAddressAllow=localhost enforces the same. */
function probePort(port, wantBanner) {
  return new Promise((resolve) => {
    let done = false;
    let buf = "";
    const s = net.connect({ host: "127.0.0.1", port });
    const finish = (v) => { if (done) return; done = true; clearTimeout(t); s.destroy(); resolve(v); };
    const t = setTimeout(() => finish("down"), PROBE_TIMEOUT_MS);
    s.on("connect", () => { if (!wantBanner) finish("up"); });
    s.on("data", (c) => {
      buf += c.toString("latin1");
      if (buf.length >= 3 || buf.includes("\n")) finish(buf.startsWith("220") ? "up" : "down");
    });
    s.on("error", () => finish("down"));
    s.on("close", () => finish("down"));
  });
}

/* ---------- the daemon ---------- */

/* options:
     config | configPath      a config object (validated here) or the file to read
     sandbox                  test/rehearsal mode (see the header)
     noPostmap                sandbox only: never run the indexer
     keys                     sandbox only: Map(kid -> 32-byte Buffer) instead of key files
     executor                 test hook with the (file, argv, options, callback) signature of
                              the child_process runner; defaults to the real one
     probe(name, port)        test hook for the status probes -> 'up'|'down'|'absent'
     now()                    clock in ms
     log(line)                journald sink (default: stdout)
     auditMaxBytes            sandbox only: rotate the service audit at this size
     hooks.beforeCommit()     sandbox only: throw an Error with .simulateCrash = true to
                              stop dead between the file writes and the state commit */
function createDaemon(options) {
  const o = options || {};
  const sandbox = !!o.sandbox;
  const cfg = o.config ? validateConfig(o.config, { sandbox }) : readConfigFile(o.configPath, { sandbox });
  if (o.noPostmap && !sandbox) throw new ConfigError("--no-postmap", "is only allowed with --sandbox");
  if (o.keys && !sandbox) throw new ConfigError("keys", "can only be injected in sandbox mode");
  const noPostmap = !!o.noPostmap;
  const nowMs = typeof o.now === "function" ? o.now : () => Date.now();
  const nowIso = () => new Date(nowMs()).toISOString();
  const log = typeof o.log === "function" ? o.log : (line) => process.stdout.write(line + "\n");
  const hooks = sandbox && o.hooks ? o.hooks : {};
  const run = typeof o.executor === "function" ? o.executor : cp.execFile;
  // Sandbox only: a small rotation size, so tests can rotate the service audit quickly.
  const auditMaxBytes = sandbox && Number.isSafeInteger(o.auditMaxBytes) && o.auditMaxBytes > 0 ? o.auditMaxBytes : AUDIT_MAX_BYTES;

  /* Keys: loaded once into this closure. keyFor is the only way the protocol code sees one. */
  let keys = null;
  const keyFor = (kid) => (keys && keys.has(kid) ? keys.get(kid) : null);

  const root = cfg.stateDir;
  const paths = Object.freeze({
    root,
    state: path.join(root, "state.json"),
    hashes: path.join(root, "hashes.json"),
    idem: path.join(root, "idem.json"),
    lock: path.join(root, "maild.lock"),
    postfix: path.join(root, "postfix"),
    dovecot: path.join(root, "dovecot"),
    sock: path.join(root, "sock"),
  });
  /* Every file this process writes is one of these constant names. Nothing a request
     carries is ever part of a path. */
  const FILE_PATH = Object.freeze({
    virtual: path.join(paths.postfix, "virtual"),
    vmailbox: path.join(paths.postfix, "vmailbox"),
    sender_login: path.join(paths.postfix, "sender_login"),
    sasl_access: path.join(paths.postfix, "sasl_access"),
    passwd: path.join(paths.dovecot, "passwd"),
  });
  const indexOf = (name) => FILE_PATH[name] + INDEX_EXT[cfg.mapType];

  /* The indexer's argv, built once and frozen: map name -> [..., "<type>:<absolute path>"].
     The call site below only ever looks an entry up by one of the four constant names. */
  const POSTMAP_ARGV = Object.freeze(Object.fromEntries(MAPS.map((m) => [m, Object.freeze(cfg.postmapPreArgs.concat([cfg.mapType + ":" + FILE_PATH[m]]))])));
  const POSTMAP_OPTIONS = Object.freeze({
    env: Object.freeze({ PATH: "/usr/sbin:/usr/bin", LANG: "C" }),
    timeout: 5000,
    maxBuffer: 65536,
    windowsHide: true,
  });

  const renderCfg = Object.freeze({
    uid: cfg.mailboxes.uid, gid: cfg.mailboxes.gid, homeBase: cfg.mailboxes.homeBase,
    restrictionClass: RESTRICTION_CLASS, mailboxes: cfg.mailboxes.effective,
  });
  const hashPolicy = Object.freeze({ schemes: cfg.mailboxes.schemes.slice(), minRounds: cfg.mailboxes.minRounds });
  const capabilities = Object.freeze({ mailboxes: cfg.mailboxes.effective });
  // The mail host itself plus the owner's co-hosted domains: no forward may target them.
  const forwardDeny = cfg.forwardDeny;

  let state = null;
  let hashes = null;
  let idemEntries = [];
  let stateError = null;       // null | 'state_missing' | 'state_invalid'
  let selfCheckCode = "not_started";
  let mapsInSync = false;
  let crashed = false;
  let started = false;
  let startedAtMs = 0;
  let audit = null;
  let server = null;
  let timer = null;
  let lockHeld = false;
  let queue = Promise.resolve();
  let reconcileKicked = false;
  const nonces = new protocol.NonceCache();
  const authFail = { count: 0, lastLogMs: 0 };
  /* Refused mutations since the last summary line: the total, counts per "<verb>/<code>",
     and when the window started. See noteRefused. */
  const refused = { total: 0, byKey: new Map(), sinceMs: null, lastFlushMs: 0 };
  /* getMailStatus probe results ({ atMs, value }) and the probe round in flight, if any. */
  let probeCache = null;
  let probeInFlight = null;
  const windows = { mut: [], pw: [], fwd: [] };
  /* Maps whose last indexer run failed. The mtime comparison alone cannot be trusted for
     them (a failed run may leave a newer, broken index), so the reconcile always rebuilds
     these until one run succeeds. */
  const dirtyIndex = new Set();

  const notReady = () => crashed || stateError !== null || selfCheckCode !== "ok" || !mapsInSync;

  /* One promise queue for everything that writes: mutations, reconciles and the periodic
     check never overlap (section 5.6). */
  function enqueue(fn) {
    const job = queue.then(fn);
    queue = job.catch(() => {});
    return job;
  }

  /* ---------- the indexer ---------- */

  function postmap(name) {
    if (noPostmap) { log("event=postmap_skipped file=" + name); return Promise.resolve(); }
    dirtyIndex.add(name);
    return new Promise((resolve, reject) => {
      run(cfg.postmapPath, POSTMAP_ARGV[name], POSTMAP_OPTIONS, (err, stdout, stderr) => {
        const out = scrubOutput(String(stdout || "") + " " + String(stderr || ""));
        if (out) log("event=postmap_output file=" + name + " text=" + JSON.stringify(out));
        if (err) {
          log("event=postmap_failed file=" + name + " code=" + (err.killed ? "timeout" : String(err.code).replace(/[^A-Za-z0-9_-]/g, "").slice(0, 20)));
          reject(new CoreError("backend_failed"));
        } else {
          dirtyIndex.delete(name);
          resolve();
        }
      });
    });
  }

  /* ---------- layout and self-check ---------- */

  /* Sandbox only: create the layout of section 5.5. On the VPS the owner creates it at
     install time (the daemon cannot give a directory the postfix or dovecot group). */
  function ensureSandboxLayout() {
    const dirs = [[root, 0o751], [paths.postfix, 0o2750], [paths.dovecot, 0o2750]];
    for (const [d, mode] of dirs) {
      fs.mkdirSync(d, { recursive: true, mode });
      if (!WIN) fs.chmodSync(d, mode);
    }
  }

  /* Section 5.6: directories, owners, groups and modes, including the setgid bit and the
     0640/0600 files. Returns 'ok' or a short code. Modes mean nothing on Windows, which is
     a test platform only, so there only existence is checked. */
  function selfCheck() {
    const dirs = [
      { p: root, mode: 0o751, group: null },
      { p: paths.postfix, mode: 0o2750, group: "postfix" },
      { p: paths.dovecot, mode: 0o2750, group: "dovecot" },
    ];
    if (!sandbox) dirs.push({ p: paths.sock, mode: 0o750, group: "zehnox-mail-client" });
    const gids = !WIN && !sandbox ? groupIds() : null;
    const uid = !WIN ? process.getuid() : null;
    for (const d of dirs) {
      let st;
      try { st = fs.statSync(d.p); } catch (_) { return "dir_missing"; }
      if (!st.isDirectory()) return "dir_missing";
      if (WIN) continue;
      if ((st.mode & 0o7777) !== d.mode) return "dir_mode";
      if (st.uid !== uid) return "dir_owner";
      if (d.group && gids) {
        if (!gids.has(d.group)) return "group_missing";
        if (st.gid !== gids.get(d.group)) return "dir_group";
      }
    }
    if (WIN) return "ok";
    const files = [
      [paths.state, 0o600], [paths.hashes, 0o600], [paths.idem, 0o600], [path.join(root, "audit.jsonl"), 0o640],
    ].concat(R.FILES.map((f) => [FILE_PATH[f], 0o640]));
    for (const [f, mode] of files) {
      let st;
      try { st = fs.statSync(f); } catch (_) { continue; } // not created yet: the reconcile writes it
      if (!st.isFile() || (st.mode & 0o777) !== mode) return "file_mode";
      if (st.uid !== uid) return "file_owner";
    }
    return "ok";
  }

  function runSelfCheck() {
    const code = selfCheck();
    if (code !== "ok" && code !== selfCheckCode) log("event=self_check_failed code=" + code);
    selfCheckCode = code;
    return code;
  }

  /* ---------- lock ----------
     The socket service and the owner CLI write modes must never write at the same time.
     A lock held by a live process refuses the second writer; a stale one is taken over. */
  function acquireLock() {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const fd = fs.openSync(paths.lock, "wx", 0o600);
        fs.writeSync(fd, String(process.pid));
        fs.closeSync(fd);
        lockHeld = true;
        return;
      } catch (e) {
        if (e.code !== "EEXIST") throw e;
        const pid = parseInt(readOrNull(paths.lock) || "", 10);
        if (pid === process.pid) { lockHeld = true; return; }
        let alive = false;
        if (Number.isSafeInteger(pid) && pid > 0) {
          try { process.kill(pid, 0); alive = true; } catch (k) { alive = k.code === "EPERM"; }
        }
        if (alive) throw new ConfigError("stateDir", "is locked by another zehnox-maild process (pid " + pid + ")");
        unlinkQuiet(paths.lock);
      }
    }
    throw new ConfigError("stateDir", "lock could not be taken");
  }
  function releaseLock() {
    if (!lockHeld) return;
    lockHeld = false;
    const pid = parseInt(readOrNull(paths.lock) || "", 10);
    if (pid === process.pid) unlinkQuiet(paths.lock);
  }

  /* ---------- state loading ---------- */

  function readJsonFile(file) {
    const text = readOrNull(file);
    if (text === null) return undefined;
    return JSON.parse(text);
  }

  function loadState() {
    // Leftovers from a crash: the live files are the truth, the reconcile repairs the rest.
    for (const f of [paths.state, paths.hashes, paths.idem].concat(R.FILES.map((n) => FILE_PATH[n]))) unlinkQuiet(f + ".tmp");
    dropPasswdPrev(); // a write interrupted by a crash: the reconcile renders passwd from hashes.json
    let s;
    let h;
    try {
      s = readJsonFile(paths.state);
      h = readJsonFile(paths.hashes);
    } catch (_) {
      stateError = "state_invalid";
      log("event=state_invalid");
      return;
    }
    if (s === undefined) {
      /* First start only. If hashes.json survives without its state, this is not a first
         start but a lost state file: refuse and let the owner restore it from backup
         (or delete hashes.json on purpose to start over). */
      if (h !== undefined) { stateError = "state_missing"; log("event=state_missing"); return; }
      s = S.bootstrapState(cfg.bootstrapForward, nowIso());
      h = S.emptyHashes();
      writeDurable(paths.hashes + ".tmp", JSON.stringify(h, null, 2) + "\n", 0o600);
      fs.renameSync(paths.hashes + ".tmp", paths.hashes);
      writeDurable(paths.state + ".tmp", JSON.stringify(s, null, 2) + "\n", 0o600);
      fs.renameSync(paths.state + ".tmp", paths.state);
      fsyncDir(root);
      log("event=bootstrap rev=" + s.rev);
    }
    if (h === undefined) h = S.emptyHashes();
    try {
      S.checkState(s);
      S.checkHashes(h);
    } catch (_) {
      stateError = "state_invalid";
      log("event=state_invalid");
      return;
    }
    state = s;
    hashes = h;
    stateError = null;
    let idem;
    try { idem = readJsonFile(paths.idem); } catch (_) { idem = undefined; log("event=idem_reset"); }
    idemEntries = idem && Array.isArray(idem.entries) ? idem.entries.filter((e) => V.isPlainObject(e) && typeof e.idem === "string") : [];
  }

  /* ---------- writing rendered files (section 5.6 steps 8-10 and 12) ---------- */

  function fileOrder(reducing) {
    // Access-reducing changes go live in Dovecot first, so a failure half way leaves the
    // more restrictive file in place; everything else goes Postfix first, passwd last.
    return reducing ? ["passwd"].concat(MAPS) : MAPS.concat(["passwd"]);
  }

  async function restore(touched) {
    let ok = true;
    for (const t of touched.slice().reverse()) {
      const live = FILE_PATH[t.name];
      try {
        if (t.existed) {
          // Rewritten rather than copied: a copy may keep the old mtime (it does on
          // Windows), and the source must look newer than any index built meanwhile.
          writeDurable(live + ".tmp", fs.readFileSync(live + ".prev"), 0o640);
          fs.renameSync(live + ".tmp", live);
          if (MAPS.includes(t.name)) await postmap(t.name);
        } else {
          unlinkQuiet(live);
          if (MAPS.includes(t.name)) unlinkQuiet(indexOf(t.name));
        }
      } catch (_) {
        ok = false;
        log("event=restore_failed file=" + t.name);
      }
    }
    return ok;
  }

  /* dovecot/passwd.prev is the rollback copy for the one write in progress, and it holds
     the previous password hashes in the dovecot-readable directory. It is removed as soon
     as that write is settled (applied, or restored), so an old or deleted mailbox's hash
     never outlives the change that replaced it (hashes.json keeps current hashes only). */
  const dropPasswdPrev = () => unlinkQuiet(FILE_PATH.passwd + ".prev");

  /* Writes the named files (tmp, fsync, rename), indexing each Postfix map right after it
     lands. The index is rebuilt in place on the live path by the indexer itself; a
     prebuilt index is never renamed over it. On any failure every file already touched is
     put back from its .prev copy and re-indexed. */
  async function applyFiles(files, names, reducing) {
    const touched = [];
    try {
      for (const name of fileOrder(reducing)) {
        if (!names.includes(name)) continue;
        const live = FILE_PATH[name];
        const existed = fs.existsSync(live);
        if (existed) fs.copyFileSync(live, live + ".prev");
        touched.push({ name, existed });
        writeDurable(live + ".tmp", files[name], 0o640);
        fs.renameSync(live + ".tmp", live);
        fsyncDir(path.dirname(live));
        if (MAPS.includes(name)) await postmap(name);
      }
    } catch (e) {
      for (const n of R.FILES) unlinkQuiet(FILE_PATH[n] + ".tmp");
      const restored = await restore(touched);
      /* Restored or not, the copy has done its job: a failed restore is repaired by the
         reconcile, which renders passwd from hashes.json, never from this copy. */
      dropPasswdPrev();
      if (!restored) {
        mapsInSync = false;
        throw new CoreError("not_ready");
      }
      throw e instanceof CoreError && e.code === "backend_failed" ? e : new CoreError("backend_failed");
    }
    // From here a crash is repaired from state.json by the startup reconcile, so the
    // rollback copy is no longer needed either.
    dropPasswdPrev();
    return touched.map((t) => t.name);
  }

  function renderChecked(s, h) {
    try {
      return R.assertRendered(R.render(s, h, renderCfg));
    } catch (e) {
      log("event=render_assert_failed reason=" + String(e.reason || e.code || "render").replace(/[^a-z_:]/g, "").slice(0, 40));
      throw new CoreError("backend_failed");
    }
  }

  const changedNames = (files) => R.FILES.filter((n) => readOrNull(FILE_PATH[n]) !== files[n]);

  /* Steps 7-11: stage state, apply files, commit state. Returns sha256 of each file that
     changed (for the service audit). Throws backend_failed (restored) or not_ready. */
  async function commitChange(nextState, nextHashes, reducing) {
    const files = renderChecked(nextState, nextHashes);
    const names = changedNames(files);
    writeDurable(paths.state + ".tmp", JSON.stringify(nextState, null, 2) + "\n", 0o600);
    writeDurable(paths.hashes + ".tmp", JSON.stringify(nextHashes, null, 2) + "\n", 0o600);
    try {
      await applyFiles(files, names, reducing);
      if (typeof hooks.beforeCommit === "function") hooks.beforeCommit();
    } catch (e) {
      if (e && e.simulateCrash === true) { crashed = true; throw new CoreError("not_ready"); }
      unlinkQuiet(paths.state + ".tmp");
      unlinkQuiet(paths.hashes + ".tmp");
      throw e;
    }
    // Commit: hashes first, then state (state.json carries rev, so it changes last).
    fs.renameSync(paths.hashes + ".tmp", paths.hashes);
    fs.renameSync(paths.state + ".tmp", paths.state);
    fsyncDir(root);
    state = nextState;
    hashes = nextHashes;
    return Object.fromEntries(names.map((n) => [n, sha256(files[n])]));
  }

  /* ---------- reconcile (section 5.6) ---------- */

  /* Renders from state, compares every live file byte for byte and every index with its
     source, and repairs mismatches the same way a mutation writes. dryRun only reports. */
  async function reconcile(opts) {
    const dryRun = !!(opts && opts.dryRun);
    if (crashed) return { ok: false, code: "crashed" };
    if (stateError || !state) { mapsInSync = false; return { ok: false, code: stateError || "not_loaded" }; }
    let files;
    try { files = renderChecked(state, hashes); } catch (_) { mapsInSync = false; return { ok: false, code: "render_assert_failed" }; }
    const mismatched = changedNames(files);
    const staleIndex = [];
    if (!noPostmap) {
      for (const m of MAPS) {
        if (mismatched.includes(m)) continue;
        if (dirtyIndex.has(m)) { staleIndex.push(m); continue; }
        let src;
        let idx;
        try { src = fs.statSync(FILE_PATH[m]); idx = fs.statSync(indexOf(m)); } catch (_) { staleIndex.push(m); continue; }
        if (idx.mtimeMs < src.mtimeMs) staleIndex.push(m);
      }
    }
    const report = { ok: true, mismatched, staleIndex, repaired: !dryRun && (mismatched.length > 0 || staleIndex.length > 0) };
    if (dryRun) return report;
    for (const n of mismatched) log("event=reconcile_mismatch file=" + n);
    for (const n of staleIndex) log("event=reconcile_stale_index file=" + n);
    try {
      if (mismatched.length) await applyFiles(files, mismatched, true);
      for (const m of staleIndex) await postmap(m);
    } catch (e) {
      mapsInSync = false;
      log("event=reconcile_failed");
      return { ok: false, code: e && e.code === "not_ready" ? "restore_failed" : "backend_failed", mismatched, staleIndex };
    }
    mapsInSync = true;
    return report;
  }

  function kickReconcile() {
    if (reconcileKicked || crashed) return;
    reconcileKicked = true;
    enqueue(async () => {
      try {
        runSelfCheck();
        if (selfCheckCode === "ok") await reconcile();
      } finally {
        reconcileKicked = false;
      }
    }).catch(() => {});
  }

  /* ---------- daemon-side global limits (section 5.4) ----------
     A brake on a compromised web process, independent of the web side's own limiters. */
  function rateCheck(verb, args) {
    const now = nowMs();
    const prune = (list, ms) => { while (list.length && now - list[0] >= ms) list.shift(); };
    prune(windows.mut, 60e3);
    prune(windows.pw, 3600e3);
    prune(windows.fwd, 3600e3);
    const pw = verb === "changeMailboxPassword" || verb === "createMailbox" || (verb === "createAddress" && args.mailbox !== null);
    const fwd = verb === "setForwarding" || verb === "removeForwarding" || (verb === "createAddress" && Array.isArray(args.forwards) && args.forwards.length > 0);
    if (windows.mut.length >= cfg.limits.mutationsPerMinute) throw new CoreError("rate_limited");
    if (pw && windows.pw.length >= cfg.limits.passwordChangesPerHour) throw new CoreError("rate_limited");
    if (fwd && windows.fwd.length >= cfg.limits.forwardingChangesPerHour) throw new CoreError("rate_limited");
    windows.mut.push(now);
    if (pw) windows.pw.push(now);
    if (fwd) windows.fwd.push(now);
  }

  /* ---------- mutations (section 5.6 steps 1-11) ---------- */

  async function mutate(p) {
    const verb = p.verb;
    const args = p.args;
    if (crashed) throw new CoreError("not_ready");
    const now = nowMs();
    const sha = core.argsSha256(verb, args);
    /* Idempotency runs first, before the rate limits and ifRev (section 5.6 step 2): a
       retry of a change that was applied (the web retries once after a timeout, with the
       same idem) gets its original success back, and is not charged against the limits a
       second time. A different change under a used key is refused here, uncharged too. */
    const cached = core.idemLookup(idemEntries, p.idem, verb, sha, now);
    if (cached) return { result: S.clone(cached), files: null, replay: true };
    rateCheck(verb, args);
    if (stateError || !state) throw new CoreError("not_ready");
    if (p.ifRev !== state.rev) throw new CoreError("conflict_rev");
    if (notReady()) throw new CoreError("not_ready");
    const r = core.apply(state, hashes, verb, args, { now: new Date(now).toISOString(), capabilities, hashPolicy, forwardDeny });
    let fileShas = null;
    if (r.changed) {
      const reducing = C.ACCESS_REDUCING.includes(verb) && !(verb === "setAddressEnabled" && args.enabled === true);
      try {
        fileShas = await commitChange(r.state, r.hashes, reducing);
      } catch (e) {
        // The live files were touched: this failure is audited in full, not summarized.
        if (e && typeof e === "object") e.writeAttempted = true;
        throw e;
      }
    } else {
      renderChecked(state, hashes); // a no-op is still asserted, like every apply
    }
    idemEntries = core.idemRemember(idemEntries, { idem: p.idem, argsSha256: sha, verb, response: r.result }, now);
    try {
      writeDurable(paths.idem + ".tmp", JSON.stringify({ v: 1, entries: idemEntries }) + "\n", 0o600);
      fs.renameSync(paths.idem + ".tmp", paths.idem);
    } catch (_) {
      // The change is committed; losing the idempotency record only weakens a later retry
      // to a conflict_rev, never to a double apply.
      log("event=idem_write_failed");
    }
    return { result: r.result, files: fileShas, replay: false };
  }

  function auditMutation(p, ok, code, rev, files) {
    const target = p.args && V.isValidLocal(p.args.local) ? p.args.local : null;
    try {
      audit.append({
        at: nowIso(), verb: p.verb, target, actor: { user: p.actor.user, ip: p.actor.ip },
        nonce: p.nonce, idem: p.idem, ok, code, rev, files: files || null,
      });
    } catch (_) {
      log("event=audit_append_failed");
    }
    log("event=mutation verb=" + p.verb + " target=" + (target || "-") + " ok=" + ok + " code=" + (code || "-") + " rev=" + rev);
  }

  /* A refused mutation (rate_limited, conflict_rev, a rule failure, not_ready, ...) changed
     nothing, and costs its sender nothing. One audit line each would let a key holder push
     every earlier record off the disk with a flood of refusals (the rotation keeps a fixed
     number of files). So refusals are counted, per verb and code, and written as one
     summary line at most once a minute, the way auth failures are logged. The first
     refusal after a quiet minute is written at once, so a lone refusal is not delayed. */
  function noteRefused(verb, code) {
    const key = verb + "/" + code;
    if (refused.total === 0) refused.sinceMs = nowMs();
    refused.total++;
    // Keys are a verb from the frozen table and a code from the closed enum: bounded.
    refused.byKey.set(key, (refused.byKey.get(key) || 0) + 1);
    flushRefused(false);
  }
  function flushRefused(force) {
    const now = nowMs();
    if (!refused.total || !audit) return;
    if (!force && now - refused.lastFlushMs < 60e3) return;
    const counts = {};
    for (const k of Array.from(refused.byKey.keys()).sort()) counts[k] = refused.byKey.get(k);
    try {
      audit.append({
        at: nowIso(), verb: null, target: null, actor: null, nonce: null, idem: null,
        ok: false, code: REFUSED_SUMMARY, rev: state ? state.rev : null, files: null,
        count: refused.total, refused: counts, since: new Date(refused.sinceMs).toISOString(),
      });
    } catch (_) {
      log("event=audit_append_failed");
    }
    log("event=mutations_refused count=" + refused.total);
    refused.total = 0;
    refused.byKey.clear();
    refused.sinceMs = null;
    refused.lastFlushMs = now;
  }

  function runMutation(p) {
    return enqueue(async () => {
      let out;
      try {
        out = await mutate(p);
      } catch (e) {
        const code = wireCode(e);
        if (e && e.writeAttempted === true) auditMutation(p, false, code, state ? state.rev : null, null);
        else noteRefused(p.verb, code);
        throw e;
      }
      // An idempotent replay was audited when it first applied.
      if (!out.replay) auditMutation(p, true, null, out.result.rev, out.files);
      return out.result;
    });
  }

  /* ---------- reads ---------- */

  function readDkimPublic() {
    const f = cfg.dkim.publicFile;
    if (!f) return null;
    let text;
    try {
      const st = fs.statSync(f);
      if (!st.isFile() || st.size > 65536) return null;
      text = fs.readFileSync(f, "utf8");
    } catch (_) {
      return null;
    }
    // Only the public p= value ever leaves this function. A file that looks like key
    // material of any other kind is refused outright.
    if (/PRIVATE/i.test(text)) { log("event=dkim_file_refused"); return null; }
    const flat = text.replace(/["\s]/g, "");
    // Tags are ;-separated; a zone-file record may also wrap the value in ( ... ).
    const m = flat.match(/(?:^|[;(])p=([A-Za-z0-9+/=]+)(?=[;)]|$)/);
    if (m) return m[1].length <= 4096 ? m[1] : null;
    return /^[A-Za-z0-9+/=]{16,4096}$/.test(flat) ? flat : null;
  }

  async function probe(name) {
    const port = cfg.probes[name];
    if (!port) return "absent";
    if (typeof o.probe === "function") {
      try { const v = await o.probe(name, port); return v === "up" || v === "down" || v === "absent" ? v : "down"; } catch (_) { return "down"; }
    }
    if (sandbox) return "absent"; // a sandbox never touches a real mail server
    return probePort(port, name !== "imap");
  }

  /* One probe round (25, 587, 993) at most every PROBE_CACHE_MS, and never two at once:
     concurrent status calls share the round in flight. */
  function probeAll() {
    const now = nowMs();
    if (probeCache && now - probeCache.atMs < PROBE_CACHE_MS) return Promise.resolve(probeCache.value);
    if (probeInFlight) return probeInFlight;
    probeInFlight = Promise.all([probe("smtp"), probe("submission"), probe("imap")])
      .then((value) => { probeCache = { atMs: nowMs(), value }; return value; })
      .finally(() => { probeInFlight = null; });
    return probeInFlight;
  }

  async function statusDoc() {
    if (notReady()) kickReconcile();
    const [smtp, submission, imap] = await probeAll();
    const check = crashed ? "crashed" : stateError || runSelfCheck();
    const up = [smtp === "up", submission === "up", mapsInSync, check === "ok"];
    let st = "degraded";
    if (up.every(Boolean)) st = "online";
    else if (smtp !== "up" && submission !== "up") st = "offline";
    return {
      domain: cfg.domain,
      rev: state ? state.rev : null,
      service: { state: st, smtp, submission, imap, mapsInSync, selfCheck: check, checkedAt: nowIso() },
      capabilities: {
        mailboxes: cfg.mailboxes.effective,
        schemes: cfg.mailboxes.schemes.slice(),
        maxForwards: C.LIMITS.maxForwardsPerAddress,
        maxAddresses: C.LIMITS.maxAddresses,
        maxExternalDestinations: C.LIMITS.maxExternalDestinationsTotal,
      },
      dkim: { selector: cfg.dkim.selector, publicKey: readDkimPublic() },
      daemon: { version: VERSION, startedAt: new Date(startedAtMs).toISOString() },
    };
  }

  function listAddresses() {
    if (stateError || !state) throw new CoreError("not_ready");
    return S.listView(state, hashes);
  }

  /* ---------- the frozen verb table ---------- */

  const HANDLERS = Object.freeze({
    getMailStatus: () => statusDoc(),
    listAddresses: () => listAddresses(),
    getAuditTail: (p) => audit.tail(p.args.limit, p.args.beforeSeq),
    createAddress: (p) => runMutation(p),
    deleteAddress: (p) => runMutation(p),
    setForwarding: (p) => runMutation(p),
    removeForwarding: (p) => runMutation(p),
    setAddressEnabled: (p) => runMutation(p),
    createMailbox: (p) => runMutation(p),
    disableMailbox: (p) => runMutation(p),
    enableMailbox: (p) => runMutation(p),
    changeMailboxPassword: (p) => runMutation(p),
  });

  /* Any code outside the daemon's closed enum is an internal failure: log a code, answer
     backend_failed, never pass an exception message on. */
  function wireCode(e) {
    if (e instanceof CoreError && C.DAEMON_CODES.includes(e.code)) return e.code;
    log("event=internal_error kind=" + String((e && e.name) || "error").replace(/[^A-Za-z]/g, "").slice(0, 20));
    return "backend_failed";
  }

  function noteAuthFailure() {
    authFail.count++;
    flushAuthFailures(false);
  }
  function flushAuthFailures(force) {
    const now = nowMs();
    if (authFail.count && (force || now - authFail.lastLogMs >= 60e3)) {
      log("event=auth_failures count=" + authFail.count);
      authFail.count = 0;
      authFail.lastLogMs = now;
    }
  }

  function respond(kid, nonce, ok, body) {
    const key = keyFor(kid);
    try {
      return ok
        ? protocol.encodeResponse(kid, key, { nonce, ok: true, result: body })
        : protocol.encodeResponse(kid, key, { nonce, ok: false, error: body });
    } catch (_) {
      log("event=response_encode_failed");
      return protocol.encodeResponse(kid, key, { nonce, ok: false, error: { code: "backend_failed" } });
    }
  }

  /* One request line in, one response line out. Exposed for tests; the socket server is a
     thin framing layer around it. */
  async function handleLine(line) {
    let decoded;
    try {
      decoded = protocol.decodeFrame("req", line, keyFor);
    } catch (_) {
      noteAuthFailure();
      return UNAUTHORIZED_LINE;
    }
    const { kid, payload } = decoded;
    const nonce = typeof payload.nonce === "string" && NONCE_RE.test(payload.nonce) ? payload.nonce : null;
    if (!started) return respond(kid, nonce, false, { code: "not_ready" });
    try {
      protocol.checkRequest(payload, { nowMs: nowMs(), startedAtMs, nonces });
    } catch (e) {
      return respond(kid, nonce, false, { code: wireCode(e) });
    }
    try {
      const result = await HANDLERS[payload.verb](payload);
      return respond(kid, nonce, true, result);
    } catch (e) {
      const code = wireCode(e);
      const refs = code === "in_use" && Array.isArray(e.refs) ? e.refs.filter(V.isValidLocal).slice(0, 50) : undefined;
      return respond(kid, nonce, false, refs ? { code, refs } : { code });
    }
  }

  /* ---------- socket server (section 5.3) ---------- */

  function onConnection(sock) {
    const chunks = [];
    let size = 0;
    let done = false;
    const kill = () => { done = true; clearTimeout(readTimer); clearTimeout(firstByteTimer); sock.destroy(); };
    const readTimer = setTimeout(kill, READ_TIMEOUT_MS);
    // Silent connections are closed early (FIRST_BYTE_MS) so they cannot pin the slots.
    const firstByteTimer = setTimeout(() => { if (size === 0) kill(); }, FIRST_BYTE_MS);
    sock.on("error", () => kill());
    sock.on("data", (chunk) => {
      if (done) return;
      clearTimeout(firstByteTimer);
      const offset = size;
      size += chunk.length;
      const nl = chunk.indexOf(10);
      // One frame of at most frameMax bytes including its LF; one byte more ends the connection.
      if (nl < 0 ? size > C.LIMITS.frameMax : offset + nl + 1 > C.LIMITS.frameMax) return kill();
      if (nl < 0) { chunks.push(chunk); return; }
      chunks.push(chunk.subarray(0, nl + 1));
      done = true;
      clearTimeout(readTimer);
      sock.pause();
      const line = Buffer.concat(chunks).toString("latin1");
      handleLine(line).then((out) => sock.end(out), () => sock.destroy());
    });
  }

  function listen(target) {
    return new Promise((resolve, reject) => {
      server = net.createServer({ allowHalfOpen: false }, onConnection);
      server.maxConnections = MAX_CONNECTIONS;
      server.once("error", reject);
      const ready = () => { server.removeListener("error", reject); server.on("error", () => log("event=server_error")); resolve(); };
      if (target === "systemd") {
        server.listen({ fd: 3 }, ready); // socket activation: systemd owns the socket inode
      } else {
        if (!WIN && typeof target === "string") {
          try { if (fs.lstatSync(target).isSocket()) fs.unlinkSync(target); } catch (_) { /* nothing to clear */ }
        }
        server.listen(target, ready);
      }
    });
  }

  /* ---------- lifecycle ---------- */

  async function start(opts) {
    // periodic:false is for the one-shot CLI modes and tests: no 60 s timer.
    // reconcile:false leaves the live files untouched at start (for --reconcile --dry-run).
    const periodic = !(opts && opts.periodic === false);
    const startReconcile = !(opts && opts.reconcile === false);
    const takeLock = !(opts && opts.lock === false);
    if (o.keys) keys = new Map(o.keys);
    else keys = loadKeys(cfg);
    for (const k of keys.values()) if (!Buffer.isBuffer(k) || k.length !== 32) throw new ConfigError("keys", "must be 32-byte keys");
    if (sandbox) ensureSandboxLayout();
    if (takeLock) {
      if (!fs.existsSync(root)) throw new ConfigError("stateDir", "does not exist (create it as described in INSTALL.md)");
      acquireLock();
    }
    startedAtMs = nowMs();
    if (cfg.mailboxes.configured && !cfg.mailboxes.gateOpen) log("event=mailbox_gate_closed");
    runSelfCheck();
    // With the directories missing nothing can be read yet; the periodic check retries.
    // A wrong file mode is reported (and refuses mutations) but the state can be read.
    if (selfCheckCode === "ok" || selfCheckCode === "file_mode") loadState();
    audit = createServiceAudit(root, nowMs, log, auditMaxBytes);
    const check = runSelfCheck();
    if (check === "ok" && !stateError && state && startReconcile) await enqueue(() => reconcile());
    started = true;
    if (periodic) {
      timer = setInterval(() => {
        flushAuthFailures(true);
        flushRefused(false);
        enqueue(async () => {
          runSelfCheck();
          if (selfCheckCode === "ok" && !crashed) {
            if (stateError || !state) loadState();
            if (!stateError && state) await reconcile();
          }
        }).catch(() => {});
      }, PERIOD_MS);
      if (timer.unref) timer.unref();
    }
    log("event=started version=" + VERSION + " rev=" + (state ? state.rev : "-") + " selfCheck=" + selfCheckCode +
        " mapsInSync=" + mapsInSync + " mailboxes=" + cfg.mailboxes.effective + (sandbox ? " sandbox=1" : ""));
    return { selfCheck: selfCheckCode, mapsInSync, stateError, rev: state ? state.rev : null };
  }

  async function close() {
    if (timer) { clearInterval(timer); timer = null; }
    flushAuthFailures(true);
    if (server) {
      await new Promise((r) => server.close(() => r()));
      server = null;
    }
    await queue;
    flushRefused(true); // the count since the last summary is never lost on a clean stop
    releaseLock();
    started = false;
  }

  /* ---------- owner CLI operations ---------- */

  /* --status: read-only. Renders from state and compares with the live files, without
     writing anything or taking the lock, so it works while the service runs. */
  function inspect() {
    const report = { version: VERSION, domain: cfg.domain, hostname: cfg.hostname, sandbox, rev: null, selfCheck: selfCheck(), mapsInSync: false, mailboxes: { configured: cfg.mailboxes.configured, gateOpen: cfg.mailboxes.gateOpen, effective: cfg.mailboxes.effective }, files: {}, lastAudit: [] };
    let s;
    let h;
    try { s = readJsonFile(paths.state); h = readJsonFile(paths.hashes); } catch (_) { report.state = "state_invalid"; }
    if (!report.state) {
      if (s === undefined) report.state = "state_missing";
      else {
        try { S.checkState(s); S.checkHashes(h || S.emptyHashes()); report.state = "ok"; report.rev = s.rev; } catch (_) { report.state = "state_invalid"; }
      }
    }
    let files = null;
    if (report.state === "ok") {
      try { files = R.assertRendered(R.render(s, h || S.emptyHashes(), renderCfg)); } catch (_) { report.state = "render_assert_failed"; }
    }
    let allSync = !!files;
    for (const n of R.FILES) {
      const live = readOrNull(FILE_PATH[n]);
      const entry = { sha256: live === null ? null : sha256(live), inSync: !!files && live === files[n] };
      if (MAPS.includes(n)) {
        try { entry.indexFresh = fs.statSync(indexOf(n)).mtimeMs >= fs.statSync(FILE_PATH[n]).mtimeMs; } catch (_) { entry.indexFresh = false; }
      }
      if (!entry.inSync) allSync = false;
      report.files[n] = entry;
    }
    report.mapsInSync = allSync;
    try { report.lastAudit = createServiceAudit(root, nowMs).tail(5, null).entries; } catch (_) { report.lastAudit = []; }
    return report;
  }

  /* --purge-tombstone: the owner has removed (or will remove) the maildir by hand. */
  async function purgeTombstone(local) {
    return enqueue(async () => {
      V.checkLocal(local);
      if (stateError || !state) throw new CoreError("not_ready");
      if (!V.hasOwn(state.tombstones, local)) throw new CoreError("not_found");
      const next = S.clone(state);
      delete next.tombstones[local];
      next.rev = state.rev + 1;
      next.updatedAt = nowIso();
      await commitChange(next, hashes, false);
      audit.append({ at: nowIso(), verb: "purgeTombstone", target: local, actor: { user: "owner-cli", ip: "::" }, nonce: null, idem: null, ok: true, code: null, rev: next.rev, files: null });
      return { rev: next.rev, maildir: cfg.mailboxes.homeBase + "/" + local + "/" };
    });
  }

  /* --import: adopt hand-made entries for the pinned domain from a Postfix source map
     (and optionally a Dovecot passwd-file). Keys of any other domain are never read into
     the state; they are only counted. Every entry goes through core.apply, so the import
     obeys exactly the rules the socket does. Mailboxes are imported first, because a
     same-domain forward may only point at an existing mailbox. */
  async function importMaps(opt) {
    return enqueue(async () => {
      if (stateError || !state) throw new CoreError("not_ready");
      const report = { imported: [], skipped: [], foreignKeys: 0, malformed: 0, dryRun: !!opt.dryRun };
      const entries = new Map(); // local -> { forwards, self }
      const text = fs.readFileSync(opt.postfixMap, "utf8");
      const logical = [];
      for (const raw of text.split(/\r?\n/)) {
        if (/^\s*(#|$)/.test(raw)) continue;
        if (/^\s/.test(raw) && logical.length) logical[logical.length - 1] += " " + raw.trim(); // continuation line
        else logical.push(raw.trim());
      }
      for (const line of logical) {
        const m = line.match(/^(\S+)\s+(.+)$/);
        if (!m) { report.malformed++; continue; }
        const key = m[1].toLowerCase();
        const at = key.lastIndexOf("@");
        if (at < 1 || key.slice(at + 1) !== C.PINNED_DOMAIN) { report.foreignKeys++; continue; }
        const local = key.slice(0, at);
        if (!V.isValidLocal(local) || C.RESERVED.includes(local)) { report.skipped.push({ local: V.isValidLocal(local) ? local : null, code: "invalid_local" }); continue; }
        const e = entries.get(local) || { forwards: [], self: false };
        for (const v of m[2].split(/[,\s]+/).filter(Boolean)) {
          if (v.toLowerCase() === key) { e.self = true; continue; }
          let d;
          try { d = V.normalizeDestination(v); } catch (_) { e.bad = true; continue; }
          e.forwards.push(d);
        }
        entries.set(local, e);
      }
      const pw = new Map();
      if (opt.passwdFile) {
        for (const raw of fs.readFileSync(opt.passwdFile, "utf8").split(/\r?\n/)) {
          if (/^\s*(#|$)/.test(raw)) continue;
          const f = raw.split(":");
          const user = (f[0] || "").toLowerCase();
          const at = user.lastIndexOf("@");
          if (at < 1 || user.slice(at + 1) !== C.PINNED_DOMAIN) { report.foreignKeys++; continue; }
          const local = user.slice(0, at);
          if (!V.isValidLocal(local)) { report.malformed++; continue; }
          pw.set(local, f[1] || "");
          if (!entries.has(local)) entries.set(local, { forwards: [], self: true });
          else entries.get(local).self = true;
        }
      }
      let s = state;
      let h = hashes;
      let changes = 0;
      const auditLines = [];
      const importCtx = () => ({ now: nowIso(), capabilities: { mailboxes: true }, hashPolicy, forwardDeny });
      const step = (verb, args, local) => {
        const r = core.apply(s, h, verb, args, importCtx());
        if (r.changed) { s = r.state; h = r.hashes; changes++; auditLines.push({ verb, target: local, rev: r.result.rev }); }
        return r.changed;
      };
      const order = Array.from(entries.keys()).sort((a, b) => Number(entries.get(b).self) - Number(entries.get(a).self) || (a < b ? -1 : 1));
      for (const local of order) {
        const e = entries.get(local);
        if (e.bad) { report.skipped.push({ local, code: "invalid_destination" }); continue; }
        try {
          if (V.hasOwn(s.addresses, local)) {
            if (s.addresses[local].protected && e.forwards.length) {
              step("setForwarding", { local, forwards: e.forwards }, local);
              report.imported.push({ local, action: "setForwarding" });
            } else {
              report.skipped.push({ local, code: "duplicate" });
            }
            continue;
          }
          const hash = pw.get(local);
          if (e.self && !hash) { report.skipped.push({ local, code: "no_password_hash" }); continue; }
          step("createAddress", { local, forwards: e.forwards, mailbox: e.self ? { passwordHash: hash } : null, reuseDeleted: true }, local);
          report.imported.push({ local, action: "createAddress", type: e.self ? (e.forwards.length ? "mailbox+forward" : "mailbox") : "forward" });
        } catch (err) {
          report.skipped.push({ local, code: err instanceof CoreError ? err.code : "backend_failed" });
        }
      }
      report.changes = changes;
      if (opt.dryRun || !changes) { report.rev = state.rev; return report; }
      if (notReady()) throw new CoreError("not_ready");
      await commitChange(s, h, false);
      for (const a of auditLines) {
        audit.append({ at: nowIso(), verb: a.verb, target: a.target, actor: { user: "owner-cli", ip: "::" }, nonce: null, idem: null, ok: true, code: null, rev: a.rev, files: null });
      }
      report.rev = s.rev;
      return report;
    });
  }

  return {
    cfg,
    paths,
    filePaths: FILE_PATH,
    POSTMAP_ARGV,
    POSTMAP_OPTIONS,
    HANDLERS_KEYS: Object.freeze(Object.keys(HANDLERS)),
    start,
    listen,
    close,
    handleLine,
    reconcile: (opts) => enqueue(() => reconcile(opts)),
    selfCheck: () => runSelfCheck(),
    status: () => statusDoc(),
    inspect,
    importMaps,
    purgeTombstone,
    get state() { return state ? S.clone(state) : null; },
    get ready() { return started && !notReady(); },
    get mapsInSync() { return mapsInSync; },
    get selfCheckCode() { return selfCheckCode; },
    get crashed() { return crashed; },
    get pending() { return queue; },
  };
}

/* The table above must serve exactly the frozen verb list: checked once at load, so a
   drift between the core and the daemon stops the process before it serves anything. */
(function assertVerbTable() {
  const names = ["getMailStatus", "listAddresses", "getAuditTail", "createAddress", "deleteAddress", "setForwarding",
    "removeForwarding", "setAddressEnabled", "createMailbox", "disableMailbox", "enableMailbox", "changeMailboxPassword"];
  if (JSON.stringify(names) !== JSON.stringify(C.VERB_NAMES)) throw new Error("zehnox-maild: verb table does not match lib/mail/core");
})();

/* ---------- manifest (section 5.1, same format as tools/mail-manifest.js) ---------- */

function manifest(daemonFile, coreDir) {
  const lines = [];
  for (const n of fs.readdirSync(coreDir).filter((f) => f.endsWith(".js")).sort()) {
    lines.push(sha256(fs.readFileSync(path.join(coreDir, n))) + "  core/" + n);
  }
  lines.push(sha256(fs.readFileSync(daemonFile)) + "  zehnox-maild.js");
  return lines.join("\n") + "\n";
}

/* ---------- CLI ---------- */

const USAGE = "usage: zehnox-maild.js --config <file> [--listen <path>] [--sandbox [--no-postmap]]\n" +
  "       zehnox-maild.js --config <file> (--status | --check-config | --reconcile [--dry-run] |\n" +
  "                          --import --postfix-map <f> [--passwd-file <f>] [--dry-run] | --purge-tombstone <local>)\n" +
  "       zehnox-maild.js --print-manifest\n";

function parseArgs(argv) {
  const out = { flags: new Set() };
  const withValue = new Set(["--config", "--listen", "--postfix-map", "--passwd-file", "--purge-tombstone"]);
  const flags = new Set(["--status", "--check-config", "--reconcile", "--import", "--dry-run", "--print-manifest", "--sandbox", "--no-postmap"]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (withValue.has(a)) {
      if (i + 1 >= argv.length || out[a] !== undefined) return null;
      out[a] = argv[++i];
    } else if (flags.has(a)) {
      out.flags.add(a);
    } else {
      return null;
    }
  }
  return out;
}

async function main(argv) {
  const args = parseArgs(argv);
  const err = (s) => process.stderr.write(s + "\n");
  if (!args) { process.stderr.write(USAGE); return 2; }
  const f = args.flags;
  if (f.has("--print-manifest")) {
    process.stdout.write(manifest(__filename, CORE_DIR));
    return 0;
  }
  if (!args["--config"]) { process.stderr.write(USAGE); return 2; }
  const sandbox = f.has("--sandbox");
  const modes = ["--status", "--check-config", "--reconcile", "--import"].filter((m) => f.has(m)).concat(args["--purge-tombstone"] !== undefined ? ["--purge-tombstone"] : []);
  if (modes.length > 1) { process.stderr.write(USAGE); return 2; }
  const mode = modes[0] || "serve";
  if (f.has("--dry-run") && mode !== "--reconcile" && mode !== "--import") { process.stderr.write(USAGE); return 2; }
  if (mode === "--import" && !args["--postfix-map"]) { process.stderr.write(USAGE); return 2; }

  let d;
  try {
    // One-shot modes print JSON on stdout, so their journal-style lines go to stderr.
    const cliLog = mode === "serve" ? undefined : (line) => process.stderr.write(line + "\n");
    d = createDaemon({ configPath: path.resolve(args["--config"]), sandbox, noPostmap: f.has("--no-postmap"), log: cliLog });
  } catch (e) {
    err(e instanceof ConfigError ? e.message : "config: could not be loaded");
    return 1;
  }
  const print = (o) => process.stdout.write(JSON.stringify(o, null, 2) + "\n");

  try {
    if (mode === "--check-config") {
      loadKeys(d.cfg);
      process.stdout.write("config ok: domain=" + d.cfg.domain + " mapType=" + d.cfg.mapType + " keys=" + Object.keys(d.cfg.keyFiles).join(",") +
        " mailboxes=" + d.cfg.mailboxes.effective + (d.cfg.mailboxes.configured && !d.cfg.mailboxes.gateOpen ? " (gate closed)" : "") + "\n");
      return 0;
    }
    if (mode === "--status") {
      let keysOk = true;
      try { loadKeys(d.cfg); } catch (_) { keysOk = false; }
      print(Object.assign(d.inspect(), { keys: keysOk ? "ok" : "error" }));
      return 0;
    }
    if (mode === "--reconcile") {
      await d.start({ periodic: false, reconcile: false });
      const r = await d.reconcile({ dryRun: f.has("--dry-run") });
      print({ selfCheck: d.selfCheckCode, mapsInSync: d.mapsInSync, reconcile: r });
      await d.close();
      return r.ok ? 0 : 1;
    }
    if (mode === "--import") {
      await d.start({ periodic: false });
      const r = await d.importMaps({ postfixMap: path.resolve(args["--postfix-map"]), passwdFile: args["--passwd-file"] ? path.resolve(args["--passwd-file"]) : null, dryRun: f.has("--dry-run") });
      print(r);
      await d.close();
      return 0;
    }
    if (mode === "--purge-tombstone") {
      await d.start({ periodic: false });
      const r = await d.purgeTombstone(args["--purge-tombstone"]);
      print({ purged: args["--purge-tombstone"], rev: r.rev, note: "Stored mail is still on disk. Remove it by hand: rm -r " + r.maildir });
      await d.close();
      return 0;
    }
    // serve
    await d.start({ periodic: true });
    const activated = process.env.LISTEN_FDS === "1" && String(process.env.LISTEN_PID) === String(process.pid);
    if (!activated && !args["--listen"]) { err("serve: no systemd socket (LISTEN_FDS) and no --listen <path>"); await d.close(); return 2; }
    if (args["--listen"] && !sandbox) { err("serve: --listen is for tests and requires --sandbox"); await d.close(); return 2; }
    await d.listen(activated ? "systemd" : args["--listen"]);
    const stop = () => { d.close().then(() => process.exit(0), () => process.exit(1)); };
    process.once("SIGTERM", stop);
    process.once("SIGINT", stop);
    return null; // keep running
  } catch (e) {
    err(e instanceof ConfigError ? e.message : "zehnox-maild: " + (e instanceof CoreError ? e.code : "failed"));
    try { await d.close(); } catch (_) { /* ignore */ }
    return 1;
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { if (code !== null) process.exitCode = code; }, () => { process.exitCode = 1; });
}

/* Operational limits, read-only, for the tests. */
const LIMITS = Object.freeze({ maxConnections: MAX_CONNECTIONS, firstByteMs: FIRST_BYTE_MS, readTimeoutMs: READ_TIMEOUT_MS, probeCacheMs: PROBE_CACHE_MS, auditMaxBytes: AUDIT_MAX_BYTES, auditKeep: AUDIT_KEEP, auditPressureMs: AUDIT_PRESSURE_MS });

module.exports = { createDaemon, validateConfig, readConfigFile, loadKeys, manifest, parseArgs, main, ConfigError, VERSION, CORE_DIR, UNAUTHORIZED_LINE, REFUSED_SUMMARY, LIMITS };
