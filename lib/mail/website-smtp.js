"use strict";
/* Website SMTP settings and the encrypted SMTP password (DESIGN.md section 10).

   createWebsiteSmtp({ dir, secretsKey, cfg, env?, now? })
     dir         DATA/mail (outside the git checkout and the image; survives redeploys)
     secretsKey  32-byte Buffer from MAIL_SECRETS_KEY(_FILE), or null. Kept in this closure.

   Files, both 0600:
     website-smtp.json  non-secret settings { v, host, port, tlsMode, username, fromLocal, fromName, updatedAt, updatedBy }
     secrets.enc.json   { v:2, alg:'A256GCM', kid:'s1', iv, tag, ct, bound:{host,port,username}, updatedAt, updatedBy }

   The password is AES-256-GCM encrypted with key = HKDF-SHA256(MAIL_SECRETS_KEY,
   "zehnox-mail", "website-smtp-v2") and AAD "zehnox/website-smtp-pass/v2|host|port|user".
   Binding the ciphertext to host, port and username means a hijacked admin session cannot
   point the stored password at a server it controls: change any of the three and the
   old ciphertext no longer decrypts (and it is deleted on that save anyway).

   config() decrypts at send time and returns a fresh object each call: the plaintext is
   never cached on a long-lived object and never serialized. publicView() never contains
   it (passwordSet is a boolean). */

const fs = require("fs");
const net = require("net");
const path = require("path");
const crypto = require("crypto");
const { writeFileAtomic } = require("../../write-file.js");
const { sanitizeHeader } = require("../../smtp.js");
const C = require("./core/constants.js");
const V = require("./core/validate.js");
const { HOST_RE } = require("./config.js");
const { mailError } = require("./provider.js");

const SETTINGS = "website-smtp.json";
const SECRETS = "secrets.enc.json";
const AAD_PREFIX = "zehnox/website-smtp-pass/v2|";
const DEFAULT_FROM_NAME = "ZEHNOX";
/* Ports an SMTP host may be reached on unless the operator sets MAIL_SMTP_PORT_ALLOWLIST.
   With any port allowed, "Test SMTP" would tell an open TCP port on an allowed host from a
   closed one (by stage and timing): a port scanner for whoever holds an admin session. */
const DEFAULT_PORTS = Object.freeze([25, 465, 587, 2525]);

const PUT_SPEC = {
  type: "object",
  props: {
    host: { type: "string", max: 253 },
    port: { type: "int", min: 1, max: 65535 },
    tlsMode: { type: "string", max: 20 },
    username: { type: "string", max: 254 },
    fromLocal: { type: "string", max: 64 },
    fromName: { type: "string", max: 200 },
    password: { type: "string", max: 512 },
    clearPassword: { type: "bool" },
  },
  required: ["host", "port", "tlsMode", "username", "fromLocal", "fromName"],
};

function deriveKey(ikm) {
  return Buffer.from(crypto.hkdfSync("sha256", ikm, Buffer.from("zehnox-mail"), Buffer.from("website-smtp-v2"), 32));
}
const aad = (b) => Buffer.from(AAD_PREFIX + b.host + "|" + b.port + "|" + b.username, "utf8");

function createWebsiteSmtp(opts) {
  const dir = opts.dir;
  const cfg = opts.cfg;
  const env = opts.env || process.env;
  const now = opts.now || (() => new Date());
  const aesKey = Buffer.isBuffer(opts.secretsKey) && opts.secretsKey.length === 32 ? deriveKey(opts.secretsKey) : null;
  const memo = {};

  const file = (n) => path.join(dir, n);

  /* Parsed files memoized by mtime: config() runs on every inquiry email. */
  function readMemo(name) {
    let st;
    try { st = fs.statSync(file(name)); } catch (_) { memo[name] = null; return null; }
    const m = memo[name];
    if (m && m.mtimeMs === st.mtimeMs && m.size === st.size) return m.value;
    let value = null;
    try { value = JSON.parse(fs.readFileSync(file(name), "utf8")); } catch (_) { value = null; }
    memo[name] = { mtimeMs: st.mtimeMs, size: st.size, value };
    return value;
  }
  function write(name, obj) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileAtomic(file(name), JSON.stringify(obj, null, 2) + "\n", { mode: 0o600 });
    memo[name] = undefined;
  }
  function remove(name) {
    try { fs.unlinkSync(file(name)); } catch (e) { if (e.code !== "ENOENT") throw e; }
    memo[name] = undefined;
  }

  function envVals() {
    const e = (k) => (typeof env[k] === "string" ? env[k].trim() : "");
    const port = parseInt(e("SMTP_PORT"), 10);
    const mode = e("SMTP_TLS_MODE").toLowerCase();
    return {
      host: e("SMTP_HOST").toLowerCase().replace(/\.$/, ""),
      port: Number.isSafeInteger(port) && port > 0 && port < 65536 ? port : null,
      tlsMode: mode === "implicit" || mode === "starttls" ? mode : null,
      user: e("SMTP_USER"),
      pass: typeof env.SMTP_PASS === "string" ? env.SMTP_PASS : "",
      from: e("SMTP_FROM"),
    };
  }

  function stored() {
    if (cfg.smtpLock) return null;
    const s = readMemo(SETTINGS);
    return V.isPlainObject(s) && s.v === 1 ? s : null;
  }

  const inDomain = (addr) => typeof addr === "string" && addr.toLowerCase().endsWith("@" + C.PINNED_DOMAIN) && V.isValidLocal(addr.slice(0, addr.lastIndexOf("@")).toLowerCase());

  /* Store value, then env, then default, field by field (section 10.2). SMTP_LOCK=1 makes
     every field env-only. From is always <fromLocal>@zehnox.com, or an env address
     in the pinned domain. */
  function effective() {
    const s = stored() || {};
    const e = envVals();
    const tlsMode = s.tlsMode === "implicit" || s.tlsMode === "starttls" ? s.tlsMode : e.tlsMode || "starttls";
    const host = typeof s.host === "string" && s.host ? s.host : e.host;
    const port = Number.isSafeInteger(s.port) ? s.port : e.port || (tlsMode === "implicit" ? 465 : 587);
    const username = typeof s.username === "string" && s.username ? s.username : e.user;
    const fromLocal = typeof s.fromLocal === "string" && V.isValidLocal(s.fromLocal) ? s.fromLocal : null;
    let from = "";
    if (fromLocal) from = V.addressOf(fromLocal);
    else if (inDomain(e.from)) from = e.from.toLowerCase();
    else if (inDomain(e.user)) from = e.user.toLowerCase();
    const fromName = typeof s.fromName === "string" && s.fromName ? s.fromName : DEFAULT_FROM_NAME;
    return { host, port, tlsMode, username, fromLocal: fromLocal || (from ? from.slice(0, from.indexOf("@")) : null), from, fromName };
  }

  function decryptStored(eff) {
    if (!aesKey || cfg.smtpLock) return null;
    const f = readMemo(SECRETS);
    if (!V.isPlainObject(f) || f.v !== 2 || f.alg !== "A256GCM" || !V.isPlainObject(f.bound)) return null;
    const b = f.bound;
    if (b.host !== eff.host || b.port !== eff.port || b.username !== eff.username) return null;
    try {
      const d = crypto.createDecipheriv("aes-256-gcm", aesKey, Buffer.from(f.iv, "base64"));
      d.setAAD(aad(eff));
      d.setAuthTag(Buffer.from(f.tag, "base64"));
      const pass = Buffer.concat([d.update(Buffer.from(f.ct, "base64")), d.final()]).toString("utf8");
      return { pass, updatedAt: typeof f.updatedAt === "string" ? f.updatedAt : null };
    } catch (_) {
      return null; // wrong key, moved ciphertext or a tampered file: no password, no detail
    }
  }

  function encrypt(pass, binding, user) {
    if (!aesKey) throw mailError("secrets_key_missing");
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
    c.setAAD(aad(binding));
    const ct = Buffer.concat([c.update(Buffer.from(pass, "utf8")), c.final()]);
    return {
      v: 2, alg: "A256GCM", kid: "s1", iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), ct: ct.toString("base64"),
      bound: { host: binding.host, port: binding.port, username: binding.username },
      updatedAt: now().toISOString(), updatedBy: typeof user === "string" ? user.slice(0, 80) : null,
    };
  }

  /* -> { pass, source: 'store'|'env'|null, updatedAt } */
  function resolvePassword(eff) {
    const st = decryptStored(eff);
    if (st) return { pass: st.pass, source: "store", updatedAt: st.updatedAt };
    const e = envVals();
    /* The env password only goes to the env host/port/user. Otherwise a hijacked session
       could re-point the host and have the server hand SMTP_PASS to it. */
    if (e.pass && e.host && eff.host === e.host && eff.port === (e.port || (eff.tlsMode === "implicit" ? 465 : 587)) && eff.username === e.user) {
      return { pass: e.pass, source: "env", updatedAt: null };
    }
    return { pass: "", source: null, updatedAt: null };
  }

  /* What sendMail needs, resolved now. A fresh object every call. */
  function config() {
    const eff = effective();
    const pw = resolvePassword(eff);
    return {
      host: eff.host, port: eff.port, tlsMode: eff.tlsMode, user: eff.username, pass: pw.pass,
      from: eff.from, fromName: eff.fromName,
      rejectUnauthorized: env.SMTP_INSECURE_TLS !== "1",
      clientName: cfg.ehloName, servername: eff.host,
    };
  }
  function ready() {
    const c = config();
    return !!(c.host && c.user && c.pass && c.from);
  }

  /* -> { list: [...], open: false }. MAIL_SMTP_HOST_ALLOWLIST, else MAIL_HOSTNAME plus env
     SMTP_HOST; empty means every host is refused. Development is held to the same rule
     (it used to accept any host name when nothing was configured, which made "Test SMTP"
     a way to probe any host the server can reach). "open" stays in the shape, always false. */
  function allowlist() {
    if (cfg.smtpHostAllowlist) return { list: cfg.smtpHostAllowlist.slice(), open: false };
    const defaults = [cfg.hostname, envVals().host].filter(Boolean);
    return { list: Array.from(new Set(defaults)), open: false };
  }

  /* Allowed ports: MAIL_SMTP_PORT_ALLOWLIST, else the standard ones plus env SMTP_PORT. */
  function ports() {
    if (cfg.smtpPortAllowlist) return cfg.smtpPortAllowlist.slice();
    const p = envVals().port;
    return Array.from(new Set(DEFAULT_PORTS.concat(p ? [p] : []))).sort((a, b) => a - b);
  }

  /* The connection target is checked again at send time for the SMTP test: settings saved
     before a rule tightened (or edited on disk) must not reach a host or port that is no
     longer allowed. Throws host_not_allowed / port_not_allowed. */
  function checkTarget(host, port) {
    if (!host || !allowlist().list.includes(host)) throw mailError("host_not_allowed", { field: "host" });
    if (!ports().includes(port)) throw mailError("port_not_allowed", { field: "port" });
  }

  function publicView() {
    const eff = effective();
    const pw = resolvePassword(eff);
    const al = allowlist();
    return {
      host: eff.host || "", port: eff.port, tlsMode: eff.tlsMode, username: eff.username || "",
      fromLocal: eff.fromLocal, fromAddress: eff.from || null, fromName: eff.fromName,
      passwordSet: !!pw.pass, passwordSource: pw.source, passwordUpdatedAt: pw.updatedAt,
      locked: cfg.smtpLock, allowlist: al.list, allowlistOpen: al.open, allowedPorts: ports(),
      secretsKeyPresent: !!aesKey, ready: !!(eff.host && eff.username && pw.pass && eff.from),
    };
  }

  /* PUT /api/mail/smtp. body is parsed JSON; opts: { actor, listAddresses: async () => ({addresses}) }.
     -> { view, warnings, audit: { changed, values, passwordRemovedByRebind, passwordSet, passwordCleared } } */
  async function update(body, o) {
    if (cfg.smtpLock) throw mailError("smtp_locked");
    try { V.schema(body, PUT_SPEC); } catch (e) { throw mailError(e.code === "unknown_field" ? "unknown_field" : "invalid_body", { field: e.field }); }
    const warnings = [];
    const host = body.host.trim().toLowerCase().replace(/\.$/, "");
    if (!host || net.isIP(host) || !HOST_RE.test(host)) throw mailError("invalid_body", { field: "host" });
    const al = allowlist();
    if (!al.list.includes(host)) throw mailError("host_not_allowed", { field: "host" });
    const port = body.port;
    if (!ports().includes(port)) throw mailError("port_not_allowed", { field: "port" });
    const tlsMode = body.tlsMode;
    if (tlsMode !== "starttls" && tlsMode !== "implicit") throw mailError("invalid_body", { field: "tlsMode" });
    if (tlsMode === "starttls" && port === 465) warnings.push("Port 465 normally expects implicit TLS.");
    if (tlsMode === "implicit" && port === 587) warnings.push("Port 587 normally expects STARTTLS.");
    const username = body.username.trim();
    if (!username || /[\r\n\0]/.test(username)) throw mailError("invalid_body", { field: "username" });
    let fromLocal;
    try { fromLocal = V.normalizeLocal(body.fromLocal); } catch (e) { throw mailError(e.code, { field: "fromLocal" }); }
    const fromName = sanitizeHeader(body.fromName).slice(0, 100);
    const password = typeof body.password === "string" && body.password.length ? body.password : null;
    if (password && body.clearPassword === true) throw mailError("invalid_body", { field: "password" });
    if (password && password.includes("\0")) throw mailError("invalid_body", { field: "password" });
    if (password && !aesKey) throw mailError("secrets_key_missing", { field: "password" });

    try {
      const list = await o.listAddresses();
      const a = list.addresses.find((x) => x.local === fromLocal);
      if (!a || !a.enabled) throw mailError("not_found", { field: "fromLocal" });
    } catch (e) {
      if (e && e.code === "not_found") throw e;
      warnings.push("The mail service could not be reached to check the From address.");
    }

    const before = effective();
    const prevStore = stored() || {};
    const next = { v: 1, host, port, tlsMode, username, fromLocal, fromName, updatedAt: now().toISOString(), updatedBy: o.actor && typeof o.actor.user === "string" ? o.actor.user.slice(0, 80) : null };
    const changed = ["host", "port", "tlsMode", "username", "fromLocal", "fromName"].filter((k) => prevStore[k] !== next[k]);
    const rebind = before.host !== host || before.port !== port || before.username !== username;
    const hadSecret = !!readMemo(SECRETS);

    write(SETTINGS, next);
    let passwordRemovedByRebind = false;
    let passwordCleared = false;
    if (password) {
      write(SECRETS, encrypt(password, { host, port, username }, next.updatedBy));
      changed.push("password");
    } else if (body.clearPassword === true) {
      if (hadSecret) remove(SECRETS);
      passwordCleared = hadSecret;
    } else if (rebind && hadSecret) {
      remove(SECRETS);
      passwordRemovedByRebind = true;
      warnings.push("The stored password was removed because the host, port or username changed. Enter it again.");
    }
    const values = {};
    for (const k of ["host", "port", "tlsMode", "username", "fromLocal"]) if (changed.includes(k)) values[k] = next[k];
    return {
      view: publicView(),
      warnings,
      audit: { changed, values, passwordRemovedByRebind, passwordSet: !!password, passwordCleared },
    };
  }

  /* POST /api/mail/smtp/rotate (section 10.5). opts: { provider, hashPool, ctx, hashOpts }.
     The generated password is never returned, logged or shown to anyone: it goes from
     randomBytes into the hash pool and the encrypted file, and the variable is dropped. */
  async function rotate(o) {
    if (cfg.smtpLock) throw mailError("smtp_locked");
    if (!aesKey) throw mailError("secrets_key_missing");
    const eff = effective();
    const s = stored();
    if (!s || !V.isValidLocal(s.fromLocal) || eff.username !== V.addressOf(s.fromLocal)) throw mailError("not_eligible");
    const addr = await o.provider.getAddress(s.fromLocal);
    if (!addr || !addr.enabled || !addr.mailbox || !addr.mailbox.enabled) throw mailError("not_eligible");
    let pass = crypto.randomBytes(32).toString("base64url");
    const hash = await o.hashPool.hash(pass, o.hashOpts || {});
    const pending = file(SECRETS + ".pending");
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileAtomic(pending, JSON.stringify(encrypt(pass, { host: eff.host, port: eff.port, username: eff.username }, o.ctx && o.ctx.actor && o.ctx.actor.user), null, 2) + "\n", { mode: 0o600 });
    pass = null;
    let result;
    try {
      result = await o.provider.changeMailboxPassword({ local: s.fromLocal, passwordHash: hash }, o.ctx);
    } catch (e) {
      try { fs.unlinkSync(pending); } catch (_) { /* nothing to clean */ }
      throw e;
    }
    try {
      fs.renameSync(pending, file(SECRETS));
      memo[SECRETS] = undefined;
    } catch (_) {
      throw mailError("rotate_not_saved");
    }
    return { result, passwordUpdatedAt: now().toISOString() };
  }

  /* Eligibility for the UI (section 10.5), without calling the provider. */
  function rotateCandidate() {
    const s = stored();
    const eff = effective();
    return s && V.isValidLocal(s.fromLocal) && eff.username === V.addressOf(s.fromLocal) ? s.fromLocal : null;
  }

  return { config, ready, publicView, update, rotate, rotateCandidate, allowlist, ports, checkTarget, secretsKeyPresent: () => !!aesKey };
}

module.exports = { createWebsiteSmtp, PUT_SPEC, DEFAULT_PORTS };
