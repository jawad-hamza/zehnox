"use strict";
/* Validation shared by the web process and the daemon (DESIGN.md section 3).
   Pure: no fs, no net, no env. Every rule here runs on both sides of the socket, so the
   daemon never trusts that the web process already checked. */

const C = require("./constants.js");
const { CoreError } = C;

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/* ---------- local part ---------- */

/* Strict form used by the core and the daemon: the value must already be the lowercase
   canonical form. Anything else is refused, never "fixed", on this side. */
function checkLocal(local) {
  if (typeof local !== "string" || !C.LOCAL_RE.test(local)) throw new CoreError("invalid_local", { field: "local" });
  if (C.RESERVED.includes(local)) throw new CoreError("reserved_local", { field: "local" });
  return local;
}

/* Node-side normalisation of what the admin typed: trim, refuse non-ASCII (so a Cyrillic
   "о" can never pass as an "o"), lowercase, then the strict check. An "@" gets the same
   code with a dedicated hint in the UI ("Enter only the part before @zehnox.com"). */
function normalizeLocal(input) {
  if (typeof input !== "string") throw new CoreError("invalid_local", { field: "local" });
  const v = input.trim();
  if (!v || v.length > 64 || /[^\x21-\x7e]/.test(v)) throw new CoreError("invalid_local", { field: "local" });
  return checkLocal(v.toLowerCase());
}

const isValidLocal = (v) => typeof v === "string" && C.LOCAL_RE.test(v);
const isProtected = (local) => C.PROTECTED.includes(local);
const addressOf = (local) => local + "@" + C.PINNED_DOMAIN;

/* ---------- forwarding destinations ---------- */

function isDestination(v) {
  if (typeof v !== "string" || v.length > C.LIMITS.destMax || !C.DEST_RE.test(v)) return false;
  const localPart = v.slice(0, v.lastIndexOf("@"));
  // DEST_RE admits dots anywhere in the local part; RFC 5321 dot-atoms do not.
  return !(localPart.startsWith(".") || localPart.endsWith(".") || localPart.includes(".."));
}

/* Node side: trim and lowercase the domain part; the local part keeps the case as typed
   (some providers are case-sensitive there, though almost none are). */
function normalizeDestination(input) {
  if (typeof input !== "string") throw new CoreError("invalid_destination", { field: "forwards" });
  const v = input.trim();
  const at = v.lastIndexOf("@");
  if (at < 1) throw new CoreError("invalid_destination", { field: "forwards" });
  const out = v.slice(0, at) + "@" + v.slice(at + 1).toLowerCase();
  if (!isDestination(out)) throw new CoreError("invalid_destination", { field: "forwards" });
  return out;
}

const destDomain = (d) => d.slice(d.lastIndexOf("@") + 1);
const isSameDomain = (d) => destDomain(d) === C.PINNED_DOMAIN;

/* Validates (strict: no trimming) and de-duplicates case-insensitively, keeping the first
   spelling. Both sides call this; the Node side normalises each entry first. */
function cleanForwards(list, opts) {
  const o = opts || {};
  const min = o.min == null ? 0 : o.min;
  const max = o.max == null ? C.LIMITS.maxForwardsPerAddress : o.max;
  if (!Array.isArray(list)) throw new CoreError("invalid_destination", { field: "forwards" });
  const seen = new Set();
  const out = [];
  for (const d of list) {
    if (!isDestination(d)) throw new CoreError("invalid_destination", { field: "forwards" });
    const k = d.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(d);
  }
  if (out.length > max) throw new CoreError("too_many_destinations", { field: "forwards" });
  if (out.length < min) throw new CoreError("no_destination", { field: "forwards" });
  return out;
}

/* ---------- password hashes (section 3.4) ---------- */

/* policy: { schemes: ['SHA512-CRYPT'] (+ 'ARGON2ID' when enabled on both sides), minRounds }.
   Returns the scheme name or throws invalid_hash / weak_rounds. {BLF-CRYPT} and anything
   else is refused: Dovecot would accept it, but we only emit and audit these two. */
function checkHash(hash, policy) {
  const p = policy || {};
  const schemes = Array.isArray(p.schemes) && p.schemes.length ? p.schemes : ["SHA512-CRYPT"];
  const minRounds = Number.isSafeInteger(p.minRounds) ? p.minRounds : C.LIMITS.minRounds;
  if (typeof hash !== "string" || hash.length > 512) throw new CoreError("invalid_hash", { field: "passwordHash" });
  let m = hash.match(C.SHA512_HASH_RE);
  if (m) {
    if (!schemes.includes("SHA512-CRYPT")) throw new CoreError("invalid_hash", { field: "passwordHash" });
    const rounds = parseInt(m[1], 10);
    if (rounds < minRounds || rounds > C.LIMITS.maxRounds) throw new CoreError("weak_rounds", { field: "passwordHash" });
    return "SHA512-CRYPT";
  }
  m = hash.match(C.ARGON2_HASH_RE);
  if (m) {
    if (!schemes.includes("ARGON2ID")) throw new CoreError("invalid_hash", { field: "passwordHash" });
    if (parseInt(m[1], 10) < C.ARGON2_MIN.m || parseInt(m[2], 10) < C.ARGON2_MIN.t) throw new CoreError("weak_rounds", { field: "passwordHash" });
    return "ARGON2ID";
  }
  throw new CoreError("invalid_hash", { field: "passwordHash" });
}

/* ---------- strict schema checker (section 3.5) ----------
   spec forms:
     { type: 'object', props: { k: spec }, required: ['k'] }   unknown keys are refused
     { type: 'string', min, max, re }                            re is a RegExp
     { type: 'int', min, max }                                   safe integer, >= 0 unless min says otherwise
     { type: 'bool' }
     { type: 'array', items: spec, min, max }
     { type: 'any' }                                             value checked by the caller
   Any spec may add nullable: true. Errors: opts.unknownCode for an unknown or forbidden key
   (Node: 'unknown_field', daemon: 'bad_request'), opts.typeCode for everything else. */
function schema(value, spec, opts) {
  const o = Object.assign({ unknownCode: "unknown_field", typeCode: "invalid_body" }, opts || {});
  walk(value, spec, o, "");
  return value;
}

function walk(v, spec, o, pathName) {
  const bad = () => { throw new CoreError(o.typeCode, pathName ? { field: pathName.split(".")[0] } : undefined); };
  if (v === null) { if (spec.nullable) return; bad(); }
  if (v === undefined) bad();
  switch (spec.type) {
    case "any": return;
    case "string":
      if (typeof v !== "string") bad();
      if (spec.min != null && v.length < spec.min) bad();
      if (spec.max != null && v.length > spec.max) bad();
      if (spec.re && !spec.re.test(v)) bad();
      return;
    case "int":
      if (!Number.isSafeInteger(v)) bad();
      if (v < (spec.min == null ? 0 : spec.min)) bad();
      if (spec.max != null && v > spec.max) bad();
      return;
    case "bool":
      if (typeof v !== "boolean") bad();
      return;
    case "array":
      if (!Array.isArray(v)) bad();
      if (spec.min != null && v.length < spec.min) bad();
      if (spec.max != null && v.length > spec.max) bad();
      for (let i = 0; i < v.length; i++) walk(v[i], spec.items, o, pathName || "items");
      return;
    case "object": {
      if (!isPlainObject(v)) bad();
      const props = spec.props || {};
      /* Object.keys lists own enumerable keys only; JSON.parse creates "__proto__" as an own
         key, so it is caught here instead of silently re-parenting the object. */
      for (const k of Object.keys(v)) {
        if (FORBIDDEN_KEYS.has(k) || !hasOwn(props, k)) throw new CoreError(o.unknownCode, { field: pathName ? pathName.split(".")[0] : k });
      }
      for (const k of spec.required || []) if (!hasOwn(v, k)) throw new CoreError(o.typeCode, { field: pathName ? pathName.split(".")[0] : k });
      for (const k of Object.keys(v)) walk(v[k], props[k], o, pathName ? pathName + "." + k : k);
      return;
    }
    default:
      throw new CoreError(o.typeCode);
  }
}

/* ---------- per-verb argument schemas (section 5.4) ----------
   Shapes only; the value rules (regexes, hash policy, references) run in core.apply. */
const L = { type: "string", min: 1, max: 64 };
const F = { type: "string", min: 3, max: C.LIMITS.destMax };
const H = { type: "string", min: 10, max: 512 };
const obj = (props, required) => ({ type: "object", props, required: required || Object.keys(props) });

const VERB_ARGS = Object.freeze({
  getMailStatus: obj({}),
  listAddresses: obj({}),
  getAuditTail: obj({ limit: { type: "int", min: 1, max: C.LIMITS.auditTailMax }, beforeSeq: { type: "int", min: 1, nullable: true } }),
  createAddress: obj({
    local: L,
    forwards: { type: "array", items: F, min: 0, max: C.LIMITS.maxForwardsPerAddress },
    mailbox: { type: "object", nullable: true, props: { passwordHash: H }, required: ["passwordHash"] },
    reuseDeleted: { type: "bool" },
  }),
  deleteAddress: obj({ local: L, confirm: { type: "string", min: 0, max: 200 } }),
  setForwarding: obj({ local: L, forwards: { type: "array", items: F, min: 1, max: C.LIMITS.maxForwardsPerAddress } }),
  removeForwarding: obj({ local: L }),
  setAddressEnabled: obj({ local: L, enabled: { type: "bool" } }),
  createMailbox: obj({ local: L, passwordHash: H }),
  disableMailbox: obj({ local: L }),
  enableMailbox: obj({ local: L }),
  changeMailboxPassword: obj({ local: L, passwordHash: H }),
});

/* Daemon semantics: an unknown verb is unknown_verb, any shape problem is bad_request. */
function checkVerbArgs(verb, args) {
  if (typeof verb !== "string" || !hasOwn(C.VERBS, verb)) throw new CoreError("unknown_verb");
  schema(args, VERB_ARGS[verb], { unknownCode: "bad_request", typeCode: "bad_request" });
  return args;
}

module.exports = {
  checkLocal, normalizeLocal, isValidLocal, isProtected, addressOf,
  isDestination, normalizeDestination, cleanForwards, destDomain, isSameDomain,
  checkHash, schema, VERB_ARGS, checkVerbArgs, isPlainObject, hasOwn,
};
