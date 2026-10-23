"use strict";
/* Redaction for everything the mail module writes to an audit record, a log line or an
   SMTP test result (DESIGN.md section 13.5).

   The primary defence is structural: error messages are constants, request bodies are
   never logged, audit details are allowlisted per action. These two functions are the
   second line, for the day someone passes the wrong object. */

const SENSITIVE_KEY_RE = /pass(word)?|secret|hash|key|token|auth|cookie|signature|sig/i;
const CRYPT_RE = /\{[A-Z0-9-]+\}\$|\$[0-9a-z]+\$/;
const B64_RUN_RE = /[A-Za-z0-9+/_-]{40,}={0,2}/g;
const MASK = "[redacted]";
const MAX_DEPTH = 8;

function redactString(s) {
  if (CRYPT_RE.test(s)) return MASK;
  return s.replace(B64_RUN_RE, MASK);
}

/* Deep clone that drops sensitive keys and masks hash-like strings and long base64 runs.
   Cycles and very deep nesting are cut rather than followed. */
function redactDeep(value, depth) {
  const d = depth || 0;
  if (d > MAX_DEPTH) return MASK;
  if (typeof value === "string") return redactString(value);
  if (value === null || typeof value !== "object") return typeof value === "function" || typeof value === "symbol" || typeof value === "bigint" ? undefined : value;
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, d + 1));
  const out = {};
  for (const k of Object.keys(value)) {
    if (k === "__proto__" || k === "constructor" || k === "prototype" || SENSITIVE_KEY_RE.test(k)) continue;
    const v = redactDeep(value[k], d + 1);
    if (v !== undefined) out[k] = v;
  }
  return out;
}

/* Every form a secret takes on the wire: itself, base64, base64url. The caller adds the
   composite forms it knows about (the AUTH PLAIN blob "\0user\0pass"). */
function secretForms(secret) {
  const s = String(secret);
  if (!s) return [];
  const b = Buffer.from(s, "utf8");
  return [s, b.toString("base64"), b.toString("base64").replace(/=+$/, ""), b.toString("base64url")];
}

/* Removes every listed secret (and its base64 forms), collapses CR/LF and whitespace,
   keeps printable ASCII only and caps the length. Longest forms are removed first so a
   secret that contains another is not left half-visible. */
function scrubString(s, secrets, max) {
  let out = String(s == null ? "" : s);
  const forms = [];
  for (const sec of secrets || []) if (sec != null && String(sec).length >= 1) forms.push(...secretForms(sec));
  forms.sort((a, b) => b.length - a.length);
  for (const f of forms) if (f) out = out.split(f).join(MASK);
  out = out.replace(/[\r\n]+/g, " ").replace(/[^\x20-\x7e]/g, "?").replace(/\s+/g, " ").trim();
  const cap = max == null ? 200 : max;
  return out.length > cap ? out.slice(0, cap) : out;
}

module.exports = { redactDeep, scrubString, secretForms, SENSITIVE_KEY_RE, MASK };
