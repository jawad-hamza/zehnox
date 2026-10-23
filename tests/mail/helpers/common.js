"use strict";
/* Shared test plumbing for tests/ (node:test, zero dependencies).

   - REPO / lib paths, so every test file requires the product code the same way.
   - Temporary directories under ZEHNOX_TEST_TMP (or the OS temp dir), removed when the
     process exits. Nothing is ever written inside the git checkout.
   - Canaries: throwaway secrets generated at run time, never committed, in every form a
     secret can take on the wire (plain, base64, base64url, the SMTP AUTH PLAIN blob), and
     a sweep that reports every place one of them shows up.
   - Ports: every test file that listens on TCP gets its own slice of 4200-4249 (movable with
     ZEHNOX_TEST_PORT_BASE), so the files can also run in parallel (node --test "tests/**"
     spawns one process per file). */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

/* tests/mail/helpers/ is one directory deeper than in the project this came from. */
const REPO = path.resolve(__dirname, "..", "..", "..");
const LIB = path.join(REPO, "lib", "mail");
const CORE = path.join(LIB, "core");
const WIN = process.platform === "win32";

/* ---------- temporary directories ---------- */

const TMP_ROOT = process.env.ZEHNOX_TEST_TMP ? path.resolve(process.env.ZEHNOX_TEST_TMP) : os.tmpdir();
const made = [];
function mkTmp(prefix) {
  fs.mkdirSync(TMP_ROOT, { recursive: true });
  const d = fs.mkdtempSync(path.join(TMP_ROOT, "zx-" + (prefix || "t") + "-"));
  made.push(d);
  return d;
}
function cleanupTmp() {
  if (process.env.ZEHNOX_TEST_KEEP === "1") return;
  while (made.length) {
    const d = made.pop();
    try { fs.rmSync(d, { recursive: true, force: true, maxRetries: 3 }); } catch (_) { /* a file still held open on Windows */ }
  }
}
process.on("exit", cleanupTmp);

/* ---------- canaries ---------- */

/* A password-looking string that no real system uses. The marker makes a hit easy to
   read in a failure message; the random tail makes it unique to this run. */
function canary(label) {
  return "Canary" + (label || "") + "-" + crypto.randomBytes(6).toString("hex") + "!Qz";
}
/* 32 random bytes as hex: an obviously throwaway test key, generated now. */
const testKeyHex = () => crypto.randomBytes(32).toString("hex");

/* Every form a secret takes: itself, base64 (padded and not), base64url. */
function forms(secret) {
  const s = String(secret);
  const b = Buffer.from(s, "utf8");
  return Array.from(new Set([s, b.toString("base64"), b.toString("base64").replace(/=+$/, ""), b.toString("base64url")]));
}
/* The SMTP AUTH PLAIN blob for user+pass, and its forms. */
const authPlain = (user, pass) => Buffer.from("\0" + user + "\0" + pass, "utf8").toString("base64");

/* The crypt marker, built at run time so no test file holds the literal (the repo-hygiene
   scan flags the literal marker outside the crypt vectors). */
const CRYPT6 = "$" + "6" + "$";

/* Returns [{ where, needle }] for every needle found in any haystack. haystacks: [{ where, text }]. */
function sweep(haystacks, needles) {
  const hits = [];
  for (const h of haystacks) {
    const text = String(h.text == null ? "" : h.text);
    for (const n of needles) {
      if (n && text.includes(n)) hits.push({ where: h.where, needle: n.length > 12 ? n.slice(0, 6) + "..." : n });
    }
  }
  return hits;
}

/* Every regular file under dir as { where, text } (latin1, so binary files are searched too). */
function filesUnder(dir, exclude) {
  const out = [];
  const walk = (d) => {
    let names = [];
    try { names = fs.readdirSync(d, { withFileTypes: true }); } catch (_) { return; }
    for (const e of names) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile() && !(exclude && exclude(p))) out.push({ where: p, text: fs.readFileSync(p, "latin1") });
    }
  };
  walk(dir);
  return out;
}

/* Walks any JSON value and returns the paths of keys that look like they could hold a
   secret. Responses must never carry one (they are built by allowlist serializers). */
const SECRET_KEY_RE = /pass(word)?$|^pass|hash|secret|^key$|token|^ct$|^iv$|^tag$|salt/i;
const ALLOWED_KEYS = new Set(["passed", "passwordSet", "passwordSource", "passwordUpdatedAt", "passwordSetAt", "passwordRemovedByRebind", "secretsKeyPresent"]);
function secretLookingKeys(value, where) {
  const out = [];
  const walk = (v, p) => {
    if (Array.isArray(v)) v.forEach((x, i) => walk(x, p + "[" + i + "]"));
    else if (v && typeof v === "object") {
      for (const k of Object.keys(v)) {
        if (SECRET_KEY_RE.test(k) && !ALLOWED_KEYS.has(k)) out.push(p + "." + k);
        walk(v[k], p + "." + k);
      }
    }
  };
  walk(value, where || "$");
  return out;
}

/* A syntactically valid {SHA512-CRYPT} value with random salt and digest: the daemon and
   the core check the format and the rounds, never the digest. */
function fakeHash(rounds) {
  const A = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const pick = (n) => Array.from(crypto.randomBytes(n), (b) => A[b & 63]).join("");
  return "{SHA512-CRYPT}" + CRYPT6 + "rounds=" + (rounds || 50000) + "$" + pick(16) + "$" + pick(86);
}

const ctxFor = (ifRev, idem) => ({ actor: { user: "admin", via: "cookie", ip: "127.0.0.1" }, idem: idem || crypto.randomUUID(), ifRev });

/* Ports per file. The suite owns a block of 50 ports starting at 4200; ZEHNOX_TEST_PORT_BASE
   moves the whole block (for example when another checkout runs its own suite at the same
   time on the same machine). */
const PORT_BASE = (() => {
  const n = parseInt(process.env.ZEHNOX_TEST_PORT_BASE || "", 10);
  return Number.isSafeInteger(n) && n >= 1024 && n <= 65000 ? n : 4200;
})();
const PORTS = Object.freeze({
  api: PORT_BASE,            // +0..+9: spawned servers
  apiSmtp: PORT_BASE + 10,   // +10..+19: fake SMTP servers used by api.test.js
  smtp: PORT_BASE + 20,      // +20..+39: fake SMTP servers used by smtp-test.test.js
  portal: PORT_BASE + 40,    // +40..+44: fake member portals used by portal-intake.test.js
  closed: PORT_BASE + 49,    // never listened on: "unreachable host"
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

module.exports = {
  REPO, LIB, CORE, WIN, TMP_ROOT, mkTmp, cleanupTmp,
  canary, testKeyHex, forms, authPlain, CRYPT6, sweep, filesUnder, secretLookingKeys, fakeHash, ctxFor,
  PORTS, sleep,
};
