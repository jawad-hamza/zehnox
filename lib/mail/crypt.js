"use strict";
/* Password hashing for mailboxes (DESIGN.md section 8.1). Pure JS on node:crypto.

   D5: the web process hashes, the daemon only ever receives a hash. Dovecot reads the
   passwd-file directly, so the format is Dovecot's: {SHA512-CRYPT}$6$rounds=R$salt$hash,
   which is glibc crypt(3) SHA-512 behind a scheme prefix. There is no crypt(3) binding in
   Node's stdlib (and no child processes here, ever), so the algorithm is implemented from
   Ulrich Drepper's "Unix crypt using SHA-256 and SHA-512" specification and checked in
   the tests against the vectors published with it.

   This runs inside hash-worker.js via hash-pool.js in production: 100,000 rounds is a few
   hundred milliseconds of CPU that must not block the event loop. */

const crypto = require("crypto");
const { SHA512_HASH_RE, ARGON2_HASH_RE, LIMITS } = require("./core/constants.js");

const ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const ROUNDS_DEFAULT = 5000;          // glibc default when no rounds= is given
const ROUNDS_MIN = 1000;              // glibc clamps below this
const ROUNDS_MAX = 999999999;         // glibc clamps above this
const SALT_MAX = 16;

/* Byte order of the final base64 encoding, from the specification (SHA-512 table). */
const ORDER = [
  [0, 21, 42], [22, 43, 1], [44, 2, 23], [3, 24, 45], [25, 46, 4], [47, 5, 26], [6, 27, 48],
  [28, 49, 7], [50, 8, 29], [9, 30, 51], [31, 52, 10], [53, 11, 32], [12, 33, 54], [34, 55, 13],
  [56, 14, 35], [15, 36, 57], [37, 58, 16], [59, 17, 38], [18, 39, 60], [40, 61, 19], [62, 20, 41],
];

function b64From24(b2, b1, b0, n) {
  let w = (b2 << 16) | (b1 << 8) | b0;
  let out = "";
  for (let i = 0; i < n; i++) { out += ITOA64[w & 0x3f]; w >>>= 6; }
  return out;
}

const sha512 = () => crypto.createHash("sha512");

/* Repeats `block` to exactly `len` bytes (the P- and S-sequences of the spec). */
function repeatTo(block, len) {
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i += block.length) block.copy(out, i, 0, Math.min(block.length, len - i));
  return out;
}

/* The raw algorithm with glibc semantics, for a setting string "$6$[rounds=N$]salt[$...]".
   Returns "$6$[rounds=N$]salt$hash86". Exported for the published test vectors. */
function sha512CryptRaw(password, setting) {
  const pw = Buffer.isBuffer(password) ? password : Buffer.from(String(password), "utf8");
  let rest = String(setting);
  if (!rest.startsWith("$6$")) throw new TypeError("not a SHA-512 crypt setting");
  rest = rest.slice(3);
  let rounds = ROUNDS_DEFAULT;
  let custom = false;
  const rm = rest.match(/^rounds=(\d+)\$/);
  if (rm) {
    custom = true;
    rounds = Math.min(ROUNDS_MAX, Math.max(ROUNDS_MIN, Number(rm[1])));
    rest = rest.slice(rm[0].length);
  }
  const saltStr = rest.split("$")[0].slice(0, SALT_MAX);
  const salt = Buffer.from(saltStr, "utf8");

  // Digest B = H(P S P)
  const B = sha512().update(pw).update(salt).update(pw).digest();

  // Digest A = H(P S B-bytes-for-len(P) and, per bit of len(P), B or P)
  const a = sha512().update(pw).update(salt);
  a.update(repeatTo(B, pw.length));
  for (let n = pw.length; n > 0; n >>>= 1) a.update(n & 1 ? B : pw);
  let Cd = a.digest();

  // P-sequence: H(P repeated len(P) times), stretched to len(P) bytes
  const dp = sha512();
  for (let i = 0; i < pw.length; i++) dp.update(pw);
  const Pseq = repeatTo(dp.digest(), pw.length);

  // S-sequence: H(S repeated 16 + A[0] times), stretched to len(S) bytes
  const ds = sha512();
  for (let i = 0; i < 16 + Cd[0]; i++) ds.update(salt);
  const Sseq = repeatTo(ds.digest(), salt.length);

  for (let i = 0; i < rounds; i++) {
    const h = sha512();
    if (i & 1) h.update(Pseq); else h.update(Cd);
    if (i % 3) h.update(Sseq);
    if (i % 7) h.update(Pseq);
    if (i & 1) h.update(Cd); else h.update(Pseq);
    Cd = h.digest();
  }

  let enc = "";
  for (const [x, y, z] of ORDER) enc += b64From24(Cd[x], Cd[y], Cd[z], 4);
  enc += b64From24(0, 0, Cd[63], 2);
  return "$6$" + (custom ? "rounds=" + rounds + "$" : "") + saltStr + "$" + enc;
}

/* 16 salt characters from ./0-9A-Za-z. The alphabet has exactly 64 symbols, so masking a
   random byte to 6 bits is already uniform: rejection sampling would reject nothing. */
function randomSalt(len) {
  const n = len || SALT_MAX;
  const bytes = crypto.randomBytes(n);
  let out = "";
  for (let i = 0; i < n; i++) out += ITOA64[bytes[i] & 63];
  return out;
}

/* Default rounds: MAIL_HASH_ROUNDS or 100,000. The floor is 50,000 (the daemon's), or the
   algorithm's own 1,000 under NODE_ENV=test so test suites stay fast. */
function defaultRounds() {
  const env = parseInt(process.env.MAIL_HASH_ROUNDS || "", 10);
  return Number.isSafeInteger(env) && env > 0 ? env : 100000;
}
function defaultMinRounds() {
  return process.env.NODE_ENV === "test" ? ROUNDS_MIN : LIMITS.minRounds;
}

/* -> "{SHA512-CRYPT}$6$rounds=R$salt16$hash86". rounds= is always written explicitly, so
   the stored hash never depends on a default that could change. */
function sha512Crypt(password, opts) {
  const o = opts || {};
  const rounds = o.rounds == null ? defaultRounds() : o.rounds;
  const minRounds = o.minRounds == null ? defaultMinRounds() : o.minRounds;
  if (!Number.isSafeInteger(rounds) || rounds < Math.max(ROUNDS_MIN, minRounds) || rounds > LIMITS.maxRounds) throw new RangeError("rounds out of range");
  const salt = o.salt == null ? randomSalt() : String(o.salt);
  if (!/^[./0-9A-Za-z]{16}$/.test(salt)) throw new RangeError("salt must be 16 characters from ./0-9A-Za-z");
  if (typeof password !== "string") throw new TypeError("password must be a string");
  const out = "{SHA512-CRYPT}" + sha512CryptRaw(password, "$6$rounds=" + rounds + "$" + salt);
  if (!SHA512_HASH_RE.test(out)) throw new Error("hash format self-check failed");
  return out;
}

/* Tests and the mock only: the production path never verifies a mailbox password (Dovecot
   does). Accepts the value with or without the {SHA512-CRYPT} prefix. */
function sha512Verify(password, hash) {
  const h = String(hash || "").replace(/^\{SHA512-CRYPT\}/, "");
  const m = h.match(/^(\$6\$(?:rounds=\d+\$)?[^$]{0,16})\$[./0-9A-Za-z]{86}$/);
  if (!m || typeof password !== "string") return false;
  const again = Buffer.from(sha512CryptRaw(password, m[1] + "$"));
  const want = Buffer.from(h);
  return again.length === want.length && crypto.timingSafeEqual(again, want);
}

/* ---------- Argon2id (off by default: MAIL_PASSWORD_SCHEME=ARGON2ID) ----------
   crypto.argon2 is experimental in Node 24, so this path exists only behind the flag and
   only when the daemon config lists ARGON2ID too. Dovecot's format is the PHC string with
   unpadded standard base64. */
const ARGON2 = Object.freeze({ memory: 65536, passes: 3, parallelism: 1, tagLength: 32, saltLength: 16 });
const argon2Available = () => typeof crypto.argon2 === "function";
const b64NoPad = (buf) => buf.toString("base64").replace(/=+$/, "");

function argon2Raw(password, salt, params) {
  return new Promise((resolve, reject) => {
    crypto.argon2("argon2id", {
      message: Buffer.from(password, "utf8"), nonce: salt,
      parallelism: params.parallelism, tagLength: params.tagLength, memory: params.memory, passes: params.passes,
    }, (err, tag) => (err ? reject(err) : resolve(tag)));
  });
}

async function argon2idDovecot(password, opts) {
  if (!argon2Available()) throw new Error("argon2 is not available in this Node build");
  if (typeof password !== "string") throw new TypeError("password must be a string");
  const p = Object.assign({}, ARGON2, opts || {});
  const salt = crypto.randomBytes(p.saltLength);
  const tag = await argon2Raw(password, salt, p);
  const out = "{ARGON2ID}$argon2id$v=19$m=" + p.memory + ",t=" + p.passes + ",p=" + p.parallelism + "$" + b64NoPad(salt) + "$" + b64NoPad(tag);
  if (!ARGON2_HASH_RE.test(out)) throw new Error("hash format self-check failed");
  return out;
}

async function argon2idVerify(password, hash) {
  const m = String(hash || "").match(/^\{ARGON2ID\}\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/);
  if (!m || !argon2Available() || typeof password !== "string") return false;
  const want = Buffer.from(m[5], "base64");
  const tag = await argon2Raw(password, Buffer.from(m[4], "base64"), { memory: +m[1], passes: +m[2], parallelism: +m[3], tagLength: want.length });
  return tag.length === want.length && crypto.timingSafeEqual(tag, want);
}

module.exports = {
  sha512Crypt, sha512Verify, sha512CryptRaw, randomSalt, defaultRounds, defaultMinRounds,
  argon2idDovecot, argon2idVerify, argon2Available, ARGON2, ITOA64,
};
