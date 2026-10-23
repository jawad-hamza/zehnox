"use strict";
/* Password hashing (lib/mail/crypt.js, hash-pool.js), DESIGN.md sections 3.4 and 8.

   The known-answer vectors are the ones published with Ulrich Drepper's "Unix crypt using
   SHA-256 and SHA-512" specification (the SHA-512 set, also glibc's crypt-sha512 tests).
   They pin default rounds, explicit rounds, salt truncation to 16 characters and the
   clamp of rounds below 1000. A pure-JS implementation that passes them is compatible
   with glibc crypt(3), and so with Dovecot's {SHA512-CRYPT}. */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const crypto = require("crypto");
const { LIB, CORE, canary, CRYPT6 } = require("./helpers/common.js");

const crypt = require(path.join(LIB, "crypt.js"));
const C = require(path.join(CORE, "constants.js"));
const V = require(path.join(CORE, "validate.js"));
const { createHashPool, WORKER_FILE } = require(path.join(LIB, "hash-pool.js"));

const D = CRYPT6; // the SHA-512 crypt marker, assembled at run time
const VECTORS = [
  [D + "saltstring", "Hello world!",
    D + "saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"],
  [D + "rounds=10000$saltstringsaltstring", "Hello world!",
    D + "rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."],
  [D + "rounds=5000$toolongsaltstring", "This is just a test",
    D + "rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"],
  [D + "rounds=1400$anotherlongsaltstring", "a very much longer text to encrypt.  This one even stretches over morethan one line.",
    D + "rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1"],
  [D + "rounds=77777$short", "we have a short salt string but not a short password",
    D + "rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"],
  [D + "rounds=123456$asaltof16chars..", "a short string",
    D + "rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"],
  [D + "rounds=10$roundstoolow", "the minimum number is still observed",
    D + "rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."],
];

test("SHA-512 crypt: Drepper's published known-answer vectors", () => {
  for (const [setting, pw, want] of VECTORS) {
    assert.equal(crypt.sha512CryptRaw(pw, setting), want, setting);
  }
});

test("SHA-512 crypt: the known answers verify, and a wrong password does not", () => {
  for (const [, pw, want] of VECTORS) {
    assert.equal(crypt.sha512Verify(pw, want), true);
    assert.equal(crypt.sha512Verify(pw + "x", want), false);
    assert.equal(crypt.sha512Verify(pw, "{SHA512-CRYPT}" + want), true, "the Dovecot prefix is accepted");
  }
  assert.equal(crypt.sha512Verify("x", "garbage"), false);
  assert.equal(crypt.sha512Verify(undefined, VECTORS[0][2]), false);
});

test("sha512Crypt: Dovecot format, explicit rounds, 16-char salt, matches the daemon regex", () => {
  const pw = canary("crypt");
  const h = crypt.sha512Crypt(pw, { rounds: 5000, minRounds: 1000 });
  assert.match(h, C.SHA512_HASH_RE);
  assert.ok(h.startsWith("{SHA512-CRYPT}" + D + "rounds=5000$"), "rounds= is always written explicitly");
  const salt = h.split("$")[3];
  assert.match(salt, /^[./0-9A-Za-z]{16}$/);
  assert.equal(crypt.sha512Verify(pw, h), true);
  assert.ok(!h.includes(pw));
  // Same password, two hashes: fresh salts.
  assert.notEqual(crypt.sha512Crypt(pw, { rounds: 1000, minRounds: 1000 }), crypt.sha512Crypt(pw, { rounds: 1000, minRounds: 1000 }));
  // A fixed salt reproduces the raw algorithm exactly.
  const fixed = crypt.sha512Crypt("Hello world!", { rounds: 10000, minRounds: 1000, salt: "saltstringsaltst" });
  assert.equal(fixed, "{SHA512-CRYPT}" + VECTORS[1][2]);
});

test("sha512Crypt: the production floor is enforced; the core accepts exactly what it emits", () => {
  assert.throws(() => crypt.sha512Crypt("x", { rounds: 1000, minRounds: C.LIMITS.minRounds }), RangeError);
  assert.throws(() => crypt.sha512Crypt("x", { rounds: 999, minRounds: 1 }), RangeError, "below glibc's own clamp");
  assert.throws(() => crypt.sha512Crypt("x", { rounds: C.LIMITS.maxRounds + 1, minRounds: 1000 }), RangeError);
  assert.throws(() => crypt.sha512Crypt("x", { rounds: 5000, minRounds: 1000, salt: "short" }), RangeError);
  assert.throws(() => crypt.sha512Crypt("x", { rounds: 5000, minRounds: 1000, salt: "$$$$$$$$$$$$$$$$" }), RangeError);
  assert.throws(() => crypt.sha512Crypt(12345, { rounds: 5000, minRounds: 1000 }), TypeError);
  const h = crypt.sha512Crypt("Correct-Horse-Battery-9", { rounds: 50000, minRounds: 50000 });
  assert.equal(V.checkHash(h, { schemes: ["SHA512-CRYPT"], minRounds: 50000 }), "SHA512-CRYPT");
  // A test-rounds hash is refused by the daemon's production floor.
  const weak = crypt.sha512Crypt("Correct-Horse-Battery-9", { rounds: 1000, minRounds: 1000 });
  assert.throws(() => V.checkHash(weak, { schemes: ["SHA512-CRYPT"], minRounds: 50000 }), (e) => e.code === "weak_rounds");
});

test("salt: uniform over the 64-symbol alphabet", () => {
  const counts = new Map();
  for (let i = 0; i < 400; i++) for (const ch of crypt.randomSalt()) counts.set(ch, (counts.get(ch) || 0) + 1);
  assert.equal(counts.size, 64);
  for (const ch of counts.keys()) assert.ok(crypt.ITOA64.includes(ch));
});

test("argon2id (behind MAIL_PASSWORD_SCHEME=ARGON2ID): Dovecot PHC format, verifies", { skip: !crypt.argon2Available() && "crypto.argon2 is not available in this Node build" }, async () => {
  const h = await crypt.argon2idDovecot("Correct-Horse-Battery-9", { memory: 19456, passes: 2 });
  assert.match(h, C.ARGON2_HASH_RE);
  assert.equal(await crypt.argon2idVerify("Correct-Horse-Battery-9", h), true);
  assert.equal(await crypt.argon2idVerify("wrong-password-123", h), false);
});

/* ---------- the worker pool ---------- */

test("hash pool: a constant worker file; 2 in flight + 4 queued, the 7th is busy (429)", async () => {
  assert.equal(WORKER_FILE, path.join(LIB, "hash-worker.js"));
  const pool = createHashPool();
  try {
    const pw = canary("pool");
    const jobs = [];
    for (let i = 0; i < 6; i++) jobs.push(pool.hash(pw, { rounds: 20000, minRounds: 1000 }));
    const st = pool.stats();
    assert.ok(st.inFlight <= 2, "at most 2 in flight");
    await assert.rejects(pool.hash(pw, { rounds: 1000, minRounds: 1000 }), (e) => e.code === "busy" && e.status === 429 && !e.message.includes(pw));
    const hashes = await Promise.all(jobs);
    for (const h of hashes) { assert.match(h, C.SHA512_HASH_RE); assert.equal(crypt.sha512Verify(pw, h), true); }
    assert.equal(new Set(hashes).size, 6, "every hash has its own salt");
  } finally {
    await pool.close();
  }
});

test("hash pool: a worker failure is a generic backend_failed; the input never leaks", async () => {
  const pool = createHashPool();
  try {
    const pw = canary("fail");
    // rounds below the floor make the worker throw; the message must stay constant.
    await assert.rejects(pool.hash(pw, { rounds: 10, minRounds: 1000 }), (e) => {
      assert.equal(e.code, "backend_failed");
      assert.equal(e.status, 502);
      assert.ok(!String(e.message).includes(pw) && !String(e.stack).includes(pw));
      return true;
    });
    await assert.rejects(pool.hash(12345, {}), (e) => e.code === "invalid_body");
    // The pool is still usable afterwards.
    assert.match(await pool.hash(pw, { rounds: 1000, minRounds: 1000 }), C.SHA512_HASH_RE);
  } finally {
    await pool.close();
  }
  await assert.rejects(pool.hash("x", {}), (e) => e.code === "unavailable");
  assert.ok(crypto.getHashes().includes("sha512"));
});
