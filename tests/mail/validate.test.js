"use strict";
/* Shared validation rules (lib/mail/core/validate.js, password-policy.js), DESIGN.md
   section 3. These run on both sides of the socket, so a hostile input refused here is
   refused by the web process AND by the daemon. */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { CORE, LIB, fakeHash, CRYPT6 } = require("./helpers/common.js");

const C = require(path.join(CORE, "constants.js"));
const V = require(path.join(CORE, "validate.js"));
const { checkPassword, REASONS } = require(path.join(LIB, "password-policy.js"));

const codeOf = (fn) => { try { fn(); return null; } catch (e) { return e.code; } };

/* ---------- local parts ---------- */

const VALID_LOCALS = ["info", "contact", "careers", "a", "x9", "a.b", "a-b_c", "a1.b2-c3_d4", "9lives", "a".repeat(64)];

/* Every entry must be refused by normalizeLocal (the web side) with invalid_local. */
const INVALID_LOCALS = [
  ["empty", ""], ["only spaces", "   "], ["leading dot", ".a"], ["trailing dot", "a."], ["double dot", "a..b"],
  ["dot underscore", "a._b"], ["leading dash", "-a"], ["trailing dash", "a-"], ["leading underscore", "_a"],
  ["plus (recipient delimiter)", "a+b"], ["plus tag", "info+tag"], ["inner space", "a b"], ["tab", "a\tb"],
  ["unicode e-acute", "é"], ["unicode mixed", "café"], ["Cyrillic o homoglyph", "infо"],
  ["fullwidth letters", "ｉｎｆｏ"], ["zero width space", "in​fo"], ["emoji", "mail\u{1f4e7}"],
  ["right-to-left override", "‮ofni"], ["CRLF", "a\r\nb"], ["LF", "a\nb"], ["CR", "a\rb"],
  ["NUL", "a\u0000b"], ["trailing NUL", "info\u0000"], ["DEL", "a\u007fb"], ["C1 control", "a\u0085b"],
  ["semicolon", "a;rm"], ["command substitution", "$(id)"], ["backticks", "`id`"], ["pipe", "a|b"],
  ["ampersand", "a&b"], ["redirect", "a>b"], ["glob", "a*"], ["question mark", "a?"], ["quote", "a\"b"],
  ["single quote", "a'b"], ["backslash", "a\\b"], ["slash", "a/b"], ["path traversal", "../etc"],
  ["dot dot", ".."], ["dot", "."], ["absolute path", "/etc/passwd"], ["windows path", "..\\..\\x"],
  ["percent-encoded at", "info%40strategicbhm.com"], ["colon include", ":include:"], ["comma", "a,b"],
  ["hash", "a#b"], ["brackets", "a[b]"], ["braces", "a{b}"], ["equals", "a=b"], ["tilde", "~root"],
  ["at sign", "info@zehnox.com"], ["other domain", "info@strategicbhm.com"], ["bare at", "@"],
  ["overlong 65", "a".repeat(65)], ["overlong 1000", "b".repeat(1000)],
];

test("local part: valid names pass on both sides and stay unchanged", () => {
  for (const l of VALID_LOCALS) {
    assert.equal(V.normalizeLocal(l), l, l);
    assert.equal(V.checkLocal(l), l, l);
    assert.equal(V.isValidLocal(l), true, l);
  }
});

test("local part fuzz: every hostile input is refused with invalid_local", () => {
  for (const [label, input] of INVALID_LOCALS) {
    assert.equal(codeOf(() => V.normalizeLocal(input)), "invalid_local", label);
    // The strict daemon-side check refuses them too (it never normalises).
    assert.notEqual(codeOf(() => V.checkLocal(input)), null, label);
  }
});

test("local part: non-string inputs are refused, never coerced", () => {
  for (const v of [null, undefined, 42, true, {}, [], ["info"], { toString: () => "info" }]) {
    assert.equal(codeOf(() => V.normalizeLocal(v)), "invalid_local", String(v));
    assert.equal(codeOf(() => V.checkLocal(v)), "invalid_local", String(v));
  }
});

test("local part: uppercase is normalised to lowercase on the web side only; the daemon side refuses it", () => {
  assert.equal(V.normalizeLocal("INFO"), "info");
  assert.equal(V.normalizeLocal("Contact.Us"), "contact.us");
  assert.equal(V.normalizeLocal("  Careers  "), "careers"); // surrounding whitespace is trimmed first
  assert.equal(codeOf(() => V.checkLocal("INFO")), "invalid_local");
  assert.equal(codeOf(() => V.checkLocal(" info")), "invalid_local");
});

test("local part: reserved system names are reserved_local (after normalisation)", () => {
  for (const r of C.RESERVED) {
    assert.equal(codeOf(() => V.normalizeLocal(r)), "reserved_local", r);
    assert.equal(codeOf(() => V.normalizeLocal(r.toUpperCase())), "reserved_local", r);
  }
  assert.equal(V.isProtected("postmaster"), true);
  assert.equal(V.isProtected("abuse"), true);
  assert.equal(V.isProtected("info"), false);
});

test("local part: the regex anchors hold against multi-line input", () => {
  // A /m-flag or missing anchor bug would let "info\nroot" through.
  for (const s of ["info\nroot", "info\r\n", "\ninfo", "info x"]) {
    assert.equal(C.LOCAL_RE.test(s), false, JSON.stringify(s));
  }
});

/* ---------- forwarding destinations ---------- */

const INVALID_DESTS = [
  ["no at", "x"], ["no dot in domain", "a@b"], ["one-letter tld", "a@b.c"], ["ip literal", "a@[1.2.3.4]"],
  ["bare ip", "a@1.2.3.4"], ["space in local", "a b@x.com"], ["CRLF header injection", "a@x.com\r\nBcc: v@y.com"],
  ["LF injection", "a@x.com\nRCPT TO:<v@y.com>"], ["pipe", "|/bin/sh@x.com"], ["file path", "/etc/passwd@x.com"],
  [":include:", ":include:@x.com"], ["quoted local", "\"q\"@x.com"], ["comma list", "a,b@x.com"],
  ["two addresses", "a@x.com, b@y.com"], ["angle brackets", "<a@x.com>"], ["display name", "Bob <a@x.com>"],
  ["leading dot", ".a@x.com"], ["trailing dot local", "a.@x.com"], ["double dot local", "a..b@x.com"],
  ["trailing dot domain", "a@x.com."], ["leading hyphen label", "a@-x.com"], ["underscore domain", "a@x_y.com"],
  ["unicode local", "é@x.com"], ["unicode domain", "a@éxample.com"], ["NUL", "a\u0000@x.com"],
  ["shell metachars", "a$(id)@x.com"], ["semicolon", "a;b@x.com"], ["backtick", "a`b@x.com"],
  ["hash comment", "a#b@x.com"], ["colon", "a:b@x.com"], ["slash", "a/b@x.com"], ["empty", ""],
  ["only at", "@"], ["missing local", "@x.com"], ["missing domain", "a@"], ["double at", "a@b@x.com"],
  ["255 chars", "a".repeat(64) + "@" + ("b".repeat(60) + ".").repeat(3) + "c".repeat(9) + ".com"],
  ["local over 64", "a".repeat(65) + "@x.com"],
  // Postfix's allow_percent_hack reads user%host@relay as a route through relay.
  ["percent hack", "x%y.example@mail.example.net"], ["percent", "a%b@x.com"],
];

test("destination fuzz: invalid addresses are refused by isDestination and normalizeDestination", () => {
  for (const [label, d] of INVALID_DESTS) {
    assert.equal(V.isDestination(d), false, label);
    assert.equal(codeOf(() => V.normalizeDestination(d)), "invalid_destination", label);
  }
  assert.ok(INVALID_DESTS.find((x) => x[0] === "255 chars")[1].length >= 255);
});

test("destination: valid addresses pass; the domain part is lowercased, the local part keeps its case", () => {
  for (const d of ["owner@example.com", "first.last@sub.example.co.uk", "a+tag@example.org", "x_y-z=1@ex-ample.io", "UPPER@example.com"]) {
    assert.equal(V.isDestination(d), true, d);
  }
  assert.equal(V.normalizeDestination("  Bob.Smith@Example.COM  "), "Bob.Smith@example.com");
  assert.equal(V.normalizeDestination("x@ZEHNOX.COM"), "x@zehnox.com"); // becomes same-domain (core then enforces the mailbox rule)
});

test("destinations: de-duplicated case-insensitively (first spelling kept), 1..10 enforced", () => {
  assert.deepEqual(V.cleanForwards(["A@example.com", "a@example.com", "b@example.com"]), ["A@example.com", "b@example.com"]);
  const eleven = Array.from({ length: 11 }, (_, i) => "u" + i + "@example.com");
  assert.equal(codeOf(() => V.cleanForwards(eleven)), "too_many_destinations");
  assert.equal(V.cleanForwards(eleven.slice(0, 10)).length, 10);
  // Duplicates do not count towards the limit.
  assert.equal(V.cleanForwards(eleven.slice(0, 10).concat(["U0@example.com"])).length, 10);
  assert.equal(codeOf(() => V.cleanForwards([], { min: 1 })), "no_destination");
  assert.equal(codeOf(() => V.cleanForwards("a@example.com")), "invalid_destination");
  assert.equal(codeOf(() => V.cleanForwards(["ok@example.com", "bad"])), "invalid_destination");
});

/* ---------- hashes ---------- */

test("hash format: SHA512-CRYPT accepted within the rounds policy; other schemes refused", () => {
  const policy = { schemes: ["SHA512-CRYPT"], minRounds: 50000 };
  assert.equal(V.checkHash(fakeHash(50000), policy), "SHA512-CRYPT");
  assert.equal(V.checkHash(fakeHash(1000000), policy), "SHA512-CRYPT");
  assert.equal(codeOf(() => V.checkHash(fakeHash(1000), policy)), "weak_rounds");
  assert.equal(codeOf(() => V.checkHash(fakeHash(49999), policy)), "weak_rounds");
  assert.equal(codeOf(() => V.checkHash(fakeHash(1000001), policy)), "weak_rounds");
  const good = fakeHash(50000);
  const bad = [
    good.replace("{SHA512-CRYPT}", "{BLF-CRYPT}"), good.replace("{SHA512-CRYPT}", ""), good.replace("{SHA512-CRYPT}", "{PLAIN}"),
    "{PLAIN}hunter2hunter2", "{SHA512-CRYPT}" + CRYPT6 + "salt$abc", good + "\n", good + ":5000:5000::/tmp::",
    good.slice(0, -1), good + "x", good.replace("rounds=50000", "rounds=50000:"), "", "x".repeat(600),
    good.replace(/\$[./0-9A-Za-z]{16}\$/, "$" + "a:b".padEnd(16, "c") + "$"),
  ];
  for (const b of bad) assert.ok(["invalid_hash", "weak_rounds"].includes(codeOf(() => V.checkHash(b, policy))), JSON.stringify(b.slice(0, 40)));
  for (const b of [null, 1, {}, []]) assert.equal(codeOf(() => V.checkHash(b, policy)), "invalid_hash");
});

test("hash format: ARGON2ID only when listed by both sides, with m >= 19456 and t >= 2", () => {
  const salt = "A".repeat(22);
  const tag = "B".repeat(43);
  const argon = (m, t) => "{ARGON2ID}$argon2id$v=19$m=" + m + ",t=" + t + ",p=1$" + salt + "$" + tag;
  assert.equal(codeOf(() => V.checkHash(argon(65536, 3), { schemes: ["SHA512-CRYPT"] })), "invalid_hash");
  assert.equal(V.checkHash(argon(65536, 3), { schemes: ["SHA512-CRYPT", "ARGON2ID"] }), "ARGON2ID");
  assert.equal(codeOf(() => V.checkHash(argon(1024, 3), { schemes: ["ARGON2ID"] })), "weak_rounds");
  assert.equal(codeOf(() => V.checkHash(argon(65536, 1), { schemes: ["ARGON2ID"] })), "weak_rounds");
});

/* ---------- strict schema ---------- */

test("schema: unknown keys, __proto__/constructor/prototype and wrong types are refused", () => {
  const spec = { type: "object", props: { rev: { type: "int" }, local: { type: "string", max: 64 }, list: { type: "array", max: 2, items: { type: "string" } } }, required: ["rev"] };
  assert.doesNotThrow(() => V.schema({ rev: 1, local: "a", list: ["x"] }, spec));
  assert.equal(codeOf(() => V.schema({ rev: 1, domain: "strategicbhm.com" }, spec)), "unknown_field");
  assert.equal(codeOf(() => V.schema({ rev: 1, address: "a@strategicbhm.com" }, spec)), "unknown_field");
  assert.equal(codeOf(() => V.schema(JSON.parse('{"rev":1,"__proto__":{"admin":true}}'), spec)), "unknown_field");
  assert.equal(codeOf(() => V.schema(JSON.parse('{"rev":1,"constructor":{"prototype":{}}}'), spec)), "unknown_field");
  assert.equal(codeOf(() => V.schema({ rev: 1, prototype: 1 }, spec)), "unknown_field");
  for (const bad of [{ rev: "1" }, { rev: 1.5 }, { rev: -1 }, { rev: 2 ** 53 }, { rev: null }, { rev: true }, {}, { rev: 1, local: 5 }, { rev: 1, local: "a".repeat(65) }, { rev: 1, list: ["a", "b", "c"] }, { rev: 1, list: [1] }, { rev: 1, list: "x" }]) {
    assert.equal(codeOf(() => V.schema(bad, spec)), "invalid_body", JSON.stringify(bad));
  }
  for (const notObj of [null, [], "x", 1, true]) assert.notEqual(codeOf(() => V.schema(notObj, spec)), null);
  // The daemon flavour maps everything onto bad_request.
  assert.equal(codeOf(() => V.schema({ rev: 1, x: 1 }, spec, { unknownCode: "bad_request", typeCode: "bad_request" })), "bad_request");
  // Nothing was re-parented by a __proto__ key along the way.
  assert.equal({}.admin, undefined);
});

test("verb args: every verb refuses unknown keys, missing keys and wrong types (daemon: bad_request)", () => {
  const L = "info";
  const H = fakeHash(50000);
  const good = {
    getMailStatus: {}, listAddresses: {}, getAuditTail: { limit: 10, beforeSeq: null },
    createAddress: { local: L, forwards: ["a@example.com"], mailbox: null, reuseDeleted: false },
    deleteAddress: { local: L, confirm: "info@zehnox.com" }, setForwarding: { local: L, forwards: ["a@example.com"] },
    removeForwarding: { local: L }, setAddressEnabled: { local: L, enabled: true }, createMailbox: { local: L, passwordHash: H },
    disableMailbox: { local: L }, enableMailbox: { local: L }, changeMailboxPassword: { local: L, passwordHash: H },
  };
  assert.deepEqual(Object.keys(good), C.VERB_NAMES);
  for (const verb of C.VERB_NAMES) {
    assert.doesNotThrow(() => V.checkVerbArgs(verb, good[verb]), verb);
    assert.equal(codeOf(() => V.checkVerbArgs(verb, Object.assign({}, good[verb], { domain: "strategicbhm.com" }))), "bad_request", verb + " +domain");
    assert.equal(codeOf(() => V.checkVerbArgs(verb, Object.assign({}, good[verb], { path: "/etc/postfix/main.cf" }))), "bad_request", verb + " +path");
    assert.equal(codeOf(() => V.checkVerbArgs(verb, Object.assign(JSON.parse('{"__proto__":1}'), good[verb]))), "bad_request", verb + " +__proto__");
    for (const k of Object.keys(good[verb])) {
      const missing = Object.assign({}, good[verb]);
      delete missing[k];
      assert.equal(codeOf(() => V.checkVerbArgs(verb, missing)), "bad_request", verb + " -" + k);
      const wrong = Object.assign({}, good[verb], { [k]: { nested: true } });
      assert.equal(codeOf(() => V.checkVerbArgs(verb, wrong)), "bad_request", verb + " wrong " + k);
    }
    assert.equal(codeOf(() => V.checkVerbArgs(verb, null)), "bad_request", verb + " null");
    assert.equal(codeOf(() => V.checkVerbArgs(verb, [])), "bad_request", verb + " array");
  }
});

/* ---------- password policy ---------- */

test("password policy: fixed reasons, never an echo of the password", () => {
  const cases = [
    ["short", "Sh0rt!pw", REASONS.length], ["too long", "x".repeat(129) + "A1!", REASONS.length],
    ["NUL", "Abcdef123456\u0000xyz", REASONS.control], ["CR", "Abcdef123456\rxyz", REASONS.control],
    ["LF", "Abcdef123456\nxyz", REASONS.control], ["C1", "Abcdef123456\u0085xyz", REASONS.control],
    ["leading space", " Abcdef123456xyz", REASONS.spaces], ["trailing space", "Abcdef123456xyz ", REASONS.spaces],
    ["contains local", "my-Contact-Pass-99", REASONS.local], ["company", "ZEHNOX-Rules-2026", REASONS.company],
    ["company domain", "xx-zehnox-yy", REASONS.company], ["common", "password1234", REASONS.common],
    ["common with suffix", "qwertyuiop!!", REASONS.common],
  ];
  for (const [label, pw, reason] of cases) {
    const r = checkPassword(pw, { local: "contact" });
    assert.ok(r, label);
    assert.equal(r.code, "weak_password", label);
    assert.equal(r.reason, reason, label);
    assert.ok(!r.reason.includes(pw.trim()), label + ": the reason must not echo the password");
    assert.ok(Object.values(REASONS).includes(r.reason), label + ": the reason is one of the fixed strings");
  }
  assert.equal(checkPassword("Correct-Horse-Battery-9", { local: "contact" }), null);
  // Length counts code points, not UTF-16 units: 11 letters + 1 emoji is 12 (13 units).
  assert.equal(checkPassword("Zq7xRm4Lp2W\u{1f511}", { local: "x" }), null);
  assert.equal(checkPassword("Zq7xRm4Lp2\u{1f511}", { local: "x" }).reason, REASONS.length, "11 code points in 12 units is still too short");
  assert.ok(checkPassword(undefined));
  assert.ok(checkPassword(123456789012));
});
