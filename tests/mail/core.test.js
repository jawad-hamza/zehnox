"use strict";
/* The pure mail state machine (lib/mail/core/core.js, state.js), DESIGN.md sections 3.2
   and 5.4. The daemon and the mock provider both run this exact function, so every rule
   proven here holds in production. */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const crypto = require("crypto");
const { CORE, fakeHash } = require("./helpers/common.js");

const C = require(path.join(CORE, "constants.js"));
const S = require(path.join(CORE, "state.js"));
const core = require(path.join(CORE, "core.js"));

const NOW = "2026-09-27T10:00:00.000Z";
const CTX = { now: NOW, capabilities: { mailboxes: true }, hashPolicy: { schemes: ["SHA512-CRYPT"], minRounds: 50000 } };
const H = () => fakeHash(50000);

/* Applies a list of [verb, args] steps; returns the final { state, hashes } and results. */
function run(steps, start, ctx) {
  let st = start || { state: S.bootstrapState("owner@example.com", NOW), hashes: S.emptyHashes() };
  const results = [];
  for (const [verb, args] of steps) {
    const r = core.apply(st.state, st.hashes, verb, args, ctx || CTX);
    st = { state: r.state, hashes: r.hashes };
    results.push(r);
  }
  return Object.assign(st, { results });
}
const codeOf = (fn) => { try { fn(); return null; } catch (e) { return e.code; } };
const applyCode = (st, verb, args, ctx) => codeOf(() => core.apply(st.state, st.hashes, verb, args, ctx || CTX));
const create = (local, forwards, hash, reuse) => ["createAddress", { local, forwards: forwards || [], mailbox: hash ? { passwordHash: hash } : null, reuseDeleted: !!reuse }];

test("verb table: frozen, exactly the 12 designed verbs; no generic dispatch", () => {
  const expected = ["getMailStatus", "listAddresses", "getAuditTail", "createAddress", "deleteAddress", "setForwarding",
    "removeForwarding", "setAddressEnabled", "createMailbox", "disableMailbox", "enableMailbox", "changeMailboxPassword"];
  assert.deepEqual(Object.keys(C.VERBS), expected);
  assert.deepEqual(C.VERB_NAMES, expected);
  assert.ok(Object.isFrozen(C.VERBS) && Object.isFrozen(C.VERB_NAMES));
  for (const v of expected) assert.ok(Object.isFrozen(C.VERBS[v]));
  assert.throws(() => { "use strict"; C.VERBS.exec = { kind: "mutate" }; }, TypeError);
  assert.throws(() => { "use strict"; C.VERBS.createAddress.kind = "read"; }, TypeError);
  assert.equal(Object.prototype.hasOwnProperty.call(C.VERBS, "exec"), false);
  const st = { state: S.bootstrapState("owner@example.com", NOW), hashes: S.emptyHashes() };
  for (const verb of ["exec", "shell", "reload", "__proto__", "constructor", "toString", "valueOf", "getMailStatus"]) {
    assert.ok(["unknown_verb", "bad_request"].includes(applyCode(st, verb, { local: "info" })), verb);
  }
});

test("create, edit and delete forwarding", () => {
  const st = run([create("info", ["owner@example.com"])]);
  assert.equal(st.results[0].result.address.address, "info@zehnox.com");
  assert.equal(st.results[0].result.address.type, "forward");
  assert.equal(st.state.rev, 2);
  const edited = run([["setForwarding", { local: "info", forwards: ["a@example.com", "b@example.com", "A@example.com"] }]], st);
  assert.deepEqual(edited.state.addresses.info.forwards, ["a@example.com", "b@example.com"]);
  assert.deepEqual(edited.results[0].audit.detail, { before: ["owner@example.com"], after: ["a@example.com", "b@example.com"] });
  // Forward-only: forwarding cannot be emptied (nowhere to deliver).
  assert.equal(applyCode(edited, "removeForwarding", { local: "info" }), "no_destination");
  const del = run([["deleteAddress", { local: "info", confirm: "info@zehnox.com" }]], edited);
  assert.equal(del.state.addresses.info, undefined);
  assert.deepEqual(del.state.tombstones.info, { deletedAt: NOW, hadMailbox: false });
  // A forward-only tombstone does not need reuseDeleted.
  const again = run([create("info", ["x@example.com"])], del);
  assert.equal(again.results[0].result.resumesExistingMaildir, false);
  assert.equal(again.state.tombstones.info, undefined);
});

test("delete needs the exact full address as confirmation", () => {
  const st = run([create("info", ["owner@example.com"])]);
  for (const bad of ["", "info", "INFO@zehnox.com", "info@strategicbhm.com", "info@zehnox.com ", "careers@zehnox.com"]) {
    assert.equal(applyCode(st, "deleteAddress", { local: "info", confirm: bad }), "confirm_mismatch", JSON.stringify(bad));
  }
});

test("duplicates, reserved and protected names", () => {
  const st = run([create("info", ["owner@example.com"])]);
  assert.equal(applyCode(st, ...create("info", ["x@example.com"])), "duplicate");
  assert.equal(applyCode(st, ...create("root", ["x@example.com"])), "reserved_local");
  assert.equal(applyCode(st, ...create("postmaster", ["x@example.com"])), "protected");
  const fresh = { state: S.emptyState(NOW), hashes: S.emptyHashes() };
  assert.equal(applyCode(fresh, ...create("abuse", ["x@example.com"])), "protected", "protected names are created by the system only");
  assert.equal(applyCode(st, ...create("Info", ["x@example.com"])), "invalid_local", "the core never normalises");
  assert.equal(applyCode(st, ...create("info@strategicbhm.com", ["x@example.com"])), "invalid_local");
});

test("protected addresses: re-pointable, never deleted, disabled, emptied or given a mailbox", () => {
  const st = run([]);
  assert.equal(applyCode(st, "deleteAddress", { local: "postmaster", confirm: "postmaster@zehnox.com" }), "protected");
  assert.equal(applyCode(st, "setAddressEnabled", { local: "abuse", enabled: false }), "protected");
  assert.equal(applyCode(st, "removeForwarding", { local: "postmaster" }), "protected");
  assert.equal(applyCode(st, "createMailbox", { local: "abuse", passwordHash: H() }), "protected");
  assert.equal(applyCode(st, "enableMailbox", { local: "abuse" }), "protected");
  const moved = run([["setForwarding", { local: "postmaster", forwards: ["ops@example.com"] }]], st);
  assert.deepEqual(moved.state.addresses.postmaster.forwards, ["ops@example.com"]);
  assert.equal(moved.state.addresses.postmaster.protected, true);
});

test("destinations: self, same-domain non-mailbox (loop prevention), same-domain mailbox", () => {
  const st = run([create("info", ["owner@example.com"]), create("sales", ["owner@example.com"])]);
  assert.equal(applyCode(st, "setForwarding", { local: "info", forwards: ["info@zehnox.com"] }), "self_destination");
  assert.equal(applyCode(st, "setForwarding", { local: "info", forwards: ["INFO@zehnox.com"] }), "self_destination");
  // sales is forward-only: pointing info at it would build an alias chain.
  assert.equal(applyCode(st, "setForwarding", { local: "info", forwards: ["sales@zehnox.com"] }), "destination_not_mailbox");
  assert.equal(applyCode(st, "setForwarding", { local: "info", forwards: ["ghost@zehnox.com"] }), "destination_not_mailbox");
  assert.equal(applyCode(st, "setForwarding", { local: "info", forwards: ["postmaster@zehnox.com"] }), "destination_not_mailbox");
  // A mailbox is a terminal target: allowed.
  const withBox = run([create("desk", [], H())], st);
  const ok = run([["setForwarding", { local: "info", forwards: ["desk@zehnox.com", "owner@example.com"] }]], withBox);
  assert.deepEqual(ok.state.addresses.info.forwards, ["desk@zehnox.com", "owner@example.com"]);
  // ...and then it is in use: it cannot be disabled, lose its mailbox or be deleted.
  assert.equal(applyCode(ok, "setAddressEnabled", { local: "desk", enabled: false }), "in_use");
  assert.equal(applyCode(ok, "deleteAddress", { local: "desk", confirm: "desk@zehnox.com" }), "in_use");
  const e = (() => { try { core.apply(ok.state, ok.hashes, "deleteAddress", { local: "desk", confirm: "desk@zehnox.com" }, CTX); } catch (x) { return x; } })();
  assert.deepEqual(e.refs, ["info"]);
  // Invalid destinations never reach the state.
  for (const bad of ["xyz", "a@b", "|/bin/sh@x.com", "a@x.com\r\nBcc: v@y.com", ":include:@x.com"]) {
    assert.equal(applyCode(st, "setForwarding", { local: "info", forwards: [bad] }), "invalid_destination", bad);
  }
  assert.equal(applyCode(st, "setForwarding", { local: "info", forwards: Array.from({ length: 11 }, (_, i) => "u" + i + "@example.com") }), "bad_request", "the schema caps the array at 10");
});

test("mailboxes: capability gate, hash policy, disable/enable, password change", () => {
  const gated = Object.assign({}, CTX, { capabilities: { mailboxes: false } });
  const base = run([create("info", ["owner@example.com"])]);
  assert.equal(applyCode(base, ...create("contact", [], H()).concat([gated])), "capability_missing");
  assert.equal(applyCode(base, "createMailbox", { local: "info", passwordHash: H() }, gated), "capability_missing");
  assert.equal(applyCode(base, "createMailbox", { local: "info", passwordHash: fakeHash(1000) }), "weak_rounds");
  assert.equal(applyCode(base, "createMailbox", { local: "info", passwordHash: "{PLAIN}secret-password" }), "invalid_hash");
  const h1 = H();
  const st = run([["createMailbox", { local: "info", passwordHash: h1 }]], base);
  assert.equal(st.results[0].result.address.type, "mailbox+forward");
  assert.equal(st.hashes.hashes.info.hash, h1);
  assert.equal(applyCode(st, "createMailbox", { local: "info", passwordHash: H() }), "duplicate");
  const off = run([["disableMailbox", { local: "info" }]], st);
  assert.equal(off.results[0].result.address.type, "forward");
  assert.equal(off.hashes.hashes.info.hash, h1, "the hash is kept for re-enabling");
  const on = run([["enableMailbox", { local: "info" }]], off);
  assert.equal(on.results[0].result.address.type, "mailbox+forward");
  const h2 = H();
  const changed = run([["changeMailboxPassword", { local: "info", passwordHash: h2 }]], on);
  assert.equal(changed.hashes.hashes.info.hash, h2);
  assert.deepEqual(Object.keys(changed.results[0].result).sort(), ["changed", "passwordSetAt", "rev"]);
  // Mailbox-only: disabling the mailbox would leave nowhere to deliver.
  const only = run([create("careers", [], H())]);
  assert.equal(applyCode(only, "disableMailbox", { local: "careers" }), "no_destination");
  // removeForwarding on mailbox+forward leaves a mailbox.
  const rm = run([["removeForwarding", { local: "info" }]], changed);
  assert.equal(rm.results[0].result.address.type, "mailbox");
  assert.equal(applyCode(base, "changeMailboxPassword", { local: "info", passwordHash: H() }), "not_found", "no mailbox yet");
  assert.equal(applyCode(base, "enableMailbox", { local: "info" }), "not_found");
});

test("hashes never enter state.json or any public view", () => {
  const h = H();
  const st = run([create("contact", ["management@example.com"], h)]);
  assert.ok(!JSON.stringify(st.state).includes(h));
  assert.ok(!JSON.stringify(st.state).includes("SHA512"));
  const view = S.listView(st.state, st.hashes);
  assert.ok(!JSON.stringify(view).includes(h));
  assert.ok(!JSON.stringify(st.results[0].result).includes(h));
  assert.equal(view.addresses.find((a) => a.local === "contact").mailbox.passwordSetAt, NOW);
});

test("tombstones: reusing a deleted mailbox's name needs reuseDeleted", () => {
  const st = run([create("old", ["x@example.com"], H()), ["deleteAddress", { local: "old", confirm: "old@zehnox.com" }]]);
  assert.deepEqual(st.state.tombstones.old, { deletedAt: NOW, hadMailbox: true });
  assert.equal(st.hashes.hashes.old, undefined, "the hash is removed on delete");
  assert.equal(st.results[1].result.mailboxDataRetained, true);
  assert.equal(applyCode(st, ...create("old", ["x@example.com"])), "tombstoned");
  const re = run([create("old", ["x@example.com"], null, true)], st);
  assert.equal(re.results[0].result.resumesExistingMaildir, true);
});

test("limits: 200 addresses and 300 external destinations per domain", () => {
  let st = { state: S.emptyState(NOW), hashes: S.emptyHashes() };
  for (let i = 0; i < C.LIMITS.maxAddresses; i++) st.state.addresses["a" + i] = { forwards: ["x" + i + "@example.com"], enabled: true, mailbox: null, protected: false, createdAt: NOW, updatedAt: NOW };
  assert.equal(applyCode(st, ...create("one-more", ["x@example.com"])), "limit_addresses");
  st = { state: S.emptyState(NOW), hashes: S.emptyHashes() };
  for (let i = 0; i < 30; i++) st.state.addresses["b" + i] = { forwards: Array.from({ length: 10 }, (_, j) => "d" + i + "-" + j + "@example.com"), enabled: true, mailbox: null, protected: false, createdAt: NOW, updatedAt: NOW };
  assert.equal(core.externalCount(st.state), 300);
  assert.equal(applyCode(st, ...create("over", ["x@example.com"])), "domain_destination_cap");
  // Same-domain mailbox targets do not count towards the external cap.
  st.state.addresses.box = { forwards: [], enabled: true, mailbox: { enabled: true }, protected: false, createdAt: NOW, updatedAt: NOW };
  st.hashes.hashes.box = { hash: H(), passwordSetAt: NOW };
  assert.doesNotThrow(() => core.apply(st.state, st.hashes, ...create("inner", ["box@zehnox.com"]), CTX));
});

test("no-op: changed:false and the rev is unchanged; inputs are never mutated", () => {
  const st = run([create("info", ["owner@example.com"])]);
  const frozenCopy = JSON.stringify(st);
  const r = core.apply(st.state, st.hashes, "setForwarding", { local: "info", forwards: ["owner@example.com"] }, CTX);
  assert.equal(r.changed, false);
  assert.equal(r.result.changed, false);
  assert.equal(r.result.rev, st.state.rev);
  assert.equal(r.state, st.state);
  const r2 = core.apply(st.state, st.hashes, "setAddressEnabled", { local: "info", enabled: true }, CTX);
  assert.equal(r2.changed, false);
  core.apply(st.state, st.hashes, "setForwarding", { local: "info", forwards: ["new@example.com"] }, CTX);
  assert.equal(JSON.stringify(st), frozenCopy, "apply is pure");
});

test("idempotency helpers: same key and args return the stored response; other args are a mismatch", () => {
  const now = Date.now();
  const idem = crypto.randomUUID();
  const args = { local: "info", forwards: ["a@example.com"] };
  const sha = core.argsSha256("setForwarding", args);
  assert.equal(sha, core.argsSha256("setForwarding", { forwards: ["a@example.com"], local: "info" }), "key order does not matter");
  let entries = core.idemRemember([], { idem, argsSha256: sha, verb: "setForwarding", response: { rev: 5, changed: true } }, now);
  assert.deepEqual(core.idemLookup(entries, idem, "setForwarding", sha, now), { rev: 5, changed: true });
  assert.equal(core.idemLookup(entries, crypto.randomUUID(), "setForwarding", sha, now), null);
  assert.throws(() => core.idemLookup(entries, idem, "setForwarding", core.argsSha256("setForwarding", { local: "info", forwards: ["b@example.com"] }), now), (e) => e.code === "idempotency_mismatch");
  assert.throws(() => core.idemLookup(entries, idem, "removeForwarding", sha, now), (e) => e.code === "idempotency_mismatch");
  // After 10 minutes the key is forgotten.
  assert.equal(core.idemLookup(entries, idem, "setForwarding", sha, now + core.IDEM_TTL_MS + 1), null);
  for (let i = 0; i < core.IDEM_MAX + 5; i++) entries = core.idemRemember(entries, { idem: crypto.randomUUID(), argsSha256: sha, verb: "x", response: {} }, now);
  assert.equal(entries.length, core.IDEM_MAX);
});

test("state documents from disk are re-validated: another domain or a foreign key is refused", () => {
  const good = S.bootstrapState("owner@example.com", NOW);
  assert.doesNotThrow(() => S.checkState(S.clone(good)));
  const bad = [
    Object.assign(S.clone(good), { domain: "strategicbhm.com" }),
    Object.assign(S.clone(good), { v: 2 }),
    (() => { const s = S.clone(good); s.addresses["info@strategicbhm.com"] = S.clone(s.addresses.abuse); return s; })(),
    (() => { const s = S.clone(good); s.addresses.abuse.forwards = ["|/bin/sh"]; return s; })(),
    (() => { const s = S.clone(good); s.addresses["../x"] = S.clone(s.addresses.abuse); return s; })(),
    (() => { const s = S.clone(good); s.tombstones["a b"] = { hadMailbox: true }; return s; })(),
  ];
  for (const s of bad) assert.equal(codeOf(() => S.checkState(s)), "not_ready");
  assert.throws(() => S.bootstrapState("postmaster@zehnox.com", NOW), (e) => e.code === "invalid_destination");
  assert.equal(codeOf(() => S.checkHashes({ v: 1, hashes: { "a@b": { hash: "x" } } })), "not_ready");
});

/* ---------- review fixes (regression tests) ---------- */

test("the mailbox gate covers password changes: no hash can be planted while mailboxes are off", () => {
  const gated = Object.assign({}, CTX, { capabilities: { mailboxes: false } });
  const st = run([create("contact", ["m@example.com"], H())]);
  // With the gate closed (e.g. a Phase B rollback), a password change is refused like every
  // other mailbox verb, so it cannot become a live login when the gate reopens.
  assert.equal(applyCode(st, "changeMailboxPassword", { local: "contact", passwordHash: H() }, gated), "capability_missing");
  assert.equal(applyCode(st, "createMailbox", { local: "contact", passwordHash: H() }, gated), "capability_missing");
  assert.equal(applyCode(st, "enableMailbox", { local: "contact" }, gated), "capability_missing");
  // An address with no mailbox still answers not_found first.
  const plain = run([create("info", ["a@example.com"])]);
  assert.equal(applyCode(plain, "changeMailboxPassword", { local: "info", passwordHash: H() }, gated), "not_found");
  // With the gate open the change goes through.
  assert.equal(run([["changeMailboxPassword", { local: "contact", passwordHash: H() }]], st).results[0].changed, true);
});

test("forwards may not target the mail host, its subdomains or a denied co-hosted domain; no percent hack", () => {
  const deny = Object.assign({}, CTX, { forwardDeny: ["mail.example.net", "cohosted.example"] });
  const st = run([create("info", ["a@example.com"])]);
  for (const d of ["root@mail.example.net", "x@MAIL.example.net", "a@sub.mail.example.net", "postmaster@cohosted.example", "b@deep.cohosted.example"]) {
    assert.equal(applyCode(st, "setForwarding", { local: "info", forwards: [d] }, deny), "invalid_destination", d);
    assert.equal(applyCode(st, ...create("relay", [d]).concat([deny])), "invalid_destination", d);
  }
  // A domain that only ends with the same letters is not a subdomain.
  assert.equal(applyCode(st, "setForwarding", { local: "info", forwards: ["a@notmail.example.net", "b@othercohosted.example"] }, deny), null);
  // "%" is refused everywhere: Postfix's allow_percent_hack would route x%y@relay through relay.
  assert.equal(applyCode(st, "setForwarding", { local: "info", forwards: ["x%y.example@mail.example.org"] }), "invalid_destination");
  // Re-enabling an address re-checks its stored list against the deny list too.
  const off = run([["setForwarding", { local: "info", forwards: ["root@mail.example.net"] }], ["setAddressEnabled", { local: "info", enabled: false }]], st);
  assert.equal(applyCode(off, "setAddressEnabled", { local: "info", enabled: true }, deny), "invalid_destination");
  // Without a deny list (the mock without MAIL_HOSTNAME) the host rule simply does not apply.
  assert.equal(core.deniedDomain("root@mail.example.net", []), false);
});

test("tombstones are capped: markers without stored mail go oldest first; past the cap with stored mail, delete is refused", () => {
  const max = C.LIMITS.maxTombstones;
  assert.equal(max, 200);
  const t = {};
  const stamp = (i) => new Date(Date.UTC(2026, 0, 1) + i * 60000).toISOString();
  for (let i = 0; i < max; i++) t["old" + i] = { deletedAt: stamp(i), hadMailbox: i % 2 === 0 };
  const st = { state: Object.assign(S.bootstrapState("owner@example.com", NOW), { tombstones: t }), hashes: S.emptyHashes() };
  // One more delete of a forward-only address: the oldest hadMailbox:false marker (old1) goes.
  const a = run([create("gone", ["a@example.com"]), ["deleteAddress", { local: "gone", confirm: "gone@zehnox.com" }]], st);
  assert.equal(Object.keys(a.state.tombstones).length, max);
  assert.ok(!("old1" in a.state.tombstones) && "gone" in a.state.tombstones && "old0" in a.state.tombstones);
  // All markers hold stored mail: the next delete that would add one is refused, nothing changes.
  const full = {};
  for (let i = 0; i < max; i++) full["box" + i] = { deletedAt: stamp(i), hadMailbox: true };
  const st2 = run([create("keep", [], H())], { state: Object.assign(S.bootstrapState("owner@example.com", NOW), { tombstones: full }), hashes: S.emptyHashes() });
  assert.equal(applyCode(st2, "deleteAddress", { local: "keep", confirm: "keep@zehnox.com" }), "limit_tombstones");
  // A forward-only delete at that point still works: its own marker is the droppable one.
  const st3 = run([create("fwd", ["a@example.com"]), ["deleteAddress", { local: "fwd", confirm: "fwd@zehnox.com" }]], st2);
  assert.equal(Object.keys(st3.state.tombstones).length, max);
  assert.ok(C.ERROR_CODES.limit_tombstones && C.DAEMON_CODES.includes("limit_tombstones"));
});

test("listAddresses lists at most maxTombstones markers (the newest), so an oversized state still fits a frame", () => {
  const protocol = require(path.join(CORE, "protocol.js"));
  const s = S.bootstrapState("owner@example.com", NOW);
  // A state that grew before the cap existed: 1500 markers with 64-character names.
  for (let i = 0; i < 1500; i++) s.tombstones[("t" + i).padEnd(64, "x")] = { deletedAt: new Date(Date.UTC(2026, 0, 1) + i * 1000).toISOString(), hadMailbox: false };
  const view = S.listView(s, S.emptyHashes());
  assert.equal(view.tombstones.length, C.LIMITS.maxTombstones);
  assert.ok(view.tombstones.some((x) => x.local.startsWith("t1499x")), "the newest is listed");
  assert.ok(!view.tombstones.some((x) => x.local.startsWith("t0x")), "the oldest is not");
  // The whole answer still encodes within responseMax.
  assert.doesNotThrow(() => protocol.encodeResponse("k1", crypto.randomBytes(32), { nonce: "0".repeat(32), ok: true, result: view }));
});
