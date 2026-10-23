"use strict";
/* MockMailProvider behaviour and persistence (lib/mail/mock-provider.js) and provider
   selection (lib/mail/index.js), DESIGN.md sections 4.2 and 4.3. The mock runs the same
   core as the daemon; only the applier differs (files under DATA/mail/mock/, no process,
   no socket). Each instance here is built from its own env object and data dir with
   createMailModule, so no test touches process.env or the real data directory. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { LIB, CORE, mkTmp, canary, fakeHash, ctxFor, secretLookingKeys, testKeyHex, CRYPT6, WIN } = require("./helpers/common.js");

const { createMailModule } = require(path.join(LIB, "index.js"));
const { MockMailProvider } = require(path.join(LIB, "mock-provider.js"));
const { loadMailConfig } = require(path.join(LIB, "config.js"));
const crypt = require(path.join(LIB, "crypt.js"));
const C = require(path.join(CORE, "constants.js"));

function mod(env, dir) {
  const logs = [];
  const m = createMailModule({ env: Object.assign({}, env), dataDir: dir || mkTmp("mockmod"), log: (...a) => logs.push(a.join(" ")), logErr: (...a) => logs.push(a.join(" ")) });
  return { m, logs };
}
function mock(envOver, dir) {
  const { cfg } = loadMailConfig(Object.assign({ NODE_ENV: "test", MAIL_BOOTSTRAP_FORWARD: "owner@example.com" }, envOver || {}));
  const d = dir || mkTmp("mock");
  return { p: new MockMailProvider({ dir: d, cfg }), dir: d };
}
const hash1000 = (pw) => crypt.sha512Crypt(pw, { rounds: 1000, minRounds: 1000 });

test("first run: protected postmaster@ and abuse@ forward to the bootstrap address; files are written", async () => {
  const { p, dir } = mock();
  const l = await p.listAddresses();
  assert.equal(l.rev, 1);
  assert.deepEqual(l.addresses.map((a) => [a.local, a.protected, a.forwards]), [["abuse", true, ["owner@example.com"]], ["postmaster", true, ["owner@example.com"]]]);
  for (const f of ["state.json", "hashes.json", "render/virtual", "render/vmailbox", "render/sender_login", "render/sasl_access", "render/passwd"]) {
    assert.ok(fs.existsSync(path.join(dir, f)), f);
    if (!WIN) assert.equal(fs.statSync(path.join(dir, f)).mode & 0o777, 0o600, f);
  }
  const info = await p.info();
  assert.deepEqual(info, { kind: "mock", domain: "zehnox.com", connected: true, mock: true, reason: null });
  const st = await p.getStatus();
  assert.equal(st.service.state, "online");
  assert.equal(st.capabilities.mailboxes, true);
  assert.match(st.dkim.publicKey, /^MOCK/);
});

test("CRUD through the MailProvider interface, with ifRev and idempotency", async () => {
  const { p, dir } = mock();
  let rev = (await p.listAddresses()).rev;
  const c = await p.createAddress({ local: "info", forwards: ["owner@example.com"], passwordHash: null }, ctxFor(rev));
  assert.equal(c.rev, rev + 1);
  assert.equal(c.address.type, "forward");
  assert.match(fs.readFileSync(path.join(dir, "render", "virtual"), "utf8"), /^info@zehnox.com owner@example\.com$/m);
  await assert.rejects(p.createAddress({ local: "sales", forwards: ["x@example.com"] }, ctxFor(rev)), (e) => e.code === "conflict_rev" && e.status === 409);
  rev = c.rev;
  const idem = crypto.randomUUID();
  const u1 = await p.updateForwarding({ local: "info", forwards: ["a@example.com", "b@example.com"] }, ctxFor(rev, idem));
  // Replay with the same key and the same args after the rev moved on: the original result.
  const u2 = await p.updateForwarding({ local: "info", forwards: ["a@example.com", "b@example.com"] }, ctxFor(rev, idem));
  assert.deepEqual(u2, u1);
  assert.equal((await p.listAddresses()).rev, u1.rev, "applied once");
  await assert.rejects(p.updateForwarding({ local: "info", forwards: ["c@example.com"] }, ctxFor(u1.rev, idem)), (e) => e.code === "idempotency_mismatch");
  const dis = await p.setAddressEnabled({ local: "info", enabled: false }, ctxFor(u1.rev));
  assert.equal(dis.address.enabled, false);
  assert.ok(!fs.readFileSync(path.join(dir, "render", "virtual"), "utf8").includes("info@"));
  const del = await p.deleteAddress({ local: "info", confirm: "info@zehnox.com" }, ctxFor(dis.rev));
  assert.equal(del.mailboxDataRetained, false);
  await assert.rejects(p.getAddress("info"), (e) => e.code === "not_found");
  await assert.rejects(p.createAddress({ local: "x", forwards: [] }, { actor: {}, ifRev: del.rev }), (e) => e.code === "missing_idempotency_key");
  await assert.rejects(p.createAddress({ local: "x", forwards: ["a@example.com"] }, { actor: {}, idem: crypto.randomUUID() }), (e) => e.code === "invalid_body");
});

test("persistence: two instances on the same directory agree; a restart keeps everything", async () => {
  const dir = mkTmp("mock-persist");
  const a = mock({}, dir).p;
  const rev = (await a.listAddresses()).rev;
  await a.createAddress({ local: "careers", forwards: [], passwordHash: hash1000(canary("p")) }, ctxFor(rev));
  const b = mock({}, dir).p;
  const l = await b.listAddresses();
  assert.equal(l.rev, rev + 1);
  assert.equal(l.addresses.find((x) => x.local === "careers").type, "mailbox");
  // A hand edit that breaks the state is refused (not_ready), not "repaired".
  const state = JSON.parse(fs.readFileSync(path.join(dir, "state.json"), "utf8"));
  state.addresses["x@strategicbhm.com"] = state.addresses.careers;
  fs.writeFileSync(path.join(dir, "state.json"), JSON.stringify(state));
  await assert.rejects(b.listAddresses(), (e) => e.code === "not_ready");
});

test("hashes: only in hashes.json; never in a list, a result, state.json or a rendered file", async () => {
  const { p, dir } = mock();
  const pw = canary("mbox");
  const h = hash1000(pw);
  const rev = (await p.listAddresses()).rev;
  const created = await p.createAddress({ local: "contact", forwards: ["m@example.com"], passwordHash: h }, ctxFor(rev));
  const pw2 = canary("mbox2");
  const h2 = hash1000(pw2);
  const changed = await p.changeMailboxPassword({ local: "contact", passwordHash: h2 }, ctxFor(created.rev));
  assert.deepEqual(Object.keys(changed).sort(), ["changed", "passwordSetAt", "rev"]);
  const list = await p.listAddresses();
  for (const out of [created, changed, list, await p.getAddress("contact"), await p.auditTail({ limit: 50 })]) {
    const text = JSON.stringify(out);
    assert.ok(!text.includes(h) && !text.includes(h2) && !text.includes(CRYPT6));
    assert.deepEqual(secretLookingKeys(out), []);
  }
  const hashes = JSON.parse(fs.readFileSync(path.join(dir, "hashes.json"), "utf8"));
  assert.equal(hashes.hashes.contact.hash, h2);
  assert.equal(crypt.sha512Verify(pw2, hashes.hashes.contact.hash), true);
  assert.equal(crypt.sha512Verify(pw, hashes.hashes.contact.hash), false);
  for (const f of fs.readdirSync(dir, { recursive: true })) {
    const full = path.join(dir, f);
    if (!fs.statSync(full).isFile()) continue;
    const text = fs.readFileSync(full, "utf8");
    assert.ok(!text.includes(pw) && !text.includes(pw2), "plaintext in " + f);
    if (f !== "hashes.json") assert.ok(!text.includes(h2) && !text.includes(CRYPT6), "hash in " + f);
  }
});

test("rounds policy: the mock takes 1000-round hashes only under NODE_ENV=test", async () => {
  const dev = mock({ NODE_ENV: "development" }).p;
  const rev = (await dev.listAddresses()).rev;
  await assert.rejects(dev.createAddress({ local: "c", forwards: [], passwordHash: hash1000("x") }, ctxFor(rev)), (e) => e.code === "backend_failed");
  const ok = await dev.createAddress({ local: "c", forwards: [], passwordHash: fakeHash(50000) }, ctxFor(rev));
  assert.equal(ok.address.type, "mailbox");
});

test("capabilities: MAIL_MOCK_CAPS=forward-only refuses mailboxes", async () => {
  const { p } = mock({ MAIL_MOCK_CAPS: "forward-only" });
  const rev = (await p.listAddresses()).rev;
  await assert.rejects(p.createAddress({ local: "c", forwards: [], passwordHash: hash1000("x") }, ctxFor(rev)), (e) => e.code === "capability_missing");
  assert.equal((await p.getStatus()).capabilities.mailboxes, false);
});

test("fault injection works outside production and is ignored in production", async () => {
  const un = mock({ MAIL_MOCK_FAIL: "unavailable" }).p;
  await assert.rejects(un.listAddresses(), (e) => e.code === "unavailable" && e.status === 503);
  assert.equal((await un.info()).connected, false);
  const bf = mock({ MAIL_MOCK_FAIL: "backend_failed" }).p;
  const rev = (await bf.listAddresses()).rev;
  await assert.rejects(bf.createAddress({ local: "x", forwards: ["a@example.com"] }, ctxFor(rev)), (e) => e.code === "backend_failed" && e.status === 502);
  const deg = mock({ MAIL_MOCK_STATUS: "degraded" }).p;
  assert.equal((await deg.getStatus()).service.state, "degraded");
  const prod = mock({ NODE_ENV: "production", MAIL_MOCK_FAIL: "unavailable", MAIL_MOCK_STATUS: "offline" }).p;
  assert.equal((await prod.getStatus()).service.state, "online");
  await assert.doesNotReject(prod.listAddresses());
});

test("seeding: MAIL_MOCK_SEED=1 seeds development only, never production", async () => {
  const dev = mock({ MAIL_MOCK_SEED: "1" }).p;
  assert.deepEqual((await dev.listAddresses()).addresses.map((a) => a.local), ["abuse", "careers", "contact", "info", "postmaster"]);
  const prod = mock({ NODE_ENV: "production", MAIL_MOCK_SEED: "1", MAIL_ALLOW_MOCK_IN_PRODUCTION: "1" }).p;
  assert.deepEqual((await prod.listAddresses()).addresses.map((a) => a.local), ["abuse", "postmaster"]);
});

test("service audit (mock): hash chained, public fields only", async () => {
  const { p } = mock();
  const rev = (await p.listAddresses()).rev;
  const idem = crypto.randomUUID();
  await p.createAddress({ local: "info", forwards: ["a@example.com"] }, Object.assign(ctxFor(rev, idem), { actor: { user: "admin; rm -rf /", ip: "not an ip" } }));
  await assert.rejects(p.createAddress({ local: "info", forwards: ["a@example.com"] }, ctxFor(rev + 1)), (e) => e.code === "duplicate");
  const t = await p.auditTail({ limit: 10 });
  assert.equal(t.entries.length, 2);
  for (const e of t.entries) assert.deepEqual(Object.keys(e).sort(), ["actor", "at", "code", "idem", "nonce", "ok", "rev", "seq", "target", "verb"]);
  assert.equal(t.entries[0].code, "duplicate");
  assert.equal(t.entries[1].idem, idem);
  assert.equal(t.entries[1].actor.user, "admin__rm_-rf__", "actor names are sanitised to the wire pattern");
  assert.equal(t.entries[1].actor.ip, "::");
});

/* ---------- provider selection (lib/mail/index.js) ---------- */

test("selection: production never silently mocks; the kill switch and the domain pin hold", async () => {
  const cases = [
    [{ NODE_ENV: "production" }, "none", "not_connected"],
    [{ NODE_ENV: "production", MAIL_PROVIDER: "mock" }, "none", "not_connected"],
    [{ NODE_ENV: "production", MAIL_PROVIDER: "mock", MAIL_ALLOW_MOCK_IN_PRODUCTION: "1" }, "mock", null],
    [{ NODE_ENV: "development" }, "mock", null],
    [{ NODE_ENV: "test", MAIL_PROVIDER: "none" }, "none", "not_connected"],
    [{ NODE_ENV: "test", MAIL_PROVIDER: "bogus" }, "none", "not_connected"],
    [{ NODE_ENV: "test", MAIL_PROVIDER: "vps" }, "none", "not_connected"],
    [{ NODE_ENV: "test", MAIL_PROVIDER: "vps", MAIL_SERVICE_SOCKET: "/nonexistent/mail.sock" }, "none", "not_connected"],
    [{ NODE_ENV: "test", MAIL_PROVIDER: "mock", MAIL_DOMAIN: "strategicbhm.com" }, "none", "domain_mismatch"],
    [{ NODE_ENV: "test", MAIL_PROVIDER: "vps", MAIL_DOMAIN: "ZEHNOX.COM.evil.com", MAIL_SERVICE_SOCKET: "/x", MAIL_SERVICE_KEY: testKeyHex() }, "none", "domain_mismatch"],
  ];
  for (const [env, kind, reason] of cases) {
    const { m } = mod(env);
    const p = m.getProvider();
    assert.equal(p.kind, kind, JSON.stringify(env));
    const info = await p.info();
    if (kind === "none") {
      assert.equal(info.reason, reason, JSON.stringify(env));
      await assert.rejects(p.listAddresses(), (e) => e.code === reason && e.status === 503);
      await assert.rejects(p.createAddress({ local: "info", forwards: ["a@example.com"] }, ctxFor(1)), (e) => e.status === 503);
      assert.equal((await p.getStatus()).service.state, "not_connected");
      assert.deepEqual(m.me(), { provider: "none", connected: false, mock: false });
    }
  }
  // With the right domain spelled in any case, the pin is satisfied.
  assert.equal(mod({ NODE_ENV: "test", MAIL_PROVIDER: "mock", MAIL_DOMAIN: "Zehnox.Com" }).m.getProvider().kind, "mock");
});

test("selection: key env values are deleted when the module loads; me() carries booleans only", () => {
  const env = { NODE_ENV: "test", MAIL_PROVIDER: "mock", MAIL_SERVICE_KEY: testKeyHex(), MAIL_SECRETS_KEY: testKeyHex() };
  const m = createMailModule({ env, dataDir: mkTmp("sel") });
  assert.equal(env.MAIL_SERVICE_KEY, undefined);
  assert.equal(env.MAIL_SECRETS_KEY, undefined);
  assert.deepEqual(m.me(), { provider: "mock", connected: true, mock: true });
  assert.equal(m.getSmtp().secretsKeyPresent(), true);
  assert.ok(!JSON.stringify(m.cfg).match(/[0-9a-f]{64}/));
});

test("hash options: rounds clamp to the receiving side's floor; default 100,000", () => {
  assert.equal(mod({ NODE_ENV: "production", MAIL_HASH_ROUNDS: "1000" }).m.hashOptions(null).rounds, 50000);
  assert.equal(mod({ NODE_ENV: "test", MAIL_HASH_ROUNDS: "1000" }).m.hashOptions(null).rounds, 1000);
  assert.equal(mod({ NODE_ENV: "production" }).m.hashOptions(null).rounds, 100000);
  assert.equal(mod({ NODE_ENV: "production", MAIL_HASH_ROUNDS: "99999999" }).m.hashOptions(null).rounds, C.LIMITS.maxRounds);
  const low = mod({ NODE_ENV: "production", MAIL_HASH_ROUNDS: "10" });
  low.m.hashOptions(null);
  assert.ok(low.logs.some((l) => /MAIL_HASH_ROUNDS is below the minimum/.test(l)));
  assert.equal(mod({ NODE_ENV: "production", MAIL_PASSWORD_SCHEME: "ARGON2ID" }).m.hashOptions({ schemes: ["SHA512-CRYPT"] }).scheme, "SHA512-CRYPT", "argon only when the mail service lists it");
});
