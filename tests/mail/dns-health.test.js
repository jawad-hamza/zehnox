"use strict";
/* DNS health, expected vs observed (lib/mail/dns-health.js, tls-probe.js), DESIGN.md
   section 12. Every case uses a stubbed resolver and an injected probe: no test touches
   real DNS or a real mail server. The resolver also records every name it was asked for,
   to prove names come only from configuration and the pinned domain. */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { LIB } = require("./helpers/common.js");

const H = require(path.join(LIB, "dns-health.js"));
const { describeCert } = require(path.join(LIB, "tls-probe.js"));

const HOST = "mail.example.net";
const IP = "198.51.100.25";
const KEY2048 = Buffer.alloc(294, 7).toString("base64");
const KEY1024 = Buffer.alloc(162, 7).toString("base64");
const CFG = { mailHostname: HOST, serverIpv4: IP, dkimSelector: "sbhm1", dmarcRua: "postmaster@zehnox.com", ehloName: "zehnox.com" };
const STATUS = { domain: "zehnox.com", kind: "vps", service: { state: "online" }, dkim: { selector: "sbhm1", publicKey: KEY2048 } };
const err = (code) => Object.assign(new Error(code), { code });

/* zone: { mx, a, txt: { name: [[chunks]] }, ptr } where any value may be an Error to throw
   or a function returning a promise. */
function resolver(zone) {
  const asked = [];
  const get = async (kind, name, v) => {
    asked.push(kind + " " + name);
    const x = typeof v === "function" ? await v() : v;
    if (x instanceof Error) throw x;
    if (x === undefined) throw err("ENOTFOUND");
    return x;
  };
  return {
    asked,
    resolveMx: (n) => get("MX", n, n === "zehnox.com" ? zone.mx : undefined),
    resolve4: (n) => get("A", n, n === HOST ? zone.a : undefined),
    resolveTxt: (n) => get("TXT", n, zone.txt && zone.txt[n]),
    reverse: (ip) => get("PTR", ip, ip === IP ? zone.ptr : undefined),
  };
}
const goodZone = () => ({
  mx: [{ priority: 10, exchange: HOST + "." }],
  a: [IP],
  ptr: [HOST],
  txt: {
    "zehnox.com": [["v=spf1 mx ip4:" + IP + " -all"], ["google-site-verification=abc"]],
    "sbhm1._domainkey.zehnox.com": [["v=DKIM1; k=rsa; p=" + KEY2048.slice(0, 200), KEY2048.slice(200)]],
    "_dmarc.zehnox.com": [["v=DMARC1; p=quarantine; rua=mailto:postmaster@zehnox.com; adkim=s; aspf=s"]],
  },
});
const probeOk = (over) => async () => Object.assign({
  stage: "done", ms: 5, banner: { code: 220, host: HOST }, starttls: true, authAfterTls: true, trusted: true, nameOk: true, error: null,
  cert: { subject: HOST, sans: [HOST], validTo: new Date(Date.now() + 90 * 86400000).toISOString(), daysLeft: 90, issuer: "Test CA" },
}, over || {});

async function check(zone, o) {
  const opts = o || {};
  const r = resolver(zone);
  const hc = H.createHealthChecker({ cfg: Object.assign({}, CFG, opts.cfg || {}), resolver: r, probe: opts.probe || probeOk(), deadlineMs: opts.deadlineMs, cacheMs: opts.cacheMs });
  const out = await hc.check({ refresh: true, status: opts.status === undefined ? STATUS : opts.status });
  const by = Object.fromEntries(out.checks.map((c) => [c.id, c]));
  return { out, by, asked: r.asked, hc };
}

test("all good: every check passes; overall pass; the output shape is fixed", async () => {
  const { out, by } = await check(goodZone());
  assert.deepEqual(out.checks.map((c) => c.id), ["mx", "mailhost_a", "spf", "dkim", "dmarc", "ptr", "submission_tls", "service", "configured_domain"]);
  for (const c of out.checks) {
    assert.equal(c.status, "pass", c.id + ": " + c.note);
    assert.deepEqual(Object.keys(c).sort(), ["expected", "id", "label", "note", "observed", "status"]);
  }
  assert.equal(out.overall, "pass");
  assert.match(by.dkim.expected[0], /^sbhm1\._domainkey\.zehnox.com\. TXT "v=DKIM1; k=rsa; p=/);
  assert.ok(by.dkim.expected[0].split('" "').length >= 2, "long TXT values are split into 255-byte strings");
});

test("DNS names come only from configuration and the pinned domain", async () => {
  const { asked } = await check(goodZone());
  const allowed = new Set(["MX zehnox.com", "A " + HOST, "TXT zehnox.com", "TXT sbhm1._domainkey.zehnox.com", "TXT _dmarc.zehnox.com", "PTR " + IP]);
  for (const a of asked) assert.ok(allowed.has(a), a);
  // Even when the daemon's status names another domain, no query goes there.
  const { asked: asked2, by } = await check(goodZone(), { status: Object.assign({}, STATUS, { domain: "strategicbhm.com" }) });
  for (const a of asked2) assert.ok(!a.includes("strategicbhm"), a);
  assert.equal(by.configured_domain.status, "fail");
});

test("missing records fail, resolver trouble is unknown (never fail)", async () => {
  const z = goodZone();
  delete z.txt["_dmarc.zehnox.com"];
  z.mx = err("ENODATA");
  z.a = err("ETIMEOUT");
  z.txt["zehnox.com"] = err("ESERVFAIL");
  z.txt["sbhm1._domainkey.zehnox.com"] = err("ECONNREFUSED");
  const { by, out } = await check(z);
  assert.equal(by.mx.status, "fail");
  assert.equal(by.mx.note, "record missing");
  assert.equal(by.dmarc.status, "fail");
  assert.equal(by.mailhost_a.status, "unknown");
  assert.equal(by.spf.status, "unknown");
  assert.equal(by.dkim.status, "unknown");
  assert.equal(out.overall, "fail");
});

test("MX: other hosts warn; wrong host fails", async () => {
  const z = goodZone();
  z.mx = [{ priority: 10, exchange: HOST }, { priority: 20, exchange: "backup.example.org" }];
  assert.equal((await check(z)).by.mx.status, "warn");
  z.mx = [{ priority: 10, exchange: "other.example.org" }];
  assert.equal((await check(z)).by.mx.status, "fail");
});

test("A record: a Cloudflare-proxied mail host fails; an address other than MAIL_SERVER_IPV4 fails", async () => {
  const z = goodZone();
  z.a = ["104.16.1.1"];
  const { by } = await check(z);
  assert.equal(by.mailhost_a.status, "fail");
  assert.match(by.mailhost_a.note, /Cloudflare/);
  z.a = ["203.0.113.7"];
  assert.equal((await check(z)).by.mailhost_a.status, "fail");
  assert.equal(H.isCloudflare("172.64.0.1"), true);
  assert.equal(H.isCloudflare("172.63.255.255"), false);
  assert.equal(H.inCidr("10.0.0.1", "10.0.0.0/8"), true);
  assert.equal(H.inCidr("not-an-ip", "10.0.0.0/8"), false);
});

test("SPF: two records, +all or ?all, and more than 10 lookups fail; ~all and >8 lookups warn", async () => {
  const spf = async (...recs) => { const z = goodZone(); z.txt["zehnox.com"] = recs.map((r) => [r]); return (await check(z)).by.spf; };
  assert.equal((await spf("v=spf1 mx -all", "v=spf1 a -all")).status, "fail");
  assert.equal((await spf("v=spf1 mx +all")).status, "fail");
  assert.equal((await spf("v=spf1 mx ?all")).status, "fail");
  assert.equal((await spf("v=spf1 mx ~all")).status, "warn");
  const inc = (n) => Array.from({ length: n }, (_, i) => "include:s" + i + ".example.com").join(" ");
  assert.equal((await spf("v=spf1 mx " + inc(10) + " -all")).status, "fail");
  const nine = await spf("v=spf1 mx " + inc(8) + " -all");
  assert.equal(nine.status, "warn");
  assert.match(nine.note, /includes not evaluated/);
  assert.equal((await spf("v=spf1 ip4:203.0.113.0/24 -all")).status, "warn", "does not cover the server");
  assert.equal((await spf("v=spf1 ip4:198.51.100.0/24 -all")).status, "pass");
  assert.equal((await spf("google-site-verification=x")).status, "fail", "no SPF record at all");
});

test("DKIM: mismatch warns, empty p= fails, no server key is unknown, RSA-1024 warns", async () => {
  const dk = async (rec, status) => { const z = goodZone(); z.txt["sbhm1._domainkey.zehnox.com"] = [[rec]]; return (await check(z, { status })).by.dkim; };
  const other = Buffer.alloc(294, 9).toString("base64");
  const mism = await dk("v=DKIM1; k=rsa; p=" + other);
  assert.equal(mism.status, "warn");
  assert.match(mism.note, /different key/);
  assert.equal((await dk("v=DKIM1; k=rsa; p=")).status, "fail");
  const noKey = await dk("v=DKIM1; k=rsa; p=" + KEY2048, Object.assign({}, STATUS, { dkim: { selector: "sbhm1", publicKey: null } }));
  assert.equal(noKey.status, "unknown");
  assert.equal(noKey.observed.length, 1, "the observed record is still shown");
  const small = await dk("v=DKIM1; k=rsa; p=" + KEY1024, Object.assign({}, STATUS, { dkim: { selector: "sbhm1", publicKey: KEY1024 } }));
  assert.equal(small.status, "warn");
  assert.match(small.note, /RSA-1024/);
});

test("DMARC: p=none warns, quarantine/reject pass, two records or a bad policy fail", async () => {
  const dm = async (...recs) => { const z = goodZone(); z.txt["_dmarc.zehnox.com"] = recs.map((r) => [r]); return (await check(z)).by.dmarc; };
  assert.equal((await dm("v=DMARC1; p=none; rua=mailto:x@zehnox.com")).status, "warn");
  assert.equal((await dm("v=DMARC1; p=reject")).status, "pass");
  assert.equal((await dm("v=DMARC1; p=none", "v=DMARC1; p=reject")).status, "fail");
  assert.equal((await dm("v=DMARC1; p=maybe")).status, "fail");
});

test("submission TLS: no STARTTLS, name mismatch, untrusted, expired fail; expiring soon warns; no answer is unknown", async () => {
  const st = async (over) => (await check(goodZone(), { probe: probeOk(over) })).by.submission_tls;
  assert.equal((await st({ starttls: false, stage: "starttls", cert: null })).status, "fail");
  assert.equal((await st({ nameOk: false })).status, "fail");
  assert.equal((await st({ trusted: false })).status, "fail");
  const cert = (days) => ({ subject: HOST, sans: [HOST], validTo: new Date(Date.now() + days * 86400000).toISOString(), daysLeft: days, issuer: "Test CA" });
  assert.equal((await st({ cert: cert(-1) })).status, "fail");
  const soon = await st({ cert: cert(5) });
  assert.equal(soon.status, "warn");
  assert.match(soon.note, /5 days/);
  assert.equal((await st({ stage: "timeout", starttls: false, cert: null, banner: null })).status, "unknown");
  assert.equal((await st({ stage: "connect", starttls: false, cert: null, banner: null })).status, "unknown");
  // describeCert reads names from the certificate itself.
  const d = describeCert({ subject: { CN: HOST }, subjectaltname: "DNS:" + HOST + ", IP Address:1.2.3.4", valid_to: new Date(Date.now() + 3 * 86400000).toUTCString(), issuer: { O: "Test" } }, HOST, Date.now());
  assert.deepEqual(d.cert.sans, [HOST]);
  assert.ok(d.cert.daysLeft >= 2 && d.cert.daysLeft <= 3);
});

test("service and domain rows follow the daemon status; not_connected is unknown", async () => {
  assert.equal((await check(goodZone(), { status: Object.assign({}, STATUS, { service: { state: "degraded" } }) })).by.service.status, "warn");
  assert.equal((await check(goodZone(), { status: Object.assign({}, STATUS, { service: { state: "offline" } }) })).by.service.status, "fail");
  const none = await check(goodZone(), { status: { domain: "zehnox.com", kind: "none", service: { state: "not_connected" }, dkim: {} } });
  assert.equal(none.by.service.status, "unknown");
  assert.equal(none.by.configured_domain.status, "unknown");
  const down = await check(goodZone(), { status: null });
  assert.equal(down.by.service.status, "unknown");
});

test("the overall deadline holds: a hung lookup reports unknown, not a hang", async () => {
  const z = goodZone();
  z.mx = () => new Promise(() => {}); // never settles
  const started = Date.now();
  const { by } = await check(z, { deadlineMs: 200 });
  assert.ok(Date.now() - started < 3000);
  assert.equal(by.mx.status, "unknown");
  assert.equal(by.mx.note, "timed out");
  assert.equal(by.spf.status, "pass", "the other checks still report");
});

test("cache: 5 minutes unless refreshed; observed strings are capped at 1 KB", async () => {
  const z = goodZone();
  z.txt["_dmarc.zehnox.com"] = [["v=DMARC1; p=reject; " + "x".repeat(3000)]];
  const r = resolver(z);
  const hc = H.createHealthChecker({ cfg: CFG, resolver: r, probe: probeOk() });
  const a = await hc.check({ refresh: false, status: STATUS });
  const n = r.asked.length;
  const b = await hc.check({ refresh: false, status: STATUS });
  assert.equal(a, b);
  assert.equal(r.asked.length, n, "served from the cache");
  await hc.check({ refresh: true, status: STATUS });
  assert.ok(r.asked.length > n, "refresh bypasses the cache");
  assert.ok(a.checks.find((c) => c.id === "dmarc").observed[0].length <= 1024);
});

test("mock mode uses a fixed offline resolver (no network)", async () => {
  const hc = H.createHealthChecker({ cfg: { mailHostname: "mail.example.invalid", dkimSelector: "sbhm1" }, resolver: H.fakeResolver("mail.example.invalid"), probe: H.fakeProbe("mail.example.invalid") });
  const out = await hc.check({ refresh: true, status: null });
  const by = Object.fromEntries(out.checks.map((c) => [c.id, c.status]));
  assert.equal(by.mx, "pass");
  assert.equal(by.spf, "pass");
  assert.equal(by.dkim, "fail");
  assert.equal(by.dmarc, "warn");
});
