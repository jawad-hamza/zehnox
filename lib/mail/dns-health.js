"use strict";
/* DNS health: expected vs observed (DESIGN.md section 12).

   createHealthChecker({ resolver?, now?, cfg, probe?, cacheMs?, deadlineMs? })
     .check({ refresh, status }) -> Health
   Health = { checkedAt, overall, checks: [{ id, label, status, expected: [..], observed: [..], note }] }
   status values: 'pass' | 'warn' | 'fail' | 'unknown'; overall is the worst of them.

   Rules that matter:
   - DNS names are built only from configuration and the pinned domain, never from input.
   - A timeout, SERVFAIL or refused query is 'unknown', never 'fail': the DNS view must not
     cry wolf because a resolver hiccuped. ENOTFOUND / ENODATA are 'fail' (record missing).
   - Everything runs under Promise.allSettled with one overall deadline (8 s); a check still
     running at the deadline reports 'unknown'.
   - The result is cached in memory for 5 minutes; check({ refresh: true }) bypasses it.
   - Observed strings are capped at 1 KB and are only ever rendered with textContent.
   - Nothing here changes DNS. The view tells the owner what to add by hand. */

const dns = require("dns");
const { PINNED_DOMAIN } = require("./core/constants.js");
const { probeSubmission } = require("./tls-probe.js");

const CACHE_MS = 5 * 60 * 1000;
const DEADLINE_MS = 8000;
const OBS_MAX = 1024;
const RANK = { pass: 0, unknown: 1, warn: 2, fail: 3 };

/* Cloudflare's published IPv4 ranges (cloudflare.com/ips-v4). A mail host inside them is
   proxied, and Cloudflare's proxy does not carry SMTP. Refresh this list when it changes. */
const CLOUDFLARE_V4 = Object.freeze([
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
  "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
  "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]);

function ipToInt(ip) {
  const p = String(ip).split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
function inCidr(ip, cidr) {
  const [base, bitsStr] = cidr.split("/");
  const bits = bitsStr === undefined ? 32 : Number(bitsStr);
  const a = ipToInt(ip);
  const b = ipToInt(base);
  if (a === null || b === null || !(bits >= 0 && bits <= 32)) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}
const isCloudflare = (ip) => CLOUDFLARE_V4.some((c) => inCidr(ip, c));

const cap = (s) => { const t = String(s); return t.length > OBS_MAX ? t.slice(0, OBS_MAX) : t; };
const worst = (list) => list.reduce((w, s) => (RANK[s] > RANK[w] ? s : w), "pass");

/* ENOTFOUND/ENODATA: the record does not exist. Anything else: we could not tell. */
function dnsStatus(err) {
  return err && (err.code === "ENOTFOUND" || err.code === "ENODATA") ? "fail" : "unknown";
}
function dnsNote(err) {
  if (!err) return "";
  if (err.code === "ENOTFOUND" || err.code === "ENODATA") return "record missing";
  if (err.code === "ETIMEOUT" || err.code === "deadline") return "DNS lookup timed out";
  return "DNS lookup failed (" + String(err.code || "error").replace(/[^A-Z_]/g, "").slice(0, 20) + ")";
}

const txtJoin = (records) => (records || []).map((chunks) => (Array.isArray(chunks) ? chunks.join("") : String(chunks)));

/* Splits a TXT value into quoted strings of at most 255 bytes, as DNS panels expect. */
function txtChunks(value) {
  const out = [];
  for (let i = 0; i < value.length; i += 255) out.push('"' + value.slice(i, i + 255) + '"');
  return out.join(" ");
}

function parseTags(rec) {
  const tags = {};
  for (const part of rec.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  }
  return tags;
}

function defaultResolver(servers) {
  const r = new dns.promises.Resolver({ timeout: 2500, tries: 2 });
  if (servers && servers.length) r.setServers(servers);
  return r;
}

/* Fixed answers for mock mode (MX pass, SPF pass, DKIM missing, DMARC p=none), so every
   badge state renders with no network at all. */
function fakeResolver(host) {
  const nf = () => Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  return {
    async resolveMx(name) { if (name === PINNED_DOMAIN) return [{ priority: 10, exchange: host }]; throw nf(); },
    async resolve4(name) { if (name === host) return ["192.0.2.10"]; throw nf(); },
    async resolveTxt(name) {
      if (name === PINNED_DOMAIN) return [["v=spf1 mx -all"]];
      if (name === "_dmarc." + PINNED_DOMAIN) return [["v=DMARC1; p=none; rua=mailto:postmaster@" + PINNED_DOMAIN + "; adkim=s; aspf=s"]];
      throw nf();
    },
    async reverse(ip) { if (ip === "192.0.2.10") return [host]; throw nf(); },
  };
}
function fakeProbe(host) {
  return async () => ({
    stage: "done", ms: 42, banner: { code: 220, host }, starttls: true, authAfterTls: true, trusted: true, nameOk: true, error: null,
    cert: { subject: host, sans: [host], validTo: new Date(Date.now() + 60 * 86400000).toISOString(), daysLeft: 60, issuer: "Mock CA" },
  });
}

function createHealthChecker(opts) {
  const o = opts || {};
  const cfg = Object.assign({ mailHostname: "", serverIpv4: "", dkimSelector: "", dmarcRua: "postmaster@" + PINNED_DOMAIN, ehloName: PINNED_DOMAIN, dnsServers: [] }, o.cfg || {});
  const resolver = o.resolver || defaultResolver(cfg.dnsServers);
  const probe = o.probe || ((p) => probeSubmission(p));
  const now = o.now || (() => new Date());
  const cacheMs = o.cacheMs == null ? CACHE_MS : o.cacheMs;
  const deadlineMs = o.deadlineMs || DEADLINE_MS;
  const domain = PINNED_DOMAIN;
  const host = cfg.mailHostname;
  let cache = null;
  let inflight = null;

  const noHost = (id, label, expected) => ({ id, label, status: "unknown", expected, observed: [], note: "MAIL_HOSTNAME is not set on the server." });

  async function mx() {
    const expected = [domain + ". MX 10 " + (host || "<mail host>") + "."];
    let rows;
    try { rows = await resolver.resolveMx(domain); } catch (e) { return { status: dnsStatus(e), expected, observed: [], note: dnsNote(e) }; }
    const hosts = rows.map((r) => String(r.exchange).toLowerCase().replace(/\.$/, ""));
    const observed = rows.map((r) => cap(r.priority + " " + String(r.exchange).toLowerCase().replace(/\.$/, "")));
    if (!host) return Object.assign(noHost(), { observed, expected });
    if (!hosts.length) return { status: "fail", expected, observed, note: "no MX record" };
    if (!hosts.includes(host)) return { status: "fail", expected, observed, note: "MX does not point at " + host };
    if (hosts.some((h) => h !== host)) return { status: "warn", expected, observed, note: "other MX hosts are listed too" };
    return { status: "pass", expected, observed, note: "" };
  }

  async function mailhostA() {
    const expected = [(host || "<mail host>") + ". A " + (cfg.serverIpv4 || "<server IPv4>") + "   (DNS-only, not proxied)"];
    if (!host) return noHost(null, null, expected);
    let ips;
    try { ips = await resolver.resolve4(host); } catch (e) { return { status: dnsStatus(e), expected, observed: [], note: dnsNote(e) }; }
    const observed = ips.map(cap);
    if (ips.some(isCloudflare)) return { status: "fail", expected, observed, note: "the mail host is proxied by Cloudflare; set it to DNS-only" };
    if (cfg.serverIpv4 && !ips.includes(cfg.serverIpv4)) return { status: "fail", expected, observed, note: "does not resolve to " + cfg.serverIpv4 };
    return { status: "pass", expected, observed, note: "" };
  }

  async function spf() {
    const want = cfg.serverIpv4 ? "v=spf1 mx ip4:" + cfg.serverIpv4 + " -all" : "v=spf1 mx -all";
    const expected = [domain + ". TXT \"" + want + "\""];
    let recs;
    try { recs = txtJoin(await resolver.resolveTxt(domain)); } catch (e) { return { status: dnsStatus(e), expected, observed: [], note: dnsNote(e) }; }
    const spfs = recs.filter((r) => /^v=spf1(\s|$)/i.test(r));
    const observed = spfs.map(cap);
    if (spfs.length === 0) return { status: "fail", expected, observed, note: "no SPF record" };
    if (spfs.length > 1) return { status: "fail", expected, observed, note: "more than one SPF record (receivers treat this as an error)" };
    const terms = spfs[0].toLowerCase().split(/\s+/).slice(1);
    const notes = [];
    let status = "pass";
    const bump = (s) => { if (RANK[s] > RANK[status]) status = s; };
    if (terms.some((t) => t === "+all" || t === "?all")) { bump("fail"); notes.push("+all or ?all lets anyone send as the domain"); }
    else if (terms.includes("~all")) { bump("warn"); notes.push("~all is a soft fail; -all is recommended"); }
    // RFC 7208 section 4.6.4: at most 10 DNS-querying terms (counted here without recursion).
    const lookups = terms.filter((t) => /^[+?~-]?(include:|a$|a:|a\/|mx$|mx:|mx\/|ptr|exists:|redirect=)/.test(t)).length;
    if (lookups > 10) { bump("fail"); notes.push(lookups + " DNS lookups (limit 10)"); }
    else if (lookups > 8) { bump("warn"); notes.push(lookups + " DNS lookups (limit 10)"); }
    const bare = terms.map((t) => t.replace(/^[+?~-]/, ""));
    const coversIp = (t) => {
      if (!t.startsWith("ip4:")) return false;
      if (!cfg.serverIpv4) return true;
      const v = t.slice(4);
      return v.includes("/") ? inCidr(cfg.serverIpv4, v) : v === cfg.serverIpv4;
    };
    const covered = bare.includes("mx") || (host && bare.includes("a:" + host)) || bare.some(coversIp);
    if (!covered) { bump("warn"); notes.push("the mail server is not covered by mx, a:" + (host || "<mail host>") + " or ip4:"); }
    if (bare.some((t) => t.startsWith("include:"))) notes.push("includes not evaluated");
    return { status, expected, observed, note: notes.join("; ") };
  }

  async function dkim(status) {
    const key = status && status.dkim && typeof status.dkim.publicKey === "string" && status.dkim.publicKey ? status.dkim.publicKey.replace(/\s+/g, "") : null;
    const selector = cfg.dkimSelector || (status && status.dkim && status.dkim.selector) || "";
    if (!selector) return { status: "unknown", expected: [], observed: [], note: "MAIL_DKIM_SELECTOR is not set on the server." };
    const name = selector + "._domainkey." + domain;
    const expected = [name + ". TXT " + (key ? txtChunks("v=DKIM1; k=rsa; p=" + key) : "(selector configured on server; public key not available)")];
    let recs;
    try { recs = txtJoin(await resolver.resolveTxt(name)); } catch (e) { return { status: dnsStatus(e), expected, observed: [], note: dnsNote(e) }; }
    const observed = recs.map(cap);
    const rec = recs.find((r) => /(^|;)\s*p=/i.test(r) || /^v=DKIM1/i.test(r));
    if (!rec) return { status: "fail", expected, observed, note: "no DKIM record" };
    const p = (parseTags(rec).p || "").replace(/\s+/g, "");
    if (!p) return { status: "fail", expected, observed, note: "empty p= (the key is revoked)" };
    const notes = [];
    let st;
    if (!key) { st = "unknown"; notes.push("the server's public key is not available to compare"); }
    else if (p === key) st = "pass";
    else { st = "warn"; notes.push("DNS has a different key than the server signs with"); }
    // An RSA-1024 SubjectPublicKeyInfo is ~162 bytes; 2048-bit is ~294.
    if (Buffer.from(p, "base64").length < 200) { if (RANK.warn > RANK[st]) st = "warn"; notes.push("the key looks like RSA-1024; use 2048 bits"); }
    return { status: st, expected, observed, note: notes.join("; ") };
  }

  async function dmarc() {
    const name = "_dmarc." + domain;
    const expected = [name + ". TXT \"v=DMARC1; p=none; rua=mailto:" + cfg.dmarcRua + "; adkim=s; aspf=s\"   (step 2: p=quarantine after 2 clean weeks)"];
    let recs;
    try { recs = txtJoin(await resolver.resolveTxt(name)); } catch (e) { return { status: dnsStatus(e), expected, observed: [], note: dnsNote(e) }; }
    const ds = recs.filter((r) => /^v=DMARC1\s*(;|$)/i.test(r));
    const observed = ds.map(cap);
    if (ds.length !== 1) return { status: "fail", expected, observed, note: ds.length ? "more than one DMARC record" : "no DMARC record" };
    const t = parseTags(ds[0]);
    const policy = (t.p || "").toLowerCase();
    const info = "rua=" + (t.rua || "none") + ", adkim=" + (t.adkim || "r") + ", aspf=" + (t.aspf || "r");
    if (policy === "none") return { status: "warn", expected, observed, note: "p=none only monitors; " + info };
    if (policy === "quarantine" || policy === "reject") return { status: "pass", expected, observed, note: info };
    return { status: "fail", expected, observed, note: "invalid policy; " + info };
  }

  async function ptr() {
    const expected = [(cfg.serverIpv4 || "<server IPv4>") + " PTR " + (host || "<mail host>") + ".   (set by the VPS provider)"];
    if (!cfg.serverIpv4 || !host) return { status: "unknown", expected, observed: [], note: "informational: set MAIL_SERVER_IPV4 and MAIL_HOSTNAME to check" };
    let names;
    try { names = await resolver.reverse(cfg.serverIpv4); } catch (e) { return { status: e && (e.code === "ENOTFOUND" || e.code === "ENODATA") ? "warn" : "unknown", expected, observed: [], note: "informational: " + dnsNote(e) }; }
    const observed = names.map((n) => cap(String(n).toLowerCase().replace(/\.$/, "")));
    return observed.includes(host) ? { status: "pass", expected, observed, note: "" } : { status: "warn", expected, observed, note: "informational: reverse DNS does not name " + host };
  }

  async function submissionTls() {
    const expected = [(host || "<mail host>") + ":587 STARTTLS with a valid certificate for " + (host || "<mail host>")];
    if (!host) return noHost(null, null, expected);
    const r = await probe({ host, port: 587, ehloName: cfg.ehloName, timeoutMs: 5000 });
    const observed = [];
    if (r.banner && r.banner.host) observed.push("banner: " + r.banner.host);
    if (r.cert) {
      observed.push("certificate: " + (r.cert.subject || "?") + (r.cert.sans.length ? " (SAN " + r.cert.sans.join(", ") + ")" : ""));
      if (r.cert.validTo) observed.push("expires: " + r.cert.validTo.slice(0, 10) + (r.cert.daysLeft != null ? " (" + r.cert.daysLeft + " days)" : ""));
    }
    if (r.authAfterTls !== null) observed.push("AUTH after TLS: " + (r.authAfterTls ? "offered" : "not offered"));
    const obs = observed.map(cap);
    if (r.stage === "timeout" || r.stage === "connect" || r.stage === "greeting" || r.stage === "ehlo") return { status: "unknown", expected, observed: obs, note: "could not complete the SMTP conversation (" + r.stage + ")" };
    if (!r.starttls) return { status: "fail", expected, observed: obs, note: "STARTTLS is not offered on 587" };
    if (r.stage !== "done" && !r.cert) return { status: "unknown", expected, observed: obs, note: "the TLS handshake did not complete" };
    if (r.cert && r.cert.daysLeft != null && r.cert.daysLeft < 0) return { status: "fail", expected, observed: obs, note: "the certificate has expired" };
    if (!r.nameOk) return { status: "fail", expected, observed: obs, note: "the certificate is not valid for " + host };
    if (!r.trusted) return { status: "fail", expected, observed: obs, note: "the certificate chain is not trusted" };
    if (r.cert && r.cert.daysLeft != null && r.cert.daysLeft < 14) return { status: "warn", expected, observed: obs, note: "the certificate expires in " + r.cert.daysLeft + " days" };
    return { status: "pass", expected, observed: obs, note: "" };
  }

  function service(status) {
    const expected = ["online"];
    if (!status) return { status: "unknown", expected, observed: [], note: "the mail service did not answer" };
    const st = status.service && status.service.state;
    const map = { online: "pass", degraded: "warn", offline: "fail", not_connected: "unknown" };
    return { status: map[st] || "unknown", expected, observed: [String(st || "unknown")], note: st === "not_connected" ? "no mail service is connected" : "" };
  }

  function configuredDomain(status) {
    const expected = [domain];
    if (!status) return { status: "unknown", expected, observed: [], note: "the mail service did not answer" };
    if (status.domain !== domain) return { status: "fail", expected, observed: [String(status.domain || "(other)")].map(cap), note: "the mail service is configured for a different domain; changes are blocked" };
    if (status.kind === "none") return { status: "unknown", expected, observed: [domain], note: "no mail service is connected" };
    return { status: "pass", expected, observed: [domain], note: "" };
  }

  const LABELS = {
    mx: "MX", mailhost_a: "Mail host A", spf: "SPF", dkim: "DKIM", dmarc: "DMARC", ptr: "Reverse DNS (PTR)",
    submission_tls: "Submission TLS (587)", service: "Mail service", configured_domain: "Configured domain",
  };

  async function run(status) {
    const jobs = [
      ["mx", () => mx()], ["mailhost_a", () => mailhostA()], ["spf", () => spf()], ["dkim", () => dkim(status)],
      ["dmarc", () => dmarc()], ["ptr", () => ptr()], ["submission_tls", () => submissionTls()],
      ["service", async () => service(status)], ["configured_domain", async () => configuredDomain(status)],
    ];
    let timer;
    const deadline = new Promise((res) => { timer = setTimeout(res, deadlineMs, "deadline"); });
    const settled = await Promise.allSettled(jobs.map(([, fn]) => Promise.race([Promise.resolve().then(fn), deadline])));
    clearTimeout(timer);
    const checks = settled.map((s, i) => {
      const id = jobs[i][0];
      const base = { id, label: LABELS[id], status: "unknown", expected: [], observed: [], note: "" };
      if (s.status === "rejected") return Object.assign(base, { note: "check failed" });
      if (s.value === "deadline") return Object.assign(base, { note: "timed out" });
      return Object.assign(base, { status: s.value.status, expected: s.value.expected || [], observed: s.value.observed || [], note: s.value.note || "" });
    });
    return { checkedAt: now().toISOString(), overall: worst(checks.map((c) => c.status)), checks };
  }

  /* opts: { refresh: bool, status: Status | null } */
  async function check(opts2) {
    const refresh = !!(opts2 && opts2.refresh);
    const t = now().getTime();
    if (!refresh && cache && t - cache.at < cacheMs) return cache.value;
    if (inflight) return inflight;
    inflight = run(opts2 && opts2.status).then((value) => { cache = { at: now().getTime(), value }; return value; }).finally(() => { inflight = null; });
    return inflight;
  }

  return { check, cached: () => (cache ? cache.value : null) };
}

module.exports = { createHealthChecker, fakeResolver, fakeProbe, defaultResolver, isCloudflare, inCidr, CLOUDFLARE_V4 };
