"use strict";
/* "Test SMTP" failure handling (lib/mail/smtp-test.js with the real smtp.js), DESIGN.md
   section 10.4. Each case runs the real client against a fake server on 127.0.0.1/::1
   (tests/helpers/fake-smtp.js) with a certificate generated now. Every failure must come
   back as { passed:false, stage, smtpCode, message, hint } with a safe message: no
   password, no username, no AUTH blob, no server text beyond the reply line, and a hint
   built from the SAVED settings, never from what the server said. */

const test = require("node:test");
const { describe, before, after } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const crypto = require("crypto");
const { REPO, LIB, PORTS, mkTmp, canary, forms, authPlain } = require("./helpers/common.js");
const { startFakeSmtp } = require("./helpers/fake-smtp.js");
const { selfSigned } = require("./helpers/x509.js");

const { sendMail } = require(path.join(REPO, "smtp.js"));
const { createSmtpTester, classify, hint, recipientAllowed } = require(path.join(LIB, "smtp-test.js"));
const { createWebsiteSmtp } = require(path.join(LIB, "website-smtp.js"));
const { loadMailConfig } = require(path.join(LIB, "config.js"));

const USER = "contact@zehnox.com";
const INQUIRY = "inbox@example.com";
const cert = selfSigned({ cn: "localhost" });
let nextPort = PORTS.smtp;

/* A saved-settings store pointing at localhost:<port>. insecure: SMTP_INSECURE_TLS=1. */
async function settings(port, pass, insecure) {
  // The fake servers listen on high ports, which only an explicit port allowlist admits.
  const env = { NODE_ENV: "test", MAIL_SMTP_HOST_ALLOWLIST: "localhost", MAIL_SMTP_PORT_ALLOWLIST: String(port) };
  if (insecure) env.SMTP_INSECURE_TLS = "1";
  const { cfg } = loadMailConfig(Object.assign({}, env));
  const dir = mkTmp("smtptest");
  const key = crypto.randomBytes(32);
  const s = createWebsiteSmtp({ dir, secretsKey: key, cfg, env });
  const body = { host: "localhost", port, tlsMode: "starttls", username: USER, fromLocal: "contact", fromName: "ZEHNOX BHM" };
  if (pass) body.password = pass;
  await s.update(body, { actor: { user: "admin" }, listAddresses: async () => ({ addresses: [{ local: "contact", enabled: true }] }) });
  // The same saved files can be reopened under another config (see the allowlist test).
  return Object.assign(s, { _dir: dir, _key: key });
}

/* Runs one test against a fake server in `mode`; returns { r, log, pass }. */
async function scenario(mode, o) {
  const opts = o || {};
  const port = opts.port || nextPort++;
  const srv = opts.noServer ? null : await startFakeSmtp({ port, mode, tls: cert, echo: opts.echo });
  const pass = canary("smtp");
  try {
    const s = await settings(port, opts.noPassword ? null : pass, opts.insecure !== false);
    const tester = createSmtpTester({ smtp: s, sendMail, timeoutMs: opts.timeoutMs || 6000 });
    const r = await tester.run({ to: opts.to, inquiryRecipient: INQUIRY, enabledAddresses: ["contact@zehnox.com"], user: "admin" });
    return { r, log: srv ? srv.log : null, pass, port };
  } finally {
    if (srv) await srv.close();
  }
}

/* The message and hint never carry a credential in any form. */
function assertSafe(r, pass) {
  const text = JSON.stringify(r);
  for (const f of forms(pass).concat(forms(USER), [authPlain(USER, pass)])) assert.ok(!text.includes(f), "leaked " + f.slice(0, 8));
  assert.match(r.message, /^[\x20-\x7e]{0,200}$/);
  assert.equal(typeof r.hint === "string" || r.hint === null, true);
}

describe("SMTP test against fake servers", () => {
  test("success: sends the fixed message to an allowlisted recipient", async () => {
    const { r, log, pass } = await scenario("accept");
    assert.equal(r.passed, true);
    assert.equal(r.stage, "sent");
    assert.equal(r.message, "Sent to " + INQUIRY);
    assert.equal(log.auths.length, 1);
    assert.equal(log.auths[0].pass, pass, "the saved password was used");
    assert.equal(log.mails.length, 1);
    assert.equal(log.mails[0].from, "<contact@zehnox.com>");
    assert.deepEqual(log.mails[0].rcpt, ["<" + INQUIRY + ">"]);
    assert.match(log.mails[0].data, /Subject: ZEHNOX website email test/);
    assertSafe(r, pass);
  });

  test("unreachable host: stage connect, hint from the saved host and port", async () => {
    const { r, pass } = await scenario(null, { noServer: true, port: PORTS.closed });
    assert.equal(r.passed, false);
    assert.equal(r.stage, "connect");
    assert.equal(r.hint, "Could not connect to localhost:" + PORTS.closed + " from the server. Check the host, port and firewall.");
    assertSafe(r, pass);
  });

  test("bad auth: stage auth with the 535 code; a hostile server's echo of the credentials is scrubbed", async () => {
    const { r, log, pass } = await scenario("authfail", { echo: true });
    assert.equal(r.passed, false);
    assert.equal(r.stage, "auth");
    assert.equal(r.smtpCode, 535);
    assert.equal(log.tlsUpgrades, 1, "credentials only after STARTTLS");
    assert.equal(log.auths.length, 1);
    assert.match(r.message, /535/);
    assert.match(r.message, /\[redacted\]/, "the echoed credentials were replaced");
    assertSafe(r, pass);
  });

  test("TLS failure: plain text instead of a handshake gives stage tls; nothing is authenticated", async () => {
    const { r, log, pass } = await scenario("badtls");
    assert.equal(r.passed, false);
    assert.equal(r.stage, "tls");
    assert.equal(log.auths.length, 0);
    assert.equal(r.hint, "The server certificate is not valid for localhost. Use the mail server's real host name, not an IP.");
    assertSafe(r, pass);
  });

  test("TLS failure: an untrusted certificate with verification on gives stage tls; nothing is authenticated", async () => {
    const { r, log, pass } = await scenario("accept", { insecure: false });
    assert.equal(r.passed, false);
    assert.equal(r.stage, "tls");
    assert.equal(log.auths.length, 0, "no credentials were sent to an unverified server");
    assert.ok(!log.lines.some((l) => /^AUTH/i.test(l)));
    assertSafe(r, pass);
  });

  test("no STARTTLS offered: stage starttls; the server never receives AUTH", async () => {
    const { r, log, pass } = await scenario("nostarttls");
    assert.equal(r.stage, "starttls");
    assert.equal(log.auths.length, 0);
    assert.ok(!log.lines.some((l) => /^AUTH/i.test(l)));
    assertSafe(r, pass);
  });

  test("timeout: a server that never answers gives stage timeout", async () => {
    const started = Date.now();
    const { r, pass } = await scenario("silent", { timeoutMs: 400 });
    assert.equal(r.stage, "timeout");
    assert.equal(r.passed, false);
    assert.ok(Date.now() - started < 5000);
    assertSafe(r, pass);
  });

  test("greeting 554 and RCPT 550 are classified by stage and code", async () => {
    const g = await scenario("greet554");
    assert.equal(g.r.stage, "greeting");
    assert.equal(g.r.smtpCode, 554);
    assertSafe(g.r, g.pass);
    const rc = await scenario("rcpt550");
    assert.equal(rc.r.stage, "rcpt");
    assert.equal(rc.r.smtpCode, 550);
    assertSafe(rc.r, rc.pass);
  });

  test("recipient not allowlisted: refused before any connection", async () => {
    for (const to of ["stranger@example.com", "info@strategicbhm.com", "someone@zehnox.com", "inbox@example.com\r\nBcc: x@y.com", "a@b"]) {
      const port = nextPort++;
      const srv = await startFakeSmtp({ port, mode: "accept", tls: cert });
      try {
        const s = await settings(port, canary("rcpt"), true);
        const tester = createSmtpTester({ smtp: s, sendMail });
        await assert.rejects(tester.run({ to, inquiryRecipient: INQUIRY, enabledAddresses: ["contact@zehnox.com"], user: "admin" }),
          (e) => e.code === "recipient_not_allowed" && e.status === 400 && !e.message.includes(to.slice(0, 8)));
        assert.equal(srv.log.connections, 0, to);
      } finally {
        await srv.close();
      }
    }
    // The allowlisted set: the inquiry recipient, the From address, enabled domain addresses.
    const o = { inquiryRecipient: INQUIRY, fromAddress: "contact@zehnox.com", enabledAddresses: ["careers@zehnox.com"] };
    assert.equal(recipientAllowed("INBOX@example.com", o), true);
    assert.equal(recipientAllowed("contact@zehnox.com", o), true);
    assert.equal(recipientAllowed("careers@zehnox.com", o), true);
    assert.equal(recipientAllowed("careers@zehnox.com.evil.com", o), false);
  });

  test("a saved target that is no longer allowed is refused before any connection (no port probing)", async () => {
    const port = nextPort++;
    const srv = await startFakeSmtp({ port, mode: "accept", tls: cert });
    try {
      // Saved while this port was allowed; then the server runs without that allowance
      // (the default ports only). The test must not connect: an open or closed port would
      // otherwise be told apart by the answer's stage and timing.
      const saved = await settings(port, canary("probe"), true);
      const env = { NODE_ENV: "test", MAIL_SMTP_HOST_ALLOWLIST: "localhost", SMTP_INSECURE_TLS: "1" };
      const s = createWebsiteSmtp({ dir: saved._dir, secretsKey: saved._key, cfg: loadMailConfig(Object.assign({}, env)).cfg, env });
      await assert.rejects(createSmtpTester({ smtp: s, sendMail }).run({ inquiryRecipient: INQUIRY, enabledAddresses: [], user: "admin" }),
        (e) => e.code === "port_not_allowed" && e.status === 400);
      // And a host that left the allowlist.
      const env2 = { NODE_ENV: "test", MAIL_SMTP_HOST_ALLOWLIST: "mail.example.net", MAIL_SMTP_PORT_ALLOWLIST: String(port), SMTP_INSECURE_TLS: "1" };
      const s2 = createWebsiteSmtp({ dir: saved._dir, secretsKey: saved._key, cfg: loadMailConfig(Object.assign({}, env2)).cfg, env: env2 });
      await assert.rejects(createSmtpTester({ smtp: s2, sendMail }).run({ inquiryRecipient: INQUIRY, enabledAddresses: [], user: "admin" }),
        (e) => e.code === "host_not_allowed" && e.status === 400);
      assert.equal(srv.log.connections, 0);
    } finally {
      await srv.close();
    }
  });

  test("not configured (no password): stage config, no connection", async () => {
    const port = nextPort++;
    const srv = await startFakeSmtp({ port, mode: "accept", tls: cert });
    try {
      const s = await settings(port, null, true);
      const r = await createSmtpTester({ smtp: s, sendMail }).run({ inquiryRecipient: INQUIRY, enabledAddresses: [] });
      assert.equal(r.stage, "config");
      assert.equal(srv.log.connections, 0);
    } finally {
      await srv.close();
    }
  });
});

test("classify: uses err.stage/err.smtpCode when present, else codes and smtp.js's own phrases", () => {
  const e = (props, msg) => Object.assign(new Error(msg || "x"), props);
  assert.deepEqual(classify(e({ stage: "auth", smtpCode: 535 })), { stage: "auth", smtpCode: 535 });
  assert.deepEqual(classify(e({ stage: "mail_from", smtpCode: 553 })), { stage: "mail_from", smtpCode: 553 });
  assert.deepEqual(classify(e({ stage: "rcpt", smtpCode: 550 })), { stage: "rcpt", smtpCode: 550 });
  assert.equal(classify(e({ stage: "rm -rf /" })).stage, "unknown");
  assert.equal(classify(e({ code: "ENOTFOUND" })).stage, "dns");
  assert.equal(classify(e({ code: "ECONNREFUSED" })).stage, "connect");
  assert.equal(classify(e({ code: "DEPTH_ZERO_SELF_SIGNED_CERT" })).stage, "tls");
  assert.equal(classify(e({ code: "ERR_TLS_CERT_ALTNAME_INVALID" })).stage, "tls");
  assert.equal(classify(e({ code: 553 }, "SMTP MAIL FROM rejected: 553 not yours")).stage, "mail_from");
  assert.equal(classify(e({}, "SMTP session timed out after 400ms")).stage, "timeout");
  assert.equal(classify(null).stage, "unknown");
  // Hints are constants plus the stored host/port: the server's text never reaches them.
  assert.equal(hint("dns", { host: "mail.example.net", port: 587 }), "The host name mail.example.net could not be resolved.");
  assert.equal(hint("anything-else"), "The SMTP test failed.");
});
