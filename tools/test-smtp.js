"use strict";
/* Tests for the SMTP client — run: node tools/test-smtp.js
   Add --live to also send one real message through the configured relay:
     SMTP_USER=info@zehnox.com SMTP_PASS=... node tools/test-smtp.js --live you@example.com

   The offline tests spin up a fake SMTP server that speaks the same STARTTLS + SASL
   handshake as Postfix, so the whole conversation is exercised without touching the
   network. */

const assert = require("assert");
const fs = require("fs");

const smtp = require("../smtp.js");
const { makeCert, fakeServer } = require("./fake-smtp.js");

const CRLF = "\r\n";
let passed = 0, failed = 0;

async function test(name, fn) {
  try { await fn(); passed++; console.log("  ok   " + name); }
  catch (e) { failed++; console.error("  FAIL " + name + "\n       " + (e && e.stack ? e.stack.split("\n").slice(0, 3).join("\n       ") : e)); }
}
/* the fake relay and its certificate live in tools/fake-smtp.js */

const baseSend = (port, extra) => Object.assign({
  host: "127.0.0.1", port, clientName: "test.local",
  user: "info@zehnox.com", pass: "s3cret",
  from: "info@zehnox.com", to: ["info@zehnox.com"],
  subject: "Hello", text: "Body line",
  rejectUnauthorized: false, timeoutMs: 8000,
}, extra);

/* ---------- pure-function tests ---------- */

(async () => {
  console.log("pure functions");

  await test("sanitizeHeader strips CR/LF so headers cannot be injected", () => {
    assert.strictEqual(smtp.sanitizeHeader("Bob\r\nBcc: victim@example.com"), "Bob Bcc: victim@example.com");
    assert.strictEqual(smtp.sanitizeHeader("a\nb"), "a b");
    assert.ok(!smtp.sanitizeHeader("x\r\ny").includes("\n"));
  });

  await test("encodeHeaderWord leaves ASCII alone and base64s the rest", () => {
    assert.strictEqual(smtp.encodeHeaderWord("New inquiry from Bob"), "New inquiry from Bob");
    const encoded = smtp.encodeHeaderWord("Café — Zehnox");
    assert.ok(/^=\?UTF-8\?B\?.+\?=$/.test(encoded), encoded);
    assert.strictEqual(Buffer.from(encoded.slice(10, -2), "base64").toString("utf8"), "Café — Zehnox");
  });

  await test("isEmail accepts real addresses and rejects injection attempts", () => {
    for (const good of ["info@zehnox.com", "a.b-c+tag@sub.example.co.uk"]) assert.ok(smtp.isEmail(good), good);
    for (const bad of ["", "no-at-sign", "a@b", "a b@c.com", "a@c.com\r\nBcc: x@y.com", "<a@b.com>", "a@b.com, c@d.com"]) {
      assert.ok(!smtp.isEmail(bad), "should reject: " + JSON.stringify(bad));
    }
  });

  await test("dotStuff doubles leading dots so DATA cannot end early", () => {
    assert.strictEqual(smtp.dotStuff("a\r\n.\r\nb"), "a\r\n..\r\nb");
    assert.strictEqual(smtp.dotStuff(".hidden"), "..hidden");
    assert.strictEqual(smtp.dotStuff("no dots here"), "no dots here");
  });

  await test("base64Body wraps at 76 chars and round-trips UTF-8", () => {
    const text = "ü".repeat(500);
    const body = smtp.base64Body(text);
    for (const line of body.split(CRLF)) assert.ok(line.length <= 76, "line too long: " + line.length);
    assert.strictEqual(Buffer.from(body.replace(/\r\n/g, ""), "base64").toString("utf8"), text);
  });

  await test("parseAuthMechanisms reads the EHLO capability list", () => {
    assert.deepStrictEqual(smtp.parseAuthMechanisms("250-mail.zehnox.com\n250-AUTH PLAIN LOGIN\n250 CHUNKING"), ["PLAIN", "LOGIN"]);
    assert.deepStrictEqual(smtp.parseAuthMechanisms("250 CHUNKING"), []);
  });

  await test("buildMessage cannot be tricked into extra headers by form input", () => {
    const msg = smtp.buildMessage({
      from: "info@zehnox.com", to: ["info@zehnox.com"],
      replyTo: "attacker@evil.com", replyToName: "Bob\r\nBcc: victim@example.com",
      subject: "Hi\r\nX-Injected: yes", text: "hello",
      date: new Date(Date.UTC(2026, 0, 2, 3, 4, 5)), messageId: "<fixed@zehnox.com>",
    });
    const [head, body] = msg.split(CRLF + CRLF);
    const headerLines = head.split(CRLF);
    // The injected text may survive as literal characters inside the Subject value; what
    // must never happen is it becoming a header line of its own.
    assert.ok(!headerLines.some((l) => /^X-Injected:/i.test(l)), "subject injection created a new header line");
    assert.ok(!headerLines.some((l) => /^Bcc:/i.test(l)), "Reply-To name injection created a Bcc header");
    assert.strictEqual(headerLines.filter((l) => /^Subject:/i.test(l)).length, 1);
    assert.ok(headerLines.includes("Subject: Hi X-Injected: yes"), "subject should be flattened onto one line");
    assert.ok(head.includes("Date: Fri, 02 Jan 2026 03:04:05 +0000"), head);
    assert.ok(head.includes("Reply-To:"), "Reply-To should be present");
    assert.strictEqual(Buffer.from(body.replace(/\r\n/g, ""), "base64").toString("utf8"), "hello");
  });

  await test("buildMessage omits Reply-To when the address is not usable", () => {
    const msg = smtp.buildMessage({ from: "info@zehnox.com", to: ["info@zehnox.com"], replyTo: "not-an-email", subject: "s", text: "t" });
    assert.ok(!/^Reply-To:/im.test(msg.split(CRLF + CRLF)[0]));
  });

  /* ---------- conversation tests ---------- */

  console.log("SMTP conversation (fake server)");
  let creds;
  try { creds = makeCert(); }
  catch (e) { console.log("  SKIP conversation tests — openssl unavailable (" + e.message + ")"); }

  if (creds) {
    await test("full STARTTLS + AUTH PLAIN handshake delivers the message", async () => {
      const srv = await fakeServer(creds);
      try {
        await smtp.sendMail(baseSend(srv.port, {
          subject: "New inquiry", text: "Name: Bob\nEmail: bob@example.com",
          replyTo: "bob@example.com", replyToName: "Bob",
        }));
        assert.ok(srv.seen.secured, "server never saw a TLS upgrade");
        assert.strictEqual(srv.seen.authUser, "info@zehnox.com");
        assert.strictEqual(srv.seen.authPass, "s3cret");
        assert.strictEqual(srv.seen.mailFrom, "info@zehnox.com");
        assert.deepStrictEqual(srv.seen.rcptTo, ["info@zehnox.com"]);
        const [head, body] = srv.seen.data.split("\n\n");
        assert.ok(/^Reply-To: "Bob" <bob@example.com>$/im.test(head), head);
        assert.strictEqual(Buffer.from(body.replace(/\n/g, ""), "base64").toString("utf8"), "Name: Bob\nEmail: bob@example.com");
      } finally { srv.close(); }
    });

    await test("falls back to AUTH LOGIN when PLAIN is not offered", async () => {
      const srv = await fakeServer(creds, { authMechs: "LOGIN" });
      try {
        await smtp.sendMail(baseSend(srv.port));
        assert.strictEqual(srv.seen.authUser, "info@zehnox.com");
        assert.strictEqual(srv.seen.authPass, "s3cret");
      } finally { srv.close(); }
    });

    await test("refuses to send credentials when STARTTLS is not offered", async () => {
      const srv = await fakeServer(creds, { offerStartTls: false });
      try {
        await assert.rejects(smtp.sendMail(baseSend(srv.port)), /STARTTLS/);
        assert.strictEqual(srv.seen.authUser, null, "credentials must not be sent in the clear");
      } finally { srv.close(); }
    });

    await test("surfaces an authentication failure instead of silently succeeding", async () => {
      const srv = await fakeServer(creds, { failAuth: true });
      try {
        await assert.rejects(smtp.sendMail(baseSend(srv.port)), /authentication rejected/i);
        assert.strictEqual(srv.seen.mailFrom, null, "must not proceed to MAIL FROM after failed auth");
      } finally { srv.close(); }
    });

    await test("a body line of a single dot does not truncate the message", async () => {
      const srv = await fakeServer(creds);
      try {
        const text = "before\n.\nafter";
        await smtp.sendMail(baseSend(srv.port, { text }));
        const body = srv.seen.data.split("\n\n")[1];
        assert.strictEqual(Buffer.from(body.replace(/\n/g, ""), "base64").toString("utf8"), text);
      } finally { srv.close(); }
    });

    await test("rejects an invalid recipient before opening a connection", async () => {
      await assert.rejects(smtp.sendMail(baseSend(1, { to: ["nope\r\nBcc: x@y.com"] })), /invalid recipient/);
    });
  }

  /* ---------- optional live send ---------- */

  const liveIdx = process.argv.indexOf("--live");
  if (liveIdx !== -1) {
    const to = process.argv[liveIdx + 1] || process.env.SMTP_FROM || "info@zehnox.com";
    console.log("live send -> " + to);
    await test("sends a real message through the configured relay", async () => {
      await smtp.sendMail({
        host: process.env.SMTP_HOST || "mail.zehnox.com",
        port: Number(process.env.SMTP_PORT) || 587,
        user: process.env.SMTP_USER, pass: process.env.SMTP_PASS,
        from: process.env.SMTP_FROM || "info@zehnox.com",
        fromName: "ZEHNOX website",
        to: [to],
        subject: "ZEHNOX SMTP test " + new Date().toISOString(),
        text: "If you are reading this, the website can send mail through mail.zehnox.com.",
        rejectUnauthorized: process.env.SMTP_INSECURE_TLS !== "1",
      });
    });
  }

  console.log((failed ? "FAILED " : "") + passed + " passed, " + failed + " failed");
  process.exitCode = failed ? 1 : 0;
})();
