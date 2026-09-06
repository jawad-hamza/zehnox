"use strict";
/* End-to-end: a real POST /api/contact against a real server process must both store the
   inquiry and email it through the relay. Run: node tools/test-contact-email.js

   The relay is the fake server from fake-smtp.js listening on localhost, so nothing
   leaves the machine. */

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const { makeCert, fakeServer, decodeMessage } = require("./fake-smtp.js");

const ROOT = path.join(__dirname, "..");
const INQUIRIES = path.join(ROOT, "data", "inquiries.json");
const PORT = 3112;
const base = "http://127.0.0.1:" + PORT;

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log("  ok   " + name); }
  catch (e) { failed++; console.error("  FAIL " + name + "\n       " + (e && e.stack ? e.stack.split("\n").slice(0, 3).join("\n       ") : e)); }
}

const waitFor = async (predicate, ms, what) => {
  const until = Date.now() + ms;
  while (Date.now() < until) { if (predicate()) return; await new Promise((r) => setTimeout(r, 50)); }
  throw new Error("timed out waiting for " + what);
};

(async () => {
  let creds;
  try { creds = makeCert(); }
  catch (e) { console.log("SKIP — openssl unavailable (" + e.message + ")"); return; }

  const relay = await fakeServer(creds);
  const inquiriesBackup = fs.existsSync(INQUIRIES) ? fs.readFileSync(INQUIRIES) : null;

  const server = spawn(process.execPath, ["server.js", String(PORT)], {
    cwd: ROOT,
    stdio: ["ignore", "pipe", "pipe"],
    env: Object.assign({}, process.env, {
      SMTP_HOST: "127.0.0.1",
      SMTP_PORT: String(relay.port),
      SMTP_USER: "info@zehnox.com",
      SMTP_PASS: "s3cret",
      SMTP_FROM: "info@zehnox.com",
      SMTP_INSECURE_TLS: "1",   // the fake relay uses a self-signed certificate
    }),
  });
  let serverLog = "";
  server.stdout.on("data", (d) => { serverLog += d; });
  server.stderr.on("data", (d) => { serverLog += d; });

  const cleanup = () => {
    try { server.kill(); } catch (_) { /* already gone */ }
    relay.close();
    if (inquiriesBackup) fs.writeFileSync(INQUIRIES, inquiriesBackup);
  };

  try {
    await waitFor(() => /listening|http:\/\//i.test(serverLog), 15000, "the server to start").catch(async () => {
      // Older builds may not log a ready line; fall back to probing the port.
      await waitFor(async () => { try { await fetch(base + "/api/me"); return true; } catch (_) { return false; } }, 5000, "the port to open");
    });
    for (let i = 0; i < 100; i++) {
      try { await fetch(base + "/api/me"); break; } catch (_) { await new Promise((r) => setTimeout(r, 100)); }
    }

    await test("the shipped form posts to /api/contact when no endpoint is configured", async () => {
      // The regression this guards: with the fallback missing, an empty site.contactEndpoint
      // skipped the POST entirely and went straight to WhatsApp, losing every enquiry.
      const js = fs.readFileSync(path.join(ROOT, "dist", "js", "site.js"), "utf8");
      const m = /const endpoint = [^;]+;/.exec(js);
      assert.ok(m, "could not find the endpoint resolution in dist/js/site.js");
      assert.ok(m[0].includes('"/api/contact"'), "endpoint must fall back to /api/contact, got: " + m[0]);

      const content = JSON.parse(fs.readFileSync(path.join(ROOT, "content.json"), "utf8"));
      assert.strictEqual(content.site.contactEndpoint, "", "content.json should leave contactEndpoint empty so the default applies");
    });

    await test("a contact submission is stored and emailed", async () => {
      const inquiry = {
        name: "Bob Example",
        email: "bob@example.com",
        phone: "03001234567",
        company: "Example Ltd",
        iam: "A business owner",
        method: "Email",
        services: ["AI Automation", "Web & Digital"],
        page: "/contact/",
        brief: "We would like to automate our order intake process end to end.",
      };
      const res = await fetch(base + "/api/contact", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(inquiry),
      });
      const body = await res.json();
      assert.strictEqual(res.status, 201, "expected 201, got " + res.status + " " + JSON.stringify(body));

      // stored copy
      const stored = JSON.parse(fs.readFileSync(INQUIRIES, "utf8"));
      assert.ok(stored.some((r) => r.id === body.id && r.email === "bob@example.com"), "inquiry was not stored");

      // emailed copy
      await waitFor(() => relay.seen.messages > 0, 15000, "the relay to receive a message");
      assert.strictEqual(relay.seen.mailFrom, "info@zehnox.com");
      assert.deepStrictEqual(relay.seen.rcptTo, ["info@zehnox.com"], "should use site.inquiryEmail from content.json");

      const { head, body: text } = decodeMessage(relay.seen.data);
      assert.ok(/^Subject: New inquiry from Bob Example \(Example Ltd\)$/im.test(head), head);
      assert.ok(/^Reply-To: "Bob Example" <bob@example\.com>$/im.test(head), "Reply-To must point at the inquirer");
      assert.ok(text.includes("We would like to automate our order intake process"), "brief missing from body");
      assert.ok(text.includes("AI Automation, Web & Digital"), "services missing from body");
      assert.ok(text.includes(body.id), "reference id missing from body");
    });

    await test("a form submission cannot inject mail headers", async () => {
      const before = relay.seen.messages;
      const res = await fetch(base + "/api/contact", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: "Mallory\r\nBcc: victim@example.com",
          email: "mallory@example.com",
          brief: "This brief is definitely long enough to pass validation checks.",
        }),
      });
      assert.strictEqual(res.status, 201, "expected 201, got " + res.status);
      await waitFor(() => relay.seen.messages > before, 15000, "the second message");

      const { head } = decodeMessage(relay.seen.mail[relay.seen.mail.length - 1]);
      assert.ok(!/^Bcc:/im.test(head), "header injection reached the message:\n" + head);
      assert.deepStrictEqual(relay.seen.rcptTo, ["info@zehnox.com", "info@zehnox.com"], "no extra recipient may be added");
    });

    await test("the server logged the send rather than an error", async () => {
      assert.ok(/emailed to info@zehnox\.com/.test(serverLog), "expected a success log line, got:\n" + serverLog.slice(-800));
      assert.ok(!/inquiry email failed/.test(serverLog), "server reported a send failure:\n" + serverLog.slice(-800));
    });
  } finally {
    cleanup();
  }

  console.log((failed ? "FAILED " : "") + passed + " passed, " + failed + " failed");
  process.exitCode = failed ? 1 : 0;
  setTimeout(() => process.exit(process.exitCode), 200);
})();
