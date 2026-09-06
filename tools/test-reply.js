"use strict";
/* Tests for replying to an enquiry, read/unread and CSV export.
   Run: node tools/test-reply.js

   Writes a known admin credential into data/ for the duration of the run and restores the
   real one afterwards, so the suite does not depend on whatever password this machine has. */

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const { makeCert, fakeServer, decodeMessage } = require("./fake-smtp.js");

const ROOT = path.join(__dirname, "..");
const DATA = path.join(ROOT, "data");
const AUTH = path.join(DATA, "admin-auth.json");
const INQUIRIES = path.join(DATA, "inquiries.json");
const USER = "admin", PASS = "test-password-123";

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log("  ok   " + name); }
  catch (e) { failed++; console.error("  FAIL " + name + "\n       " + (e && e.message ? e.message : e)); }
}

const waitFor = async (pred, ms, what) => {
  const until = Date.now() + ms;
  while (Date.now() < until) { if (pred()) return; await new Promise((r) => setTimeout(r, 50)); }
  throw new Error("timed out waiting for " + what);
};

function startServer(port, env) {
  const s = spawn(process.execPath, ["server.js", String(port)], {
    cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
    env: Object.assign({}, process.env, env),
  });
  s.log = "";
  s.stdout.on("data", (d) => { s.log += d; });
  s.stderr.on("data", (d) => { s.log += d; });
  return s;
}

const ready = async (base) => {
  for (let i = 0; i < 120; i++) {
    try { await fetch(base + "/api/me"); return; } catch (_) { await new Promise((r) => setTimeout(r, 100)); }
  }
  throw new Error("server never came up at " + base);
};

(async () => {
  let creds;
  try { creds = makeCert(); }
  catch (e) { console.log("SKIP — openssl unavailable (" + e.message + ")"); return; }

  const authBackup = fs.existsSync(AUTH) ? fs.readFileSync(AUTH) : null;
  const inqBackup = fs.existsSync(INQUIRIES) ? fs.readFileSync(INQUIRIES) : null;

  // Same derivation the server uses, so the known password verifies.
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(PASS, salt, 64, { N: 16384, r: 8, p: 1 }).toString("hex");
  fs.writeFileSync(AUTH, JSON.stringify({ username: USER, salt, hash, updatedAt: new Date().toISOString() }, null, 2) + "\n");
  fs.writeFileSync(INQUIRIES, "[]\n");

  const relay = await fakeServer(creds);
  const PORT = 3116, base = "http://127.0.0.1:" + PORT;
  const server = startServer(PORT, {
    SMTP_HOST: "127.0.0.1", SMTP_PORT: String(relay.port),
    SMTP_USER: "info@zehnox.com", SMTP_PASS: "s3cret",
    SMTP_FROM: "info@zehnox.com", SMTP_INSECURE_TLS: "1",
  });
  const BARE_PORT = 3117, bareBase = "http://127.0.0.1:" + BARE_PORT;
  const bare = startServer(BARE_PORT, { SMTP_USER: "", SMTP_PASS: "" });

  const cleanup = () => {
    try { server.kill(); } catch (_) { /* gone */ }
    try { bare.kill(); } catch (_) { /* gone */ }
    relay.close();
    if (authBackup) fs.writeFileSync(AUTH, authBackup); else try { fs.unlinkSync(AUTH); } catch (_) { /* none */ }
    if (inqBackup) fs.writeFileSync(INQUIRIES, inqBackup);
  };

  try {
    await ready(base);
    await ready(bareBase);

    const login = await (await fetch(base + "/api/login", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: USER, password: PASS }),
    })).json();
    assert.ok(login.ok, "login failed: " + JSON.stringify(login));
    const auth = { "Content-Type": "application/json", Authorization: "Bearer " + login.session };

    const submit = async (over) => {
      const res = await fetch(base + "/api/contact", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.assign({
          name: "Bob Example", email: "bob@example.com", phone: "03001234567",
          company: "Example Ltd", iam: "A business owner", method: "Email",
          services: ["AI Automation"], page: "/contact",
          brief: "We would like to automate our order intake process end to end.",
        }, over)),
      });
      const body = await res.json();
      assert.strictEqual(res.status, 201, "submit failed: " + JSON.stringify(body));
      return body.id;
    };

    const normalId = await submit({});
    const dangerousId = await submit({ name: "=cmd|' /C calc'!A0", email: "mallory@example.com" });
    await waitFor(() => relay.seen.messages >= 2, 15000, "the forwarding emails");

    await test("a reply is emailed to the enquirer and stored on the record", async () => {
      const before = relay.seen.messages;
      const res = await fetch(base + "/api/inquiries/" + normalId + "/reply", {
        method: "POST", headers: auth,
        body: JSON.stringify({ subject: "Re: your enquiry", message: "Thanks Bob — we can help.\nLet's talk Tuesday." }),
      });
      const body = await res.json();
      assert.strictEqual(res.status, 200, JSON.stringify(body));
      await waitFor(() => relay.seen.messages > before, 15000, "the reply to be sent");

      const { head, body: text } = decodeMessage(relay.seen.mail[relay.seen.mail.length - 1]);
      assert.ok(/^To: <bob@example\.com>$/im.test(head), "reply must go to the enquirer:\n" + head);
      assert.ok(/^From: "ZEHNOX" <info@zehnox\.com>$/im.test(head), "wrong From:\n" + head);
      assert.ok(/^Reply-To: .*<info@zehnox\.com>$/im.test(head), "their answer must come back to the shared inbox:\n" + head);
      assert.ok(/^Subject: Re: your enquiry$/im.test(head), head);
      assert.ok(text.includes("Thanks Bob — we can help."), "reply text missing");
      assert.ok(text.includes("> We would like to automate"), "original enquiry should be quoted");

      const list = await (await fetch(base + "/api/inquiries", { headers: auth })).json();
      const rec = list.find((q) => q.id === normalId);
      assert.strictEqual(rec.replies.length, 1, "reply not stored");
      assert.strictEqual(rec.replies[0].by, USER);
      assert.strictEqual(rec.read, true, "replying should mark the enquiry read");
    });

    await test("an empty reply and an unknown enquiry are rejected", async () => {
      const empty = await fetch(base + "/api/inquiries/" + normalId + "/reply", {
        method: "POST", headers: auth, body: JSON.stringify({ message: "   " }),
      });
      assert.strictEqual(empty.status, 400, "empty reply should be rejected");
      const missing = await fetch(base + "/api/inquiries/does-not-exist/reply", {
        method: "POST", headers: auth, body: JSON.stringify({ message: "hello" }),
      });
      assert.strictEqual(missing.status, 404, "unknown id should 404");
    });

    await test("replying requires a session", async () => {
      const res = await fetch(base + "/api/inquiries/" + normalId + "/reply", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: "hello" }),
      });
      assert.strictEqual(res.status, 401, "unauthenticated reply returned " + res.status);
    });

    await test("a server with no SMTP configured says so instead of faking success", async () => {
      const login2 = await (await fetch(bareBase + "/api/login", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: USER, password: PASS }),
      })).json();
      assert.ok(login2.ok, "login on the bare server failed");
      const res = await fetch(bareBase + "/api/inquiries/" + normalId + "/reply", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + login2.session },
        body: JSON.stringify({ message: "hello" }),
      });
      assert.strictEqual(res.status, 503, "expected 503, got " + res.status);
      const body = await res.json();
      assert.ok(/not set up/i.test(body.error), "unhelpful error: " + body.error);
    });

    await test("read and unread can be toggled", async () => {
      const set = async (read) => {
        const res = await fetch(base + "/api/inquiries/" + dangerousId, {
          method: "PATCH", headers: auth, body: JSON.stringify({ read }),
        });
        assert.strictEqual(res.status, 200, "PATCH returned " + res.status);
        return (await res.json()).read;
      };
      assert.strictEqual(await set(true), true);
      assert.strictEqual(await set(false), false);
      const bad = await fetch(base + "/api/inquiries/" + dangerousId, {
        method: "PATCH", headers: auth, body: JSON.stringify({ read: "yes" }),
      });
      assert.strictEqual(bad.status, 400, "a non-boolean should be rejected");
    });

    await test("the CSV export is well formed and neutralises spreadsheet formulas", async () => {
      const res = await fetch(base + "/api/inquiries.csv", { headers: { Authorization: "Bearer " + login.session } });
      assert.strictEqual(res.status, 200);
      assert.ok(/text\/csv/.test(res.headers.get("content-type")), "wrong content type");
      assert.ok(/attachment; filename=/.test(res.headers.get("content-disposition") || ""), "should download as a file");
      // Check the bytes, not res.text() — UTF-8 decoding strips a leading BOM.
      const bytes = Buffer.from(await res.arrayBuffer());
      assert.deepStrictEqual([...bytes.subarray(0, 3)], [0xEF, 0xBB, 0xBF], "missing the BOM Excel needs to read UTF-8");
      const csv = bytes.toString("utf8").replace(/^\uFEFF/, "");
      const lines = csv.split("\r\n");
      assert.ok(lines[0].startsWith("receivedAt,name,email"), "unexpected header: " + lines[0]);
      // The name began with "=", which Excel would otherwise execute. It gains a leading
      // apostrophe; it needs no quoting, since it holds no comma, quote or newline.
      const nameCell = lines.find((l) => l.includes("mallory@example.com")).split(",")[1];
      assert.ok(nameCell.startsWith("'="), "formula cell was not neutralised: " + nameCell);
      assert.ok(!/(^|,)=cmd/.test(csv), "a raw formula cell survived:\n" + csv);
      assert.ok(csv.includes("bob@example.com"), "the enquiry is missing from the export");
    });

    await test("the CSV export requires a session", async () => {
      const res = await fetch(base + "/api/inquiries.csv");
      assert.strictEqual(res.status, 401, "unauthenticated export returned " + res.status);
    });
  } finally {
    cleanup();
  }

  console.log((failed ? "FAILED " : "") + passed + " passed, " + failed + " failed");
  process.exitCode = failed ? 1 : 0;
  setTimeout(() => process.exit(process.exitCode), 200);
})();
