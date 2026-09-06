"use strict";
/* A fake SMTP submission server for tests: speaks the same STARTTLS + SASL handshake as
   the Postfix relay at mail.zehnox.com, and records what it was told. Shared by
   tools/test-smtp.js and tools/test-contact-email.js. */

const net = require("net");
const tls = require("tls");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const CRLF = "\r\n";
const NUL = String.fromCharCode(0);

/* Generated per run rather than committed, so there is no certificate to expire. */
function makeCert() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zx-smtp-cert-"));
  const key = path.join(dir, "key.pem"), cert = path.join(dir, "cert.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert,
    "-days", "3650", "-nodes", "-subj", "/CN=localhost"], { stdio: "ignore" });
  const pair = { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
  fs.rmSync(dir, { recursive: true, force: true });
  return pair;
}

/* opts: { authMechs, offerStartTls, failAuth, onMessage } */
function fakeServer(creds, opts) {
  const o = Object.assign({ authMechs: "PLAIN LOGIN", offerStartTls: true, failAuth: false, onMessage: null }, opts);
  // `mail` holds every message received; `data` is the most recent one, which is all the
  // single-message tests need.
  const seen = { mailFrom: null, rcptTo: [], data: "", mail: [], authUser: null, authPass: null, secured: false, messages: 0 };

  const server = net.createServer((plain) => {
    // TLS state is per connection: a second submission opens a fresh socket and must be
    // offered STARTTLS again, exactly as Postfix would.
    let sock = plain, buf = "", inData = false, loginStage = null, isSecure = false, current = "";
    const write = (s) => sock.write(s + CRLF);
    const ehlo = () => {
      const lines = ["250-fake.test", "250-PIPELINING", "250-SIZE 10240000"];
      if (!isSecure && o.offerStartTls) lines.push("250-STARTTLS");
      if (isSecure) lines.push("250-AUTH " + o.authMechs);
      lines.push("250 8BITMIME");
      sock.write(lines.join(CRLF) + CRLF);
    };

    const onLine = (line) => {
      if (inData) {
        if (line === ".") {
          inData = false;
          seen.data = current;
          seen.mail.push(current);
          current = "";
          seen.messages++;
          write("250 2.0.0 Ok: queued as FAKE1");
          if (o.onMessage) o.onMessage(seen);
          return;
        }
        current += (line.startsWith("..") ? line.slice(1) : line) + "\n";
        return;
      }
      if (loginStage === "user") { seen.authUser = Buffer.from(line, "base64").toString("utf8"); loginStage = "pass"; write("334 UGFzc3dvcmQ6"); return; }
      if (loginStage === "pass") {
        seen.authPass = Buffer.from(line, "base64").toString("utf8"); loginStage = null;
        return write(o.failAuth ? "535 5.7.8 Error: authentication failed" : "235 2.7.0 Authentication successful");
      }

      const upper = line.toUpperCase();
      if (upper.startsWith("EHLO") || upper.startsWith("HELO")) return ehlo();
      if (upper === "STARTTLS") {
        if (!o.offerStartTls) return write("502 5.5.1 Error: command not implemented");
        write("220 2.0.0 Ready to start TLS");
        const secure = new tls.TLSSocket(plain, { isServer: true, secureContext: tls.createSecureContext(creds) });
        sock = secure; isSecure = true; seen.secured = true; buf = "";
        secure.on("data", onData);
        secure.on("error", () => {});
        return;
      }
      if (upper.startsWith("AUTH PLAIN")) {
        // SASL PLAIN is authzid NUL authcid NUL password — NUL-separated, not space-separated.
        const parts = Buffer.from(line.slice("AUTH PLAIN".length).trim(), "base64").toString("utf8").split(NUL);
        seen.authUser = parts[1]; seen.authPass = parts[2];
        return write(o.failAuth ? "535 5.7.8 Error: authentication failed" : "235 2.7.0 Authentication successful");
      }
      if (upper === "AUTH LOGIN") { loginStage = "user"; return write("334 VXNlcm5hbWU6"); }
      if (upper.startsWith("MAIL FROM")) { seen.mailFrom = /<([^>]*)>/.exec(line)[1]; return write("250 2.1.0 Ok"); }
      if (upper.startsWith("RCPT TO")) { seen.rcptTo.push(/<([^>]*)>/.exec(line)[1]); return write("250 2.1.5 Ok"); }
      if (upper === "DATA") { inData = true; return write("354 End data with <CR><LF>.<CR><LF>"); }
      if (upper === "QUIT") { write("221 2.0.0 Bye"); return sock.end(); }
      write("500 5.5.2 Unrecognized command");
    };

    const onData = (chunk) => {
      buf += chunk.toString("utf8");
      let i;
      while ((i = buf.indexOf(CRLF)) !== -1) { const line = buf.slice(0, i); buf = buf.slice(i + 2); onLine(line); }
    };

    plain.on("data", onData);
    plain.on("error", () => {});
    write("220 fake.test ESMTP ready");
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ port: server.address().port, seen, close: () => server.close() }));
  });
}

/* The message body arrives base64-encoded; give tests the readable form back. */
function decodeMessage(raw) {
  const [head, body] = String(raw).split("\n\n");
  return { head: head || "", body: Buffer.from(String(body || "").replace(/\n/g, ""), "base64").toString("utf8") };
}

module.exports = { makeCert, fakeServer, decodeMessage };
