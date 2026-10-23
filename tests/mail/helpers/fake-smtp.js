"use strict";
/* A scriptable fake SMTP submission server on node:net (+ node:tls after STARTTLS).

   startFakeSmtp({ port, mode, tls: {key, cert}, ... }) -> { port, log, close(), setMode() }

   It speaks just enough of RFC 5321 / 3207 / 4954 for smtp.js: greeting, EHLO, STARTTLS,
   EHLO again, AUTH PLAIN or LOGIN, MAIL FROM, RCPT TO, DATA, QUIT. `mode` picks a failure:
     accept       everything succeeds (default)
     silent       accepts the connection and never says anything (timeout)
     greet554     "554 go away" as the greeting
     nostarttls   EHLO without STARTTLS (credentials must never be sent)
     badtls       answers STARTTLS with 220, then writes plain text instead of a handshake
     authfail     535 to AUTH; with echo:true the reply repeats the credentials it received
                  (a hostile server), to prove the client scrubs them
     rcpt550      550 to RCPT TO
   Everything received is logged (lines, auths with the decoded user/pass, mails), so a
   test can assert what did and did not reach the wire. It never relays anything. */

const net = require("net");
const tls = require("tls");

function startFakeSmtp(opts) {
  const o = opts || {};
  const log = { connections: 0, lines: [], auths: [], mails: [], tlsUpgrades: 0 };
  let mode = o.mode || "accept";
  const sockets = new Set();

  const server = net.createServer((raw) => {
    log.connections++;
    sockets.add(raw);
    raw.on("close", () => sockets.delete(raw));
    raw.on("error", () => {});
    if (mode === "silent") return; // say nothing, ever
    let sock = raw;
    let secure = false;
    let buf = "";
    let inData = false;
    let data = "";
    let authLogin = null; // AUTH LOGIN state
    let cur = { from: null, rcpt: [] };
    const w = (line) => { try { sock.write(line + "\r\n"); } catch (_) { /* closed */ } };

    const onLine = (line) => {
      log.lines.push(line);
      if (inData) {
        if (line === ".") { inData = false; log.mails.push({ from: cur.from, rcpt: cur.rcpt, data }); cur = { from: null, rcpt: [] }; w("250 2.0.0 queued as FAKE"); return; }
        data += line + "\n";
        return;
      }
      if (authLogin) {
        const v = Buffer.from(line.trim(), "base64").toString("utf8");
        if (authLogin.step === 1) { authLogin.user = v; authLogin.step = 2; w("334 UGFzc3dvcmQ6"); return; }
        log.auths.push({ mech: "LOGIN", user: authLogin.user, pass: v, blob: null });
        authLogin = null;
        return mode === "authfail" ? w("535 5.7.8 Authentication credentials invalid") : w("235 2.7.0 ok");
      }
      const u = line.toUpperCase();
      if (u.startsWith("EHLO") || u.startsWith("HELO")) {
        w("250-fake.smtp.test");
        if (!secure && mode !== "nostarttls") w("250-STARTTLS");
        if (secure || mode === "nostarttls") w("250-AUTH PLAIN LOGIN");
        w("250 8BITMIME");
      } else if (u === "STARTTLS") {
        w("220 2.0.0 ready to start TLS");
        if (mode === "badtls") { setTimeout(() => { try { raw.write("THIS IS NOT A TLS HANDSHAKE\r\n\r\n"); raw.end(); } catch (_) { /* closed */ } }, 20); return; }
        raw.removeAllListeners("data");
        const t = new tls.TLSSocket(raw, { isServer: true, key: o.tls.key, cert: o.tls.cert });
        t.on("error", () => {});
        t.on("data", onData);
        sock = t;
        secure = true;
        buf = "";
        log.tlsUpgrades++;
      } else if (u.startsWith("AUTH PLAIN")) {
        const blob = line.slice(10).trim();
        const parts = Buffer.from(blob, "base64").toString("utf8").split("\0");
        log.auths.push({ mech: "PLAIN", user: parts[1], pass: parts[2], blob });
        if (mode === "authfail") w("535 5.7.8 Authentication failed" + (o.echo ? " for " + blob + " user=" + parts[1] + " pass=" + parts[2] : ""));
        else w("235 2.7.0 Authentication successful");
      } else if (u === "AUTH LOGIN") {
        authLogin = { step: 1, user: null };
        w("334 VXNlcm5hbWU6");
      } else if (u.startsWith("MAIL FROM:")) {
        cur.from = line.slice(10);
        w("250 2.1.0 ok");
      } else if (u.startsWith("RCPT TO:")) {
        if (mode === "rcpt550") { w("550 5.1.1 mailbox unavailable"); return; }
        cur.rcpt.push(line.slice(8));
        w("250 2.1.5 ok");
      } else if (u === "DATA") {
        inData = true;
        data = "";
        w("354 end with <CRLF>.<CRLF>");
      } else if (u === "QUIT") {
        w("221 2.0.0 bye");
        try { sock.end(); } catch (_) { /* closed */ }
      } else {
        w("502 5.5.2 command not recognized");
      }
    };
    const onData = (chunk) => {
      buf += chunk.toString("utf8");
      let i;
      while ((i = buf.indexOf("\r\n")) !== -1) { const l = buf.slice(0, i); buf = buf.slice(i + 2); onLine(l); }
    };
    raw.on("data", onData);
    if (mode === "greet554") { w("554 5.3.2 go away"); return; }
    w("220 fake.smtp.test ESMTP ready");
  });

  /* Dual stack when the platform has it ("localhost" may resolve to ::1 first), IPv4 only
     otherwise. The host name the tests save is "localhost", so either works. */
  const listen = (host, extra) => new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(Object.assign({ port: o.port || 0, host }, extra || {}), () => { server.removeListener("error", reject); resolve(); });
  });

  return listen("::", { ipv6Only: false }).catch(() => listen("127.0.0.1")).then(() => ({
    port: server.address().port,
    log,
    setMode(m) { mode = m; },
    close() {
      for (const s of sockets) { try { s.destroy(); } catch (_) { /* gone */ } }
      return new Promise((r) => server.close(() => r()));
    },
  }));
}

module.exports = { startFakeSmtp };
