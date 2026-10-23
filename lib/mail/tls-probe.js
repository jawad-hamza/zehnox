"use strict";
/* Submission TLS probe for the DNS view (DESIGN.md section 12, check 7).

   probeSubmission({ host, port = 587, ehloName, timeoutMs = 5000, connect?, tlsConnect?, now?, ca? })
     -> { stage, ms, banner: { code, host } | null, starttls, authAfterTls, cert, trusted, nameOk, error }

   It connects to the mail host (from the container that is a hairpin through the public
   IP), reads the 220 banner, sends EHLO, requires STARTTLS, upgrades with the host as SNI
   and reports the certificate: subject, SANs, days to expiry, whether the chain verifies
   and whether the name matches. Then QUIT. It never authenticates and never sends mail.

   The certificate is inspected with rejectUnauthorized:false on purpose: a bad
   certificate is the thing being reported, so the handshake must complete to describe it.
   Nothing is sent over that connection except EHLO and QUIT.

   Hard deadline for the whole conversation; every socket is destroyed on exit.
   `connect` / `tlsConnect` are injectable for tests (net.createConnection / tls.connect). */

const net = require("net");
const tls = require("tls");

const CRLF = "\r\n";
const BANNER_HOST_RE = /^[A-Za-z0-9.-]{1,253}$/;

/* Minimal SMTP reply reader: joins "250-..." continuation lines into one reply. */
function reader(socket) {
  let buf = "";
  let lines = [];
  const ready = [];
  const waiters = [];
  let failure = null;
  const settle = () => {
    while (ready.length && waiters.length) waiters.shift().resolve(ready.shift());
    if (failure) while (waiters.length) waiters.shift().reject(failure);
  };
  const onData = (chunk) => {
    buf += chunk.toString("latin1");
    if (buf.length > 65536) { failure = new Error("reply too long"); settle(); return; }
    let i;
    while ((i = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, i).replace(/\r$/, "");
      buf = buf.slice(i + 1);
      lines.push(line);
      if (/^\d{3}(?: |$)/.test(line)) { ready.push({ code: parseInt(line.slice(0, 3), 10), lines }); lines = []; }
      else if (!/^\d{3}-/.test(line)) { failure = new Error("malformed reply"); }
    }
    settle();
  };
  const onError = (e) => { failure = failure || e || new Error("socket error"); settle(); };
  const onClose = () => { failure = failure || new Error("closed"); settle(); };
  socket.on("data", onData);
  socket.on("error", onError);
  socket.on("close", onClose);
  return {
    read() {
      if (ready.length) return Promise.resolve(ready.shift());
      if (failure) return Promise.reject(failure);
      return new Promise((resolve, reject) => waiters.push({ resolve, reject }));
    },
    detach() { socket.removeListener("data", onData); socket.removeListener("error", onError); socket.removeListener("close", onClose); },
  };
}

function hasExt(reply, name) {
  return reply.lines.some((l, i) => i > 0 && new RegExp("^\\d{3}[ -]" + name + "(?:[ =]|$)", "i").test(l));
}

function describeCert(cert, host, nowMs) {
  if (!cert || !Object.keys(cert).length) return { cert: null, nameOk: false };
  const sans = String(cert.subjectaltname || "").split(",").map((s) => s.trim()).filter((s) => s.startsWith("DNS:")).map((s) => s.slice(4).toLowerCase()).slice(0, 20);
  const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
  const daysLeft = validTo && !isNaN(validTo) ? Math.floor((validTo.getTime() - nowMs) / 86400000) : null;
  let nameOk = false;
  try { nameOk = tls.checkServerIdentity(host, cert) === undefined; } catch (_) { nameOk = false; }
  const cn = cert.subject && typeof cert.subject.CN === "string" ? cert.subject.CN : null;
  return {
    cert: {
      subject: cn ? cn.slice(0, 253) : null,
      sans,
      validTo: validTo && !isNaN(validTo) ? validTo.toISOString() : null,
      daysLeft,
      issuer: cert.issuer && typeof cert.issuer.O === "string" ? cert.issuer.O.slice(0, 100) : null,
    },
    nameOk,
  };
}

function probeSubmission(opts) {
  const host = String(opts.host || "");
  const port = opts.port || 587;
  const ehloName = String(opts.ehloName || "localhost").replace(/[^A-Za-z0-9.-]/g, "") || "localhost";
  const timeoutMs = opts.timeoutMs || 5000;
  const connect = opts.connect || ((h, p) => net.createConnection({ host: h, port: p }));
  const tlsConnect = opts.tlsConnect || ((o) => tls.connect(o));
  const now = opts.now || (() => Date.now());
  const started = now();

  const out = { stage: "connect", ms: 0, banner: null, starttls: false, authAfterTls: null, cert: null, trusted: false, nameOk: false, error: null };
  return new Promise((resolve) => {
    let sock = null;
    let secure = null;
    let finished = false;
    const done = (stage, error) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      out.stage = stage;
      out.error = error || null;
      out.ms = now() - started;
      try { if (secure) secure.destroy(); } catch (_) { /* already gone */ }
      try { if (sock) sock.destroy(); } catch (_) { /* already gone */ }
      resolve(out);
    };
    const timer = setTimeout(() => done("timeout", "timeout"), timeoutMs);

    (async () => {
      let stage = "connect";
      try {
        sock = connect(host, port);
        // A late reset (after done() or between STARTTLS and the TLS wrap) must never become
        // an unhandled error event that takes the whole server down.
        sock.on("error", () => {});
        await new Promise((res, rej) => { sock.once("connect", res); sock.once("error", rej); });
        stage = "greeting";
        let io = reader(sock);
        const greet = await io.read();
        const bh = (greet.lines[0] || "").slice(4).split(/\s+/)[0] || "";
        out.banner = { code: greet.code, host: BANNER_HOST_RE.test(bh) ? bh.toLowerCase() : null };
        if (greet.code !== 220) return done("greeting", "bad_greeting");
        stage = "ehlo";
        sock.write("EHLO " + ehloName + CRLF);
        const ehlo = await io.read();
        if (ehlo.code !== 250) return done("ehlo", "ehlo_rejected");
        out.starttls = hasExt(ehlo, "STARTTLS");
        if (!out.starttls) { sock.write("QUIT" + CRLF); return done("starttls", "no_starttls"); }
        stage = "starttls";
        sock.write("STARTTLS" + CRLF);
        const go = await io.read();
        if (go.code !== 220) return done("starttls", "starttls_rejected");
        io.detach();
        stage = "tls";
        secure = tlsConnect({ socket: sock, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, ca: opts.ca });
        secure.on("error", () => {});
        await new Promise((res, rej) => { secure.once("secureConnect", res); secure.once("error", rej); });
        out.trusted = secure.authorized === true;
        const d = describeCert(secure.getPeerCertificate(), host, now());
        out.cert = d.cert;
        out.nameOk = d.nameOk;
        io = reader(secure);
        stage = "ehlo_tls";
        secure.write("EHLO " + ehloName + CRLF);
        const ehlo2 = await io.read();
        out.authAfterTls = ehlo2.code === 250 && hasExt(ehlo2, "AUTH");
        secure.write("QUIT" + CRLF);
        return done("done", null);
      } catch (e) {
        return done(stage, stage === "connect" ? (e && e.code === "ENOTFOUND" ? "dns" : "connect_failed") : "protocol");
      }
    })();
  });
}

module.exports = { probeSubmission, describeCert };
