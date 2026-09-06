"use strict";
/* Minimal SMTP submission client — Node standard library only (net + tls).

   This project has no package.json and no node_modules on purpose, so there is no
   nodemailer. What we need is narrow: hand one message to our own Postfix relay at
   mail.zehnox.com:587 over STARTTLS with SASL auth. That is a few hundred lines of
   well-specified protocol, so we implement exactly that and nothing else — no pooling,
   no queueing, no attachments, no DSN handling.

   The parts most likely to bite are exported separately so they can be tested without a
   socket: header sanitising, RFC 2047 encoding, and dot-stuffing. */

const net = require("net");
const tls = require("tls");
const crypto = require("crypto");
const os = require("os");

const CRLF = "\r\n";
const NUL = "\u0000";

/* ---------- message construction ---------- */

/* Header values here come from a public web form: the inquirer types their own name and
   email address. A bare CR or LF in one of those values would terminate the header and
   let them inject headers of their own — an extra Bcc:, a forged body — and relay mail
   through our server. Folding or escaping invites mistakes, so drop the control
   characters outright. */
function sanitizeHeader(value) {
  return String(value == null ? "" : value).replace(/[\r\n\u0000]+/g, " ").replace(/\s+/g, " ").trim();
}

const NON_ASCII = /[^\x20-\x7E]/;

/* RFC 2047 encoded-word. Plain ASCII goes through untouched so ordinary subjects stay
   readable in the raw message; anything else (Urdu names, curly quotes, em dashes) is
   base64'd, because a raw 8-bit byte in a header is not portable. */
function encodeHeaderWord(value) {
  const clean = sanitizeHeader(value);
  if (!NON_ASCII.test(clean)) return clean;
  return "=?UTF-8?B?" + Buffer.from(clean, "utf8").toString("base64") + "?=";
}

/* Deliberately strict: no spaces, no angle brackets, no control characters. Anything that
   fails this never reaches a MAIL FROM / RCPT TO / Reply-To line. */
const EMAIL_RE = /^[^\s@<>,;:"\\()[\]\u0000-\u001f]+@[^\s@<>,;:"\\()[\]\u0000-\u001f]+\.[a-z0-9-]{2,}$/i;
function isEmail(value) {
  const v = String(value == null ? "" : value).trim();
  return v.length <= 320 && EMAIL_RE.test(v);
}

/* "Display Name" <addr@example.com>, with the name encoded and dropped if it is empty. */
function formatAddress(address, name) {
  const addr = String(address || "").trim();
  const label = encodeHeaderWord(name);
  if (!label) return "<" + addr + ">";
  return (NON_ASCII.test(sanitizeHeader(name)) ? label : '"' + label.replace(/["\\]/g, "") + '"') + " <" + addr + ">";
}

/* RFC 5322 wants "+0000", toUTCString() ends in "GMT". */
function rfc5322Date(date) {
  return date.toUTCString().replace(/GMT$/, "+0000");
}

/* base64 at 76 characters per line. Using base64 for the body rather than 8bit or
   quoted-printable solves three problems at once: no line ever exceeds the 998-character
   limit, no line can begin with a "." and end the DATA stage early, and UTF-8 survives
   servers that do not advertise 8BITMIME. */
function base64Body(text) {
  const encoded = Buffer.from(String(text == null ? "" : text), "utf8").toString("base64");
  const lines = [];
  for (let i = 0; i < encoded.length; i += 76) lines.push(encoded.slice(i, i + 76));
  return lines.join(CRLF);
}

/* RFC 5321 §4.5.2: a line consisting of a single "." ends DATA, so any body line that
   really starts with "." must be doubled. The base64 body above can never produce one,
   but this stays correct if the body encoding ever changes. */
function dotStuff(data) {
  return String(data).replace(/^\./gm, "..");
}

function buildMessage(opts) {
  const date = opts.date || new Date();
  const domain = String(opts.from || "").split("@")[1] || os.hostname();
  const messageId = opts.messageId || "<" + crypto.randomUUID() + "@" + domain + ">";
  const headers = [
    "From: " + formatAddress(opts.from, opts.fromName),
    "To: " + opts.to.map((a) => "<" + a + ">").join(", "),
  ];
  /* Reply-To is what makes the forwarded inquiry useful: hitting Reply in the mailbox
     answers the person who filled in the form, not our own send address. */
  if (opts.replyTo && isEmail(opts.replyTo)) headers.push("Reply-To: " + formatAddress(opts.replyTo, opts.replyToName));
  headers.push(
    "Subject: " + encodeHeaderWord(opts.subject),
    "Date: " + rfc5322Date(date),
    "Message-ID: " + messageId,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: base64",
    /* Tells autoresponders on the receiving end not to bounce a vacation reply back at
       us, which would otherwise loop against the Reply-To address. */
    "Auto-Submitted: auto-generated"
  );
  return headers.join(CRLF) + CRLF + CRLF + base64Body(opts.text);
}

/* ---------- protocol plumbing ---------- */

/* Reads CRLF-delimited SMTP replies off a socket, joining the multiline form
   ("250-FIRST" ... "250 LAST") into one reply. Detachable so the same logic can be
   re-attached to the TLS socket after STARTTLS. */
function attachReader(socket) {
  let buffer = "";
  let pending = [];        // lines of the reply currently being accumulated
  const ready = [];        // complete replies not yet consumed
  const waiters = [];      // read() callers waiting for a reply
  let failure = null;

  const settle = () => {
    while (ready.length && waiters.length) waiters.shift().resolve(ready.shift());
    if (failure) while (waiters.length) waiters.shift().reject(failure);
  };
  const onData = (chunk) => {
    buffer += chunk.toString("binary");
    let idx;
    while ((idx = buffer.indexOf(CRLF)) !== -1) {
      const line = Buffer.from(buffer.slice(0, idx), "binary").toString("utf8");
      buffer = buffer.slice(idx + 2);
      pending.push(line);
      // The final line of a reply has a space (not "-") in the fourth column.
      if (/^\d{3}(?: |$)/.test(line)) {
        ready.push({ code: parseInt(line.slice(0, 3), 10), lines: pending, text: pending.join("\n") });
        pending = [];
      }
    }
    settle();
  };
  const onError = (e) => { failure = e; settle(); };
  const onClose = () => { failure = failure || new Error("SMTP connection closed unexpectedly"); settle(); };

  socket.on("data", onData);
  socket.on("error", onError);
  socket.on("close", onClose);

  return {
    read() {
      if (ready.length) return Promise.resolve(ready.shift());
      if (failure) return Promise.reject(failure);
      return new Promise((resolve, reject) => { waiters.push({ resolve, reject }); });
    },
    detach() {
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
      return buffer;
    },
  };
}

function connect(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    const onError = (e) => { socket.destroy(); reject(e); };
    socket.setTimeout(timeoutMs, () => onError(new Error("timed out connecting to " + host + ":" + port)));
    socket.once("error", onError);
    socket.once("connect", () => { socket.removeListener("error", onError); socket.setTimeout(0); resolve(socket); });
  });
}

function upgradeToTls(socket, host, rejectUnauthorized, timeoutMs) {
  return new Promise((resolve, reject) => {
    // RFC 6066 forbids an IP literal as the SNI server name, and Node warns about it.
    const servername = net.isIP(host) === 0 ? host : undefined;
    const secure = tls.connect({ socket, servername, rejectUnauthorized });
    const timer = setTimeout(() => { secure.destroy(); reject(new Error("TLS handshake timed out")); }, timeoutMs);
    const onError = (e) => { clearTimeout(timer); secure.destroy(); reject(e); };
    secure.once("error", onError);
    secure.once("secureConnect", () => { clearTimeout(timer); secure.removeListener("error", onError); resolve(secure); });
  });
}

/* ---------- the conversation ---------- */

function parseAuthMechanisms(ehloText) {
  const m = /^\d{3}[ -]AUTH[ =]([^\r\n]*)$/im.exec(String(ehloText));
  return m ? m[1].trim().toUpperCase().split(/\s+/).filter(Boolean) : [];
}

async function sendMail(options) {
  const host = String(options.host || "").trim();
  const port = Number(options.port) || 587;
  const user = String(options.user || "");
  const pass = String(options.pass || "");
  const from = String(options.from || "").trim();
  const to = (Array.isArray(options.to) ? options.to : [options.to]).map((a) => String(a || "").trim()).filter(Boolean);
  const timeoutMs = Number(options.timeoutMs) || 15000;
  const rejectUnauthorized = options.rejectUnauthorized !== false;
  const clientName = String(options.clientName || os.hostname() || "localhost");

  if (!host) throw new Error("SMTP host is not configured");
  if (!isEmail(from)) throw new Error("invalid SMTP sender address");
  if (!to.length) throw new Error("no recipient");
  for (const rcpt of to) if (!isEmail(rcpt)) throw new Error("invalid recipient address: " + rcpt);

  const message = buildMessage({
    from, fromName: options.fromName, to,
    replyTo: options.replyTo, replyToName: options.replyToName,
    subject: options.subject, text: options.text, date: options.date, messageId: options.messageId,
  });

  let socket = await connect(host, port, timeoutMs);
  let io = attachReader(socket);

  /* One deadline for the whole session. A relay that accepts the connection and then
     stalls must not hold a request open indefinitely. */
  let expired = false;
  const deadline = setTimeout(() => { expired = true; socket.destroy(new Error("SMTP session timed out after " + timeoutMs + "ms")); }, timeoutMs);

  const expect = async (codes, what) => {
    const reply = await io.read();
    if (!codes.includes(reply.code)) {
      const err = new Error("SMTP " + what + " rejected: " + reply.text);
      err.code = reply.code;
      throw err;
    }
    return reply;
  };
  const cmd = (line, codes, what) => { socket.write(line + CRLF); return expect(codes, what); };

  try {
    await expect([220], "greeting");
    let ehlo = await cmd("EHLO " + clientName, [250], "EHLO");

    if (!/^\d{3}[ -]STARTTLS\s*$/im.test(ehlo.text)) {
      throw new Error(host + ":" + port + " does not offer STARTTLS; refusing to send credentials in the clear");
    }
    await cmd("STARTTLS", [220], "STARTTLS");
    io.detach();
    socket = await upgradeToTls(socket, host, rejectUnauthorized, timeoutMs);
    io = attachReader(socket);
    /* RFC 3207: the EHLO must be repeated over the encrypted channel, and only the
       capabilities advertised there may be trusted — the cleartext ones were forgeable. */
    ehlo = await cmd("EHLO " + clientName, [250], "EHLO after STARTTLS");

    if (user || pass) {
      const mechs = parseAuthMechanisms(ehlo.text);
      if (mechs.includes("PLAIN")) {
        await cmd("AUTH PLAIN " + Buffer.from(NUL + user + NUL + pass, "utf8").toString("base64"), [235], "authentication");
      } else if (mechs.includes("LOGIN")) {
        await cmd("AUTH LOGIN", [334], "authentication");
        await cmd(Buffer.from(user, "utf8").toString("base64"), [334], "authentication (username)");
        await cmd(Buffer.from(pass, "utf8").toString("base64"), [235], "authentication (password)");
      } else {
        throw new Error("no supported SASL mechanism at " + host + " (offered: " + (mechs.join(" ") || "none") + ")");
      }
    }

    await cmd("MAIL FROM:<" + from + ">", [250], "MAIL FROM");
    for (const rcpt of to) await cmd("RCPT TO:<" + rcpt + ">", [250, 251], "RCPT TO <" + rcpt + ">");
    await cmd("DATA", [354], "DATA");
    socket.write(dotStuff(message) + CRLF + "." + CRLF);
    const accepted = await expect([250], "message");
    try { await cmd("QUIT", [221], "QUIT"); } catch (_) { /* the message is already accepted; a rude close here is harmless */ }
    return { response: accepted.text };
  } catch (e) {
    if (expired) throw new Error("SMTP session timed out after " + timeoutMs + "ms");
    throw e;
  } finally {
    clearTimeout(deadline);
    io.detach();
    socket.destroy();
  }
}

module.exports = { sendMail, buildMessage, sanitizeHeader, encodeHeaderWord, formatAddress, base64Body, dotStuff, isEmail, parseAuthMechanisms, rfc5322Date };
