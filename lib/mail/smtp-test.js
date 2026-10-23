"use strict";
/* "Test SMTP" for the website sender (DESIGN.md section 10.4).

   classify(err)          -> { stage, smtpCode }
   hint(stage, settings)  -> constant sentence; host and port come from the validated,
                             stored settings, never from the server's reply
   recipientAllowed(to, { inquiryRecipient, fromAddress, enabledAddresses }) -> bool
   createSmtpTester({ smtp, sendMail, now?, timeoutMs? }).run({ to, inquiryRecipient, enabledAddresses, user })
     -> { passed, stage, smtpCode, ms, message, hint, to }   (throws MailError recipient_not_allowed)

   Only the SAVED settings are used: a draft would let the stored password travel to an
   unsaved host. The message is fixed (no user text), and recipients are allowlisted (D9),
   so this cannot be turned into a mail relay. */

const { isEmail } = require("../../smtp.js");
const { scrubString } = require("./redact.js");
const { mailError } = require("./provider.js");

const STAGES = new Set(["config", "dns", "connect", "greeting", "ehlo", "starttls", "tls", "auth", "mail_from", "rcpt", "data", "timeout"]);
const TLS_CODES = /^(ERR_TLS_|CERT_|UNABLE_TO_|DEPTH_ZERO_|SELF_SIGNED_|ERR_SSL_|HOSTNAME_MISMATCH)/;

/* Prefers err.stage / err.smtpCode (set by smtp.js once it carries them). Until then it
   falls back on error codes and on the fixed phrases smtp.js itself writes ("SMTP RCPT TO
   ... rejected"). The text is used only to pick a stage; it is never shown unscrubbed. */
function classify(err) {
  const e = err || {};
  const smtpCode = Number.isInteger(e.smtpCode) ? e.smtpCode : Number.isInteger(e.code) && e.code >= 200 && e.code < 600 ? e.code : null;
  if (typeof e.stage === "string" && STAGES.has(e.stage)) return { stage: e.stage, smtpCode };
  const code = typeof e.code === "string" ? e.code : "";
  const msg = String(e.message || "");
  let stage = "unknown";
  if (/not configured|invalid SMTP sender|no recipient/i.test(msg)) stage = "config";
  else if (code === "ENOTFOUND" || code === "EAI_AGAIN" || code === "EAI_NONAME") stage = "dns";
  else if (/timed out|timeout/i.test(msg) || code === "ETIMEDOUT") stage = /connecting to/i.test(msg) ? "connect" : "timeout";
  else if (["ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH", "EADDRNOTAVAIL"].includes(code)) stage = "connect";
  else if (TLS_CODES.test(code) || /certificate|self.signed|altnames/i.test(msg)) stage = "tls";
  else if (/does not offer STARTTLS|STARTTLS rejected/i.test(msg)) stage = "starttls";
  else if (/greeting rejected/i.test(msg)) stage = "greeting";
  else if (/EHLO/.test(msg)) stage = "ehlo";
  else if (/authentication|SASL mechanism/i.test(msg)) stage = "auth";
  else if (/MAIL FROM/.test(msg)) stage = "mail_from";
  else if (/RCPT TO/.test(msg)) stage = "rcpt";
  else if (/\bDATA\b|message rejected/i.test(msg)) stage = "data";
  else if (code === "ECONNRESET" || /closed unexpectedly/i.test(msg)) stage = "connect";
  return { stage, smtpCode };
}

function hint(stage, s) {
  const host = (s && s.host) || "the host";
  const port = (s && s.port) || "";
  switch (stage) {
    case "config": return "Website email is not fully configured (host, username, password, From).";
    case "dns": return "The host name " + host + " could not be resolved.";
    case "connect": return "Could not connect to " + host + ":" + port + " from the server. Check the host, port and firewall.";
    case "greeting": return "The server did not greet correctly.";
    case "ehlo": return "The server refused the EHLO greeting.";
    case "starttls": return "The server does not offer STARTTLS on this port, so credentials were not sent. Use 587, or switch to implicit TLS on 465.";
    case "tls": return "The server certificate is not valid for " + host + ". Use the mail server's real host name, not an IP.";
    case "auth": return "The server rejected the username or password.";
    case "mail_from": return "The server refused this From address for this login.";
    case "rcpt": return "The server refused the recipient.";
    case "data": return "The server refused the message.";
    case "timeout": return "The server did not answer in time.";
    default: return "The SMTP test failed.";
  }
}

function recipientAllowed(to, o) {
  const t = String(to || "").trim().toLowerCase();
  if (!t || !isEmail(t)) return false;
  const allowed = new Set();
  if (o.inquiryRecipient) allowed.add(String(o.inquiryRecipient).toLowerCase());
  if (o.fromAddress) allowed.add(String(o.fromAddress).toLowerCase());
  for (const a of o.enabledAddresses || []) allowed.add(String(a).toLowerCase());
  return allowed.has(t);
}

/* Every form the credentials take on the wire, for scrubString. */
function credentialForms(user, pass) {
  const out = [];
  if (pass) out.push(pass);
  if (user) out.push(user);
  if (user || pass) out.push("\0" + (user || "") + "\0" + (pass || ""));
  return out;
}

function createSmtpTester(opts) {
  const smtp = opts.smtp;
  const sendMail = opts.sendMail;
  const now = opts.now || (() => Date.now());
  const timeoutMs = opts.timeoutMs || 12000;

  async function run(r) {
    const settings = smtp.config();
    const to = r && typeof r.to === "string" && r.to.trim() ? r.to.trim() : String((r && r.inquiryRecipient) || "");
    if (!recipientAllowed(to, { inquiryRecipient: r && r.inquiryRecipient, fromAddress: settings.from, enabledAddresses: r && r.enabledAddresses })) {
      throw mailError("recipient_not_allowed", { field: "to" });
    }
    const where = { host: settings.host, port: settings.port };
    if (!(settings.host && settings.user && settings.pass && settings.from)) {
      return { passed: false, stage: "config", smtpCode: null, ms: 0, message: "Website email is not fully configured.", hint: hint("config", where), to };
    }
    /* Only an allowlisted host on an allowed port is ever contacted (throws a 400 before any
       connection), so this cannot be pointed at other hosts or ports to probe them. */
    smtp.checkTarget(settings.host, settings.port);
    const started = now();
    try {
      await sendMail({
        host: settings.host, port: settings.port, tlsMode: settings.tlsMode, servername: settings.servername,
        user: settings.user, pass: settings.pass, from: settings.from, fromName: settings.fromName,
        to: [to], subject: "ZEHNOX BHM website email test",
        text: "Time (UTC): " + new Date().toISOString() + "\nAdmin: " + String((r && r.user) || "admin").replace(/[^\x20-\x7e]/g, "").slice(0, 80) +
          "\n\nSent from the ZEHNOX admin panel to confirm SMTP settings.\n",
        rejectUnauthorized: settings.rejectUnauthorized, clientName: settings.clientName, timeoutMs,
      });
      return { passed: true, stage: "sent", smtpCode: 250, ms: now() - started, message: "Sent to " + to, hint: null, to };
    } catch (err) {
      const c = classify(err);
      const firstLine = String((err && err.message) || "").split("\n")[0];
      const message = scrubString(firstLine, credentialForms(settings.user, settings.pass), 200);
      return { passed: false, stage: c.stage, smtpCode: c.smtpCode, ms: now() - started, message, hint: hint(c.stage, where), to };
    }
  }

  return { run };
}

module.exports = { classify, hint, recipientAllowed, credentialForms, createSmtpTester, STAGES };
