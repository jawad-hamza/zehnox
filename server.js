#!/usr/bin/env node
/* ZEHNOX site server — zero-dependency Node (CONTRACT.md §8)
   node server.js [port=3000]
     /            → dist/ (static, falls back to dist/404.html)
     /admin/      → admin/ (static admin UI)
     /api/...     → JSON API. Admin routes need a signed-in session: POST /api/login {username, password}
                    returns a session id (send it as "Authorization: Bearer <session>"; it is also set as an
                    HttpOnly cookie). Credentials live in data/admin-auth.json (scrypt hash) and can be changed
                    from the admin (POST /api/account). First run creates user "admin" with a random password
                    written to data/initial-password.txt.
   Environment: HOST (default 127.0.0.1), TRUST_PROXY=1 to read X-Forwarded-For for rate limiting.
*/
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { build } = require("./build.js");
const { writeFileAtomic } = require("./write-file.js");
const { sendMail, isEmail } = require("./smtp.js");

const ROOT = __dirname;
const DIST = path.join(ROOT, "dist");
const ADMIN = path.join(ROOT, "admin");
const SRC = path.join(ROOT, "src");
const DATA = path.join(ROOT, "data");
const UPLOADS = path.join(SRC, "uploads");
const CONTENT_FILE = path.join(ROOT, "content.json");
const TOKEN_FILE = path.join(DATA, "admin-token.txt");
const INQUIRIES_FILE = path.join(DATA, "inquiries.json");

const PORT = parseInt(process.argv[2] || process.env.PORT || "3000", 10) || 3000;
const HOST = process.env.HOST || "127.0.0.1";
const TRUST_PROXY = process.env.TRUST_PROXY === "1";

const JSON_LIMIT = 1 * 1024 * 1024;        // 1 MB for ordinary JSON bodies
const UPLOAD_LIMIT = 8 * 1024 * 1024;      // 8 MB request body (5 MB file, base64 encoded)
const MAX_FILE_BYTES = 5 * 1024 * 1024;    // 5 MB decoded file
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX = 5;                        // POST /api/contact per IP per window
const MAX_INQUIRIES = 5000;

const MIME = {
  ".html": "text/html; charset=utf-8", ".htm": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8",
  ".xml": "application/xml; charset=utf-8", ".txt": "text/plain; charset=utf-8", ".md": "text/markdown; charset=utf-8",
  ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp",
  ".gif": "image/gif", ".avif": "image/avif", ".ico": "image/x-icon", ".woff": "font/woff", ".woff2": "font/woff2",
  ".ttf": "font/ttf", ".otf": "font/otf", ".mp4": "video/mp4", ".webm": "video/webm", ".mp3": "audio/mpeg",
  ".pdf": "application/pdf", ".map": "application/json; charset=utf-8", ".webmanifest": "application/manifest+json"
};
const IMAGE_TYPES = { "image/png": ".png", "image/jpeg": ".jpg", "image/jpg": ".jpg", "image/webp": ".webp", "image/svg+xml": ".svg" };
const ALLOWED_EXT = new Set([".png", ".jpg", ".jpeg", ".webp", ".svg"]);

/* ---------- boot: data dir + admin credentials ---------- */
const AUTH_FILE = path.join(DATA, "admin-auth.json");
const INITIAL_PW_FILE = path.join(DATA, "initial-password.txt");
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;   // a session lives 12 hours of inactivity
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX = 10;                          // sign-in attempts per IP per window

function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 64, { N: 16384, r: 8, p: 1 }).toString("hex");
}
function readAuth() {
  try {
    const a = JSON.parse(fs.readFileSync(AUTH_FILE, "utf8"));
    if (a && typeof a.username === "string" && typeof a.salt === "string" && typeof a.hash === "string") return a;
  } catch (_) { /* missing or corrupt */ }
  return null;
}
function writeAuth(username, password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const rec = { username, salt, hash: hashPassword(password, salt), updatedAt: new Date().toISOString() };
  writeFileAtomic(AUTH_FILE, JSON.stringify(rec, null, 2) + "\n", { mode: 0o600 });
  return rec;
}
function verifyPassword(password) {
  const a = readAuth();
  if (!a) return false;
  const given = Buffer.from(hashPassword(password, a.salt), "hex");
  const want = Buffer.from(a.hash, "hex");
  return given.length === want.length && crypto.timingSafeEqual(given, want);
}
let generatedPassword = "";
function ensureData() {
  fs.mkdirSync(DATA, { recursive: true });
  if (!readAuth()) {
    generatedPassword = crypto.randomBytes(9).toString("base64url");
    writeAuth("admin", generatedPassword);
    fs.writeFileSync(INITIAL_PW_FILE, "ZEHNOX admin — first sign-in\nusername: admin\npassword: " + generatedPassword + "\n\nChange both in /admin/ → Account. This file is deleted after the first change.\n", { mode: 0o600 });
    console.log("Created the first admin account (username: admin). The password is in data/initial-password.txt");
  }
  try { fs.unlinkSync(TOKEN_FILE); } catch (_) { /* old token file from earlier versions */ }
  if (!fs.existsSync(INQUIRIES_FILE)) fs.writeFileSync(INQUIRIES_FILE, "[]\n");
}
ensureData();

/* sessions live in memory: restarting the server signs everyone out */
const sessions = new Map();
function createSession(username) {
  const id = crypto.randomBytes(32).toString("hex");
  sessions.set(id, { username, expires: Date.now() + SESSION_TTL_MS });
  return id;
}
function sessionFrom(req) {
  let id = "";
  const m = /^Bearer\s+([a-f0-9]{64})$/i.exec(String(req.headers.authorization || "").trim());
  if (m) id = m[1].toLowerCase();
  else { const c = /(?:^|;\s*)zx_session=([a-f0-9]{64})/i.exec(String(req.headers.cookie || "")); if (c) id = c[1].toLowerCase(); }
  const sess = id && sessions.get(id);
  if (!sess) return null;
  if (sess.expires < Date.now()) { sessions.delete(id); return null; }
  sess.expires = Date.now() + SESSION_TTL_MS;
  return { id, username: sess.username };
}
function sessionCookie(req, id) {
  const secure = TRUST_PROXY && String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https";
  return "zx_session=" + id + "; Path=/; Max-Age=" + Math.floor(SESSION_TTL_MS / 1000) + "; HttpOnly; SameSite=Strict" + (secure ? "; Secure" : "");
}
setInterval(() => { const now = Date.now(); for (const [k, v] of sessions) if (v.expires < now) sessions.delete(k); }, 60 * 1000).unref();
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------- helpers ---------- */
const log = (...a) => console.log(new Date().toISOString(), ...a);
const logErr = (...a) => console.error(new Date().toISOString(), ...a);

function readContentSafe() {
  try { return JSON.parse(fs.readFileSync(CONTENT_FILE, "utf8")); } catch (e) { logErr("content.json unreadable:", e.message); return null; }
}

function siteOrigin() {
  const c = readContentSafe();
  const u = c && c.site && typeof c.site.url === "string" ? c.site.url.trim() : "";
  try { return u ? new URL(u).origin : ""; } catch (_) { return ""; }
}

function requestOrigin(req) {
  const host = req.headers.host;
  if (!host) return "";
  const proto = TRUST_PROXY && req.headers["x-forwarded-proto"] ? String(req.headers["x-forwarded-proto"]).split(",")[0].trim() : "http";
  return proto + "://" + host;
}

/* CORS: only the server's own origin (and the configured site.url origin, so a statically hosted
   copy of the site can post the contact form here). Never "*". */
function cors(req, res) {
  const origin = req.headers.origin;
  if (!origin) return;
  const allowed = [requestOrigin(req), siteOrigin()].filter(Boolean);
  const alt = requestOrigin(req).replace("://localhost", "://127.0.0.1");
  if (alt !== requestOrigin(req)) allowed.push(alt);
  if (allowed.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Max-Age", "600");
  }
}

function send(res, status, body, headers) {
  const h = Object.assign({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }, headers || {});
  const data = typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, h);
  res.end(data);
}
const sendJson = (res, status, obj) => send(res, status, obj);
const fail = (res, status, message) => sendJson(res, status, { ok: false, error: message });

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;
    req.on("data", (c) => {
      if (done) return;
      size += c.length;
      if (size > limit) {
        done = true;
        chunks.length = 0;
        req.pause();            // stop reading; the caller answers 413 and closes the connection
        reject(Object.assign(new Error("Request body too large"), { status: 413 }));
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function readJson(req, limit) {
  const buf = await readBody(req, limit);
  if (!buf.length) throw Object.assign(new Error("Empty request body"), { status: 400 });
  try { return JSON.parse(buf.toString("utf8")); }
  catch (_) { throw Object.assign(new Error("Body must be valid JSON"), { status: 400 }); }
}

const authorized = (req) => !!sessionFrom(req);

/* failed sign-in attempts per IP: only failures count, a successful sign-in clears the counter */
const loginHits = new Map();
function loginBlocked(ip) {
  const now = Date.now();
  const arr = (loginHits.get(ip) || []).filter((t) => now - t < LOGIN_WINDOW_MS);
  loginHits.set(ip, arr);
  return arr.length >= LOGIN_MAX;
}
function loginFailed(ip) {
  const arr = loginHits.get(ip) || [];
  arr.push(Date.now());
  loginHits.set(ip, arr);
}

function clientIp(req) {
  if (TRUST_PROXY) {
    const xff = req.headers["x-forwarded-for"];
    if (xff) return String(xff).split(",")[0].trim();
  }
  return (req.socket && req.socket.remoteAddress) || "unknown";
}

/* in-memory sliding-window rate limiter */
const hits = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < RATE_WINDOW_MS);
  if (arr.length >= RATE_MAX) { hits.set(ip, arr); return true; }
  arr.push(now);
  hits.set(ip, arr);
  return false;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, arr] of hits) {
    const keep = arr.filter((t) => now - t < RATE_WINDOW_MS);
    if (keep.length) hits.set(ip, keep); else hits.delete(ip);
  }
}, RATE_WINDOW_MS).unref();

/* builds are serialised so two admin actions never write dist/ at once */
let buildChain = Promise.resolve();
function runBuild() {
  const p = buildChain.then(() => build({ quiet: true }));
  buildChain = p.catch(() => {});
  return p;
}

/* ---------- inquiries store ---------- */
function readInquiries() {
  try {
    const parsed = JSON.parse(fs.readFileSync(INQUIRIES_FILE, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    if (fs.existsSync(INQUIRIES_FILE)) {
      const backup = INQUIRIES_FILE + "." + Date.now() + ".corrupt";
      try { fs.copyFileSync(INQUIRIES_FILE, backup); logErr("inquiries.json unreadable, backed up to " + path.basename(backup)); } catch (_) { /* ignore */ }
    }
    return [];
  }
}
function writeInquiries(list) {
  writeFileAtomic(INQUIRIES_FILE, JSON.stringify(list, null, 2) + "\n");
}

/* ---------- validation ---------- */
const str = (v, max) => (typeof v === "string" ? v.trim().slice(0, max || 500) : "");
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_RE = /^\+?[0-9 ()-]{7,20}$/;

function validateInquiry(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { error: "Body must be a JSON object" };
  const name = str(body.name, 200);
  const email = str(body.email, 320);
  const phone = str(body.phone, 40);
  const company = str(body.company, 200);
  const iam = str(body.iam, 100);
  const method = str(body.method, 60);
  const brief = str(body.brief, 5000);
  const page = str(body.page, 500);
  const services = Array.isArray(body.services) ? body.services.map((s) => str(s, 80)).filter(Boolean).slice(0, 10)
    : typeof body.services === "string" ? [str(body.services, 80)].filter(Boolean) : [];
  const problems = [];
  if (!name) problems.push("name is required");
  if (!EMAIL_RE.test(email)) problems.push("a valid email is required");
  if (phone && !PHONE_RE.test(phone)) problems.push("phone must be 7–20 digits");
  if (!brief || brief.length < 20) problems.push("brief must be at least 20 characters");
  if (problems.length) return { error: problems.join("; ") };
  return { value: { name, email, phone, company, iam, services, brief, method, page } };
}

function validateContentShape(c) {
  if (!c || typeof c !== "object" || Array.isArray(c)) return "Content must be a JSON object";
  const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);
  for (const k of ["site", "contact", "social", "legal"]) if (!isObj(c[k])) return '"' + k + '" must be an object';
  for (const k of ["team", "work", "posts"]) {
    if (!Array.isArray(c[k])) return '"' + k + '" must be an array';
    if (!c[k].every(isObj)) return 'every item in "' + k + '" must be an object';
  }
  for (const k of Object.keys(c.site)) if (c.site[k] != null && typeof c.site[k] !== "string") return 'site.' + k + ' must be a string';
  for (const k of Object.keys(c.contact)) if (c.contact[k] != null && typeof c.contact[k] !== "string") return 'contact.' + k + ' must be a string';
  for (const k of Object.keys(c.social)) if (c.social[k] != null && typeof c.social[k] !== "string") return 'social.' + k + ' must be a string';
  for (const k of Object.keys(c.legal)) if (c.legal[k] != null && typeof c.legal[k] !== "string") return 'legal.' + k + ' must be a string';
  for (const p of c.posts) { if (p.slug != null && typeof p.slug !== "string") return "post.slug must be a string"; if (p.tags != null && !Array.isArray(p.tags)) return "post.tags must be an array"; }
  for (const w of c.work) if (w.tags != null && !Array.isArray(w.tags)) return "work.tags must be an array";
  if (c.site.url) { try { new URL(c.site.url); } catch (_) { return "site.url must be a full URL (https://…)"; } }
  if (c.site.inquiryWebhook) { try { new URL(c.site.inquiryWebhook); } catch (_) { return "site.inquiryWebhook must be a full URL"; } }
  if (c.site.inquiryEmail && !isEmail(c.site.inquiryEmail.trim())) return "site.inquiryEmail must be one email address, like info@zehnox.com";
  return "";
}

function safeUploadName(name, ext) {
  let base = path.basename(String(name || "upload")).toLowerCase();
  base = base.replace(/\.[a-z0-9]+$/i, "");                   // drop given extension; we add the real one
  base = base.replace(/[^a-z0-9._-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "").slice(0, 80) || "upload";
  return base + ext;
}

function uniquePath(dir, filename) {
  const ext = path.extname(filename), stem = filename.slice(0, -ext.length);
  let candidate = filename, n = 2;
  while (fs.existsSync(path.join(dir, candidate))) candidate = stem + "-" + n++ + ext;
  return candidate;
}

/* ---------- email forward (fire-and-forget) ---------- */

/* Credentials come from the environment only — never from content.json, which the admin
   panel writes and git tracks. With SMTP_USER/SMTP_PASS unset, forwarding is skipped and
   the inquiry is still stored; a misconfigured relay must never cost us a lead. */
const SMTP = {
  host: process.env.SMTP_HOST || "mail.zehnox.com",
  port: parseInt(process.env.SMTP_PORT || "587", 10) || 587,
  user: process.env.SMTP_USER || "",
  pass: process.env.SMTP_PASS || "",
  from: process.env.SMTP_FROM || "info@zehnox.com",
  // Escape hatch for a relay with a self-signed certificate. Verification stays on unless
  // this is set deliberately.
  rejectUnauthorized: process.env.SMTP_INSECURE_TLS !== "1",
};
let smtpWarned = false;

/* Where inquiries are emailed: the admin's "Forward inquiries to" field, falling back to
   the public contact address so this works before anyone touches the setting. */
function inquiryRecipient(content) {
  const c = content || readContentSafe();
  const configured = c && c.site && typeof c.site.inquiryEmail === "string" ? c.site.inquiryEmail.trim() : "";
  const fallback = c && c.contact && typeof c.contact.email === "string" ? c.contact.email.trim() : "";
  const chosen = configured || fallback;
  return isEmail(chosen) ? chosen : "";
}

function inquiryEmailBody(record) {
  const rows = [
    ["Name", record.name],
    ["Email", record.email],
    ["Phone", record.phone],
    ["Company", record.company],
    ["They are", record.iam],
    ["Services", Array.isArray(record.services) ? record.services.join(", ") : ""],
    ["Preferred contact", record.method],
    ["Sent from page", record.page],
    ["Received", record.receivedAt],
    ["Reference", record.id],
  ].filter(([, v]) => v);
  return rows.map(([k, v]) => k + ": " + v).join("\n") +
    "\n\nBrief\n-----\n" + (record.brief || "") +
    "\n\n-- \nSent by the ZEHNOX website. Reply to this email to answer " + record.name + " directly.\n";
}

function emailInquiry(record) {
  const to = inquiryRecipient();
  if (!to) { logErr("inquiry email skipped: no valid recipient (set site.inquiryEmail or contact.email)"); return; }
  if (!SMTP.user || !SMTP.pass) {
    if (!smtpWarned) { smtpWarned = true; logErr("inquiry email skipped: SMTP_USER/SMTP_PASS are not set"); }
    return;
  }
  sendMail({
    host: SMTP.host, port: SMTP.port, user: SMTP.user, pass: SMTP.pass,
    from: SMTP.from, fromName: "ZEHNOX website", to: [to],
    // Reply goes to the person who filled in the form, not to our own send address.
    replyTo: record.email, replyToName: record.name,
    subject: "New inquiry from " + record.name + (record.company ? " (" + record.company + ")" : ""),
    text: inquiryEmailBody(record),
    rejectUnauthorized: SMTP.rejectUnauthorized,
  })
    .then(() => log("inquiry " + record.id + " emailed to " + to))
    .catch((e) => logErr("inquiry email failed for " + record.id + ": " + (e && e.message ? e.message : e)));
}

/* ---------- webhook forward (fire-and-forget) ---------- */
function forwardInquiry(record) {
  const c = readContentSafe();
  const hook = c && c.site && typeof c.site.inquiryWebhook === "string" ? c.site.inquiryWebhook.trim() : "";
  if (!hook) return;
  if (typeof fetch !== "function") { logErr("webhook: global fetch unavailable"); return; }
  let signal;
  try { signal = AbortSignal.timeout(10000); } catch (_) { signal = undefined; }
  fetch(hook, { method: "POST", headers: { "Content-Type": "application/json", "User-Agent": "ZEHNOX-site/1.0" }, body: JSON.stringify({ type: "inquiry", inquiry: record }), signal })
    .then((r) => { if (!r.ok) logErr("webhook responded " + r.status + " for inquiry " + record.id); })
    .catch((e) => logErr("webhook failed for inquiry " + record.id + ": " + (e && e.message ? e.message : e)));
}

/* ---------- static files ---------- */
function resolveStatic(baseDir, urlPath) {
  let decoded;
  try { decoded = decodeURIComponent(urlPath); } catch (_) { return null; }
  if (decoded.includes("\0")) return null;
  const rel = path.normalize(decoded).replace(/^(\.\.[/\\])+/, "");
  const abs = path.resolve(baseDir, "." + path.sep + rel);
  if (abs !== baseDir && !abs.startsWith(baseDir + path.sep)) return null;
  return abs;
}

function statFile(p) {
  try { const s = fs.statSync(p); return s.isFile() ? s : null; } catch (_) { return null; }
}

function serveFile(req, res, abs, status) {
  const ext = path.extname(abs).toLowerCase();
  const type = MIME[ext] || "application/octet-stream";
  const st = fs.statSync(abs);
  const preset = res.getHeader("Cache-Control"); // e.g. "no-store" set by the /admin/ route wins over the default
  // js/content.js is rewritten by every admin save. Cached for an hour like the other .js files, edits stay
  // invisible on pages the browser has already seen, so it revalidates like the html does.
  const generated = path.normalize(abs) === path.join(DIST, "js", "content.js");
  const cache = preset ? String(preset) : generated || ext === ".html" || ext === ".xml" || ext === ".txt" || ext === ".json" ? "no-cache" : "public, max-age=3600";
  const headers = { "Content-Type": type, "Content-Length": st.size, "Cache-Control": cache, "X-Content-Type-Options": "nosniff", "Last-Modified": st.mtime.toUTCString() };
  if (ext === ".html") { headers["X-Frame-Options"] = "SAMEORIGIN"; headers["Referrer-Policy"] = "strict-origin-when-cross-origin"; }
  res.writeHead(status || 200, headers);
  if (req.method === "HEAD") { res.end(); return; }
  const stream = fs.createReadStream(abs);
  stream.on("error", (e) => { logErr("stream error", abs, e.message); if (!res.headersSent) fail(res, 500, "Read error"); else res.destroy(); });
  stream.pipe(res);
}

function serveStatic(req, res, baseDir, urlPath, notFound) {
  const abs = resolveStatic(baseDir, urlPath);
  if (!abs) return notFound();
  const candidates = [abs];
  if (urlPath.endsWith("/")) candidates.unshift(path.join(abs, "index.html"));
  else { candidates.push(path.join(abs, "index.html")); if (!path.extname(abs)) candidates.push(abs + ".html"); }
  for (const c of candidates) {
    if (statFile(c)) {
      // a directory requested without a trailing slash → redirect so relative links resolve
      if (c === path.join(abs, "index.html") && !urlPath.endsWith("/")) {
        const target = urlPath + "/";
        res.writeHead(301, { Location: target, "Cache-Control": "no-cache" }); res.end(); return;
      }
      return serveFile(req, res, c, 200);
    }
  }
  return notFound();
}

/* dist/404.html is authored with root-relative links ("css/style.css", data-root=""). It is served for
   unknown URLs at any depth (/services/missing.html), so those links are made absolute ("/css/style.css",
   data-root="/") before sending; site.js reads data-root to build its own links. */
const RELATIVE_URL_ATTR = /(\s(?:href|src)=")(?![a-z][a-z0-9+.-]*:|\/|#|\?)([^"]*")/gi;
function absolutize404(html) {
  return html
    .replace(RELATIVE_URL_ATTR, "$1/$2")
    .replace(/(<body\b[^>]*\sdata-root=")(")/i, "$1/$2");
}

function notFoundPage(req, res) {
  const page = path.join(DIST, "404.html");
  if (!statFile(page)) return send(res, 404, "404 — not found", { "Content-Type": "text/plain; charset=utf-8" });
  let html;
  try { html = absolutize404(fs.readFileSync(page, "utf8")); }
  catch (e) { logErr("404 page unreadable:", e.message); return send(res, 404, "404 — not found", { "Content-Type": "text/plain; charset=utf-8" }); }
  const body = Buffer.from(html, "utf8");
  const headers = { "Content-Type": MIME[".html"], "Content-Length": body.length, "Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "SAMEORIGIN", "Referrer-Policy": "strict-origin-when-cross-origin" };
  res.writeHead(404, headers);
  res.end(req.method === "HEAD" ? undefined : body);
}

/* ---------- API ---------- */
async function handleApi(req, res, url) {
  const method = req.method;
  const p = url.pathname;

  // public: contact form
  if (p === "/api/contact") {
    if (method !== "POST") return fail(res, 405, "Method not allowed");
    const ip = clientIp(req);
    if (rateLimited(ip)) return fail(res, 429, "Too many requests. Please try again in a minute.");
    const body = await readJson(req, JSON_LIMIT);
    const v = validateInquiry(body);
    if (v.error) return fail(res, 400, v.error);
    const record = Object.assign({ id: crypto.randomUUID(), receivedAt: new Date().toISOString() }, v.value, { ip });
    const list = readInquiries();
    list.push(record);
    while (list.length > MAX_INQUIRIES) list.shift();
    writeInquiries(list);
    log("inquiry " + record.id + " from " + record.email);
    emailInquiry(record);
    forwardInquiry(record);
    return sendJson(res, 201, { ok: true, id: record.id });
  }

  // public: sign in / sign out
  if (p === "/api/login") {
    if (method !== "POST") return fail(res, 405, "Method not allowed");
    const ip = clientIp(req);
    if (loginBlocked(ip)) return fail(res, 429, "Too many failed sign-in attempts. Try again in 15 minutes.");
    const body = await readJson(req, 64 * 1024);
    const username = str(body && body.username, 80);
    const password = body && typeof body.password === "string" ? body.password : "";
    const a = readAuth();
    const userOk = !!a && username.length === a.username.length && crypto.timingSafeEqual(Buffer.from(username.toLowerCase()), Buffer.from(a.username.toLowerCase()));
    const passOk = verifyPassword(password);
    if (!userOk || !passOk) {
      loginFailed(ip);
      const left = Math.max(0, LOGIN_MAX - (loginHits.get(ip) || []).length);
      await delay(500);
      log("failed admin sign-in from " + ip + " (" + left + " attempts left)");
      return sendJson(res, 401, { ok: false, error: "Wrong username or password.", remaining: left });
    }
    loginHits.delete(ip);
    const id = createSession(a.username);
    log("admin sign-in: " + a.username + " from " + ip);
    return send(res, 200, { ok: true, session: id, username: a.username }, { "Set-Cookie": sessionCookie(req, id) });
  }
  if (p === "/api/logout") {
    if (method !== "POST") return fail(res, 405, "Method not allowed");
    const s = sessionFrom(req);
    if (s) sessions.delete(s.id);
    return send(res, 200, { ok: true }, { "Set-Cookie": "zx_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict" });
  }

  // everything else is admin-only
  const session = sessionFrom(req);
  if (!session) return send(res, 401, JSON.stringify({ ok: false, error: "Not signed in" }), { "WWW-Authenticate": 'Bearer realm="zehnox-admin"' });

  if (p === "/api/me") {
    if (method !== "GET") return fail(res, 405, "Method not allowed");
    return sendJson(res, 200, { ok: true, username: session.username });
  }

  if (p === "/api/account") {
    if (method !== "POST") return fail(res, 405, "Method not allowed");
    const body = await readJson(req, 64 * 1024);
    const current = body && typeof body.currentPassword === "string" ? body.currentPassword : "";
    if (!verifyPassword(current)) { await delay(500); return fail(res, 403, "The current password is wrong"); }
    const a = readAuth();
    const username = body.username == null || String(body.username).trim() === "" ? a.username : str(body.username, 80);
    const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";
    if (!/^[a-z0-9][a-z0-9._-]{2,39}$/i.test(username)) return fail(res, 400, "Username must be 3–40 characters: letters, digits, dots, dashes or underscores");
    if (newPassword && newPassword.length < 8) return fail(res, 400, "The new password must be at least 8 characters");
    if (newPassword.length > 200) return fail(res, 400, "The new password is too long");
    if (!newPassword && username === a.username) return fail(res, 400, "Nothing to change");
    writeAuth(username, newPassword || current);
    try { fs.unlinkSync(INITIAL_PW_FILE); } catch (_) { /* already gone */ }
    for (const [k] of sessions) if (k !== session.id) sessions.delete(k);   // other devices must sign in again
    sessions.get(session.id).username = username;
    log("admin account updated (username: " + username + (newPassword ? ", new password" : "") + ")");
    return sendJson(res, 200, { ok: true, username });
  }

  if (p === "/api/content") {
    if (method === "GET") {
      const c = readContentSafe();
      if (!c) return fail(res, 500, "content.json could not be read");
      return sendJson(res, 200, c);
    }
    if (method === "PUT") {
      const body = await readJson(req, JSON_LIMIT);
      const problem = validateContentShape(body);
      if (problem) return fail(res, 400, problem);
      writeFileAtomic(CONTENT_FILE, JSON.stringify(body, null, 2) + "\n");
      log("content.json updated");
      try {
        const result = await runBuild();
        return sendJson(res, 200, { ok: true, saved: true, build: { ms: result.ms, stats: result.stats, messages: result.messages } });
      } catch (e) {
        logErr("build after save failed:", e.message);
        return sendJson(res, 500, { ok: false, saved: true, error: "Saved, but build failed: " + e.message });
      }
    }
    return fail(res, 405, "Method not allowed");
  }

  if (p === "/api/build") {
    if (method !== "POST") return fail(res, 405, "Method not allowed");
    try {
      const result = await runBuild();
      return sendJson(res, 200, { ok: true, build: { ms: result.ms, stats: result.stats, messages: result.messages } });
    } catch (e) {
      logErr("build failed:", e.message);
      return fail(res, 500, "Build failed: " + e.message);
    }
  }

  if (p === "/api/upload") {
    if (method !== "POST") return fail(res, 405, "Method not allowed");
    const body = await readJson(req, UPLOAD_LIMIT);
    if (!body || typeof body !== "object") return fail(res, 400, "Body must be a JSON object");
    const dataUrl = typeof body.dataUrl === "string" ? body.dataUrl : "";
    const m = /^data:([a-z0-9.+/-]+);base64,([A-Za-z0-9+/=\s]+)$/i.exec(dataUrl);
    if (!m) return fail(res, 400, "dataUrl must be a base64 data: URL");
    const mime = m[1].toLowerCase();
    const ext = IMAGE_TYPES[mime];
    if (!ext) return fail(res, 415, "Only PNG, JPG, WEBP and SVG images are accepted");
    const bytes = Buffer.from(m[2].replace(/\s+/g, ""), "base64");
    if (!bytes.length) return fail(res, 400, "Empty file");
    if (bytes.length > MAX_FILE_BYTES) return fail(res, 413, "File is larger than 5 MB");
    const givenExt = path.extname(String(body.name || "")).toLowerCase();
    const finalExt = ALLOWED_EXT.has(givenExt) && (givenExt === ext || (givenExt === ".jpeg" && ext === ".jpg")) ? givenExt : ext;
    fs.mkdirSync(UPLOADS, { recursive: true });
    const filename = uniquePath(UPLOADS, safeUploadName(body.name, finalExt));
    fs.writeFileSync(path.join(UPLOADS, filename), bytes);
    // make it available on the live site immediately (dist mirrors src/uploads on the next build anyway)
    try { fs.mkdirSync(path.join(DIST, "uploads"), { recursive: true }); fs.writeFileSync(path.join(DIST, "uploads", filename), bytes); } catch (e) { logErr("could not mirror upload into dist:", e.message); }
    log("upload saved: uploads/" + filename + " (" + bytes.length + " bytes)");
    return sendJson(res, 201, { ok: true, path: "uploads/" + filename, bytes: bytes.length });
  }

  if (p === "/api/inquiries") {
    if (method !== "GET") return fail(res, 405, "Method not allowed");
    return sendJson(res, 200, readInquiries().slice().reverse());
  }

  const del = /^\/api\/inquiries\/([A-Za-z0-9-]{1,80})$/.exec(p);
  if (del) {
    if (method !== "DELETE") return fail(res, 405, "Method not allowed");
    const list = readInquiries();
    const next = list.filter((i) => i && i.id !== del[1]);
    if (next.length === list.length) return fail(res, 404, "Inquiry not found");
    writeInquiries(next);
    log("inquiry deleted " + del[1]);
    return sendJson(res, 200, { ok: true, id: del[1] });
  }

  return fail(res, 404, "Unknown API route");
}

/* ---------- request router ---------- */
async function handle(req, res) {
  let url;
  try { url = new URL(req.url || "/", "http://" + (req.headers.host || "localhost")); }
  catch (_) { return fail(res, 400, "Bad request"); }
  const p = url.pathname;

  cors(req, res);
  if (req.method === "OPTIONS") { res.writeHead(res.getHeader("Access-Control-Allow-Origin") ? 204 : 403); res.end(); return; }

  if (p === "/api" || p.startsWith("/api/")) {
    try { await handleApi(req, res, url); }
    catch (e) {
      const status = e && e.status ? e.status : 500;
      if (status >= 500) logErr("api error", req.method, p, e && e.stack ? e.stack : e);
      if (res.headersSent) { res.destroy(); return; }
      if (status === 413) {
        // body was cut short: answer, then close the connection so the client stops sending
        res.setHeader("Connection", "close");
        res.once("finish", () => { try { req.socket.destroy(); } catch (_) { /* ignore */ } });
      }
      fail(res, status, status >= 500 ? "Internal server error" : e.message);
    }
    return;
  }

  if (req.method !== "GET" && req.method !== "HEAD") return fail(res, 405, "Method not allowed");

  if (p === "/admin") { res.writeHead(301, { Location: "/admin/" + url.search }); res.end(); return; }
  if (p.startsWith("/admin/")) {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Robots-Tag", "noindex, nofollow");
    return serveStatic(req, res, ADMIN, p.slice("/admin".length), () => send(res, 404, "Admin file not found", { "Content-Type": "text/plain; charset=utf-8" }));
  }

  /* Pages live on disk as about.html but are served at /about. Both used to answer 200,
     which is duplicate content as far as a search engine is concerned, so the file form
     permanently redirects to the route. Only for files that actually exist — anything else
     must still reach the 404 page. */
  if (/\.html$/i.test(p) && statFile(resolveStatic(DIST, p))) {
    let clean = p.replace(/\.html$/i, "");
    if (clean.endsWith("/index")) clean = clean.slice(0, -"index".length);
    if (!clean) clean = "/";
    res.writeHead(301, { Location: clean + url.search, "Cache-Control": "no-cache" });
    res.end();
    return;
  }

  return serveStatic(req, res, DIST, p, () => notFoundPage(req, res));
}

/* ---------- start ---------- */
async function start() {
  if (!statFile(path.join(DIST, "index.html"))) {
    log("dist/ is missing — running an initial build");
    try { await runBuild(); } catch (e) { logErr("initial build failed:", e.message); }
  }
  const server = http.createServer((req, res) => {
    handle(req, res).catch((e) => {
      logErr("unhandled", e && e.stack ? e.stack : e);
      try { if (!res.headersSent) fail(res, 500, "Internal server error"); else res.destroy(); } catch (_) { /* ignore */ }
    });
  });
  server.keepAliveTimeout = 5000;
  server.headersTimeout = 10000;
  server.requestTimeout = 30000;
  server.on("clientError", (err, socket) => { if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"); });
  server.on("error", (e) => { logErr("server error:", e.message); if (e.code === "EADDRINUSE") process.exit(1); });
  server.listen(PORT, HOST, () => {
    const shownHost = HOST === "0.0.0.0" || HOST === "::" ? "localhost" : HOST;
    console.log("");
    console.log("ZEHNOX site server");
    console.log("  site   : http://" + shownHost + ":" + PORT + "/");
    console.log("  admin  : http://" + shownHost + ":" + PORT + "/admin/");
    const a = readAuth();
    console.log("  user   : " + (a ? a.username : "admin"));
    if (generatedPassword) console.log("  pass   : " + generatedPassword + "   (first run — also saved in data/initial-password.txt)");
    else console.log("  pass   : (set in /admin/ → Account; to reset, delete data/admin-auth.json and restart)");
    console.log("");
  });
  const stop = () => { log("shutting down"); server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 2000).unref(); };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

process.on("uncaughtException", (e) => logErr("uncaughtException", e && e.stack ? e.stack : e));
process.on("unhandledRejection", (e) => logErr("unhandledRejection", e && e.stack ? e.stack : e));

start();
