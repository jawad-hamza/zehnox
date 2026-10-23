"use strict";
/* Builds sandboxed zehnox-maild instances for the daemon and VPS-provider tests.

   Every daemon runs with sandbox:true on a temporary state directory, with a key file
   generated now (0600), and with either the fake indexer script (helpers/fake-postmap.js,
   run through the daemon's real execFile) or an injected executor that records argv.
   Nothing here touches Postfix, Dovecot, systemd or a system path. The web process never
   requires the daemon; only these tests do. */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { REPO, CORE, WIN, mkTmp } = require("./common.js");

const DAEMON_FILE = path.join(REPO, "mail-daemon", "zehnox-maild.js");
const FAKE_POSTMAP = path.join(__dirname, "fake-postmap.js");
const maild = require(DAEMON_FILE);
const protocol = require(path.join(CORE, "protocol.js"));
const C = require(path.join(CORE, "constants.js"));

function makeConfig(dir, over) {
  const key = crypto.randomBytes(32);
  const keyFile = path.join(dir, "k1.key");
  fs.writeFileSync(keyFile, key.toString("hex") + "\n", { mode: 0o600 });
  const cfg = Object.assign({
    domain: "zehnox.com", hostname: "mail.example.net", mapType: "hash",
    postmapPath: process.execPath, postmapPreArgs: [FAKE_POSTMAP],
    stateDir: path.join(dir, "state"), bootstrapForward: "owner@example.com",
    mailboxes: { enabled: true, uid: 5000, gid: 5000, homeBase: "/var/vmail/zehnox.com", schemes: ["SHA512-CRYPT"], minRounds: 50000, gate: { senderLoginEnforced: true, outboundRateLimited: true } },
    dkim: { selector: "sbhm1", publicFile: null },
    probes: { smtp: 25, submission: 587, imap: 993 },
    keys: { k1: keyFile },
  }, over || {});
  return { cfg, key };
}

/* Records every indexer call and behaves like a successful postmap (writes <map>.db). */
function recordingExecutor(opts) {
  const o = opts || {};
  const calls = [];
  const fn = (file, argv, options, cb) => {
    calls.push({ file, argv, options });
    const src = String(argv[argv.length - 1]).replace(/^(hash|lmdb):/, "");
    setImmediate(() => {
      if (o.fail && o.fail(path.basename(src), calls.length)) {
        const e = new Error("exit 75");
        e.code = 75;
        return cb(e, "EXECUTOR-STDOUT-CANARY", "EXECUTOR-STDERR-CANARY");
      }
      try { fs.writeFileSync(src + ".db", fs.readFileSync(src)); } catch (_) { /* restoring a missing file */ }
      cb(null, "EXECUTOR-STDOUT-CANARY", "");
    });
  };
  fn.calls = calls;
  return fn;
}

async function newDaemon(opts) {
  const o = opts || {};
  const dir = o.dir || mkTmp("maild");
  const made = o.made || makeConfig(dir, o.over);
  const logs = [];
  const d = maild.createDaemon(Object.assign({ config: made.cfg, sandbox: true, log: (l) => logs.push(String(l)) }, o.extra || {}));
  const started = await d.start({ periodic: false });
  return { d, dir, cfg: made.cfg, key: made.key, made, logs, started };
}

/* The web side of the protocol, in-process: sign, hand the line to handleLine, verify. */
function client(key, kid) {
  const k = kid || "k1";
  const lines = [];
  async function call(d, verb, args, extra) {
    const e = extra || {};
    const mut = C.VERBS[verb] && C.VERBS[verb].kind === "mutate";
    const payload = protocol.buildRequest({ verb, args, idem: e.idem || (mut ? crypto.randomUUID() : undefined), ifRev: e.ifRev, actor: { user: "admin", ip: "127.0.0.1" }, nowMs: e.nowMs || Date.now(), nonce: e.nonce });
    const line = await d.handleLine(protocol.encodeFrame("req", k, key, payload));
    lines.push(line);
    return protocol.verifyResponse(line, k, key, payload.nonce);
  }
  return { call, lines };
}

async function currentRev(d, c) {
  const r = await c.call(d, "listAddresses", {});
  if (!r.ok) throw new Error("listAddresses failed: " + r.error.code);
  return r.result.rev;
}

/* A Unix socket path, or a named pipe on Windows (DESIGN.md section 15). */
function listenTarget(dir) {
  return WIN ? "\\\\.\\pipe\\zehnox-mail-tests-" + crypto.randomBytes(6).toString("hex") : path.join(dir, "mail.sock");
}

module.exports = { maild, protocol, C, DAEMON_FILE, FAKE_POSTMAP, makeConfig, recordingExecutor, newDaemon, client, currentRev, listenTarget };
