"use strict";
/* Entry point of the mail module for server.js (DESIGN.md sections 4.2 and 9).

   const mail = require("./lib/mail");
   mail.configure({ dataDir: DATA, log, logErr })   // optional; defaults match server.js
   mail.getProvider()     MailProvider singleton (mock | vps | none), chosen once
   mail.smtp.config()     effective website SMTP settings, password decrypted now
   mail.smtp.ready()      boolean
   mail.me()              { provider, connected, mock } for /api/me (booleans + kind only)

   The configuration (and so the key material) is loaded when this file is first required:
   the key env values are deleted from process.env right away, before any request is
   served or any child environment could be built. Everything else is created lazily. */

const path = require("path");
const { loadMailConfig } = require("./config.js");
const C = require("./core/constants.js");
const P = require("./provider.js");
const crypt = require("./crypt.js");
const { sendMail } = require("../../smtp.js");

/* createMailModule is exported so tests can build an isolated instance from their own env
   and data dir. The default export below is the process-wide singleton. */
function createMailModule(opts) {
  const o = opts || {};
  const loaded = loadMailConfig(o.env || process.env);
  const cfg = loaded.cfg;
  const keys = loaded.keys; // stays in this closure
  let dataDir = o.dataDir || null;
  let log = o.log || ((...a) => console.log(new Date().toISOString(), ...a));
  let logErr = o.logErr || ((...a) => console.error(new Date().toISOString(), ...a));
  let provider = null;
  let smtpStore = null;
  let hashPool = null;
  let audit = null;
  let health = null;
  let warned = false;
  const seenWarnings = new Set();

  const warnOnce = (msg) => { if (!seenWarnings.has(msg)) { seenWarnings.add(msg); logErr(msg); } };

  function configure(c) {
    if (c && c.dataDir) dataDir = c.dataDir;
    if (c && c.log) log = c.log;
    if (c && c.logErr) logErr = c.logErr;
  }
  const dataRoot = () => path.resolve(dataDir || process.env.DATA_DIR || path.join(__dirname, "..", "..", "data"));
  const mailDir = () => path.join(dataRoot(), "mail");

  function startupWarnings() {
    if (warned) return;
    warned = true;
    // Fixed codes only: a key's value or path content never reaches a log line.
    for (const w of loaded.warnings) warnOnce("mail: config warning " + w);
  }

  function getSmtp() {
    if (!smtpStore) {
      const { createWebsiteSmtp } = require("./website-smtp.js");
      smtpStore = createWebsiteSmtp({ dir: mailDir(), secretsKey: keys.secrets, cfg, env: o.env || process.env });
    }
    return smtpStore;
  }

  function getHealth(kind) {
    if (!health) {
      const H = require("./dns-health.js");
      const hcfg = { mailHostname: cfg.hostname, serverIpv4: cfg.serverIpv4, dkimSelector: cfg.dkimSelector, dmarcRua: cfg.dmarcRua, ehloName: cfg.ehloName, dnsServers: cfg.dnsServers };
      if (kind === "mock" && !cfg.mock.realDns) {
        /* Mock mode: fixed answers, no network. A placeholder host keeps every row
           renderable when MAIL_HOSTNAME is unset in development. */
        const host = cfg.hostname || "mail.example.invalid";
        health = H.createHealthChecker({ cfg: Object.assign({}, hcfg, { mailHostname: host }), resolver: H.fakeResolver(host), probe: H.fakeProbe(host) });
      } else {
        health = H.createHealthChecker({ cfg: hcfg });
      }
    }
    return health;
  }

  function deps(kind) {
    const { createSmtpTester } = require("./smtp-test.js");
    return { health: getHealth(kind), smtpTester: createSmtpTester({ smtp: getSmtp(), sendMail: o.sendMail || sendMail }) };
  }

  /* Selection rules, section 4.2. Production never silently mocks (D12). */
  function getProvider() {
    if (provider) return provider;
    startupWarnings();
    const setting = cfg.providerSetting;
    if (cfg.domain !== C.PINNED_DOMAIN) {
      warnOnce("mail: MAIL_DOMAIN is not " + C.PINNED_DOMAIN + "; mail management is disabled");
      provider = new P.NullProvider({ reason: "domain_mismatch" }, deps("none"));
    } else if (setting === "vps") {
      if (!cfg.socketPath || !keys.service) {
        warnOnce("mail: MAIL_PROVIDER=vps needs MAIL_SERVICE_SOCKET and a service key; mail management is disabled");
        provider = new P.NullProvider({ reason: "not_connected" }, deps("none"));
      } else {
        const { VpsMailProvider } = require("./vps-provider.js");
        provider = new VpsMailProvider({ socketPath: cfg.socketPath, kid: keys.service.kid, key: keys.service.key }, deps("vps"));
      }
    } else if (setting === "mock" || (setting === "" && !cfg.production)) {
      if (cfg.production && !cfg.allowMockInProduction) {
        logErr("mail: MAIL_PROVIDER=mock is refused in production (set MAIL_ALLOW_MOCK_IN_PRODUCTION=1 for staging only)");
        provider = new P.NullProvider({ reason: "not_connected" }, deps("none"));
      } else {
        const { MockMailProvider } = require("./mock-provider.js");
        provider = new MockMailProvider({ dir: path.join(mailDir(), "mock"), cfg }, deps("mock"));
      }
    } else {
      if (setting && setting !== "none") warnOnce("mail: unknown MAIL_PROVIDER value; mail management is disabled");
      provider = new P.NullProvider({ reason: "not_connected" }, deps("none"));
    }
    return provider;
  }

  function getHashPool() {
    if (!hashPool) hashPool = require("./hash-pool.js").createHashPool();
    return hashPool;
  }

  function getAudit() {
    if (!audit) {
      const { createAppAudit } = require("./audit.js");
      audit = createAppAudit({ file: path.join(mailDir(), "audit.jsonl"), provider: () => getProvider().kind, logErr });
    }
    return audit;
  }

  /* Options for hashPool.hash(). Rounds are clamped to the floor the receiving side
     enforces, so a low MAIL_HASH_ROUNDS fails loudly at startup-time config, not per hash.
     ARGON2ID is used only when requested, available in this Node, and advertised by the
     mail service. */
  function hashOptions(capabilities) {
    const minRounds = cfg.nodeEnv === "test" ? 1000 : C.LIMITS.minRounds;
    let rounds = cfg.hashRounds;
    if (rounds < minRounds) { warnOnce("mail: MAIL_HASH_ROUNDS is below the minimum; using " + minRounds); rounds = minRounds; }
    if (rounds > C.LIMITS.maxRounds) rounds = C.LIMITS.maxRounds;
    const argon = cfg.passwordScheme === "ARGON2ID" && crypt.argon2Available() && capabilities && Array.isArray(capabilities.schemes) && capabilities.schemes.includes("ARGON2ID");
    return { scheme: argon ? "ARGON2ID" : "SHA512-CRYPT", rounds, minRounds };
  }

  /* /api/me: the provider kind and two booleans, nothing else. Synchronous: for the VPS
     provider "connected" is the outcome of the last call to the daemon. */
  function me() {
    const p = getProvider();
    let connected = false;
    if (p.kind === "mock") connected = !(cfg.mock.fail === "unavailable" && !cfg.production);
    else if (p.kind === "vps") connected = p.lastConnected === true;
    return { provider: p.kind, connected, mock: p.kind === "mock" };
  }

  const smtp = {
    config: () => getSmtp().config(),
    ready: () => getSmtp().ready(),
  };

  return {
    configure, getProvider, getSmtp, getHashPool, getAudit, hashOptions, me, smtp,
    mailDir, cfg, log: (...a) => log(...a), logErr: (...a) => logErr(...a),
  };
}

const instance = createMailModule();
module.exports = Object.assign({}, instance, { createMailModule });
