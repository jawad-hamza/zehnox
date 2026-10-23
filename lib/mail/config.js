"use strict";
/* Mail configuration from the environment (DESIGN.md sections 6.2, 10.1 and 13.4).

   loadMailConfig(env) -> { cfg, keys, warnings }
     cfg       frozen, non-secret settings (safe to inspect, never contains a key)
     keys      { service: { kid, key: Buffer } | null, secrets: Buffer | null }
               The caller (index.js) keeps these in a closure and hands the Buffers only to
               the VPS provider and the SMTP secret store. They are never exported,
               logged, serialized or put into an Error.
     warnings  fixed codes (no values) for a one-time startup log line

   Keys come from files (preferred: *_KEY_FILE, a read-only bind mount, which keeps them
   out of `docker inspect`) or, for development and tests, from 64-hex env values. Once
   read, the env values are deleted from process.env so child environments and later
   /proc/self/environ reads by code in this process do not see them. */

const fs = require("fs");
const { PINNED_DOMAIN } = require("./core/constants.js");

const HEX64 = /^[0-9a-fA-F]{64}$/;
const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
/* Env names that hold key material. MAIL_SECRET_KEY is accepted as an alias of
   MAIL_SECRETS_KEY (the singular spelling is an easy slip in a .env file). */
const SECRET_ENV = ["MAIL_SERVICE_KEY", "MAIL_SECRETS_KEY", "MAIL_SECRET_KEY"];

const str = (v) => (typeof v === "string" ? v.trim() : "");

/* -> { buf, error } where error is a fixed code. The file content is never echoed. */
function readKey(fileVar, valueVar, env, altValueVar) {
  const file = str(env[fileVar]);
  if (file) {
    let text;
    try { text = fs.readFileSync(file, "utf8").trim(); } catch (_) { return { buf: null, error: fileVar.toLowerCase() + "_unreadable" }; }
    if (!HEX64.test(text)) return { buf: null, error: fileVar.toLowerCase() + "_invalid" };
    return { buf: Buffer.from(text, "hex"), error: null };
  }
  const raw = str(env[valueVar]) || (altValueVar ? str(env[altValueVar]) : "");
  if (!raw) return { buf: null, error: null };
  if (!HEX64.test(raw)) return { buf: null, error: valueVar.toLowerCase() + "_invalid" };
  return { buf: Buffer.from(raw, "hex"), error: null };
}

function list(v, lower) {
  return str(v).split(",").map((x) => (lower ? x.trim().toLowerCase() : x.trim())).filter(Boolean);
}

function loadMailConfig(envIn) {
  const env = envIn || process.env;
  const warnings = [];
  const nodeEnv = str(env.NODE_ENV);
  const production = nodeEnv === "production";

  const service = readKey("MAIL_SERVICE_KEY_FILE", "MAIL_SERVICE_KEY", env);
  const secrets = readKey("MAIL_SECRETS_KEY_FILE", "MAIL_SECRETS_KEY", env, "MAIL_SECRET_KEY");
  if (service.error) warnings.push(service.error);
  if (secrets.error) warnings.push(secrets.error);
  for (const k of SECRET_ENV) if (Object.prototype.hasOwnProperty.call(env, k)) delete env[k];

  const kid = str(env.MAIL_SERVICE_KEY_ID) || "k1";
  if (!/^[a-z0-9]{1,16}$/.test(kid)) warnings.push("mail_service_key_id_invalid");

  const dnsServers = list(env.MAIL_DNS_SERVERS).filter((ip) => {
    if (IPV4_RE.test(ip)) return true;
    warnings.push("mail_dns_servers_invalid");
    return false;
  });
  const hostname = str(env.MAIL_HOSTNAME).toLowerCase().replace(/\.$/, "");
  if (hostname && !HOST_RE.test(hostname)) warnings.push("mail_hostname_invalid");
  const ipv4 = str(env.MAIL_SERVER_IPV4);
  if (ipv4 && !IPV4_RE.test(ipv4)) warnings.push("mail_server_ipv4_invalid");
  const selector = str(env.MAIL_DKIM_SELECTOR);
  if (selector && !/^[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?$/i.test(selector)) warnings.push("mail_dkim_selector_invalid");
  const rounds = parseInt(str(env.MAIL_HASH_ROUNDS), 10);
  const allowRaw = str(env.MAIL_SMTP_HOST_ALLOWLIST);
  const portsRaw = str(env.MAIL_SMTP_PORT_ALLOWLIST);
  const ports = list(portsRaw).map((p) => (/^\d{1,5}$/.test(p) ? parseInt(p, 10) : NaN));
  if (ports.some((p) => !(p >= 1 && p <= 65535))) warnings.push("mail_smtp_port_allowlist_invalid");

  const cfg = Object.freeze({
    nodeEnv,
    production,
    providerSetting: str(env.MAIL_PROVIDER).toLowerCase(),        // '', 'mock', 'vps', 'none'
    domain: str(env.MAIL_DOMAIN).toLowerCase() || PINNED_DOMAIN,
    allowMockInProduction: str(env.MAIL_ALLOW_MOCK_IN_PRODUCTION) === "1",
    socketPath: str(env.MAIL_SERVICE_SOCKET),
    serviceKeyId: /^[a-z0-9]{1,16}$/.test(kid) ? kid : null,
    hasServiceKey: !!service.buf,
    hasSecretsKey: !!secrets.buf,
    hostname: hostname && HOST_RE.test(hostname) ? hostname : "",
    serverIpv4: ipv4 && IPV4_RE.test(ipv4) ? ipv4 : "",
    dkimSelector: selector && /^[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?$/i.test(selector) ? selector.toLowerCase() : "",
    dmarcRua: str(env.MAIL_DMARC_RUA) || "postmaster@" + PINNED_DOMAIN,
    dnsServers: Object.freeze(dnsServers),
    /* null = unset. website-smtp.js applies the production default (MAIL_HOSTNAME plus env
       SMTP_HOST) and the "empty means refuse everything" rule. */
    smtpHostAllowlist: allowRaw ? Object.freeze(list(allowRaw, true)) : null,
    /* null = unset: website-smtp.js allows the standard submission ports plus env SMTP_PORT.
       Set only by the operator (tests use it to reach their fake servers on high ports). */
    smtpPortAllowlist: portsRaw ? Object.freeze(ports.filter((p) => p >= 1 && p <= 65535)) : null,
    bootstrapForward: str(env.MAIL_BOOTSTRAP_FORWARD),
    hashRounds: Number.isSafeInteger(rounds) && rounds > 0 ? rounds : 100000,
    passwordScheme: str(env.MAIL_PASSWORD_SCHEME).toUpperCase() === "ARGON2ID" ? "ARGON2ID" : "SHA512-CRYPT",
    ehloName: str(env.SMTP_EHLO_NAME) || PINNED_DOMAIN,
    smtpLock: str(env.SMTP_LOCK) === "1",
    mock: Object.freeze({
      seed: str(env.MAIL_MOCK_SEED) === "1",
      caps: str(env.MAIL_MOCK_CAPS).toLowerCase() === "forward-only" ? "forward-only" : "full",
      status: ["online", "degraded", "offline"].includes(str(env.MAIL_MOCK_STATUS)) ? str(env.MAIL_MOCK_STATUS) : "online",
      fail: ["unavailable", "backend_failed", "slow"].includes(str(env.MAIL_MOCK_FAIL)) ? str(env.MAIL_MOCK_FAIL) : "",
      realDns: str(env.MAIL_MOCK_REAL_DNS) === "1",
    }),
  });

  const keys = {
    service: service.buf && cfg.serviceKeyId ? { kid: cfg.serviceKeyId, key: service.buf } : null,
    secrets: secrets.buf,
  };
  return { cfg, keys, warnings };
}

module.exports = { loadMailConfig, HOST_RE, IPV4_RE, SECRET_ENV };
