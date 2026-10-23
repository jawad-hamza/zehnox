"use strict";
/* Shared constants for the mail module. Pure: stdlib only, Node >= 18, no fs, net or subprocess modules.

   This directory (lib/mail/core/) is copied verbatim onto the VPS next to the privileged
   daemon (docs/mail/DESIGN.md section 5.1), so the web process and the daemon enforce the
   exact same rules from the exact same bytes. Nothing in here may read the environment,
   touch the disk or open a socket: the daemon runs under ProtectSystem=strict and the
   manifest check compares these files byte for byte. */

/* D4: the domain is a constant, never an input. No verb, route or body can name another
   domain, so a hijacked admin session can at worst edit zehnox.com. */
const PINNED_DOMAIN = "zehnox.com";

/* System and service account names. Letting the admin create "root@" or "postfix@" would
   collide with local delivery on the shared host and confuse bounce handling. */
const RESERVED = Object.freeze([
  "root", "daemon", "bin", "sys", "sync", "nobody", "mailer-daemon", "postfix", "dovecot",
  "opendkim", "vmail", "www-data", "zehnox-mail", "nginx", "docker",
]);

/* RFC 2142 role addresses. They must always deliver somewhere, so they are created by the
   system as forwards and can be re-pointed but never deleted, disabled, emptied or turned
   into a mailbox (a mailbox would add a SASL login nobody asked for). */
const PROTECTED = Object.freeze(["postmaster", "abuse"]);

const LIMITS = Object.freeze({
  maxAddresses: 200,
  maxForwardsPerAddress: 10,
  maxExternalDestinationsTotal: 300,
  minRounds: 50000,        // production floor for SHA512-CRYPT; the mock may use 1000 under NODE_ENV=test
  maxRounds: 1000000,
  frameMax: 16384,         // one request frame, bytes, including the trailing LF
  responseMax: 262144,     // one response frame, bytes
  destMax: 254,            // RFC 5321 path length
  auditTailMax: 200,
  /* Deleted-address markers kept in state.json. Without a cap, create/delete cycles grow
     listAddresses past responseMax and lock the panel out for good. Markers without stored
     mail (hadMailbox:false) are dropped oldest first; past the cap with stored mail on every
     one, deleteAddress is refused (limit_tombstones) until the owner purges some. */
  maxTombstones: 200,
});

/* The frozen verb table (section 5.4). A test asserts Object.keys(VERBS) equals this list
   exactly: there is no generic dispatch, and adding a verb must be a reviewed change here. */
const VERBS = Object.freeze({
  getMailStatus:         Object.freeze({ kind: "read" }),
  listAddresses:         Object.freeze({ kind: "read" }),
  getAuditTail:          Object.freeze({ kind: "read" }),
  createAddress:         Object.freeze({ kind: "mutate" }),
  deleteAddress:         Object.freeze({ kind: "mutate" }),
  setForwarding:         Object.freeze({ kind: "mutate" }),
  removeForwarding:      Object.freeze({ kind: "mutate" }),
  setAddressEnabled:     Object.freeze({ kind: "mutate" }),
  createMailbox:         Object.freeze({ kind: "mutate" }),
  disableMailbox:        Object.freeze({ kind: "mutate" }),
  enableMailbox:         Object.freeze({ kind: "mutate" }),
  changeMailboxPassword: Object.freeze({ kind: "mutate" }),
});
const VERB_NAMES = Object.freeze(Object.keys(VERBS));

/* Verbs that take access away. The daemon applies dovecot/passwd before the Postfix maps
   for these, so a failure half way leaves the more restrictive file already live. */
const ACCESS_REDUCING = Object.freeze(["disableMailbox", "deleteAddress", "setAddressEnabled", "changeMailboxPassword"]);

/* 1 to 64 characters, alphanumeric at both ends, single separators only. No "+" (the
   recipient delimiter), no "@", no quotes, no whitespace, no unicode. */
const LOCAL_RE = /^[a-z0-9](?:[a-z0-9]|[._-](?=[a-z0-9])){0,63}$/;
/* Forwarding destination. Deliberately narrower than RFC 5322: no quoted local parts, no
   IP literals, no bare hosts, nothing Postfix could read as a pipe, file or :include:.
   No "%" either: with allow_percent_hack (on by default) Postfix reads user%host@relay as a
   route through relay, which would turn a forward into a relay to any host. */
const DEST_RE = /^[A-Za-z0-9._+=-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
/* A rendered map key: always a valid local part at the pinned domain. */
const KEY_RE = /^[a-z0-9](?:[a-z0-9]|[._-](?=[a-z0-9])){0,63}@zehnox\.com$/;

/* Password hash formats accepted on the wire (section 3.4). The daemon never sees plaintext. */
const SHA512_HASH_RE = /^\{SHA512-CRYPT\}\$6\$rounds=(\d{4,7})\$[./0-9A-Za-z]{16}\$[./0-9A-Za-z]{86}$/;
const ARGON2_HASH_RE = /^\{ARGON2ID\}\$argon2id\$v=19\$m=(\d+),t=(\d+),p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/;
const ARGON2_MIN = Object.freeze({ m: 19456, t: 2 });

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ACTOR_USER_RE = /^[A-Za-z0-9._@-]{1,64}$/;
const ACTOR_IP_RE = /^[0-9A-Fa-f:.]{2,45}$/;

/* The closed set of public error codes (section 4.1). Messages are constants: upstream text
   from the daemon, SMTP or DNS is never passed through to a response. */
const ERROR_CODES = Object.freeze({
  invalid_body:            { status: 400, message: "The request body is not valid." },
  unknown_field:           { status: 400, message: "The request contains a field that is not allowed." },
  missing_idempotency_key: { status: 400, message: "This request needs an Idempotency-Key header." },
  invalid_local:           { status: 400, message: "Use lowercase letters, digits, dot, dash or underscore (1-64). Enter only the part before @zehnox.com." },
  reserved_local:          { status: 400, message: "That name is reserved by the mail system." },
  invalid_destination:     { status: 400, message: "One of the forwarding addresses is not a valid email address." },
  self_destination:        { status: 400, message: "An address cannot forward to itself." },
  destination_not_mailbox: { status: 400, message: "Forwarding to a zehnox.com address is only allowed to an enabled mailbox." },
  too_many_destinations:   { status: 400, message: "An address can forward to at most 10 destinations." },
  domain_destination_cap:  { status: 409, message: "The domain has reached its limit of 300 forwarding destinations." },
  weak_password:           { status: 400, message: "That password is too weak." },
  confirm_mismatch:        { status: 400, message: "Type the full address to confirm." },
  host_not_allowed:        { status: 400, message: "That SMTP host is not on the server's allowlist." },
  port_not_allowed:        { status: 400, message: "That SMTP port is not allowed. Use 587 (STARTTLS) or 465 (implicit TLS)." },
  recipient_not_allowed:   { status: 400, message: "Test messages can only go to the inquiry recipient or a zehnox.com address." },
  protected:               { status: 403, message: "This system address is required and cannot be changed this way." },
  not_found:               { status: 404, message: "No such address." },
  method_not_allowed:      { status: 405, message: "This method is not allowed here." },
  unsupported_media_type:  { status: 415, message: "Send JSON." },
  body_too_large:          { status: 413, message: "The request body is too large." },
  duplicate:               { status: 409, message: "That address already exists." },
  tombstoned:              { status: 409, message: "This address was deleted and its stored mail still exists. Confirm reuse to continue." },
  no_destination:          { status: 409, message: "The change would leave the address with nowhere to deliver mail." },
  in_use:                  { status: 409, message: "Other addresses forward here. Change them first." },
  conflict_rev:            { status: 409, message: "Mail settings changed elsewhere. The list has been reloaded; try again." },
  idempotency_mismatch:    { status: 409, message: "This request key was already used for a different change." },
  capability_missing:      { status: 409, message: "Mailboxes are not enabled on the mail server yet." },
  limit_addresses:         { status: 409, message: "The domain has reached its limit of 200 addresses." },
  limit_tombstones:        { status: 409, message: "Too many deleted addresses still have stored mail on the server. Ask the server owner to purge old ones first." },
  smtp_locked:             { status: 409, message: "Website email settings are managed on the server." },
  not_eligible:            { status: 409, message: "A new random password can only be used when the sender is a mailbox signed in as itself." },
  rate_limited:            { status: 429, message: "Too many requests. Try again later." },
  busy:                    { status: 429, message: "The server is busy. Try again in a moment." },
  internal:                { status: 500, message: "Something went wrong on the server." },
  rotate_not_saved:        { status: 500, message: "Password rotated on the mail server but could not be saved here. Rotate again." },
  backend_failed:          { status: 502, message: "The mail service could not apply the change; nothing was modified." },
  bad_response:            { status: 502, message: "The mail service response could not be verified." },
  not_connected:           { status: 503, message: "Email service not connected." },
  unavailable:             { status: 503, message: "The mail service is not reachable." },
  domain_mismatch:         { status: 503, message: "The mail service is configured for a different domain." },
  not_ready:               { status: 503, message: "The mail service is repairing its files. Try again shortly." },
  secrets_key_missing:     { status: 503, message: "The server has no key for storing SMTP passwords." },
});

/* Codes the daemon may put on the wire (its closed enum). Everything the core can throw is
   here; the protocol-only codes (unauthorized, replay, ...) are the daemon's own. The VPS
   provider maps any code outside this set to backend_failed. */
const DAEMON_CODES = Object.freeze([
  // core rule failures (map 1:1 onto ERROR_CODES)
  "invalid_local", "reserved_local", "invalid_destination", "self_destination", "destination_not_mailbox",
  "too_many_destinations", "domain_destination_cap", "confirm_mismatch", "protected", "not_found",
  "duplicate", "tombstoned", "no_destination", "in_use", "conflict_rev", "idempotency_mismatch",
  "capability_missing", "limit_addresses", "limit_tombstones", "rate_limited", "busy", "backend_failed", "not_ready",
  "domain_mismatch",
  // daemon/protocol only (map to backend_failed publicly: the web side sent something wrong)
  "unauthorized", "bad_request", "unknown_verb", "replay", "stale", "invalid_hash", "weak_rounds",
]);

/* Thrown by the pure core and by the protocol checks. `code` is always from DAEMON_CODES;
   `refs` carries validated local parts only (for in_use). No message ever holds input. */
class CoreError extends Error {
  constructor(code, extra) {
    super(code);
    this.name = "CoreError";
    this.code = code;
    if (extra && extra.field) this.field = extra.field;
    if (extra && Array.isArray(extra.refs)) this.refs = extra.refs.slice();
  }
}

module.exports = {
  PINNED_DOMAIN, RESERVED, PROTECTED, LIMITS, VERBS, VERB_NAMES, ACCESS_REDUCING,
  LOCAL_RE, DEST_RE, KEY_RE, SHA512_HASH_RE, ARGON2_HASH_RE, ARGON2_MIN,
  UUID_V4_RE, ACTOR_USER_RE, ACTOR_IP_RE,
  ERROR_CODES, DAEMON_CODES, CoreError,
};
