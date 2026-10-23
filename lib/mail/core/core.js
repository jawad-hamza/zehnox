"use strict";
/* The pure mail state machine (DESIGN.md section 5.4, "Semantics").

   apply(state, hashes, verb, args, ctx) -> { state, hashes, result, audit, changed }

   Pure: it never mutates its inputs, never reads a clock (ctx.now is passed in), never
   touches the disk. The daemon and the mock provider run this same function, so every
   rule (protected names, references, caps, tombstones) is enforced identically in both,
   and the mock is an honest rehearsal of production. Failures throw CoreError with a code
   from constants.DAEMON_CODES.

   ctx = {
     now: ISO string,                                   // stamped on records
     capabilities: { mailboxes: bool },                 // D10 gate; false refuses every mailbox verb
     hashPolicy: { schemes: ['SHA512-CRYPT'], minRounds },
     forwardDeny: ['mail.example.net', ...]            // optional: domains (and their subdomains)
   }                                                    // no forward may target

   Idempotency and ifRev are the applier's job (they need its stores), but the helpers for
   them live here too so both appliers implement them the same way. */

const crypto = require("crypto");
const C = require("./constants.js");
const V = require("./validate.js");
const S = require("./state.js");
const { CoreError } = C;

/* ---------- helpers ---------- */

const selfAddress = (local) => V.addressOf(local).toLowerCase();

/* Locals whose forwarding list points at `local`@domain. Disabled addresses count too:
   re-enabling one must never resurrect a forward to a target that is gone. */
function referrers(state, local, exceptLocal) {
  const target = selfAddress(local);
  return Object.keys(state.addresses)
    .filter((l) => l !== exceptLocal && l !== local && state.addresses[l].forwards.some((d) => d.toLowerCase() === target))
    .sort();
}

function externalCount(state) {
  let n = 0;
  for (const l of Object.keys(state.addresses)) for (const d of state.addresses[l].forwards) if (!V.isSameDomain(d.toLowerCase())) n++;
  return n;
}

/* True when the destination's domain is one of `deny` or a subdomain of one. The daemon
   passes its own mail host name (and any co-hosted domains the owner lists): a forward to
   root@<mail host> would be delivered locally through /etc/aliases, and one to another
   domain on the shared MTA would reach its mailboxes, neither of which zehnox.com
   addresses may do. */
function deniedDomain(dest, deny) {
  if (!Array.isArray(deny) || !deny.length) return false;
  const dom = V.destDomain(dest.toLowerCase());
  return deny.some((d) => typeof d === "string" && d && (dom === d || dom.endsWith("." + d)));
}

/* Validates a new forwarding list for `local` against the state it will live in. A same-
   domain destination must be an existing, enabled address with an enabled mailbox: that
   makes it a terminal target, so alias chains (and so loops) cannot be built. */
function checkForwards(state, local, list, min, ctx) {
  const forwards = V.cleanForwards(list, { min, max: C.LIMITS.maxForwardsPerAddress });
  const self = selfAddress(local);
  const deny = ctx && ctx.forwardDeny;
  for (const d of forwards) {
    const lower = d.toLowerCase();
    if (lower === self) throw new CoreError("self_destination", { field: "forwards" });
    if (deniedDomain(lower, deny)) throw new CoreError("invalid_destination", { field: "forwards" });
    if (V.isSameDomain(lower)) {
      const tl = lower.slice(0, lower.lastIndexOf("@"));
      const t = V.isValidLocal(tl) && V.hasOwn(state.addresses, tl) ? state.addresses[tl] : null;
      if (!t || !t.enabled || !t.mailbox || !t.mailbox.enabled) throw new CoreError("destination_not_mailbox", { field: "forwards" });
    }
  }
  return forwards;
}

function checkCap(next) {
  if (externalCount(next) > C.LIMITS.maxExternalDestinationsTotal) throw new CoreError("domain_destination_cap", { field: "forwards" });
}

function getRec(state, local) {
  if (!V.hasOwn(state.addresses, local)) throw new CoreError("not_found");
  return state.addresses[local];
}

function needMailboxCap(ctx) {
  if (!ctx.capabilities || ctx.capabilities.mailboxes !== true) throw new CoreError("capability_missing");
}

/* Keeps at most LIMITS.maxTombstones markers. Markers without stored mail only inform (a
   later create of that name needs no confirmation), so the oldest of those go first. A
   marker with stored mail is what makes a reuse of the name an explicit choice, so those
   are never dropped here: past the cap the delete is refused instead. Mutates `tombs`
   (always the fresh clone inside apply). */
function capTombstones(tombs) {
  const max = C.LIMITS.maxTombstones;
  let n = Object.keys(tombs).length;
  if (n <= max) return;
  const droppable = Object.keys(tombs)
    .filter((l) => tombs[l].hadMailbox !== true)
    .sort((a, b) => String(tombs[a].deletedAt || "").localeCompare(String(tombs[b].deletedAt || "")) || (a < b ? -1 : 1));
  for (const l of droppable) {
    if (n <= max) break;
    delete tombs[l];
    n--;
  }
  if (n > max) throw new CoreError("limit_tombstones");
}

/* Deterministic JSON (sorted keys) so equal documents compare and hash equal. */
function canonical(v) {
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (v && typeof v === "object") return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
  return JSON.stringify(v === undefined ? null : v);
}

/* The state minus timestamps and rev: what decides whether anything really changed. */
function substance(state) {
  const out = {};
  for (const l of Object.keys(state.addresses)) {
    const a = state.addresses[l];
    out[l] = { f: a.forwards, e: a.enabled, m: a.mailbox, p: a.protected };
  }
  return canonical({ a: out, t: Object.keys(state.tombstones).sort().map((l) => [l, state.tombstones[l].hadMailbox]) });
}

/* ---------- apply ---------- */

function apply(state, hashes, verb, args, ctx) {
  if (!ctx || typeof ctx.now !== "string") throw new CoreError("bad_request");
  V.checkVerbArgs(verb, args);
  if (C.VERBS[verb].kind !== "mutate") throw new CoreError("bad_request");
  V.checkLocal(args.local);
  const local = args.local;
  const now = ctx.now;
  const next = S.clone(state);
  const nextHashes = S.clone(hashes);
  const policy = ctx.hashPolicy || {};
  let result;
  let detail = {};

  switch (verb) {
    case "createAddress": {
      if (V.isProtected(local)) throw new CoreError("protected");
      if (V.hasOwn(next.addresses, local)) throw new CoreError("duplicate", { field: "local" });
      if (Object.keys(next.addresses).length >= C.LIMITS.maxAddresses) throw new CoreError("limit_addresses");
      const forwards = checkForwards(next, local, args.forwards, 0, ctx);
      if (!forwards.length && !args.mailbox) throw new CoreError("no_destination", { field: "forwards" });
      if (args.mailbox) { needMailboxCap(ctx); V.checkHash(args.mailbox.passwordHash, policy); }
      let resumes = false;
      if (V.hasOwn(next.tombstones, local)) {
        const t = next.tombstones[local];
        if (t.hadMailbox && args.reuseDeleted !== true) throw new CoreError("tombstoned", { field: "local" });
        resumes = t.hadMailbox === true;
        delete next.tombstones[local];
      }
      next.addresses[local] = { forwards, enabled: true, mailbox: args.mailbox ? { enabled: true } : null, protected: false, createdAt: now, updatedAt: now };
      if (args.mailbox) nextHashes.hashes[local] = { hash: args.mailbox.passwordHash, passwordSetAt: now };
      else delete nextHashes.hashes[local];
      checkCap(next);
      result = () => ({ address: S.publicAddress(local, next.addresses[local], nextHashes), resumesExistingMaildir: resumes });
      detail = { type: S.addressType(next.addresses[local]), forwards };
      break;
    }

    case "deleteAddress": {
      const rec = getRec(next, local);
      if (args.confirm !== V.addressOf(local)) throw new CoreError("confirm_mismatch", { field: "confirm" });
      if (rec.protected) throw new CoreError("protected");
      const refs = referrers(next, local);
      if (refs.length) throw new CoreError("in_use", { refs });
      const hadMailbox = !!rec.mailbox;
      detail = { type: S.addressType(rec), mailboxDataRetained: hadMailbox };
      delete next.addresses[local];
      delete nextHashes.hashes[local];
      /* The maildir is never deleted (the owner purges it by hand). The tombstone makes a
         later create of the same name an explicit, confirmed reuse of that stored mail. */
      const prior = V.hasOwn(next.tombstones, local) && next.tombstones[local].hadMailbox === true;
      next.tombstones[local] = { deletedAt: now, hadMailbox: hadMailbox || prior };
      capTombstones(next.tombstones);
      result = () => ({ mailboxDataRetained: hadMailbox });
      break;
    }

    case "setForwarding": {
      const rec = getRec(next, local);
      const before = rec.forwards.slice();
      rec.forwards = checkForwards(next, local, args.forwards, 1, ctx);
      checkCap(next);
      detail = { before, after: rec.forwards.slice() };
      result = () => ({ address: S.publicAddress(local, rec, nextHashes) });
      break;
    }

    case "removeForwarding": {
      const rec = getRec(next, local);
      if (rec.protected) throw new CoreError("protected");
      if (!(rec.mailbox && rec.mailbox.enabled)) throw new CoreError("no_destination");
      detail = { before: rec.forwards.slice() };
      rec.forwards = [];
      result = () => ({ address: S.publicAddress(local, rec, nextHashes) });
      break;
    }

    case "setAddressEnabled": {
      const rec = getRec(next, local);
      if (rec.protected) throw new CoreError("protected");
      if (args.enabled) {
        // Re-validate the stored list: it must still be deliverable as it would be if set now.
        checkForwards(next, local, rec.forwards, 0, ctx);
        if (!rec.forwards.length && !(rec.mailbox && rec.mailbox.enabled)) throw new CoreError("no_destination");
        if (rec.mailbox && rec.mailbox.enabled) needMailboxCap(ctx);
      } else {
        const refs = referrers(next, local);
        if (refs.length) throw new CoreError("in_use", { refs });
      }
      rec.enabled = args.enabled;
      result = () => ({ address: S.publicAddress(local, rec, nextHashes) });
      break;
    }

    case "createMailbox": {
      const rec = getRec(next, local);
      if (rec.protected) throw new CoreError("protected");
      needMailboxCap(ctx);
      if (rec.mailbox && rec.mailbox.enabled) throw new CoreError("duplicate");
      V.checkHash(args.passwordHash, policy);
      rec.mailbox = { enabled: true };
      nextHashes.hashes[local] = { hash: args.passwordHash, passwordSetAt: now };
      detail = {};
      result = () => ({ address: S.publicAddress(local, rec, nextHashes) });
      break;
    }

    case "disableMailbox": {
      const rec = getRec(next, local);
      if (!rec.mailbox) throw new CoreError("not_found");
      if (rec.mailbox.enabled) {
        if (!rec.forwards.length) throw new CoreError("no_destination");
        const refs = referrers(next, local);
        if (refs.length) throw new CoreError("in_use", { refs });
      }
      // The hash is kept so re-enabling needs no new password.
      rec.mailbox = { enabled: false };
      result = () => ({ address: S.publicAddress(local, rec, nextHashes) });
      break;
    }

    case "enableMailbox": {
      const rec = getRec(next, local);
      if (rec.protected) throw new CoreError("protected");
      if (!rec.mailbox || !V.hasOwn(nextHashes.hashes, local)) throw new CoreError("not_found");
      needMailboxCap(ctx);
      rec.mailbox = { enabled: true };
      result = () => ({ address: S.publicAddress(local, rec, nextHashes) });
      break;
    }

    case "changeMailboxPassword": {
      const rec = getRec(next, local);
      if (!rec.mailbox) throw new CoreError("not_found");
      /* The gate covers passwords too: with mailboxes off, a hash planted now would become
         a live login the moment the owner opens the gate again. */
      needMailboxCap(ctx);
      V.checkHash(args.passwordHash, policy);
      nextHashes.hashes[local] = { hash: args.passwordHash, passwordSetAt: now };
      result = () => ({ passwordSetAt: now });
      break;
    }

    default:
      throw new CoreError("unknown_verb");
  }

  const hashChanged = canonical(hashes.hashes) !== canonical(nextHashes.hashes);
  const changed = hashChanged || substance(state) !== substance(next);
  if (!changed) {
    /* No-op: same files, same state, same rev (section 5.4). Report the current view. */
    const view = verb === "deleteAddress" || verb === "createAddress" ? result() : resultFromState(verb, state, hashes, local);
    return { state, hashes, result: Object.assign({ rev: state.rev, changed: false }, view), audit: { verb, target: local, detail }, changed: false };
  }
  if (V.hasOwn(next.addresses, local) && verb !== "createAddress") next.addresses[local].updatedAt = now;
  next.rev = state.rev + 1;
  next.updatedAt = now;
  return { state: next, hashes: nextHashes, result: Object.assign({ rev: next.rev, changed: true }, result()), audit: { verb, target: local, detail }, changed: true };
}

function resultFromState(verb, state, hashes, local) {
  if (verb === "changeMailboxPassword") {
    const h = hashes.hashes[local];
    return { passwordSetAt: h ? h.passwordSetAt : null };
  }
  return { address: S.publicAddress(local, state.addresses[local], hashes) };
}

/* ---------- idempotency (section 5.6 step 2) ---------- */

const IDEM_MAX = 1000;
const IDEM_TTL_MS = 10 * 60 * 1000;

function argsSha256(verb, args) {
  return crypto.createHash("sha256").update(verb + "\n" + canonical(args)).digest("hex");
}

/* Returns the stored response for a repeat of the same request, null for a new key, or
   throws idempotency_mismatch when the key was used for different arguments. Runs before
   the ifRev check so a retry of an already-applied change returns its original success. */
function idemLookup(entries, idem, verb, sha, nowMs) {
  const list = Array.isArray(entries) ? entries : [];
  for (const e of list) {
    if (!e || e.idem !== idem) continue;
    if (typeof e.at === "number" && nowMs - e.at > IDEM_TTL_MS) continue;
    if (e.verb !== verb || e.argsSha256 !== sha) throw new CoreError("idempotency_mismatch");
    return e.response;
  }
  return null;
}

/* Returns a new list with the entry added, expired entries dropped and the size capped. */
function idemRemember(entries, entry, nowMs) {
  const list = (Array.isArray(entries) ? entries : []).filter((e) => e && typeof e.at === "number" && nowMs - e.at <= IDEM_TTL_MS && e.idem !== entry.idem);
  list.push({ idem: entry.idem, argsSha256: entry.argsSha256, verb: entry.verb, response: entry.response, at: nowMs });
  return list.slice(-IDEM_MAX);
}

module.exports = { apply, referrers, externalCount, deniedDomain, capTombstones, canonical, argsSha256, idemLookup, idemRemember, IDEM_MAX, IDEM_TTL_MS };
