"use strict";
/* The mail state document and its public views (DESIGN.md sections 4 and 5.5).

   state.json  { v:1, domain, rev, updatedAt,
                 addresses: { <local>: { forwards, enabled, mailbox: null|{enabled}, protected, createdAt, updatedAt } },
                 tombstones: { <local>: { deletedAt, hadMailbox } } }
   hashes.json { v:1, hashes: { <local>: { hash, passwordSetAt } } }

   Hashes live in their own document so that state.json, the thing that gets logged,
   diffed and backed up most, never holds one. The public serializers below copy fields one
   by one from an allowlist: a hash can only reach a response if someone adds it here. */

const C = require("./constants.js");
const V = require("./validate.js");
const { CoreError } = C;

function emptyState(now) {
  return { v: 1, domain: C.PINNED_DOMAIN, rev: 0, updatedAt: now, addresses: {}, tombstones: {} };
}
function emptyHashes() {
  return { v: 1, hashes: {} };
}

/* First start only (state.json missing): the protected role addresses, forwarding to the
   owner. Deliberately the only way postmaster@ and abuse@ ever come into existence. */
function bootstrapState(bootstrapForward, now) {
  if (!V.isDestination(bootstrapForward) || V.isSameDomain(bootstrapForward)) throw new CoreError("invalid_destination", { field: "bootstrapForward" });
  const s = emptyState(now);
  for (const local of C.PROTECTED) {
    s.addresses[local] = { forwards: [bootstrapForward], enabled: true, mailbox: null, protected: true, createdAt: now, updatedAt: now };
  }
  s.rev = 1;
  return s;
}

/* Re-validates a parsed state document (from disk). Anything unexpected is refused rather
   than repaired: the caller treats it as not_ready so a hand-edited file cannot sneak a
   foreign key into the rendered maps. */
function checkState(s) {
  const bad = () => { throw new CoreError("not_ready"); };
  if (!V.isPlainObject(s) || s.v !== 1 || s.domain !== C.PINNED_DOMAIN || !Number.isSafeInteger(s.rev) || s.rev < 0) bad();
  if (!V.isPlainObject(s.addresses) || !V.isPlainObject(s.tombstones)) bad();
  for (const local of Object.keys(s.addresses)) {
    const a = s.addresses[local];
    if (!V.isValidLocal(local) || !V.isPlainObject(a)) bad();
    if (!Array.isArray(a.forwards) || a.forwards.some((d) => !V.isDestination(d))) bad();
    if (typeof a.enabled !== "boolean" || typeof a.protected !== "boolean") bad();
    if (a.mailbox !== null && !(V.isPlainObject(a.mailbox) && typeof a.mailbox.enabled === "boolean")) bad();
  }
  for (const local of Object.keys(s.tombstones)) {
    const t = s.tombstones[local];
    if (!V.isValidLocal(local) || !V.isPlainObject(t) || typeof t.hadMailbox !== "boolean") bad();
  }
  return s;
}
function checkHashes(h) {
  if (!V.isPlainObject(h) || h.v !== 1 || !V.isPlainObject(h.hashes)) throw new CoreError("not_ready");
  for (const local of Object.keys(h.hashes)) {
    const e = h.hashes[local];
    if (!V.isValidLocal(local) || !V.isPlainObject(e) || typeof e.hash !== "string") throw new CoreError("not_ready");
  }
  return h;
}

/* JSON round trip: the documents are plain JSON by construction, and this is the one clone
   that cannot share a nested array between the old and the new state. */
const clone = (o) => JSON.parse(JSON.stringify(o));

/* type is derived, never stored (section 4). */
function addressType(rec) {
  const box = !!(rec.mailbox && rec.mailbox.enabled);
  if (box && rec.forwards.length) return "mailbox+forward";
  if (box) return "mailbox";
  return "forward";
}

/* The one place a public Address is built from the state (daemon listAddresses and the
   mock). passwordSetAt is the only thing read from the hashes document. */
function publicAddress(local, rec, hashes) {
  const h = hashes && hashes.hashes && V.hasOwn(hashes.hashes, local) ? hashes.hashes[local] : null;
  return {
    local,
    address: V.addressOf(local),
    type: addressType(rec),
    enabled: rec.enabled === true,
    protected: rec.protected === true,
    forwards: rec.forwards.slice(),
    mailbox: rec.mailbox ? { enabled: rec.mailbox.enabled === true, passwordSetAt: h && typeof h.passwordSetAt === "string" ? h.passwordSetAt : null } : null,
    createdAt: rec.createdAt || null,
    updatedAt: rec.updatedAt || null,
  };
}

function publicTombstone(local, t) {
  return { local, deletedAt: t.deletedAt || null, hadMailbox: t.hadMailbox === true };
}

/* listAddresses result, sorted by local part so the UI and golden tests are stable. At most
   LIMITS.maxTombstones markers are listed (the newest), so a state that grew past the cap
   before it existed, or was edited by hand, still fits one response frame: listAddresses is
   the only way the web learns rev, so it must never fail on size. */
function listView(state, hashes) {
  const locals = Object.keys(state.addresses).sort();
  const t = state.tombstones;
  const newest = Object.keys(t)
    .sort((a, b) => String(t[b].deletedAt || "").localeCompare(String(t[a].deletedAt || "")) || (a < b ? -1 : 1))
    .slice(0, C.LIMITS.maxTombstones)
    .sort();
  return {
    rev: state.rev,
    addresses: locals.map((l) => publicAddress(l, state.addresses[l], hashes)),
    tombstones: newest.map((l) => publicTombstone(l, t[l])),
  };
}

module.exports = { emptyState, emptyHashes, bootstrapState, checkState, checkHashes, clone, addressType, publicAddress, publicTombstone, listView };
