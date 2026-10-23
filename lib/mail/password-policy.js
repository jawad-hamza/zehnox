"use strict";
/* Mailbox password policy (DESIGN.md section 3.3). Node only: the daemon never sees
   plaintext, so this is the one place a password's content can be judged.

   checkPassword(pw, { local }) -> null | { code: 'weak_password', reason }

   `reason` is always one of the fixed strings below: never an echo of the password, so it
   can go into the public error message and the UI without a second thought. */

const COMMON = new Set(require("./common-passwords.js"));

const REASONS = Object.freeze({
  length: "use 12 to 128 characters",
  control: "control characters are not allowed",
  spaces: "it cannot start or end with a space",
  local: "it cannot contain the address name",
  company: "it cannot contain the company name",
  common: "it is a commonly used password",
});

const weak = (key) => ({ code: "weak_password", reason: REASONS[key] });

function checkPassword(pw, opts) {
  if (typeof pw !== "string") return weak("length");
  // Code points, not UTF-16 units, so an emoji counts once.
  const len = Array.from(pw).length;
  if (len < 12 || len > 128) return weak("length");
  // C0, DEL and C1 controls: this also excludes NUL, CR and LF.
  if (/[\u0000-\u001f\u007f-\u009f]/.test(pw)) return weak("control");
  if (/^\s|\s$/.test(pw)) return weak("spaces");
  const lower = pw.toLowerCase();
  const local = opts && typeof opts.local === "string" ? opts.local.toLowerCase() : "";
  // A one- or two-letter local part ("a@") would forbid half the alphabet; skip those.
  if (local.length >= 3 && lower.includes(local)) return weak("local");
  if (lower.includes("zehnox")) return weak("company"); // also covers the domain, "zehnox.com"
  const stripped = lower.replace(/[\d\W_]+$/, "");
  if (COMMON.has(lower) || (stripped && COMMON.has(stripped))) return weak("common");
  return null;
}

module.exports = { checkPassword, REASONS };
