"use strict";
/* A throwaway self-signed certificate, built at test time with node:crypto only.

   Node's stdlib can make key pairs and signatures but not certificates, and the suite
   must not depend on openssl being installed or commit any key material. So this writes
   the few DER structures an X.509 v3 certificate needs (RFC 5280) by hand: an EC P-256
   key, a subject/issuer CN, a validity window and a subjectAltName with DNS names, signed
   with ecdsa-with-SHA256. Good enough for a TLS server in a test; nothing else. */

const crypto = require("crypto");

function len(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n >>>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag, content) => Buffer.concat([Buffer.from([tag]), len(content.length), content]);
const seq = (...items) => tlv(0x30, Buffer.concat(items));
const set = (...items) => tlv(0x31, Buffer.concat(items));
const explicit = (n, content) => tlv(0xa0 + n, content);
function int(buf) {
  let b = Buffer.from(buf);
  while (b.length > 1 && b[0] === 0 && b[1] < 0x80) b = b.subarray(1);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}
function oid(str) {
  const parts = str.split(".").map(Number);
  const out = [40 * parts[0] + parts[1]];
  for (const p of parts.slice(2)) {
    const stack = [p & 0x7f];
    let v = p >>> 7;
    while (v > 0) { stack.unshift((v & 0x7f) | 0x80); v >>>= 7; }
    out.push(...stack);
  }
  return tlv(0x06, Buffer.from(out));
}
const utf8 = (s) => tlv(0x0c, Buffer.from(s, "utf8"));
function utcTime(d) {
  const p = (n) => String(n).padStart(2, "0");
  const s = p(d.getUTCFullYear() % 100) + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) + p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds()) + "Z";
  return tlv(0x17, Buffer.from(s, "ascii"));
}
const bitString = (buf) => tlv(0x03, Buffer.concat([Buffer.from([0]), buf]));
const octet = (buf) => tlv(0x04, buf);
const name = (cn) => seq(set(seq(oid("2.5.4.3"), utf8(cn))));

const pem = (label, der) => "-----BEGIN " + label + "-----\n" + der.toString("base64").match(/.{1,64}/g).join("\n") + "\n-----END " + label + "-----\n";

/* -> { key, cert } in PEM form, for tls.createSecureContext / new tls.TLSSocket.
   opts: { cn = 'localhost', dns = [cn], days = 2, notBeforeDays = -1 } (negative days make
   an already-expired certificate). */
function selfSigned(opts) {
  const o = opts || {};
  const cn = o.cn || "localhost";
  const dns = o.dns || [cn];
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = publicKey.export({ type: "spki", format: "der" });
  const sigAlg = seq(oid("1.2.840.10045.4.3.2"));
  const now = Date.now();
  const notBefore = new Date(now + (o.notBeforeDays == null ? -1 : o.notBeforeDays) * 86400000);
  const notAfter = new Date(now + (o.days == null ? 2 : o.days) * 86400000);
  const san = seq(oid("2.5.29.17"), octet(seq(...dns.map((d) => tlv(0x82, Buffer.from(d, "ascii"))))));
  const tbs = seq(
    explicit(0, int(Buffer.from([2]))),
    int(crypto.randomBytes(8)),
    sigAlg,
    name(cn),
    seq(utcTime(notBefore), utcTime(notAfter)),
    name(cn),
    spki,
    explicit(3, seq(san)),
  );
  const sig = crypto.sign("sha256", tbs, privateKey);
  const certDer = seq(tbs, sigAlg, bitString(sig));
  return { key: privateKey.export({ type: "pkcs8", format: "pem" }), cert: pem("CERTIFICATE", certDer) };
}

module.exports = { selfSigned };
