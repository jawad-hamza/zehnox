"use strict";
/* worker_threads entry for hash-pool.js (DESIGN.md section 8.2).

   Receives { id, password, scheme, rounds, minRounds } and answers { id, hash } or
   { id, error: true }. The error carries no text on purpose: an exception message could
   one day include the input, and the pool maps every failure to a generic backend_failed.
   The plaintext lives only in this message and the local variable below. */

const { parentPort } = require("worker_threads");
const crypt = require("./crypt.js");

parentPort.on("message", async (msg) => {
  const id = msg && msg.id;
  try {
    let hash;
    if (msg.scheme === "ARGON2ID") hash = await crypt.argon2idDovecot(msg.password);
    else hash = crypt.sha512Crypt(msg.password, { rounds: msg.rounds, minRounds: msg.minRounds });
    parentPort.postMessage({ id, hash });
  } catch (_) {
    parentPort.postMessage({ id, error: true });
  }
});
