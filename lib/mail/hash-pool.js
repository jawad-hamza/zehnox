"use strict";
/* Password hashing off the event loop (DESIGN.md section 8.2).

   100,000 SHA-512 rounds is a few hundred milliseconds of pure CPU. On the main thread it
   would stall every request, including the public site, for that long per hash. So hashes
   run in a worker_threads pool: 2 workers, created lazily, at most 2 hashes in flight and
   4 more queued. Anything beyond that is refused with 429 busy instead of queueing without
   bound, which is also a brake on anyone hammering the password routes.

   The worker file is a constant path (the no-exec-surface test checks this): no request
   data ever chooses what code runs. Workers are unref'd while idle so an idle pool never
   keeps the process alive, and ref'd while a hash is pending so a test awaiting one does. */

const path = require("path");
const { Worker } = require("worker_threads");
const { mailError } = require("./provider.js");
const crypt = require("./crypt.js");

const WORKER_FILE = path.join(__dirname, "hash-worker.js");
const HASH_TIMEOUT_MS = 30 * 1000;

function createHashPool(opts) {
  const o = opts || {};
  const size = o.size || 2;
  const queueMax = o.queue == null ? 4 : o.queue;
  const timeoutMs = o.timeoutMs || HASH_TIMEOUT_MS;
  const slots = [];      // { worker, busy, job }
  const queue = [];      // jobs waiting for a free slot
  let nextId = 1;
  let closed = false;

  function startSlot() {
    const slot = { worker: null, busy: false, job: null };
    const w = new Worker(WORKER_FILE);
    w.unref();
    w.on("message", (msg) => {
      const job = slot.job;
      if (!job || !msg || msg.id !== job.id) return;
      finish(slot, msg.error || typeof msg.hash !== "string" ? mailError("backend_failed") : null, msg.hash);
    });
    // A crashed worker is replaced on the next job; its pending hash fails generically.
    const dead = () => {
      const i = slots.indexOf(slot);
      if (i >= 0) slots.splice(i, 1);
      if (slot.job) finish(slot, mailError("backend_failed"));
    };
    w.on("error", dead);
    w.on("exit", dead);
    slot.worker = w;
    slots.push(slot);
    return slot;
  }

  function finish(slot, err, hash) {
    const job = slot.job;
    slot.job = null;
    slot.busy = false;
    if (slot.worker) slot.worker.unref();
    if (job) {
      clearTimeout(job.timer);
      if (err) job.reject(err); else job.resolve(hash);
    }
    pump();
  }

  function run(slot, job) {
    slot.busy = true;
    slot.job = job;
    slot.worker.ref();
    job.timer = setTimeout(() => {
      // A hung hash: kill the worker (the exit handler fails the job and frees the slot).
      slot.worker.terminate().catch(() => {});
    }, timeoutMs);
    const msg = job.msg;
    job.msg = null; // the pool keeps no reference to the plaintext once it is posted
    slot.worker.postMessage(msg);
  }

  function pump() {
    while (queue.length) {
      let slot = slots.find((s) => !s.busy);
      if (!slot && slots.length < size) slot = startSlot();
      if (!slot) return;
      run(slot, queue.shift());
    }
  }

  /* hash(password, { scheme?: 'SHA512-CRYPT'|'ARGON2ID', rounds?, minRounds? }) -> Promise<string>
     Rejects with MailError busy (429) when 2 are running and 4 are queued, or
     backend_failed (502) on any worker failure. */
  function hash(password, hopts) {
    if (closed) return Promise.reject(mailError("unavailable"));
    if (typeof password !== "string") return Promise.reject(mailError("invalid_body"));
    const h = hopts || {};
    const inFlight = slots.filter((s) => s.busy).length;
    if (inFlight >= size && queue.length >= queueMax) return Promise.reject(mailError("busy"));
    return new Promise((resolve, reject) => {
      queue.push({
        id: nextId++, resolve, reject, timer: null,
        msg: {
          id: nextId - 1, password,
          scheme: h.scheme === "ARGON2ID" ? "ARGON2ID" : "SHA512-CRYPT",
          rounds: h.rounds == null ? crypt.defaultRounds() : h.rounds,
          minRounds: h.minRounds == null ? crypt.defaultMinRounds() : h.minRounds,
        },
      });
      pump();
    });
  }

  function stats() {
    return { workers: slots.length, inFlight: slots.filter((s) => s.busy).length, queued: queue.length, size, queueMax };
  }

  async function close() {
    closed = true;
    while (queue.length) { const j = queue.shift(); j.reject(mailError("unavailable")); }
    await Promise.all(slots.slice().map((s) => s.worker.terminate().catch(() => {})));
  }

  return { hash, stats, close };
}

module.exports = { createHashPool, WORKER_FILE };
