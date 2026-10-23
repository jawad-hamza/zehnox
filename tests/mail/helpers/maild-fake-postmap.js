"use strict";
/* A stand-in for /usr/sbin/postmap, used only by tests/maild.test.js (sandbox mode).
   tests/helpers/fake-postmap.js is the same idea for tests/daemon.test.js; this one prints
   the canary lines maild.test.js checks for.

   The sandboxed daemon runs it as  <node> fake-postmap.js <type>:<absolute map path>
   (config: postmapPath = process.execPath, postmapPreArgs = [this file]). The daemon hands
   the indexer a minimal environment (PATH and LANG only), so the test steers this script
   through a control file instead of variables:

     <stateDir>/fake-postmap.json   { "fail": ["virtual"] | "all", "failAfter": n }   optional
     <stateDir>/fake-postmap.log    one JSON line per call: { argv }                  appended

   On success it writes <map>.db (or .lmdb) as a copy of the source, so the index is newer
   than its source like a real one, and prints a canary line on stdout that the tests
   check never reaches a response. It never touches anything outside the state dir. */

const fs = require("fs");
const path = require("path");

const argv = process.argv.slice(2);
const spec = argv[argv.length - 1] || "";
const m = spec.match(/^(hash|lmdb):(.+)$/);
if (!m) {
  process.stderr.write("fake-postmap: bad argument\n");
  process.exit(64);
}
const mapPath = m[2];
const name = path.basename(mapPath);
const stateDir = path.dirname(path.dirname(mapPath));
const control = path.join(stateDir, "fake-postmap.json");
const logFile = path.join(stateDir, "fake-postmap.log");

let ctl = {};
try { ctl = JSON.parse(fs.readFileSync(control, "utf8")); } catch (_) { ctl = {}; }
let calls = 0;
try { calls = fs.readFileSync(logFile, "utf8").split("\n").filter(Boolean).length; } catch (_) { calls = 0; }
fs.appendFileSync(logFile, JSON.stringify({ argv }) + "\n");

process.stdout.write("FAKE-POSTMAP-STDOUT-CANARY " + name + "\n");
const failList = ctl.fail === "all" ? true : Array.isArray(ctl.fail) && ctl.fail.includes(name);
const failNow = failList && (!Number.isSafeInteger(ctl.failAfter) || calls >= ctl.failAfter);
if (failNow) {
  process.stderr.write("FAKE-POSTMAP-STDERR-CANARY fatal: " + name + "\n");
  process.exit(75);
}
fs.writeFileSync(mapPath + (m[1] === "lmdb" ? ".lmdb" : ".db"), fs.readFileSync(mapPath));
