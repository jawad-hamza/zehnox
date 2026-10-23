"use strict";
/* Stand-in for /usr/sbin/postmap, run by the sandboxed daemon in the daemon tests as
     <node> fake-postmap.js <type>:<absolute map path>
   (config: postmapPath = process.execPath, postmapPreArgs = [this file]).

   The daemon passes only PATH and LANG to the indexer, so this script is steered by a
   control file next to the state instead of environment variables:
     <stateDir>/fake-postmap.json   { "fail": ["virtual", ...] | "all", "failAfter": n, "once": bool }
     <stateDir>/fake-postmap.log    one JSON line per call: { argv, name }
   On success it writes <map>.db (a copy of the source, newer than it, like a real index)
   and prints a stdout canary; on failure it prints a stderr canary and exits 75. The
   tests check that neither canary ever reaches a response. It touches nothing outside
   the state directory. */

const fs = require("fs");
const path = require("path");

const argv = process.argv.slice(2);
const m = String(argv[argv.length - 1] || "").match(/^(hash|lmdb):(.+)$/);
if (!m) { process.stderr.write("fake-postmap: bad argument\n"); process.exit(64); }
const mapPath = m[2];
const name = path.basename(mapPath);
const stateDir = path.dirname(path.dirname(mapPath));
let ctl = {};
try { ctl = JSON.parse(fs.readFileSync(path.join(stateDir, "fake-postmap.json"), "utf8")); } catch (_) { ctl = {}; }
const logFile = path.join(stateDir, "fake-postmap.log");
let calls = 0;
try { calls = fs.readFileSync(logFile, "utf8").split("\n").filter(Boolean).length; } catch (_) { calls = 0; }
fs.appendFileSync(logFile, JSON.stringify({ argv, name }) + "\n");
process.stdout.write("TESTS-FAKE-POSTMAP-STDOUT " + name + "\n");
const listed = ctl.fail === "all" || (Array.isArray(ctl.fail) && ctl.fail.includes(name));
if (listed && (!Number.isSafeInteger(ctl.failAfter) || calls >= ctl.failAfter)) {
  // "once": fail this call only (the restore that follows then succeeds).
  if (ctl.once === true) fs.unlinkSync(path.join(stateDir, "fake-postmap.json"));
  process.stderr.write("TESTS-FAKE-POSTMAP-STDERR fatal: " + name + "\n");
  process.exit(75);
}
fs.writeFileSync(mapPath + (m[1] === "lmdb" ? ".lmdb" : ".db"), fs.readFileSync(mapPath));
