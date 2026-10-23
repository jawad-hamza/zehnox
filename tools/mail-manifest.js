"use strict";
/* Prints the install manifest of the mail daemon (docs/mail/DESIGN.md sections 5.1 and 16).

   The daemon is installed by hand on the VPS as
     /usr/local/lib/zehnox-mail/zehnox-maild.js
     /usr/local/lib/zehnox-mail/core/*.js          (copied from lib/mail/core/)
   and the owner checks the installed bytes against this manifest, computed from the
   reviewed git tag. The names are the installed layout, so this output and the daemon's
   own `--print-manifest` are byte-identical when the files match:

     node tools/mail-manifest.js                         print the manifest of this checkout
     node tools/mail-manifest.js --check <install dir>   compare an installed copy (exit 1 on any difference)

   Hashes are over the raw file bytes. The repository stores LF (.gitattributes), so a
   checkout on the VPS and the copied files agree. Reads files only; never writes. */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

/* One line per file, "<sha256>  <installed name>", core files sorted, the daemon last. */
function manifestOf(daemonFile, coreDir) {
  const lines = [];
  for (const n of fs.readdirSync(coreDir).filter((f) => f.endsWith(".js")).sort()) {
    lines.push(sha256(fs.readFileSync(path.join(coreDir, n))) + "  core/" + n);
  }
  lines.push(sha256(fs.readFileSync(daemonFile)) + "  zehnox-maild.js");
  return lines.join("\n") + "\n";
}

/* The manifest of a repository checkout. */
function manifest(repoRoot) {
  const root = repoRoot || path.join(__dirname, "..");
  return manifestOf(path.join(root, "mail-daemon", "zehnox-maild.js"), path.join(root, "lib", "mail", "core"));
}

/* The manifest of an installed copy (the /usr/local/lib/zehnox-mail layout). */
function installedManifest(dir) {
  return manifestOf(path.join(dir, "zehnox-maild.js"), path.join(dir, "core"));
}

function main(argv) {
  if (argv.length === 0) {
    process.stdout.write(manifest());
    return 0;
  }
  if (argv.length === 2 && argv[0] === "--check") {
    const want = manifest();
    let got;
    try { got = installedManifest(path.resolve(argv[1])); } catch (_) { process.stderr.write("mail-manifest: cannot read the installed files\n"); return 1; }
    if (got === want) { process.stdout.write("mail-manifest: installed files match this checkout\n"); return 0; }
    const w = new Set(want.split("\n"));
    const g = new Set(got.split("\n"));
    for (const l of want.split("\n")) if (l && !g.has(l)) process.stdout.write("expected " + l + "\n");
    for (const l of got.split("\n")) if (l && !w.has(l)) process.stdout.write("found    " + l + "\n");
    return 1;
  }
  process.stderr.write("usage: node tools/mail-manifest.js [--check <install dir>]\n");
  return 2;
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));

module.exports = { manifest, installedManifest, manifestOf };
