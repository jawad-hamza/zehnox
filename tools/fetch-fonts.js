"use strict";
/* Re-downloads the self-hosted webfonts from Google Fonts into src/fonts/ and prints the
   @font-face rules that belong at the top of src/css/style.css.

   Run: node tools/fetch-fonts.js          (writes the files, prints the CSS)
        node tools/fetch-fonts.js --check  (downloads nothing; just reports drift)

   The site serves its own font files rather than linking Google's stylesheet: a
   third-party stylesheet in front of the first paint cost Lighthouse 1,710 ms, and it put
   every visitor's IP in front of Google. Only the Latin subsets are kept — unicode-range
   means a browser fetches just the ones a page actually needs.

   After running this, paste the printed rules over the @font-face block in style.css and
   update the two <link rel="preload"> hints in the page heads if a version changed;
   tools/test-page-shell.js fails if the CSS and the files on disk disagree. */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const DIR = path.join(ROOT, "src", "fonts");
const CHECK = process.argv.includes("--check");

/* Asking for a weight *range* gets the variable font in one file; asking for discrete
   weights (400;500;600) gets three static instances and triples the download. */
const URL = "https://fonts.googleapis.com/css2" +
  "?family=Fraunces:ital,opsz,wght@0,9..144,300..700;1,9..144,300..700" +
  "&family=Archivo:wght@400..600" +
  "&family=JetBrains+Mono:wght@500" +
  "&display=swap";

/* Google serves woff2 only to a browser-shaped User-Agent; anything else gets truetype. */
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const KEEP = new Set(["latin", "latin-ext"]);

function parse(css) {
  const faces = [];
  const re = /\/\*\s*([a-z-]+)\s*\*\/\s*@font-face\s*\{([^}]*)\}/g;
  let m;
  while ((m = re.exec(css))) {
    const body = m[2];
    const get = (k) => { const v = new RegExp(k + ":\\s*([^;]+);").exec(body); return v ? v[1].trim() : ""; };
    const url = /url\(([^)]+)\)/.exec(body);
    faces.push({
      subset: m[1],
      family: get("font-family").replace(/['"]/g, ""),
      style: get("font-style"),
      weight: get("font-weight"),
      stretch: get("font-stretch"),
      unicodeRange: get("unicode-range"),
      url: url ? url[1] : "",
    });
  }
  return faces;
}

/* The upstream version (…/s/archivo/v25/…) goes into the filename, so a file at a given
   URL can never change and server.js can cache src/fonts/ for a year. A version bump
   writes new names and the old files simply fall out of use. */
function slug(f) {
  const ver = (/\/s\/[^/]+\/(v\d+)\//.exec(f.url) || [, "v0"])[1];
  return f.family.toLowerCase().replace(/[^a-z0-9]+/g, "-") + "-" +
    (f.style === "italic" ? "italic-" : "") +
    String(f.weight).replace(/\s+/g, "-") + "-" + f.subset + "." + ver + ".woff2";
}

function rule(f) {
  return "@font-face {\n" +
    "  font-family: '" + f.family + "';\n" +
    "  font-style: " + f.style + ";\n" +
    "  font-weight: " + f.weight + ";\n" +
    (f.stretch ? "  font-stretch: " + f.stretch + ";\n" : "") +
    "  font-display: swap;\n" +
    "  src: url(../fonts/" + slug(f) + ") format('woff2');\n" +
    "  unicode-range: " + f.unicodeRange + ";\n" +
    "}";
}

(async () => {
  const res = await fetch(URL, { headers: { "User-Agent": UA } });
  if (!res.ok) throw new Error("Google Fonts returned " + res.status);
  const faces = parse(await res.text()).filter((f) => KEEP.has(f.subset));
  if (!faces.length) throw new Error("no Latin faces in the response — did the css2 API change?");

  const wanted = faces.map(slug);
  const have = fs.existsSync(DIR) ? fs.readdirSync(DIR).filter((f) => f.endsWith(".woff2")) : [];
  const missing = wanted.filter((f) => have.indexOf(f) === -1);
  const stale = have.filter((f) => wanted.indexOf(f) === -1);

  if (CHECK) {
    for (const f of missing) console.log("  missing  " + f);
    for (const f of stale) console.log("  stale    " + f);
    console.log(missing.length || stale.length
      ? "\nout of date — run without --check"
      : "up to date: " + have.length + " file(s)");
    /* exitCode rather than exit(): killing the process while fetch keep-alive sockets are
       still closing trips a libuv assertion on Windows and loses the real exit code. */
    process.exitCode = missing.length || stale.length ? 1 : 0;
    return;
  }

  fs.mkdirSync(DIR, { recursive: true });
  let total = 0;
  for (const f of faces) {
    const name = slug(f);
    const buf = Buffer.from(await (await fetch(f.url, { headers: { "User-Agent": UA } })).arrayBuffer());
    fs.writeFileSync(path.join(DIR, name), buf);
    total += buf.length;
    console.log("  " + String(Math.round(buf.length / 1024) + " KB").padStart(7) + "  " + name);
  }
  for (const f of stale) console.log("  (stale, delete by hand: " + f + ")");
  console.log("\n" + faces.length + " file(s), " + Math.round(total / 1024) + " KB\n");
  console.log("--- paste over the @font-face block in src/css/style.css ---\n");
  console.log(faces.map(rule).join("\n"));
})();
