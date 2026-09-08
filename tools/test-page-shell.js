"use strict";
/* Two invariants of the page shell that regress silently and are painful to spot by eye.
   Run: node tools/test-page-shell.js

   1. There is always a visible cursor. The site hides the native one and draws its own,
      so the native one may only be hidden once the custom one is actually tracking.
   2. Nothing third-party blocks the first paint. */

const assert = require("assert");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const css = fs.readFileSync(path.join(ROOT, "src/css/style.css"), "utf8");
const js = fs.readFileSync(path.join(ROOT, "src/js/site.js"), "utf8");

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log("  ok   " + name); }
  catch (e) { failed++; console.error("  FAIL " + name + "\n       " + (e && e.message ? e.message : e)); }
}

function pages(dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) pages(full, out);
    else if (entry.name.endsWith(".html")) out.push(full);
  }
  return out;
}

console.log("page shell");

test("the native cursor is only hidden once the custom one is live", () => {
  const hides = css.split("\n").filter((l) => /cursor:\s*none/.test(l));
  assert.ok(hides.length, "nothing hides the native cursor any more — is the custom cursor gone?");
  for (const line of hides) {
    assert.ok(/\.has-cursor\b/.test(line),
      "cursor: none is not gated on .has-cursor, so the page loads with no cursor at all — " + line.trim().slice(0, 100));
  }
});

test("the custom cursor is hidden until it knows where the pointer is", () => {
  assert.ok(/\.cursor\s*\{[^}]*opacity:\s*0/.test(css), ".cursor must start invisible, not parked at the top-left corner");
  assert.ok(/\.cursor\.is-live\s*\{[^}]*opacity:\s*1/.test(css), ".cursor.is-live must reveal it");
  assert.ok(js.includes('cursor.classList.add("is-live")'), "site.js never reveals the cursor");
  assert.ok(js.includes('documentElement.classList.add("has-cursor")'), "site.js never unlocks cursor: none");
  // Both must happen inside the mousemove handler, not at startup.
  const move = js.slice(js.indexOf('addEventListener("mousemove"'));
  const end = move.indexOf("{ passive: true }");
  assert.ok(end > 0, "could not find the end of the mousemove handler");
  const body = move.slice(0, end);
  assert.ok(body.includes('classList.add("has-cursor")'), "has-cursor is added before the first pointer move");
});

test("the cursor does not depend on the animation library loading", () => {
  assert.ok(!/if \(fine && cursor && hasGsap\)/.test(js),
    "the cursor block is gated on hasGsap: if GSAP fails to load there is no cursor at all");
  assert.ok(/const set = hasGsap \? gsap\.quickSetter/.test(js), "no non-GSAP fallback writer");
  assert.ok(/else \(function loop\(\)/.test(js), "no non-GSAP fallback loop");
});

test("no page reaches a third party for anything in the critical path", () => {
  const files = pages(path.join(ROOT, "src"), []);
  assert.ok(files.length > 10, "expected to find the site's pages");
  for (const file of files) {
    const html = fs.readFileSync(file, "utf8");
    const rel = path.relative(ROOT, file);
    assert.ok(!/fonts\.(googleapis|gstatic)\.com/.test(html), rel + ": still loads fonts from Google");
    for (const tag of html.match(/<link[^>]*rel=["']stylesheet["'][^>]*>/gi) || []) {
      assert.ok(!/https?:\/\//.test(tag), rel + ": a third-party stylesheet blocks the first paint — " + tag.slice(0, 90));
    }
    for (const f of ["archivo-400-600-latin", "fraunces-300-700-latin"]) {
      assert.ok(new RegExp('rel="preload" href="/fonts/' + f + '\\.v\\d+\\.woff2" as="font" type="font/woff2" crossorigin').test(html),
        rel + ": " + f + " is not preloaded, so headings and body text flash in a fallback face");
    }
  }
});

test("every @font-face points at a file that is actually on disk", () => {
  const declared = [...css.matchAll(/url\(\.\.\/fonts\/([^)]+)\)/g)].map((m) => m[1]);
  assert.ok(declared.length >= 8, "expected the Latin subsets of all three families, found " + declared.length);
  const onDisk = new Set(fs.readdirSync(path.join(ROOT, "src/fonts")));
  for (const f of declared) assert.ok(onDisk.has(f), "style.css references src/fonts/" + f + ", which does not exist");
  // Versioned names are what make the year-long immutable cache in server.js safe.
  for (const f of declared) assert.ok(/\.v\d+\.woff2$/.test(f), f + " has no version in its name, so it cannot be cached immutably");
});

/* ---------- filter chips ----------
   The active chip on /work sits in <section class="sec sec--light light">, where two
   equally-weighted rules both claim its colour. Resolving the cascade by hand is the only
   way to catch a repeat: each rule reads fine on its own, and only their order gives you a
   black label on a black pill. */

/* Comments and at-rules out of the way, so `selector { decls }` is all that is left.
   @media/@supports rules are dropped on purpose: they apply conditionally, and the bug
   being pinned down here is in the unconditional cascade. */
function baseRules(cssText) {
  const src = cssText.replace(/\/\*[\s\S]*?\*\//g, "");
  let out = "", i = 0;
  while (i < src.length) {
    if (src[i] !== "@") { out += src[i++]; continue; }
    let j = src.indexOf("{", i);
    if (j === -1) break;
    let depth = 1;
    for (j++; j < src.length && depth > 0; j++) {
      if (src[j] === "{") depth++;
      else if (src[j] === "}") depth--;
    }
    i = j;
  }
  return out;
}

/* Enough of a cascade to settle one element: class selectors, descendant combinators and
   :not(.class) — which is all these rules use. */
function winningStyle(cssText, el, ancestors) {
  const matchesCompound = (compound, classes) => {
    const negatives = [...compound.matchAll(/:not\(\.([\w-]+)\)/g)].map((m) => m[1]);
    const positives = compound.replace(/:not\([^)]*\)/g, "").split(".").filter(Boolean);
    return positives.every((c) => classes.has(c)) && negatives.every((c) => !classes.has(c));
  };
  const won = {};
  let order = 0;
  let seen = 0;
  for (const block of baseRules(cssText).matchAll(/([^{}]+)\{([^}]*)\}/g)) {
    const selectors = block[1].trim(), body = block[2];
    for (const selector of selectors.split(",")) {
      seen++;
      const parts = selector.trim().split(/\s+/);
      if (!parts.length || parts.some((p) => !/^[.:][\w.:()-]*$/.test(p))) continue;   // classes only
      if (!matchesCompound(parts[parts.length - 1], el)) continue;
      const needed = parts.slice(0, -1);
      if (!needed.every((p) => ancestors.some((a) => matchesCompound(p, a)))) continue;
      const weight = (selector.match(/\.[\w-]+/g) || []).length;
      order++;
      for (const decl of body.split(";")) {
        const i = decl.indexOf(":");
        if (i < 0) continue;
        const prop = decl.slice(0, i).trim(), value = decl.slice(i + 1).trim();
        const prev = won[prop];
        if (!prev || weight > prev.weight || (weight === prev.weight && order > prev.order)) {
          won[prop] = { value, weight, order };
        }
      }
    }
  }
  won.__stats = { selectorsScanned: seen, rulesApplied: order };
  return won;
}

test("the active filter chip on /work is legible", () => {
  const html = fs.readFileSync(path.join(ROOT, "src/work.html"), "utf8");
  const section = /<section class="([^"]*)"[^>]*id="work"/.exec(html);
  assert.ok(section, "could not find the work section — has the markup changed?");
  const ancestors = [new Set(section[1].split(/\s+/)), new Set(["filters", "reveal"])];
  const style = winningStyle(css, new Set(["chip", "is-active"]), ancestors);

  // Guard the guard: a parser that silently matches nothing would pass everything below.
  assert.ok(style.__stats.selectorsScanned > 500, "the stylesheet barely parsed — " + style.__stats.selectorsScanned + " selectors");
  assert.ok(style.__stats.rulesApplied >= 4, "expected several chip rules to apply, got " + style.__stats.rulesApplied);
  assert.ok(style.color && style.background, "no colour resolved for the active chip at all");
  assert.notStrictEqual(style.color.value, style.background.value,
    "the active chip paints its label the same colour as its pill (" + style.color.value + ") — it is invisible");
  // The .light theme owns this section, so it should win outright: white label, ink pill.
  assert.strictEqual(style.background.value, "var(--ink)", "unexpected pill colour: " + style.background.value);
  assert.strictEqual(style.color.value, "var(--paper)", "unexpected label colour: " + style.color.value);
});

/* ---------- analytics ----------
   The GA4 tag is injected by build.js, not pasted into the pages, so these check the
   built output rather than the sources: that every public page carries exactly one tag,
   that none of the sources carry it, and that the admin panel carries none at all. */

const GA_ID = "G-5FYXZZP8N1";
const DIST = path.join(ROOT, "dist");

test("every built public page carries exactly one GA4 tag", () => {
  assert.ok(fs.existsSync(DIST), "dist/ is missing — run node build.js first");
  const built = pages(DIST, []);
  assert.ok(built.length > 20, "expected the built site, found " + built.length + " page(s)");
  for (const file of built) {
    const html = fs.readFileSync(file, "utf8");
    const rel = path.relative(ROOT, file);
    const loaders = html.match(/googletagmanager\.com\/gtag\/js\?id=/g) || [];
    assert.strictEqual(loaders.length, 1, rel + ": found " + loaders.length + " gtag loaders, expected exactly 1");
    assert.ok(html.includes('gtag/js?id=' + GA_ID), rel + ": wrong or missing measurement id");
    assert.ok(html.includes("gtag('config', '" + GA_ID + "')"), rel + ": the tag never configures the property");
  }
});

test("the GA4 tag sits in the head, after the charset declaration", () => {
  for (const file of pages(DIST, [])) {
    const html = fs.readFileSync(file, "utf8");
    const rel = path.relative(ROOT, file);
    const tag = html.indexOf("googletagmanager.com");
    const charset = html.search(/<meta[^>]+charset=/i);
    const headEnd = html.search(/<\/head>/i);
    assert.ok(charset !== -1 && charset < tag, rel + ": the tag is before <meta charset>, which must come first");
    assert.ok(tag < headEnd, rel + ": the tag is outside <head>");
  }
});

test("no source page hardcodes the tag — it comes from the build", () => {
  for (const file of pages(path.join(ROOT, "src"), [])) {
    const html = fs.readFileSync(file, "utf8");
    assert.ok(!html.includes("googletagmanager.com"),
      path.relative(ROOT, file) + ": has a hardcoded GA tag, which would double up with the injected one");
  }
});

test("the admin panel is never tagged", () => {
  for (const name of fs.readdirSync(path.join(ROOT, "admin"))) {
    const body = fs.readFileSync(path.join(ROOT, "admin", name), "utf8");
    assert.ok(!body.includes("googletagmanager.com") && !body.includes(GA_ID),
      "admin/" + name + ": analytics must never reach the admin panel");
  }
});

console.log("\n" + (failed ? "FAILED " : "") + passed + " passed, " + failed + " failed");
process.exit(failed ? 1 : 0);
