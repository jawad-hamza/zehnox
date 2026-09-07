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

console.log("\n" + (failed ? "FAILED " : "") + passed + " passed, " + failed + " failed");
process.exit(failed ? 1 : 0);
