"use strict";
/* Verifies the extensionless routing contract — run: node tools/test-routes.js

   Every page is served at /about; the underlying /about.html permanently redirects to it;
   nothing that ships to a browser still links to a .html page; and unknown URLs still 404. */

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const ROOT = path.join(__dirname, "..");
const DIST = path.join(ROOT, "dist");
const PORT = 3114;
const base = "http://127.0.0.1:" + PORT;

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log("  ok   " + name); }
  catch (e) { failed++; console.error("  FAIL " + name + "\n       " + (e && e.message ? e.message : e)); }
}

/* Every .html file in dist, as a "/services/ai-automation.html" style url path. */
function distPages(dir, prefix, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith("_")) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) distPages(full, prefix + "/" + entry.name, out);
    else if (entry.name.endsWith(".html")) out.push(prefix + "/" + entry.name);
  }
  return out;
}

const routeFor = (page) => {
  let clean = page.replace(/\.html$/, "");
  if (clean.endsWith("/index")) clean = clean.slice(0, -"index".length);
  return clean || "/";
};

(async () => {
  const pages = distPages(DIST, "", []).filter((p) => p !== "/404.html");
  const server = spawn(process.execPath, ["server.js", String(PORT)], { cwd: ROOT, stdio: "ignore" });
  const cleanup = () => { try { server.kill(); } catch (_) { /* already gone */ } };

  try {
    for (let i = 0; i < 100; i++) {
      try { await fetch(base + "/"); break; } catch (_) { await new Promise((r) => setTimeout(r, 100)); }
    }

    await test("every page answers 200 at its extensionless route (" + pages.length + " pages)", async () => {
      const bad = [];
      for (const page of pages) {
        const route = routeFor(page);
        const res = await fetch(base + route, { redirect: "manual" });
        if (res.status !== 200) bad.push(route + " -> " + res.status);
      }
      assert.deepStrictEqual(bad, [], "routes that did not answer 200:\n" + bad.join("\n"));
    });

    await test("every .html url 301s to its route", async () => {
      const bad = [];
      for (const page of pages) {
        const res = await fetch(base + page, { redirect: "manual" });
        const want = routeFor(page);
        if (res.status !== 301 || res.headers.get("location") !== want) {
          bad.push(page + " -> " + res.status + " " + (res.headers.get("location") || ""));
        }
      }
      assert.deepStrictEqual(bad, [], "urls that did not redirect correctly:\n" + bad.join("\n"));
    });

    await test("/index.html redirects to / and the query string survives", async () => {
      const res = await fetch(base + "/index.html", { redirect: "manual" });
      assert.strictEqual(res.status, 301);
      assert.strictEqual(res.headers.get("location"), "/");
      const q = await fetch(base + "/about.html?utm_source=x", { redirect: "manual" });
      assert.strictEqual(q.headers.get("location"), "/about?utm_source=x");
    });

    await test("unknown urls still 404 rather than redirecting", async () => {
      for (const p of ["/nope", "/nope.html", "/services/nope.html", "/services/nope"]) {
        const res = await fetch(base + p, { redirect: "manual" });
        assert.strictEqual(res.status, 404, p + " returned " + res.status);
      }
    });

    await test("no shipped page links to a .html route", async () => {
      const offenders = [];
      for (const page of distPages(DIST, "", [])) {
        const html = fs.readFileSync(path.join(DIST, page.slice(1)), "utf8");
        const links = html.match(/\s(?:href|action)="[^"]*\.html[^"]*"/gi) || [];
        for (const link of links) offenders.push(page + "  " + link.trim());
      }
      assert.deepStrictEqual(offenders, [], "internal .html links still present:\n" + offenders.join("\n"));
    });

    await test("the generated js builds extensionless links", async () => {
      const js = fs.readFileSync(path.join(DIST, "js", "site.js"), "utf8") +
                 fs.readFileSync(path.join(DIST, "js", "home.js"), "utf8");
      assert.ok(!/["'][^"']*\.html["']/.test(js.replace(/dataset\.html/g, "")), "site.js/home.js still reference a .html page");
    });

    await test("the sitemap lists routes, not files", async () => {
      const xml = fs.readFileSync(path.join(DIST, "sitemap.xml"), "utf8");
      assert.ok(!/\.html</.test(xml), "sitemap still contains .html entries");
      assert.ok(xml.includes("<loc>https://zehnox.com/about</loc>"), "expected /about in the sitemap");
      assert.ok(xml.includes("<loc>https://zehnox.com/insights/brief-before-build</loc>"), "expected the post route in the sitemap");
    });

    await test("nav highlighting treats every spelling of a page as the same page", async () => {
      // Pull the shipped normaliser out of dist/js/site.js so this tests the real code.
      const js = fs.readFileSync(path.join(DIST, "js", "site.js"), "utf8");
      const m = /const norm = \(p\) =>[^;]+;/.exec(js);
      assert.ok(m, "could not find the nav path normaliser in dist/js/site.js");
      const norm = new Function("return " + m[0].replace(/^const norm = /, "").replace(/;$/, ""))();

      assert.strictEqual(norm("/"), "/");
      assert.strictEqual(norm("/index.html"), "/");
      assert.strictEqual(norm("/about"), "/about");
      assert.strictEqual(norm("/about/"), "/about");
      assert.strictEqual(norm("/about.html"), "/about");
      assert.strictEqual(norm("/services/ai-automation"), "/services/ai-automation");

      // A section link stays lit on its children, and the home link does not swallow everything.
      const active = (href, here) => { const p = norm(href), h = norm(here); return p === h || (p !== "/" && h.startsWith(p + "/")); };
      assert.ok(active("/services", "/services/ai-automation"), "/services should be active on a child page");
      assert.ok(active("/services", "/services"), "/services should be active on itself");
      assert.ok(active("/", "/"), "home should be active on the homepage");
      assert.ok(!active("/", "/about"), "home must not be active on /about");
      assert.ok(!active("/about", "/services"), "/about must not be active on /services");
      assert.ok(!active("/work", "/services/ai-automation"), "unrelated links must stay inactive");
    });

    await test("admin and api are untouched by the redirect", async () => {
      const admin = await fetch(base + "/admin/", { redirect: "manual" });
      assert.strictEqual(admin.status, 200, "/admin/ returned " + admin.status);
      const api = await fetch(base + "/api/me", { redirect: "manual" });
      assert.strictEqual(api.status, 401, "/api/me returned " + api.status);
    });
  } finally {
    cleanup();
  }

  console.log((failed ? "FAILED " : "") + passed + " passed, " + failed + " failed");
  process.exitCode = failed ? 1 : 0;
  setTimeout(() => process.exit(process.exitCode), 200);
})();
