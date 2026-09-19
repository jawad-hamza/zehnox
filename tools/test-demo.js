"use strict";
/* Product demos and product pages — run: node tools/test-demo.js   (after node build.js)

   Prototypes/<Name>/ is published verbatim to /demo/<name>/, kept out of search, and linked
   from the product page alongside a trial download. These pin down the parts that break
   quietly: a demo link that 404s, a download button pointing at nothing, a screenshot
   squashed because its declared size is not its real size. */

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const ROOT = path.join(__dirname, "..");
const SRC = path.join(ROOT, "src");
const DIST = path.join(ROOT, "dist");
const PROTOTYPES = path.join(ROOT, "Prototypes");
const PORT = 3116;
const base = "http://127.0.0.1:" + PORT;

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log("  ok   " + name); }
  catch (e) { failed++; console.error("  FAIL " + name + "\n       " + (e && e.message ? e.message : e)); }
}

function files(dir, out, rel) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const r = rel ? rel + "/" + e.name : e.name;
    if (e.isDirectory()) files(path.join(dir, e.name), out, r); else out.push(r);
  }
  return out;
}
const slugOf = (name) => name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
const demos = fs.existsSync(PROTOTYPES)
  ? fs.readdirSync(PROTOTYPES, { withFileTypes: true }).filter((e) => e.isDirectory() && !/^[._]/.test(e.name)).map((e) => ({ name: e.name, slug: slugOf(e.name) }))
  : [];

/* Real pixel size of a WebP or JPEG, read from the file header. */
function imageSize(file) {
  const b = fs.readFileSync(file);
  if (b.toString("ascii", 0, 4) === "RIFF" && b.toString("ascii", 8, 12) === "WEBP") {
    const t = b.toString("ascii", 12, 16);
    if (t === "VP8X") return [1 + b.readUIntLE(24, 3), 1 + b.readUIntLE(27, 3)];
    if (t === "VP8L") { const v = b.readUInt32LE(21); return [1 + (v & 0x3fff), 1 + ((v >> 14) & 0x3fff)]; }
    if (t === "VP8 ") return [b.readUInt16LE(26) & 0x3fff, b.readUInt16LE(28) & 0x3fff];
  }
  if (b[0] === 0xff && b[1] === 0xd8) {
    for (let i = 2; i < b.length - 9;) {
      if (b[i] !== 0xff) { i++; continue; }
      const marker = b[i + 1], len = b.readUInt16BE(i + 2);
      if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker)) return [b.readUInt16BE(i + 7), b.readUInt16BE(i + 5)];
      i += 2 + len;
    }
  }
  return null;
}

(async () => {
  console.log("product demos");
  assert.ok(fs.existsSync(DIST), "dist/ is missing — run node build.js first");

  await test("every prototype is published whole to /demo/<name>/ (" + demos.map((d) => d.slug).join(", ") + ")", () => {
    assert.ok(demos.length, "no prototypes found under Prototypes/");
    for (const d of demos) {
      for (const rel of files(path.join(PROTOTYPES, d.name), [], "")) {
        const out = path.join(DIST, "demo", d.slug, rel);
        if (/^readme\.txt$/i.test(path.basename(rel))) {
          assert.ok(!fs.existsSync(out), "demo/" + d.slug + "/" + rel + " is internal and must not be published");
          continue;
        }
        assert.ok(fs.existsSync(out), "demo/" + d.slug + "/" + rel + " was not published");
        if (!rel.endsWith(".html")) {
          assert.ok(fs.readFileSync(out).equals(fs.readFileSync(path.join(PROTOTYPES, d.name, rel))), "demo/" + d.slug + "/" + rel + " changed on the way through");
        }
      }
    }
  });

  await test("every link inside a demo resolves to a published file", () => {
    const broken = [];
    for (const d of demos) {
      const root = path.join(DIST, "demo", d.slug);
      for (const rel of files(root, [], "").filter((f) => /\.(html|css)$/.test(f))) {
        const text = fs.readFileSync(path.join(root, rel), "utf8");
        const refs = [...text.matchAll(/(?:href|src)="([^"]+)"|url\(\s*["']?([^"')]+)["']?\s*\)/g)].map((m) => m[1] || m[2]);
        for (const ref of refs) {
          if (/^(?:[a-z]+:|\/\/|#|data:)/i.test(ref)) continue;          // external, anchor or inline
          const target = ref.split(/[?#]/)[0];
          if (!target) continue;
          const abs = path.resolve(path.dirname(path.join(root, rel)), target);
          if (!fs.existsSync(abs)) broken.push("demo/" + d.slug + "/" + rel + " -> " + ref);
        }
      }
    }
    assert.deepStrictEqual(broken, [], "broken demo links:\n" + broken.join("\n"));
  });

  await test("demos stay out of search: not in the sitemap, disallowed in robots.txt", () => {
    const xml = fs.readFileSync(path.join(DIST, "sitemap.xml"), "utf8");
    assert.ok(!/\/demo\//.test(xml), "a demo page is listed in the sitemap");
    assert.ok(/^Disallow: \/demo\/$/m.test(fs.readFileSync(path.join(DIST, "robots.txt"), "utf8")), "robots.txt does not disallow /demo/");
  });

  await test("product screenshots declare their real proportions", () => {
    // A mismatch here is what squashed the ZehnBot screenshots: the browser reserves the
    // declared shape, and any CSS that pins one side keeps it.
    const bad = [];
    for (const page of files(SRC, [], "").filter((f) => f.endsWith(".html") && !f.startsWith("_"))) {
      const html = fs.readFileSync(path.join(SRC, page), "utf8");
      for (const m of html.matchAll(/<img[^>]*\ssrc="((?:\.\.\/)*products\/[^"]+)"[^>]*>/g)) {
        const w = /\swidth="(\d+)"/.exec(m[0]), h = /\sheight="(\d+)"/.exec(m[0]);
        const file = path.join(SRC, m[1].replace(/^(\.\.\/)+/, ""));
        if (!w || !h) { bad.push(page + ": " + m[1] + " has no width/height"); continue; }
        const real = imageSize(file);
        if (!real) { bad.push(page + ": " + m[1] + " missing or unreadable"); continue; }
        const declared = +w[1] / +h[1], actual = real[0] / real[1];
        if (Math.abs(declared / actual - 1) > 0.01) bad.push(page + ": " + m[1] + " declares " + w[1] + "x" + h[1] + " but is " + real.join("x"));
      }
    }
    assert.deepStrictEqual(bad, [], bad.join("\n"));
  });

  await test("ZehnMS is listed under Products, Local Business and Work", () => {
    assert.ok(fs.readFileSync(path.join(SRC, "solutions.html"), "utf8").includes('href="/zehnms"'), "/solutions does not link to /zehnms");
    assert.ok(fs.readFileSync(path.join(SRC, "solutions/local-business.html"), "utf8").includes('href="/zehnms"'), "/solutions/local-business does not link to /zehnms");
    const work = JSON.parse(fs.readFileSync(path.join(ROOT, "content.json"), "utf8")).work || [];
    assert.ok(work.some((w) => w.url === "/zehnms"), "content.json work has no entry for /zehnms");
  });

  await test("the ZehnMS page's demo button opens the demo", () => {
    const html = fs.readFileSync(path.join(SRC, "zehnms.html"), "utf8");
    const m = /href="(\/demo\/[^"]+)"[^>]*>See online demo</.exec(html);
    assert.ok(m, "no \"See online demo\" button pointing into /demo/");
    const target = path.join(DIST, m[1].replace(/\/$/, "/index.html"));
    assert.ok(fs.existsSync(target), m[1] + " is not a published page");
  });

  /* Installers are not in the repo — they live on the VPS — so the page must link to the
     stable /download/<product> route, never to a file that only exists on one machine. */
  await test("the ZehnMS download button uses the stable /download/zehnms route", () => {
    const html = fs.readFileSync(path.join(SRC, "zehnms.html"), "utf8");
    const button = /<a[^>]*href="\/download\/zehnms"[^>]*>Download trial</.exec(html);
    assert.ok(button, "\"Download trial\" does not point at /download/zehnms");
    // The server already sends Content-Disposition: attachment. With the download attribute
    // as well, a missing installer makes the browser save the 404 page as if it were the setup.
    assert.ok(!/\sdownload[\s>=]/.test(button[0]), "the button must not carry the download attribute — it turns an error page into a fake installer");
    assert.ok(!fs.existsSync(path.join(SRC, "downloads")), "src/downloads/ exists — installers belong on the server, not in the site sources");
    assert.ok(!fs.existsSync(path.join(DIST, "downloads")), "dist/downloads/ exists — an installer is being built into the site");
  });

  /* ---- the running server, pointed at a throwaway downloads folder ---- */
  const os = require("os");
  const downloads = fs.mkdtempSync(path.join(os.tmpdir(), "zx-downloads-"));
  const payload = Buffer.from("MZ fake installer " + Date.now());
  fs.writeFileSync(path.join(downloads, "ZehnMS-Setup-1.9.0.exe"), "older");
  fs.writeFileSync(path.join(downloads, "ZehnMS-Setup-1.10.0.exe"), payload);   // newest, but sorts first as text
  fs.writeFileSync(path.join(downloads, "ZehnMS-Setup-2.0.0.exe.part"), "an upload still in progress");
  fs.writeFileSync(path.join(downloads, "OtherApp-Setup-9.9.9.exe"), "another product");
  const server = spawn(process.execPath, ["server.js", String(PORT)], {
    cwd: ROOT, stdio: "ignore", env: Object.assign({}, process.env, { DOWNLOADS_DIR: downloads }),
  });
  try {
    for (let i = 0; i < 100; i++) { try { await fetch(base + "/"); break; } catch (_) { await new Promise((r) => setTimeout(r, 100)); } }

    await test("demo pages answer 200 at their own .html names — no redirect, noindex", async () => {
      for (const d of demos) {
        for (const p of ["/demo/" + d.slug + "/", "/demo/" + d.slug + "/index.html"].concat(
          files(path.join(DIST, "demo", d.slug), [], "").filter((f) => f.endsWith(".html")).map((f) => "/demo/" + d.slug + "/" + f))) {
          const res = await fetch(base + p, { redirect: "manual" });
          assert.strictEqual(res.status, 200, p + " returned " + res.status + " " + (res.headers.get("location") || ""));
          assert.match(res.headers.get("x-robots-tag") || "", /noindex/, p + " is missing X-Robots-Tag: noindex");
        }
      }
    });

    await test("/zehnms answers 200 and is indexable", async () => {
      const res = await fetch(base + "/zehnms", { redirect: "manual" });
      assert.strictEqual(res.status, 200);
      assert.ok(!res.headers.get("x-robots-tag"), "the product page must stay indexable");
      assert.ok(fs.readFileSync(path.join(DIST, "sitemap.xml"), "utf8").includes("/zehnms</loc>"), "/zehnms is not in the sitemap");
    });

    await test("/download/zehnms sends the newest version, compared as numbers", async () => {
      const res = await fetch(base + "/download/zehnms", { redirect: "manual" });
      assert.strictEqual(res.status, 302);
      assert.strictEqual(res.headers.get("location"), "/downloads/ZehnMS-Setup-1.10.0.exe", "1.10.0 must beat 1.9.0, and a half-uploaded .part must be ignored");
      assert.strictEqual(res.headers.get("cache-control"), "no-cache", "the redirect must not be cached, or a new version would not show");
    });

    await test("the installer downloads intact, as an attachment", async () => {
      const res = await fetch(base + "/downloads/ZehnMS-Setup-1.10.0.exe");
      assert.strictEqual(res.status, 200);
      assert.ok(Buffer.from(await res.arrayBuffer()).equals(payload), "the bytes served are not the file on disk");
      assert.strictEqual(res.headers.get("content-disposition"), 'attachment; filename="ZehnMS-Setup-1.10.0.exe"');
      assert.strictEqual(res.headers.get("cache-control"), "public, max-age=300", "a re-uploaded installer must show within minutes");
      assert.match(res.headers.get("x-robots-tag") || "", /noindex/);
    });

    await test("the downloads folder cannot be listed or escaped", async () => {
      for (const p of ["/download/nothing", "/download/", "/downloads/", "/downloads/..%2fserver.js", "/downloads/%2e%2e/server.js", "/download/..%2f..%2fetc"]) {
        const res = await fetch(base + p, { redirect: "manual" });
        const body = await res.text();
        assert.ok(res.status === 404 || res.status === 400, p + " returned " + res.status);
        assert.ok(!body.includes("createServer"), p + " leaked server source");
      }
    });
  } finally {
    server.kill();
    try { fs.rmSync(downloads, { recursive: true, force: true }); } catch (_) { /* best effort */ }
  }

  /* ---- a server with no installer at all: the button must still start a download ---- */
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), "zx-downloads-empty-"));
  const bare = spawn(process.execPath, ["server.js", String(PORT + 1)], {
    cwd: ROOT, stdio: "ignore", env: Object.assign({}, process.env, { DOWNLOADS_DIR: empty }),
  });
  try {
    const base2 = "http://127.0.0.1:" + (PORT + 1);
    for (let i = 0; i < 100; i++) { try { await fetch(base2 + "/"); break; } catch (_) { await new Promise((r) => setTimeout(r, 100)); } }

    await test("with no installer on the server, /download/zehnms falls back to a direct download", async () => {
      const res = await fetch(base2 + "/download/zehnms", { redirect: "manual" });
      assert.strictEqual(res.status, 302, "the Download button would dead-end on a 404");
      const to = res.headers.get("location") || "";
      assert.match(to, /^https:\/\//, "fallback must be an absolute https url: " + to);
      // A Drive share link (/file/d/…/view) opens a preview page, not a download.
      assert.ok(!/drive\.google\.com\/file\/d\//.test(to), "fallback is a Drive preview link, which does not start a download: " + to);
      if (/drive\.usercontent\.google\.com/.test(to)) assert.match(to, /[?&]confirm=t\b/, "without confirm=t, Drive stops large files on a virus-scan page");
      assert.strictEqual(res.headers.get("cache-control"), "no-cache", "the fallback must not be cached, or the server copy would never take over");
    });

    await test("a product with no installer and no fallback still 404s", async () => {
      const res = await fetch(base2 + "/download/nothing", { redirect: "manual" });
      assert.strictEqual(res.status, 404);
    });
  } finally {
    bare.kill();
    try { fs.rmSync(empty, { recursive: true, force: true }); } catch (_) { /* best effort */ }
  }

  console.log("\n" + (failed ? "FAILED " : "") + passed + " passed, " + failed + " failed");
  process.exitCode = failed ? 1 : 0;
  setTimeout(() => process.exit(process.exitCode), 200);
})();
