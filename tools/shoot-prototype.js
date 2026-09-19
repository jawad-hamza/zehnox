"use strict";
/* Captures marketing screenshots of a product prototype, straight to WebP, using the Chrome
   (or Edge) already installed on this machine. No dependencies: it launches the browser
   headless and talks to it over the DevTools protocol with Node's built-in WebSocket.

   Run: node tools/shoot-prototype.js            (every product in SHOTS)
        node tools/shoot-prototype.js zehnms     (one product)

   Output lands in src/products/<product>/, next to the other product images. Re-run it
   after changing a prototype so the product page never shows a stale screen. */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const ROOT = path.join(__dirname, "..");
const PORT = 9333;

/* What to shoot. viewport is in CSS pixels; scale is the device pixel ratio, so a 1440 wide
   desktop at 1.5 lands at 2160px — sharp on a retina screen, still small as WebP. */
const SHOTS = {
  zehnms: {
    dir: "Prototypes/ZehnMS",
    shots: [
      { page: "dashboard.html", out: "dashboard.webp", width: 1440, height: 900, scale: 1.5, mobile: false },
      { page: "receipt.html", out: "receipt-phone.webp", width: 390, height: 780, scale: 2, mobile: true },
      { page: "dashboard.html", out: "og.jpg", width: 1200, height: 630, scale: 1, mobile: false, format: "jpeg" },
    ],
  },
};

const BROWSERS = [
  process.env.CHROME_PATH,
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
].filter(Boolean);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function cdp(wsUrl) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    let id = 0;
    const pending = new Map(), waiters = [];
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && pending.has(msg.id)) {
        const { ok, fail } = pending.get(msg.id);
        pending.delete(msg.id);
        msg.error ? fail(new Error(msg.error.message)) : ok(msg.result);
      } else if (msg.method) {
        for (const w of waiters.slice()) if (w.method === msg.method) { waiters.splice(waiters.indexOf(w), 1); w.ok(msg.params); }
      }
    };
    ws.onerror = () => reject(new Error("could not connect to the browser"));
    ws.onopen = () => resolve({
      send: (method, params) => new Promise((ok, fail) => { const n = ++id; pending.set(n, { ok, fail }); ws.send(JSON.stringify({ id: n, method, params: params || {} })); }),
      once: (method, ms) => new Promise((ok, fail) => { waiters.push({ method, ok }); setTimeout(() => fail(new Error("timed out waiting for " + method)), ms || 15000); }),
      close: () => ws.close(),
    });
  });
}

(async () => {
  const exe = BROWSERS.find((p) => fs.existsSync(p));
  if (!exe) throw new Error("no Chrome or Edge found — set CHROME_PATH");
  const only = process.argv[2];
  const products = Object.keys(SHOTS).filter((k) => !only || k === only);
  if (!products.length) throw new Error("unknown product " + only + " — known: " + Object.keys(SHOTS).join(", "));

  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "zx-shoot-"));
  const browser = spawn(exe, [
    "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run", "--no-default-browser-check",
    "--remote-debugging-port=" + PORT, "--user-data-dir=" + profile, "about:blank",
  ], { stdio: "ignore" });

  try {
    let target = null;
    for (let i = 0; i < 100 && !target; i++) {
      try { target = (await (await fetch("http://127.0.0.1:" + PORT + "/json/list")).json()).find((t) => t.type === "page"); }
      catch (_) { await sleep(100); }
    }
    if (!target) throw new Error("the browser never opened a page");
    const page = await cdp(target.webSocketDebuggerUrl);
    await page.send("Page.enable");

    for (const product of products) {
      const spec = SHOTS[product];
      const outDir = path.join(ROOT, "src", "products", product);
      fs.mkdirSync(outDir, { recursive: true });
      for (const s of spec.shots) {
        await page.send("Emulation.setDeviceMetricsOverride", { width: s.width, height: s.height, deviceScaleFactor: s.scale, mobile: s.mobile });
        const url = "file:///" + path.join(ROOT, spec.dir, s.page).split(path.sep).join("/");
        const loaded = page.once("Page.loadEventFired");
        await page.send("Page.navigate", { url });
        await loaded;
        // Wait for the webfont, then let any entry transitions settle before the shutter.
        await page.send("Runtime.evaluate", { expression: "document.fonts.ready.then(() => true)", awaitPromise: true });
        await sleep(400);
        const format = s.format || "webp";
        const shot = await page.send("Page.captureScreenshot", { format, quality: format === "jpeg" ? 82 : 80 });
        const buf = Buffer.from(shot.data, "base64");
        fs.writeFileSync(path.join(outDir, s.out), buf);
        console.log("  " + String(Math.round(buf.length / 1024) + " KB").padStart(7) + "  " +
          (s.width * s.scale) + "x" + (s.height * s.scale) + "  src/products/" + product + "/" + s.out);
      }
    }
    page.close();
  } finally {
    browser.kill();
    await sleep(300);
    try { fs.rmSync(profile, { recursive: true, force: true }); } catch (_) { /* the browser may still hold a lock */ }
  }
})().catch((e) => { console.error("shoot-prototype: " + e.message); process.exitCode = 1; });
