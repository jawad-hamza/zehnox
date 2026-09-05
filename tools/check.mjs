/* Headless QA for the ZEHNOX site. Dev-only; uses the Playwright already installed in ../Zehnox.
   Usage: node tools/check.mjs <baseUrl> [outDir] [page1.html page2.html ...]
   Without pages, checks every .html under src/ (excluding _templates) plus generated insights pages.
   Reports per page + viewport: page errors, console errors, failed requests, horizontal overflow,
   reveals still hidden after scrolling, and saves screenshots (top, mid, bottom) to outDir. */
import { createRequire } from "node:module";
import { readdirSync, statSync, mkdirSync, existsSync } from "node:fs";
import { join, relative, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const require = createRequire(join(root, "..", "Zehnox", "package.json"));
const { chromium } = require("@playwright/test");

const [base = "http://127.0.0.1:8766/", outDir = join(root, "tools", "shots"), ...pageArgs] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });

function listPages(dir, prefix = "") {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) { if (!["_templates", "uploads", "brand", "css", "js"].includes(name)) out.push(...listPages(p, prefix + name + "/")); }
    else if (name.endsWith(".html")) out.push(prefix + name);
  }
  return out;
}
const srcDir = existsSync(join(root, "dist")) && base.includes("dist") ? join(root, "dist") : join(root, "src");
const pages = pageArgs.length ? pageArgs : listPages(srcDir);

const VIEWPORTS = [["desktop", { width: 1440, height: 900 }, false], ["laptop", { width: 1280, height: 720 }, false], ["mobile", { width: 390, height: 844 }, true]];
const browser = await chromium.launch();
let failures = 0;
for (const page of pages) {
  for (const [vp, size, mobile] of VIEWPORTS) {
    const ctx = await browser.newContext({ viewport: size, isMobile: mobile, hasTouch: mobile });
    const p = await ctx.newPage();
    const issues = [];
    p.on("pageerror", (e) => issues.push("pageerror: " + e.message));
    p.on("console", (m) => { if (m.type() === "error") issues.push("console: " + m.text()); });
    p.on("requestfailed", (r) => { if (!/fonts\.g|cdnjs|jsdelivr/.test(r.url())) issues.push("requestfailed: " + r.url()); });
    p.on("response", (r) => { if (r.status() >= 400 && r.url().startsWith(base)) issues.push("http " + r.status() + ": " + r.url().replace(base, "")); });
    try {
      await p.goto(base + page, { waitUntil: "load", timeout: 60000 });
      await p.waitForTimeout(3200);
      const slug = page.replace(/[\/.]/g, "_");
      await p.screenshot({ path: join(outDir, `${slug}-${vp}-top.png`) });
      const h = await p.evaluate(() => document.body.scrollHeight);
      for (let y = 0; y < h; y += 480) { await p.mouse.wheel(0, 480); await p.waitForTimeout(50); }
      await p.waitForTimeout(2500);
      await p.screenshot({ path: join(outDir, `${slug}-${vp}-bottom.png`) });
      const report = await p.evaluate(() => {
        const vis = (el) => { const r = el.getBoundingClientRect(); return r.bottom > 0 && r.top < innerHeight; };
        return {
          overflowX: document.documentElement.scrollWidth > innerWidth + 1,
          hiddenReveals: [...document.querySelectorAll(".reveal")].filter((e) => vis(e) && getComputedStyle(e).opacity === "0").length,
          loading: document.body.classList.contains("is-loading"),
          title: document.title,
          h1: (document.querySelector("h1") || {}).textContent || "(no h1)",
          hasFinal: !!document.querySelector(".final"),
          hasFooter: !!document.querySelector("footer.footer"),
          brokenLinks: [...document.querySelectorAll('a[href$=".html"]')].map((a) => a.getAttribute("href")).filter((h, i, arr) => arr.indexOf(h) === i),
          smallTaps: mobileTaps(),
        };
        function mobileTaps() {
          if (innerWidth > 500) return 0;
          return [...document.querySelectorAll("a, button")].filter((el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && r.height < 32 && getComputedStyle(el).display !== "inline"; }).length;
        }
      });
      if (report.overflowX) issues.push("horizontal overflow");
      if (report.hiddenReveals) issues.push(report.hiddenReveals + " reveals still hidden in viewport");
      if (report.loading) issues.push("body still has is-loading");
      if (!report.hasFinal) issues.push("missing .final conversion block");
      if (!report.hasFooter) issues.push("missing footer");
      // verify internal links resolve
      for (const href of report.brokenLinks) {
        if (/^https?:/.test(href)) continue;
        const target = new URL(href, base + page).toString();
        const r = await p.request.get(target).catch(() => null);
        if (!r || r.status() >= 400) issues.push("broken link: " + href);
      }
      const status = issues.length ? "FAIL" : "ok";
      if (issues.length) failures++;
      console.log(`${status}  ${page} [${vp}]  "${report.title}"` + (issues.length ? "\n      - " + issues.join("\n      - ") : ""));
    } catch (e) {
      failures++;
      console.log(`FAIL  ${page} [${vp}]  ${e.message.split("\n")[0]}`);
    }
    await ctx.close();
  }
}
await browser.close();
console.log(`\n${pages.length} pages × ${VIEWPORTS.length} viewports, ${failures} failing. Screenshots in ${relative(process.cwd(), outDir) || "."}`);
process.exit(failures ? 1 : 0);
