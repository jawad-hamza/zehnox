#!/usr/bin/env node
/* ZEHNOX site builder — src/ → dist/  (CONTRACT.md §7)
   - copies src/ to dist/ (skips _templates/)
   - regenerates src/js/content.js AND dist/js/content.js from content.json (window.CONTENT)
   - expands src/_templates/post.html once per post into dist/insights/<slug>.html
   - publishes each Prototypes/<Name>/ demo verbatim to dist/demo/<name>/ (kept out of the sitemap)
   - injects the Google Analytics tag and the AdSense verification meta into every html page,
     and the ZehnBot chat widget into every public one (not /demo/), on their way into dist/
   - writes dist/sitemap.xml (every html page, using site.url) and dist/robots.txt
   - idempotent: files in dist/ that this build did not produce are deleted
   Node built-ins only. Usage: node build.js   |   const { build } = require("./build"); build();
*/
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = __dirname;
const SRC = path.join(ROOT, "src");
const DIST = path.join(ROOT, "dist");
const CONTENT_FILE = path.join(ROOT, "content.json");
const TEMPLATE_FILE = path.join(SRC, "_templates", "post.html");
const SKIP_DIRS = new Set(["_templates"]);
/* Product prototypes: static click-through demos for customers, kept at the repo root so
   they can still be opened by double-clicking. Each Prototypes/<Name>/ is published as-is
   to dist/demo/<name>/ — its own relative .html links, css and fonts untouched. */
const PROTOTYPES = path.join(ROOT, "Prototypes");
const DEMO_DIR = "demo";
const PROTOTYPE_SKIP = new Set(["readme.txt"]);   // notes for us, not for customers
const CONTENT_JS_HEADER = "/* generated from content.json by build.js - do not edit by hand */";
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/* ---------- small helpers ---------- */
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const inline = (s) => esc(s).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/\*(.+?)\*/g, "<em>$1</em>");

/* Light markdown → HTML. Mirrors site.js textToHtml exactly:
   blank-line paragraphs, ## / ### headings, - and 1. lists, > quotes, **bold**, *italic*. */
function textToHtml(text) {
  return String(text || "").replace(/\r/g, "").trim().split(/\n\s*\n/).map((block) => {
    const lines = block.split("\n");
    if (/^###\s/.test(lines[0])) return "<h3>" + inline(lines[0].replace(/^###\s+/, "")) + "</h3>";
    if (/^##\s/.test(lines[0])) return "<h2>" + inline(lines[0].replace(/^##\s+/, "")) + "</h2>";
    if (lines.every((l) => /^[-*]\s/.test(l))) return "<ul>" + lines.map((l) => "<li>" + inline(l.replace(/^[-*]\s+/, "")) + "</li>").join("") + "</ul>";
    if (lines.every((l) => /^\d+[.)]\s/.test(l))) return "<ol>" + lines.map((l) => "<li>" + inline(l.replace(/^\d+[.)]\s+/, "")) + "</li>").join("") + "</ol>";
    if (/^>\s/.test(lines[0])) return "<blockquote>" + inline(lines.map((l) => l.replace(/^>\s?/, "")).join(" ")) + "</blockquote>";
    return "<p>" + lines.map(inline).join("<br>") + "</p>";
  }).filter(Boolean).join("\n");
}

/* "2026-08-20" → "20 Aug 2026" (same output as site.js fmtDate, en-GB, without relying on ICU). */
function dateDisplay(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(iso || "").trim());
  if (!m) return esc(iso);
  const month = MONTHS[parseInt(m[2], 10) - 1];
  return month ? m[3] + " " + month + " " + m[1] : esc(iso);
}

function slugify(s) {
  return String(s || "").toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 120);
}

function siteUrl(content) {
  const u = content && content.site && typeof content.site.url === "string" ? content.site.url.trim() : "";
  return (u || "https://zehnox.com").replace(/\/+$/, "");
}

function readContent() {
  const raw = fs.readFileSync(CONTENT_FILE, "utf8");
  const content = JSON.parse(raw);
  if (!content || typeof content !== "object") throw new Error("content.json must contain a JSON object");
  return content;
}

/* Settings the server acts on but no page should ever read. window.CONTENT ships to every
   visitor, so anything left in here is public: the webhook URL would be an open endpoint
   for anyone to POST to, and the forwarding address is an inbox we would be publishing to
   scrapers. site.contactEndpoint deliberately stays \u2014 src/js/site.js reads it. */
const SERVER_ONLY_SITE_KEYS = ["inquiryWebhook", "inquiryEmail"];

function publicContent(content) {
  if (!content || typeof content.site !== "object" || content.site === null) return content;
  const site = Object.assign({}, content.site);
  for (const key of SERVER_ONLY_SITE_KEYS) delete site[key];
  return Object.assign({}, content, { site });
}

/* Serialise for a <script> tag: never let "</script" or line separators break the page. */
function contentJs(content) {
  const json = JSON.stringify(publicContent(content)).replace(/<\//g, "<\\/").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  return CONTENT_JS_HEADER + "\nwindow.CONTENT = " + json + ";\n";
}

/* ---------- analytics ----------
   Google Analytics 4. The tag lives here, in one place, instead of being pasted into
   twenty-odd src/*.html heads: every page that reaches dist/ picks it up on the way
   through makeWriter, including the insight pages expanded from the post template.
   The admin panel is served straight out of admin/ by server.js and never passes through
   this build, so it stays untagged by construction.
   Set GA_MEASUREMENT_ID="" in the environment to build an untagged copy of the site. */
const GA_MEASUREMENT_ID = process.env.GA_MEASUREMENT_ID !== undefined
  ? process.env.GA_MEASUREMENT_ID.trim()
  : "G-5FYXZZP8N1";

const isHtml = (rel) => /\.html?$/i.test(rel);

function analyticsTag(nl) {
  return [
    "<!-- Google tag (gtag.js) — injected by build.js; edit GA_MEASUREMENT_ID there, not here -->",
    '<script async src="https://www.googletagmanager.com/gtag/js?id=' + GA_MEASUREMENT_ID + '"></script>',
    "<script>",
    "  window.dataLayer = window.dataLayer || [];",
    "  function gtag(){dataLayer.push(arguments);}",
    "  gtag('js', new Date());",
    "",
    "  gtag('config', '" + GA_MEASUREMENT_ID + "');",
    "</script>",
  ].join(nl);
}

/* Put a snippet as high in <head> as possible — but after <meta charset>, which has to stay
   first, because a browser only looks for the encoding in the opening bytes of the document. */
function insertInHead(html, rel, snippet, what) {
  const nl = html.indexOf("\r\n") !== -1 ? "\r\n" : "\n";
  const charset = /<meta[^>]+charset=[^>]*>/i.exec(html);
  const head = /<head[^>]*>/i.exec(html);
  const anchor = charset || head;
  if (!anchor) throw new Error(rel + ": no <head> to put the " + what + " in");
  const at = anchor.index + anchor[0].length;
  return html.slice(0, at) + nl + snippet(nl) + html.slice(at);
}

function withAnalytics(html, rel) {
  if (!GA_MEASUREMENT_ID) return html;
  if (html.indexOf("googletagmanager.com") !== -1) return html;   // already tagged; never double up
  return insertInHead(html, rel, analyticsTag, "analytics tag");
}

/* ---------- AdSense site verification ----------
   Google reads this from the <head> of the site's pages to confirm the domain belongs to
   this AdSense account. Injected here for the same reason as the analytics tag: one place
   to change it, and every page — including generated ones — carries it.
   Set ADSENSE_ACCOUNT="" in the environment to build without it. */
const ADSENSE_ACCOUNT = process.env.ADSENSE_ACCOUNT !== undefined
  ? process.env.ADSENSE_ACCOUNT.trim()
  : "ca-pub-3920913029248414";

function withAdsense(html, rel) {
  if (!ADSENSE_ACCOUNT) return html;
  if (html.indexOf("google-adsense-account") !== -1) return html;
  return insertInHead(html, rel, () => '<meta name="google-adsense-account" content="' + esc(ADSENSE_ACCOUNT) + '">', "AdSense meta tag");
}

/* ---------- ZehnBot chat widget ----------
   The site runs its own product: every public page gets the ZehnBot widget, injected here
   like the analytics tag so it lives in one place. Not on /demo/ pages, where the launcher
   would sit on top of the prototype's own bottom bar.
   Loaded async rather than defer: a deferred script holds back DOMContentLoaded until it
   arrives, so a slow bot.zehnox.com would hold back this whole site with it. The widget
   finds its own tag and starts once document.body exists, so it does not need defer.
   Set CHAT_WIDGET_SRC="" in the environment to build without it. */
const CHAT_WIDGET_SRC = process.env.CHAT_WIDGET_SRC !== undefined
  ? process.env.CHAT_WIDGET_SRC.trim()
  : "https://bot.zehnox.com/static/widget.js?client_id=zehnox-db881c";

function withChatWidget(html, rel) {
  if (!CHAT_WIDGET_SRC) return html;
  if (rel.split(path.sep).join("/").startsWith(DEMO_DIR + "/")) return html;
  if (html.indexOf("bot.zehnox.com/static/widget.js") !== -1) return html;   // already there; never twice
  const end = html.search(/<\/body>/i);
  if (end === -1) throw new Error(rel + ": no </body> to put the chat widget before");
  const nl = html.indexOf("\r\n") !== -1 ? "\r\n" : "\n";
  return html.slice(0, end) + '<script src="' + esc(CHAT_WIDGET_SRC) + '" async></script>' + nl + html.slice(end);
}

const withSiteTags = (html, rel) => withChatWidget(withAdsense(withAnalytics(html, rel), rel), rel);

/* ---------- output tracking (so stale files can be removed) ---------- */
function makeWriter(written) {
  const ensureDir = (dir) => fs.mkdirSync(dir, { recursive: true });
  return {
    write(rel, data) {
      const abs = path.join(DIST, rel);
      ensureDir(path.dirname(abs));
      fs.writeFileSync(abs, isHtml(rel) ? withSiteTags(String(data), rel) : data);
      written.add(path.normalize(rel));
    },
    /* Pages are read, tagged and written rather than copied byte for byte; everything
       else (css, js, fonts, uploads, svg) still takes the plain copy path. */
    copy(srcAbs, rel) {
      const abs = path.join(DIST, rel);
      ensureDir(path.dirname(abs));
      if (isHtml(rel)) fs.writeFileSync(abs, withSiteTags(fs.readFileSync(srcAbs, "utf8"), rel));
      else fs.copyFileSync(srcAbs, abs);
      written.add(path.normalize(rel));
    }
  };
}

function copyTree(srcDir, relDir, out, stats) {
  for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
    const rel = relDir ? path.join(relDir, entry.name) : entry.name;
    const abs = path.join(srcDir, entry.name);
    // "_templates/" and any other underscore-prefixed file or folder (e.g. insights/_preview.html) are dev-only
    if (entry.name.startsWith("_") || entry.name.startsWith(".")) continue;
    if (entry.isDirectory()) {
      if (!relDir && SKIP_DIRS.has(entry.name)) continue;
      copyTree(abs, rel, out, stats);
    } else if (entry.isFile()) {
      if (path.normalize(rel) === path.normalize(path.join("js", "content.js"))) continue; // regenerated below
      out.copy(abs, rel);
      stats.copied++;
    }
  }
}

function copyPrototype(srcDir, relDir, out, stats) {
  for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
    if (entry.name.startsWith(".") || PROTOTYPE_SKIP.has(entry.name.toLowerCase())) continue;
    const abs = path.join(srcDir, entry.name);
    const rel = path.join(relDir, entry.name);
    if (entry.isDirectory()) copyPrototype(abs, rel, out, stats);
    else if (entry.isFile()) { out.copy(abs, rel); stats.copied++; }
  }
}

/* Every Prototypes/<Name>/ becomes /demo/<name>/. Returns the published names. */
function publishPrototypes(out, stats) {
  if (!fs.existsSync(PROTOTYPES)) return [];
  const names = [];
  for (const entry of fs.readdirSync(PROTOTYPES, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name.startsWith(".") || entry.name.startsWith("_")) continue;
    const slug = entry.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
    if (!slug) continue;
    copyPrototype(path.join(PROTOTYPES, entry.name), path.join(DEMO_DIR, slug), out, stats);
    names.push(slug);
  }
  return names;
}

function removeStale(written, log) {
  if (!fs.existsSync(DIST)) return 0;
  let removed = 0;
  const walk = (dir, relDir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const rel = relDir ? path.join(relDir, entry.name) : entry.name;
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(abs, rel);
        if (fs.readdirSync(abs).length === 0) fs.rmdirSync(abs);
      } else if (!written.has(path.normalize(rel))) {
        fs.rmSync(abs, { force: true });
        removed++;
        log("  stale: removed " + rel.split(path.sep).join("/"));
      }
    }
  };
  walk(DIST, "");
  return removed;
}

/* ---------- template expansion ---------- */
function postContext(post, content) {
  const slug = slugify(post.slug || post.title);
  const tags = Array.isArray(post.tags) ? post.tags.map((t) => String(t)).filter(Boolean) : [];
  const url = siteUrl(content) + "/insights/" + slug;
  return {
    site: {
      url: siteUrl(content),
      name: (content.site && content.site.name) || "ZEHNOX",
      slogan: (content.site && content.site.slogan) || "From Mind to World",
      ecosystemLine: (content.site && content.site.ecosystemLine) || ""
    },
    post: {
      slug,
      title: post.title || "",
      date: post.date || "",
      dateDisplay: dateDisplay(post.date),
      tags: tags.join(", "),
      tag: tags[0] || "Insight",
      tagsHtml: tags.map((t) => '<span class="row__tag">' + esc(t) + "</span>").join(""),
      description: post.description || "",
      bodyHtml: textToHtml(post.body),
      url
    }
  };
}

const RAW_TOKENS = new Set(["post.bodyHtml", "post.tagsHtml"]);

function expandTemplate(template, ctx, warn) {
  return template.replace(/\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}/g, (match, key) => {
    const value = key.split(".").reduce((o, k) => (o == null ? undefined : o[k]), ctx);
    if (value === undefined) { warn("unknown template token " + match + " (left empty)"); return ""; }
    if (RAW_TOKENS.has(key)) return String(value);
    if (key === "post.dateDisplay") return String(value); // already escaped
    return esc(value);
  });
}

/* ---------- sitemap / robots ---------- */
function sitemapXml(pages, content, posts) {
  const base = siteUrl(content);
  const lastmod = new Map(posts.map((p) => ["insights/" + p.slug + ".html", p.date]));
  const items = pages
    .filter((p) => p !== "404.html")
    .sort((a, b) => (a === "index.html" ? -1 : b === "index.html" ? 1 : a.localeCompare(b)))
    .map((p) => {
      // The pages are files on disk (about.html) but the site is served at extensionless
      // routes (/about), and only one of the two may appear in the sitemap.
      const loc = p === "index.html" ? base + "/" : base + "/" + p.replace(/\.html$/, "");
      const mod = lastmod.get(p);
      return "  <url><loc>" + esc(loc) + "</loc>" + (mod && /^\d{4}-\d{2}-\d{2}$/.test(mod) ? "<lastmod>" + mod + "</lastmod>" : "") + "</url>";
    });
  return '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + items.join("\n") + "\n</urlset>\n";
}

function robotsTxt(content) {
  return "User-agent: *\nAllow: /\nDisallow: /admin/\nDisallow: /api/\nDisallow: /" + DEMO_DIR + "/\n\nSitemap: " + siteUrl(content) + "/sitemap.xml\n";
}

/* ---------- main ---------- */
function build(options) {
  const opts = options || {};
  const quiet = !!opts.quiet;
  const messages = [];
  const log = (m) => { messages.push(m); if (!quiet) console.log(m); };
  const warn = (m) => { messages.push("warning: " + m); if (!quiet) console.warn("warning: " + m); };
  const started = Date.now();
  const stats = { copied: 0, posts: 0, pages: 0, removed: 0, warnings: 0 };

  if (!fs.existsSync(SRC)) throw new Error("src/ not found at " + SRC);
  const content = readContent();
  const written = new Set();
  const out = makeWriter(written);

  // 1. copy src → dist
  fs.mkdirSync(DIST, { recursive: true });
  copyTree(SRC, "", out, stats);
  const demos = publishPrototypes(out, stats);

  // 2. content.js in both places
  const js = contentJs(content);
  fs.mkdirSync(path.join(SRC, "js"), { recursive: true });
  fs.writeFileSync(path.join(SRC, "js", "content.js"), js);
  out.write(path.join("js", "content.js"), js);

  // 3. insights posts
  const posts = [];
  const rawPosts = Array.isArray(content.posts) ? content.posts : [];
  if (fs.existsSync(TEMPLATE_FILE)) {
    const template = fs.readFileSync(TEMPLATE_FILE, "utf8");
    const seen = new Set();
    for (const post of rawPosts) {
      if (!post || typeof post !== "object") { warn("skipping a post that is not an object"); continue; }
      const ctx = postContext(post, content);
      if (!ctx.post.slug) { warn("skipping post without a usable slug/title"); continue; }
      if (seen.has(ctx.post.slug)) { warn("duplicate post slug \"" + ctx.post.slug + "\" — later post skipped"); continue; }
      seen.add(ctx.post.slug);
      out.write(path.join("insights", ctx.post.slug + ".html"), expandTemplate(template, ctx, warn));
      posts.push(ctx.post);
      stats.posts++;
    }
  } else if (rawPosts.length) {
    warn("src/_templates/post.html not found — " + rawPosts.length + " insight page(s) not generated");
  }

  // 4. sitemap + robots (every html page now in dist, minus the demos: dummy data is not
  //    something to rank for, so they stay out of the index)
  const pages = [...written].filter((f) => f.endsWith(".html")).map((f) => f.split(path.sep).join("/"))
    .filter((f) => !f.startsWith(DEMO_DIR + "/"));
  out.write("sitemap.xml", sitemapXml(pages, content, posts));
  out.write("robots.txt", robotsTxt(content));
  stats.pages = pages.length;

  // 5. stale files
  stats.removed = removeStale(written, log);
  stats.warnings = messages.filter((m) => m.startsWith("warning:")).length;

  const ms = Date.now() - started;
  log("build: " + stats.copied + " files copied, " + stats.posts + " insight page(s), " +
      (demos.length ? demos.length + " demo(s) at /" + DEMO_DIR + "/ (" + demos.join(", ") + "), " : "") +
      stats.pages + " html page(s) in sitemap, " +
      stats.removed + " stale file(s) removed, " + stats.warnings + " warning(s) — " + ms + " ms → " + path.relative(ROOT, DIST) + "/");
  return { ok: true, ms, stats, messages, dist: DIST };
}

module.exports = { build, textToHtml, dateDisplay, slugify, contentJs, postContext, expandTemplate };

if (require.main === module) {
  try {
    build();
  } catch (err) {
    console.error("build failed: " + (err && err.message ? err.message : err));
    process.exit(1);
  }
}
