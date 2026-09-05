#!/usr/bin/env node
/* ZEHNOX site builder — src/ → dist/  (CONTRACT.md §7)
   - copies src/ to dist/ (skips _templates/)
   - regenerates src/js/content.js AND dist/js/content.js from content.json (window.CONTENT)
   - expands src/_templates/post.html once per post into dist/insights/<slug>.html
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

/* Serialise for a <script> tag: never let "</script" or line separators break the page. */
function contentJs(content) {
  const json = JSON.stringify(content).replace(/<\//g, "<\\/").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  return CONTENT_JS_HEADER + "\nwindow.CONTENT = " + json + ";\n";
}

/* ---------- output tracking (so stale files can be removed) ---------- */
function makeWriter(written) {
  const ensureDir = (dir) => fs.mkdirSync(dir, { recursive: true });
  return {
    write(rel, data) {
      const abs = path.join(DIST, rel);
      ensureDir(path.dirname(abs));
      fs.writeFileSync(abs, data);
      written.add(path.normalize(rel));
    },
    copy(srcAbs, rel) {
      const abs = path.join(DIST, rel);
      ensureDir(path.dirname(abs));
      fs.copyFileSync(srcAbs, abs);
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
  const url = siteUrl(content) + "/insights/" + slug + ".html";
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
      const loc = p === "index.html" ? base + "/" : base + "/" + p;
      const mod = lastmod.get(p);
      return "  <url><loc>" + esc(loc) + "</loc>" + (mod && /^\d{4}-\d{2}-\d{2}$/.test(mod) ? "<lastmod>" + mod + "</lastmod>" : "") + "</url>";
    });
  return '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + items.join("\n") + "\n</urlset>\n";
}

function robotsTxt(content) {
  return "User-agent: *\nAllow: /\nDisallow: /admin/\nDisallow: /api/\n\nSitemap: " + siteUrl(content) + "/sitemap.xml\n";
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

  // 4. sitemap + robots (every html page now in dist)
  const pages = [...written].filter((f) => f.endsWith(".html")).map((f) => f.split(path.sep).join("/"));
  out.write("sitemap.xml", sitemapXml(pages, content, posts));
  out.write("robots.txt", robotsTxt(content));
  stats.pages = pages.length;

  // 5. stale files
  stats.removed = removeStale(written, log);
  stats.warnings = messages.filter((m) => m.startsWith("warning:")).length;

  const ms = Date.now() - started;
  log("build: " + stats.copied + " files copied, " + stats.posts + " insight page(s), " + stats.pages + " html page(s) in sitemap, " +
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
