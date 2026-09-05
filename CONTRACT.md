# ZEHNOX site — build contract

Read this before touching anything in `zehnox-site/`. It is the agreement between every page,
the shared runtime, the content file, and the admin backend.

## 1. Layout of the project

```
zehnox-site/
  content.json          ← every editable value (contact, socials, team, work, posts, legal). Edited by the admin UI.
  src/                  ← the site source. Static HTML/CSS/JS. No build tooling, no frameworks.
    index.html          ← homepage (done; the reference for tone, header, footer, CTA block, contact form)
    css/style.css       ← the ONLY stylesheet. Homepage styles + the inner-page kit (section "INNER-PAGE KIT").
    js/site.js          ← shared runtime for every page (content binding, Lenis, nav, cursor, reveals, team roster, contact form)
    js/home.js          ← homepage only
    js/content.js       ← GENERATED from content.json (window.CONTENT). Never edit by hand.
    brand/              ← logo SVGs
    uploads/            ← images uploaded through the admin (portraits, work images)
    _templates/         ← page templates the builder expands (post.html for insights articles)
    <pages>.html, services/*.html, solutions/*.html, insights/*.html
  build.js              ← src → dist: copies files, regenerates js/content.js, expands templates, writes sitemap.xml
  server.js             ← zero-dependency Node server: serves dist/, hosts /admin, JSON API, stores inquiries
  admin/                ← vanilla admin UI (edit content.json, upload images, build, view inquiries)
  data/                 ← runtime data (admin token, inquiries.json). Not deployed.
  dist/                 ← READY-TO-DEPLOY output of build.js. Upload this folder to any static host.
  tools/check.mjs       ← headless QA (desktop + mobile) over every page
```

Node 24 is available. Use ONLY Node built-ins (`http`, `fs`, `path`, `crypto`). No `npm install`, no `package.json` dependencies.

## 2. Pages to build (spec §5) and where they live

| Page | File | Root prefix |
|---|---|---|
| About | `src/about.html` | `` |
| Services hub | `src/services.html` | `` |
| Service detail ×5 | `src/services/{ai-automation,creative-studio,web-and-digital,software-solutions,training}.html` | `../` |
| Solutions hub | `src/solutions.html` | `` |
| Solution detail ×8 | `src/solutions/{local-business,corporate,education,startups,creators,real-estate,trading,international}.html` | `../` |
| Work | `src/work.html` | `` |
| Insights index | `src/insights.html` | `` |
| Insight article template | `src/_templates/post.html` (builder expands to `insights/<slug>.html`) | `../` |
| Contact | `src/contact.html` | `` |
| Thank you | `src/thank-you.html` | `` |
| Privacy / Terms / Cookies | `src/privacy.html`, `src/terms.html`, `src/cookies.html` | `` |
| 404 | `src/404.html` | `` |

**Root prefix rule.** Every relative URL in a page is prefixed with the page's root prefix: `css/style.css` at root,
`../css/style.css` one level down. Also set `<body data-root="">` or `<body data-root="../">` so `site.js` can build links.

## 3. Page skeleton (copy exactly, then fill the `<main>`)

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PAGE TITLE — ZEHNOX</title>
<meta name="description" content="140–160 characters, no promises, no pricing.">
<link rel="icon" href="{ROOT}brand/zehnox-mark.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,300..700;1,9..144,300..700&family=Archivo:wght@400;500;600&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="{ROOT}css/style.css">
</head>
<body class="is-loading" data-root="{ROOT}">

<div class="cursor" aria-hidden="true"><span class="cursor__label"></span></div>

<header class="top" id="top">
  <a class="brand" href="{ROOT}index.html"><img src="{ROOT}brand/zehnox-lockup-dark.svg" alt="ZEHNOX" width="176" height="36"></a>
  <nav class="nav" id="nav" aria-label="Primary">
    <a href="{ROOT}index.html">Home</a><a href="{ROOT}about.html">About</a><a href="{ROOT}services.html">Services</a><a href="{ROOT}solutions.html">Solutions</a><a href="{ROOT}work.html">Work</a><a href="{ROOT}insights.html">Insights</a><a href="{ROOT}contact.html">Contact</a>
  </nav>
  <div class="top__actions">
    <a class="top__wa" href="https://wa.me/923435441132" data-wa="" target="_blank" rel="noopener">WhatsApp Us</a>
    <a class="btn btn--lime" href="{ROOT}contact.html" data-cursor="Book">Book a Consultation</a>
    <button class="burger" aria-expanded="false" aria-controls="nav" aria-label="Menu"><span></span><span></span></button>
  </div>
</header>

<main>
  <!-- page hero -->
  <section class="phero">
    <div class="sun"></div>
    <div class="container phero__inner">
      <nav class="crumbs reveal" aria-label="Breadcrumb"><a href="{ROOT}index.html">Home</a><i>/</i><a href="{ROOT}services.html">Services</a><i>/</i><span>AI Automation</span></nav>
      <span class="mono reveal">01 — Section label</span>
      <h1 class="mask"><span class="rise">Headline in sentence case, <em>with one lime phrase.</em></span></h1>
      <p class="phero__lead reveal">One or two sentences. Executive, calm, no hype.</p>
      <div class="phero__cta reveal">
        <a class="btn btn--lime btn--lg" href="{ROOT}contact.html" data-cursor="Book">Book a Consultation</a>
        <a class="btn btn--outline btn--lg" href="{ROOT}contact.html" data-cursor="Start">Start Your AI Transformation</a>   <!-- only where spec §9 says so -->
      </div>
    </div>
  </section>

  <!-- ...sections... -->

  <!-- final conversion block — REQUIRED on every page (spec §9 rule 1) -->
  <section class="final" id="book">
    <div class="final__marquee" aria-hidden="true"><div class="final__track"><span>Book a Consultation</span><span>From Mind to World</span><span>Book a Consultation</span><span>From Mind to World</span></div></div>
    <div class="container final__inner">
      <h2 class="final__h2"><span class="mask"><span class="rise">The next build</span></span><span class="mask"><span class="rise">starts with <em>a conversation.</em></span></span></h2>
      <p class="reveal">Schedule a strategic conversation. No public pricing, no pressure: scope first, then a proposal tailored to the engagement.</p>
      <div class="final__cta reveal">
        <a class="btn btn--lime btn--lg" href="{ROOT}contact.html" data-cursor="Book">Book a Consultation</a>
        <a class="btn btn--outline btn--lg" href="https://wa.me/923435441132" data-wa="" target="_blank" rel="noopener" data-cursor="Chat">WhatsApp <span data-wa-display>+92 343 5441132</span></a>
      </div>
    </div>
  </section>
</main>

<footer class="footer">
  <div class="container footer__grid">
    <div class="footer__brand">
      <img src="{ROOT}brand/zehnox-lockup-dark.svg" alt="ZEHNOX" width="176" height="36">
      <p class="footer__slogan">From Mind to World</p>
      <p>The innovation, AI automation, and creative technology brand inside the STRATEGIC Ecosystem.</p>
    </div>
    <div><h4>Services</h4><a href="{ROOT}services/ai-automation.html">AI Automation</a><a href="{ROOT}services/creative-studio.html">Creative Studio</a><a href="{ROOT}services/web-and-digital.html">Web &amp; Digital</a><a href="{ROOT}services/software-solutions.html">Software Solutions</a><a href="{ROOT}services/training.html">Training</a></div>
    <div><h4>Solutions</h4><a href="{ROOT}solutions/local-business.html">Local Businesses</a><a href="{ROOT}solutions/corporate.html">Corporates</a><a href="{ROOT}solutions/education.html">Schools &amp; Colleges</a><a href="{ROOT}solutions/startups.html">Startups</a><a href="{ROOT}solutions/creators.html">Creators</a><a href="{ROOT}solutions/real-estate.html">Real Estate</a><a href="{ROOT}solutions/trading.html">Trading &amp; Business Communities</a><a href="{ROOT}solutions/international.html">International Clients</a></div>
    <div><h4>Company</h4><a href="{ROOT}about.html">About</a><a href="{ROOT}work.html">Work</a><a href="{ROOT}insights.html">Insights</a><a href="{ROOT}contact.html">Contact</a></div>
    <div><h4>Contact</h4><a href="https://wa.me/923435441132" data-wa="" target="_blank" rel="noopener">WhatsApp <span data-wa-display>+92 343 5441132</span></a><a data-href="contact.email" data-prefix="mailto:" data-field="contact.email" data-ph="[Insert primary email address]"></a><a data-href="contact.phone" data-prefix="tel:" data-field="contact.phone" data-ph="[Insert primary phone number]"></a><span data-field="contact.office" data-ph="[Insert office address — Mirpur, AJK]"></span>
      <div class="social" data-list="social"></div>
    </div>
  </div>
  <div class="container footer__bottom">
    <span>© <span id="year">2026</span> ZEHNOX — A STRATEGIC Ecosystem Brand. All rights reserved.</span>
    <span><a href="{ROOT}privacy.html">Privacy Policy</a><a href="{ROOT}terms.html">Terms of Use</a><a href="{ROOT}cookies.html">Cookie Policy</a></span>
    <span class="mono">Engineered by ZEHNOX.</span>
  </div>
</footer>

<a class="wa-sticky" href="https://wa.me/923435441132" data-wa="" target="_blank" rel="noopener" aria-label="WhatsApp Us">
  <svg viewBox="0 0 24 24" width="26" height="26" fill="currentColor" aria-hidden="true"><path d="M17.5 14.4c-.3-.1-1.8-.9-2-1-.3-.1-.5-.1-.7.1-.2.3-.8 1-.9 1.2-.2.2-.3.2-.6.1-.3-.1-1.3-.5-2.4-1.5-.9-.8-1.5-1.8-1.7-2.1-.2-.3 0-.5.1-.6l.4-.5c.1-.2.2-.3.3-.5.1-.2 0-.4 0-.5l-.9-2.2c-.2-.6-.5-.5-.7-.5h-.6c-.2 0-.5.1-.8.4-.3.3-1 1-1 2.5s1.1 2.9 1.2 3.1c.1.2 2.1 3.2 5.1 4.5.7.3 1.3.5 1.7.6.7.2 1.4.2 1.9.1.6-.1 1.8-.7 2-1.4.2-.7.2-1.3.2-1.4-.1-.2-.3-.3-.6-.4M12 21.8a9.8 9.8 0 0 1-5-1.4l-.4-.2-3.7 1 1-3.6-.2-.4A9.8 9.8 0 1 1 12 21.8m8.4-18.2A11.8 11.8 0 0 0 12 .1C5.5.1.2 5.4.2 11.9c0 2.1.5 4.1 1.6 5.9L0 24l6.3-1.7a11.8 11.8 0 0 0 5.7 1.4c6.5 0 11.8-5.3 11.8-11.8 0-3.2-1.2-6.1-3.4-8.3"/></svg>
</a>

<script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/ScrollTrigger.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/lenis@1/dist/lenis.min.js"></script>
<script src="{ROOT}js/content.js"></script>
<script src="{ROOT}js/site.js"></script>
</body>
</html>
```

Replace `{ROOT}` with `` or `../`. Do not load `home.js` on inner pages. Do not add inline `<style>` or `<script>` blocks; if a page needs a behaviour the kit lacks, add a small, well-named block to `site.js` guarded by a feature check (`document.querySelector(...)`).

## 4. The component kit (all in `css/style.css`, section "INNER-PAGE KIT")

| Purpose | Markup |
|---|---|
| Section | `<section class="sec [sec--light|sec--tint|sec--cobalt]"><div class="container">…</div></section>` — alternate dark / light down the page. |
| Section head | `<div class="sec__head"><span class="mono reveal">02 — Label</span><h2 class="mask"><span class="rise">Heading.</span></h2><p class="reveal">Lead.</p></div>` |
| Grids | `.grid-2`, `.grid-3`, `.grid-4` (collapse to 1 column ≤860px) |
| Card | `<article class="tilecard reveal" data-hue="ai"><span class="mono">01</span><h3>Name</h3><p>Description.</p></article>`; as a link: `<a class="tilecard reveal" href="…" data-cursor="Open">…<span class="ul">Explore</span></a>`; big variant `tilecard tilecard--big`. `data-hue` ∈ ai, creative, web, software, training. |
| Sub-service list inside a card | `<ul class="hue-list"><li>…</li></ul>` |
| Approach steps | `<ol class="steps"><li class="reveal"><h3>Step</h3><p>…</p></li>…</ol>` (numbers are automatic) |
| Use cases | `<ul class="cases"><li class="reveal"><span class="mono">01</span><p>Scenario…</p></li></ul>` |
| Outcome statements | `<ul class="outcomes"><li class="reveal">Designed to…</li></ul>` |
| Bundle (solution pages) | `<div class="bundle reveal" data-hue="ai"><h3>AI Automation</h3><ul class="hue-list">…</ul><a class="ul" href="../services/ai-automation.html">See AI Automation</a></div>` |
| FAQ | `<div class="faq"><details class="faq__item"><summary>Question?<i></i></summary><div class="faq__body"><p>Answer.</p></div></details></div>` |
| Notice / disclaimer | `<p class="notice reveal">…</p>` |
| Prose | `<div class="prose">` for article and legal text; `<div class="prose" data-html="legal.privacy" data-ph="[Insert reviewed Privacy Policy text]"></div>` binds editable text. |
| Editorial rows | `.row` / `.row--feature` (see homepage Work & Insights). Lists render from content: `<div data-list="posts" [data-limit="3"]></div>`, `<div data-list="work" [data-vertical="Web &amp; Digital"]></div>`. |
| Team | `<div class="team__filters reveal" id="teamFilters"></div><div class="team__grid"><div class="stage reveal" id="stage"></div><div class="roster reveal" id="roster" data-list="team" data-stage="stage" data-filters="teamFilters"></div></div>` inside `<section class="team">` |
| Related strip | `<div class="related"><a href="…"><span class="mono">Solution</span><h3>Corporates</h3></a>…</div>` |
| Filters | `<div class="filters"><button class="chip is-active" data-filter="all">All</button>…</div>` (wire in `site.js` with a small guarded block) |
| Contact form | Copy the whole `<form class="form reveal" id="form" novalidate data-contact>…</form>` and `.form__done` block from `index.html`, unchanged. |
| Centered page (404, thank-you) | `<section class="centered"><div class="centered__inner">…</div></section>` |
| Buttons | `.btn.btn--lime`, `.btn.btn--outline`, size `.btn--lg`; text link `.ul` |
| Reveal on scroll | add `reveal` to blocks; headings use `<h2 class="mask"><span class="rise">…</span></h2>` |

**Mobile is not optional.** Every page must read as well at 390px as at 1440px: no horizontal overflow, tap targets ≥ 44px, headings that wrap to ≤ 4 lines, grids collapsing to one column, sections keeping generous spacing. The kit does this by default; do not fight it with custom widths.

## 5. Editable content — `content.json`

```
site.{name, slogan, url, ecosystemLine, contactEndpoint, inquiryWebhook}
contact.{whatsapp (digits only), whatsappDisplay, email, phone, office, mapEmbed (iframe src URL)}
social.{instagram, linkedin, youtube, facebook, tiktok, x}          (URLs or "")
team[]  {name, role, discipline, bio, quote?, photo (path under uploads/ or URL), founder?}   — empty name = placeholder slot
work[]  {slug, title, vertical, year, summary, tags[], url}
posts[] {slug, title, date (YYYY-MM-DD), tags[], description, body (light markdown: ##, -, 1., **bold**)}
legal.{privacy, terms, cookies}   (light markdown; "" = placeholder)
```

Binding attributes handled by `site.js`:
- `data-field="contact.email" data-ph="[Insert …]"` → text (placeholder styled `.ph` when empty)
- `data-href="contact.email" data-prefix="mailto:"` → href (removed when empty)
- `data-html="legal.privacy" data-ph="…"` → light-markdown to HTML (placeholder block when empty)
- `data-wa=""` on any `<a>` → `https://wa.me/<contact.whatsapp>`; `data-wa="text"` adds a prefilled message; `data-wa-display` → display number
- `data-list="social|posts|work|team"`

A value that is empty MUST render as a visible dashed placeholder, never as invented content.

## 6. Content and copy rules (spec §11, §16 — non-negotiable)

- Source of truth for service and solution copy: `../Zehnox/content/services.ts` and `../Zehnox/content/solutions.ts` (read them; use their names, definitions, sub-services, use cases, approach, differentiators, FAQ, contexts, bundles, outcomes verbatim or lightly refined). Every one of the 37 sub-services must appear on its parent service page.
- Never invent: client names, testimonials, metrics, team members, certifications, addresses, emails, prices.
- No pricing anywhere. No "guaranteed", "100%", "risk-free", "cutting-edge", "next-gen", "disrupt", "synergy".
- Outcomes are directional: "designed to", "engineered to", "built to support".
- Trading Dashboard and the Trading solution page must carry the disclaimer: "Trading dashboards and related tooling built by ZEHNOX are operational systems. They are not financial advice and do not predict or guarantee trading outcomes."
- ZEHNOX and STRATEGIC always in capitals. Slogan "From Mind to World" only in anchor moments.
- CTA labels are fixed: "Book a Consultation" (primary, every page ends with it), "Start Your AI Transformation" (AI Automation page, Training page, Solutions hub, AI-relevant contexts), "WhatsApp Us", "Send a Message".
- Every page ends with the `.final` block, then the footer.

## 7. Builder contract (`build.js`)

`node build.js` → `dist/`: copy `src/` (excluding `_templates/`), regenerate `js/content.js` from `content.json`,
expand `src/_templates/post.html` once per post into `dist/insights/<slug>.html` (tokens: `{{post.title}}`,
`{{post.date}}`, `{{post.dateDisplay}}`, `{{post.tags}}`, `{{post.description}}`, `{{post.bodyHtml}}`, `{{post.slug}}`;
plus `{{site.url}}`), write `sitemap.xml` and `robots.txt`. Idempotent, deletes stale files in `dist/`.

## 8. Server contract (`server.js`)

`node server.js [port=3000]` → serves `dist/` at `/` (falls back to `dist/404.html`), the admin at `/admin/`, and JSON API:
`GET /api/content`, `PUT /api/content` (validates JSON shape, writes `content.json`, then rebuilds), `POST /api/upload`
(`{name, dataUrl}` → saved to `src/uploads/<safe-name>`, returns `{path}`), `POST /api/build`, `GET /api/inquiries`,
`POST /api/contact` (public; stores to `data/inquiries.json`, forwards to `site.inquiryWebhook` if set, rate-limited),
`DELETE /api/inquiries/:id`, `POST /api/login` (public: `{username, password}` → `{session, username}`, also set as an
HttpOnly cookie), `POST /api/logout`, `GET /api/me`, `POST /api/account` (`{currentPassword, username?, newPassword?}`).
Every admin route requires `Authorization: Bearer <session>` (or the cookie). Credentials are a salted scrypt hash in
`data/admin-auth.json`; the first run creates user `admin` with a random password saved to `data/initial-password.txt`.
No third-party packages.
