# ZEHNOX website

Static HTML/CSS/JS site with a zero-dependency Node backend for editing content, uploading images and
collecting inquiries. No npm, no frameworks, no build tooling beyond `node build.js`.

Requirements: Node 20 or newer (Node 24 is used in development). Nothing to install.

```
content.json      every editable value (contact, socials, team, work, posts, legal) — edited by the admin UI
src/              site source (HTML, css/style.css, js/site.js, brand/, uploads/, _templates/)
build.js          src/ → dist/  (regenerates js/content.js, expands insight posts, writes sitemap.xml + robots.txt)
server.js         serves dist/, hosts /admin/, JSON API, stores inquiries in data/
admin/            the admin UI (vanilla HTML/JS)
data/             runtime data: admin-auth.json (hashed credentials), inquiries.json  — never deploy this folder
dist/             READY-TO-DEPLOY output of build.js
tools/check.mjs   headless QA over every page (dev only)
```

## 1. Build the site

```
node build.js
```

What it does, every time (it is idempotent and removes stale files from `dist/`):

1. Copies `src/` to `dist/` (skipping `src/_templates/` and any other file or folder whose name starts with `_`
   or `.`, so dev-only previews such as `insights/_preview.html` never ship).
2. Regenerates `src/js/content.js` **and** `dist/js/content.js` from `content.json` (`window.CONTENT`).
   Never edit `js/content.js` by hand — edit `content.json` (or use the admin) and rebuild.
3. Expands `src/_templates/post.html` once per entry in `posts[]` into `dist/insights/<slug>.html`.
   Available tokens: `{{post.title}}`, `{{post.date}}`, `{{post.dateDisplay}}` (e.g. `20 Aug 2026`), `{{post.tags}}`
   (comma-separated), `{{post.tagsHtml}}` (`<span class="row__tag">` per tag), `{{post.tag}}` (first tag),
   `{{post.description}}`, `{{post.bodyHtml}}` (light markdown → HTML), `{{post.slug}}`, `{{post.url}}`,
   `{{site.url}}`, `{{site.name}}`, `{{site.slogan}}`. Everything is HTML-escaped except `bodyHtml` and `tagsHtml`.
4. Writes `dist/sitemap.xml` (every HTML page except `404.html`, using `site.url`) and `dist/robots.txt`.

Light markdown supported in `posts[].body` and `legal.*`: blank-line paragraphs, `## Heading`, `### Sub-heading`,
`- item` lists, `1. item` lists, `> quote`, `**bold**`, `*italic*`.

## 2. Run the admin

```
node server.js            # port 3000
node server.js 3100       # any port
```

On first run the server creates `data/`, creates the admin account (username `admin`, random password, stored as a
salted scrypt hash in `data/admin-auth.json`, the password also saved to `data/initial-password.txt`), and prints:

```
ZEHNOX site server
  site   : http://127.0.0.1:3000/
  admin  : http://127.0.0.1:3000/admin/
  user   : admin
  pass   : <12 characters>   (first run — also saved in data/initial-password.txt)
```

Open the admin URL, sign in, and you can edit every value in `content.json`, upload portraits and work
images, view and delete inquiries, trigger a rebuild, and change the username and password under **Account**.
Saving content writes `content.json` (2-space JSON) and rebuilds `dist/` automatically.

- Sessions last 12 hours of inactivity and live in memory; restarting the server signs everyone out.
- Sign-in attempts are limited to 10 per 15 minutes per IP.
- Lost password: delete `data/admin-auth.json` and restart; a fresh `admin` account is created and printed.
- The server listens on `127.0.0.1` by default. To expose it on a machine's network interfaces (behind a reverse
  proxy such as Caddy or nginx with HTTPS), run `HOST=0.0.0.0 node server.js 3000`. When it sits behind a proxy,
  also set `TRUST_PROXY=1` so rate limiting uses the real client address from `X-Forwarded-For`.
- If `dist/` does not exist yet, the server runs a build on start.

### JSON API

Admin routes require `Authorization: Bearer <session>` where the session id comes from `POST /api/login`
(it is also set as an HttpOnly cookie). `POST /api/contact`, `POST /api/login` and `POST /api/logout` are public.

| Method | Route | Body / result |
|---|---|---|
| POST | `/api/login` | `{username, password}` → `{ok, session, username}` (401 on wrong credentials, 429 after 10 attempts / 15 min) |
| POST | `/api/logout` | ends the session |
| GET | `/api/me` | → `{ok, username}` |
| POST | `/api/account` | `{currentPassword, username?, newPassword?}` → `{ok, username}`; other sessions are ended |
| GET | `/api/content` | → the current `content.json` |
| PUT | `/api/content` | full content object → validated (objects/arrays present), written, then `build()` runs; → `{ok, saved, build}` |
| POST | `/api/build` | → `{ok, build:{ms, stats, messages}}` |
| POST | `/api/upload` | `{name, dataUrl}` (PNG/JPG/WEBP/SVG, ≤ 5 MB) → `{ok, path:"uploads/<safe-name>"}`; saved to `src/uploads/` and mirrored into `dist/uploads/` |
| GET | `/api/inquiries` | → array of inquiries, newest first |
| DELETE | `/api/inquiries/:id` | → `{ok, id}` |
| POST | `/api/contact` | public; `{name, email, phone?, company?, iam?, services[]?, brief, method?, page?}` → `{ok, id}` (201). Rate-limited to 5 requests per minute per IP. |

Uploaded file names are sanitised (`My Portrait (1).PNG` → `my-portrait-1.png`); an existing name gets a numeric
suffix instead of being overwritten. CORS is allowed only for the server's own origin and the origin of `site.url` —
never `*`.

## 3. Deploy

### Option A — static hosting only (no backend)

Run `node build.js` and upload the **contents of `dist/`** to any static host (Netlify, Vercel, Cloudflare Pages,
GitHub Pages, S3, cPanel `public_html`, …). Configure the host to serve `404.html` for unknown paths where
possible. Point the host's custom domain at the URL you set in `site.url` so the sitemap and canonical links match.

With no backend, the contact form still works: the POST to `/api/contact` has nothing to answer it, so the form
falls back to opening WhatsApp with the message pre-filled (`contact.whatsapp`) and no inquiry is lost.

### Option B — Node server (site + admin + inquiries)

Copy the whole project (without `data/` — it is created on the target) to a machine with Node, then run
`node server.js 3000` under a process manager (systemd, pm2, a Windows service, Docker). Put a reverse proxy with
HTTPS in front of it and sign in to `/admin/` with the printed first-run credentials (then change them under Account). The form posts to `/api/contact` on
this server by default, so `site.contactEndpoint` should stay empty.

Example systemd unit:

```
[Service]
WorkingDirectory=/srv/zehnox-site
ExecStart=/usr/bin/node server.js 3000
Environment=HOST=127.0.0.1
Environment=TRUST_PROXY=1
Restart=always
```

### Option C — static host + separate Node server for the API

Deploy `dist/` statically (A) and run `server.js` elsewhere (B). Set `site.contactEndpoint` to the full URL of the
API, e.g. `https://api.zehnox.com/api/contact`. Because the server only allows CORS for its own origin and for the
origin of `site.url`, make sure `site.url` is exactly the public origin of the static site (`https://zehnox.com`).

Whichever option you use, rebuild and redeploy `dist/` after every content change made outside the Node server.

## 4. Fill the placeholders

Every value that is still empty renders on the site as a visible dashed placeholder such as
`[Insert primary email address]` — nothing is ever invented. Fill them in the admin (or directly in `content.json`
and rebuild):

| Key | What to enter |
|---|---|
| `site.url` | The public URL of the site, no trailing slash (`https://zehnox.com`) |
| `site.contactEndpoint` | Overrides where the contact form posts. Empty (the default) posts to this server's `/api/contact` |
| `site.inquiryWebhook` | Optional URL that receives every inquiry as JSON (see §5) |
| `contact.whatsapp` / `contact.whatsappDisplay` | Digits only (`923435441132`) / how it should read (`+92 343 5441132`) |
| `contact.email`, `contact.phone`, `contact.office` | Primary email, phone, office address (Mirpur, AJK) |
| `contact.mapEmbed` | The `src` URL of a Google Maps embed iframe (shown on the Contact page when set) |
| `social.*` | Full profile URLs; leave `""` to show a placeholder |
| `team[]` | One entry per member: `name`, `role`, `discipline` (AI Automation, Creative Studio, Web & Digital, Software Solutions, Training, Leadership), `bio`, optional `quote`, `photo` (upload a portrait; the admin stores `uploads/<file>`), `founder: true` for the founder. An entry with an empty `name` stays a placeholder slot. |
| `work[]` | `slug`, `title`, `vertical` (one of the five services), `year`, `summary`, `tags[]`, `url` (leave `""` if there is nothing to link to) |
| `posts[]` | `slug` (lowercase, hyphens), `title`, `date` (`YYYY-MM-DD`), `tags[]`, `description` (used for the meta description), `body` (light markdown) |
| `legal.privacy`, `legal.terms`, `legal.cookies` | Reviewed legal text in light markdown. Empty = placeholder block on the page. |

Do not add pricing, testimonials, client names, metrics or certifications that are not real: the copy rules of
the site (see `CONTRACT.md` §6) apply to content entered through the admin too.

## 5. Connect the contact form

The form in `src/index.html` and `src/contact.html` (`form[data-contact]`) validates in the browser, then:

1. `POST`s JSON (`{name, email, phone, company, iam, services, brief, method, page}`) to `site.contactEndpoint`,
   or to `/api/contact` when that setting is empty, and expects a 2xx response.
2. If the request fails — including on a static deployment where nothing answers `/api/contact` — it opens
   WhatsApp with the full message pre-filled.

**Using the built-in server.** Leave `site.contactEndpoint` empty (same host) or set it to the full URL of the
server. Inquiries are stored in `data/inquiries.json` and listed in the admin under Inquiries. Each record is
`{id, receivedAt, name, email, phone, company, iam, services, brief, method, page, ip}`.

**Forwarding to a webhook (email, Slack, CRM, Zapier/Make, …).** Set `site.inquiryWebhook` to any HTTPS URL.
After storing an inquiry the server sends, fire-and-forget:

```
POST <inquiryWebhook>
Content-Type: application/json

{ "type": "inquiry", "inquiry": { "id": "…", "receivedAt": "…", "name": "…", "email": "…", … } }
```

Failures are logged on the server console and never affect the visitor's submission. A Zapier "Catch Hook",
Make "Custom webhook", n8n Webhook node, or a tiny serverless function that emails the payload all work as-is.

**Using a third-party form service instead of the server.** Point `site.contactEndpoint` at any service that
accepts a JSON `POST` and answers with a 2xx (for example a Formspree or Basin endpoint with JSON enabled, or your
own function). The payload is the object listed above. If the service answers with a non-2xx status the visitor
is sent to WhatsApp instead, so the enquiry still arrives.

## 6. Quality check (development)

With a static server on `src/` or `dist/` (e.g. `node server.js 3100` for `dist/`), run:

```
node tools/check.mjs http://127.0.0.1:3100/ tools/shots
```

It loads every page at desktop, laptop and mobile widths, reports page errors, failed requests, horizontal
overflow and hidden reveals, and writes screenshots to `tools/shots/`. It uses the Playwright installation of the
sibling `../Zehnox` project and is not needed for building or deploying.
