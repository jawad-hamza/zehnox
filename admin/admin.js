/* ZEHNOX Admin — vanilla runtime. No libraries.
   Talks to server.js (CONTRACT.md §8): GET/PUT /api/content, POST /api/upload, POST /api/build,
   GET /api/inquiries, DELETE /api/inquiries/:id, POST /api/login, POST /api/logout, POST /api/account.
   Every admin call carries Authorization: Bearer <session id> obtained from /api/login. */
(function () {
  "use strict";

  /* ---------- constants ---------- */
  const TOKEN_KEY = "zx_admin_session";
  const DISCIPLINES = ["Leadership", "AI Automation", "Creative Studio", "Web & Digital", "Software Solutions", "Training"];
  const VERTICALS = ["AI Automation", "Creative Studio", "Web & Digital", "Software Solutions", "Training"];
  const SOCIAL_KEYS = ["instagram", "linkedin", "youtube", "facebook", "tiktok", "x"];
  const PANELS = ["site", "social", "team", "work", "insights", "legal", "inquiries", "account"];
  const MAX_UPLOAD = 5 * 1024 * 1024;

  /* ---------- dom helpers ---------- */
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const attr = (s) => esc(s).replace(/'/g, "&#39;");

  /* ---------- light markdown → HTML (identical rules to site.js textToHtml) ---------- */
  const inline = (s) => esc(s).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/\*(.+?)\*/g, "<em>$1</em>");
  const textToHtml = (text) => String(text || "").replace(/\r/g, "").trim().split(/\n\s*\n/).map((block) => {
    const lines = block.split("\n");
    if (/^###\s/.test(lines[0])) return "<h3>" + inline(lines[0].replace(/^###\s+/, "")) + "</h3>";
    if (/^##\s/.test(lines[0])) return "<h2>" + inline(lines[0].replace(/^##\s+/, "")) + "</h2>";
    if (lines.every((l) => /^[-*]\s/.test(l))) return "<ul>" + lines.map((l) => "<li>" + inline(l.replace(/^[-*]\s+/, "")) + "</li>").join("") + "</ul>";
    if (lines.every((l) => /^\d+[.)]\s/.test(l))) return "<ol>" + lines.map((l) => "<li>" + inline(l.replace(/^\d+[.)]\s+/, "")) + "</li>").join("") + "</ol>";
    if (/^>\s/.test(lines[0])) return "<blockquote>" + inline(lines.map((l) => l.replace(/^>\s?/, "")).join(" ")) + "</blockquote>";
    return "<p>" + lines.map(inline).join("<br>") + "</p>";
  }).join("\n");

  const slugify = (s) => String(s || "").toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/&/g, " and ").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  const today = () => new Date().toISOString().slice(0, 10);
  const splitTags = (s) => String(s || "").split(",").map((t) => t.trim()).filter(Boolean);
  const isUrl = (s) => /^https?:\/\/\S+$/i.test(String(s).trim());
  /* Google Maps' "Share → Embed a map" hands over a whole <iframe …> snippet, not a bare
     URL. Accept either and store just the src, which is what src/js/site.js reads. */
  const mapSrc = (s) => {
    const raw = String(s == null ? "" : s).trim();
    const pasted = raw.match(/src=["']([^"']+)["']/);
    return (pasted ? pasted[1] : raw).trim();
  };
  const isSlug = (s) => /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(s);
  const isIsoDate = (s) => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
    const d = new Date(s + "T00:00:00Z");
    return !isNaN(d) && d.toISOString().slice(0, 10) === s;
  };

  /* ---------- state ---------- */
  let token = "";
  try { token = localStorage.getItem(TOKEN_KEY) || ""; } catch (e) { token = ""; }
  let content = null;          // working model
  let savedJson = "";          // serialized snapshot of the last loaded/saved state
  const previews = {};         // uploaded path → data URL (for instant previews before rebuild)
  let inquiriesLoaded = false;
  let currentPanel = "site";

  const el = {
    toast: $("#toast"), auth: $("#auth"), authForm: $("#authForm"), authUser: $("#authUser"), authPass: $("#authPass"), authError: $("#authError"),
    whoami: $("#whoami"), accountForm: $("#accountForm"), accountError: $("#accountError"),
    fail: $("#fail"), failMessage: $("#failMessage"), loading: $("#loading"), app: $("#app"), main: $("#main"),
    dirtyState: $("#dirtyState"), dirtyText: $("#dirtyText"), problems: $("#problems"), problemsList: $("#problemsList"),
    teamList: $("#teamList"), workList: $("#workList"), postList: $("#postList"), inquiries: $("#inquiries"), inquiriesCount: $("#inquiriesCount"),
    inquiriesSearch: $("#inquiriesSearch"), inquiriesService: $("#inquiriesService"), inquiriesUnread: $("#inquiriesUnread")
  };

  /* ---------- toast ---------- */
  let toastTimer = 0;
  function toast(message, kind, ms) {
    el.toast.textContent = message;
    el.toast.className = "toast" + (kind ? " toast--" + kind : "");
    el.toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.toast.hidden = true; }, ms || (kind === "error" ? 6000 : 3200));
  }

  /* ---------- screens ---------- */
  function show(screen) {
    ["auth", "fail", "loading", "app"].forEach((k) => { el[k].hidden = k !== screen; });
  }
  function showAuth(message) {
    show("auth");
    el.authError.textContent = message || "";
    el.authError.hidden = !message;
    el.authPass.value = "";
    setTimeout(() => (el.authUser.value ? el.authPass : el.authUser).focus(), 50);
  }

  /* ---------- API ---------- */
  async function api(method, path, body) {
    const headers = { Accept: "application/json", Authorization: "Bearer " + token };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    let res;
    try {
      res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store" });
    } catch (e) {
      throw new Error("Could not reach the server at " + location.origin + ". Is `node server.js` running on this port?");
    }
    if (res.status === 401 || res.status === 403) {
      showAuth("Your session has ended. Sign in again.");
      const err = new Error("Not signed in."); err.auth = true; throw err;
    }
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = { raw: text }; }
    if (!res.ok) {
      const msg = data && (data.error || data.message || (typeof data.raw === "string" && data.raw.slice(0, 200)));
      const err = new Error(msg || (method + " " + path + " failed (" + res.status + ")")); err.data = data; throw err;
    }
    return data;
  }

  /* ---------- model ---------- */
  const str = (v) => (v == null ? "" : String(v));
  const arr = (v) => (Array.isArray(v) ? v : []);
  const tagsOf = (v) => (Array.isArray(v) ? v.map(str).map((t) => t.trim()).filter(Boolean) : splitTags(v));

  function normalize(raw) {
    if (raw && !raw.site && raw.content && raw.content.site) raw = raw.content;
    const r = raw && typeof raw === "object" ? raw : {};
    const site = r.site || {}, contact = r.contact || {}, social = r.social || {}, legal = r.legal || {};
    return {
      site: { name: str(site.name) || "ZEHNOX", slogan: str(site.slogan) || "From Mind to World", url: str(site.url), ecosystemLine: str(site.ecosystemLine) || "A STRATEGIC Ecosystem brand", contactEndpoint: str(site.contactEndpoint), inquiryWebhook: str(site.inquiryWebhook), inquiryEmail: str(site.inquiryEmail) },
      contact: { whatsapp: str(contact.whatsapp), whatsappDisplay: str(contact.whatsappDisplay), email: str(contact.email), phone: str(contact.phone), office: str(contact.office), mapEmbed: str(contact.mapEmbed) },
      social: SOCIAL_KEYS.reduce((o, k) => { o[k] = str(social[k]); return o; }, {}),
      team: arr(r.team).map((m) => ({ name: str(m.name), role: str(m.role), discipline: str(m.discipline) || "AI Automation", bio: str(m.bio), quote: str(m.quote), photo: str(m.photo), founder: !!m.founder })),
      work: arr(r.work).map((w) => ({ slug: str(w.slug), title: str(w.title), vertical: VERTICALS.includes(w.vertical) ? w.vertical : (str(w.vertical) || "Web & Digital"), year: str(w.year), summary: str(w.summary), tags: tagsOf(w.tags), url: str(w.url) })),
      posts: arr(r.posts).map((p) => ({ slug: str(p.slug), title: str(p.title), date: str(p.date), tags: tagsOf(p.tags), description: str(p.description), body: str(p.body) })),
      legal: { privacy: str(legal.privacy), terms: str(legal.terms), cookies: str(legal.cookies) }
    };
  }

  /* Canonical output — exactly the shape of content.json (key order included). */
  function toJSON() {
    const c = content;
    return {
      site: { name: c.site.name, slogan: c.site.slogan, url: c.site.url.trim(), ecosystemLine: c.site.ecosystemLine, contactEndpoint: c.site.contactEndpoint.trim(), inquiryWebhook: c.site.inquiryWebhook.trim(), inquiryEmail: c.site.inquiryEmail.trim() },
      contact: { whatsapp: c.contact.whatsapp.trim(), whatsappDisplay: c.contact.whatsappDisplay.trim(), email: c.contact.email.trim(), phone: c.contact.phone.trim(), office: c.contact.office.trim(), mapEmbed: mapSrc(c.contact.mapEmbed) },
      social: SOCIAL_KEYS.reduce((o, k) => { o[k] = c.social[k].trim(); return o; }, {}),
      team: c.team.map((m) => {
        const out = { name: m.name.trim(), role: m.role.trim(), discipline: m.discipline.trim(), bio: m.bio.trim() };
        if (m.quote.trim()) out.quote = m.quote.trim();
        out.photo = m.photo.trim();
        if (m.founder) out.founder = true;
        return out;
      }),
      work: c.work.map((w) => ({ slug: w.slug.trim(), title: w.title.trim(), vertical: w.vertical, year: w.year.trim(), summary: w.summary.trim(), tags: w.tags.slice(), url: w.url.trim() })),
      posts: c.posts.map((p) => ({ slug: p.slug.trim(), title: p.title.trim(), date: p.date.trim(), tags: p.tags.slice(), description: p.description.trim(), body: p.body.replace(/\r/g, "") })),
      legal: { privacy: c.legal.privacy.replace(/\r/g, ""), terms: c.legal.terms.replace(/\r/g, ""), cookies: c.legal.cookies.replace(/\r/g, "") }
    };
  }

  const getPath = (path) => path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), content);
  function setPath(path, value) {
    const keys = path.split(".");
    let o = content;
    for (let i = 0; i < keys.length - 1; i++) { if (o == null) return; o = o[keys[i]]; }
    if (o != null) o[keys[keys.length - 1]] = value;
  }

  /* ---------- dirty tracking ---------- */
  function isDirty() { return !!content && JSON.stringify(toJSON()) !== savedJson; }
  function updateDirty() {
    const dirty = isDirty();
    el.dirtyState.dataset.dirty = dirty ? "true" : "false";
    el.dirtyText.textContent = dirty ? "Unsaved changes" : "All changes saved";
    document.title = (dirty ? "• " : "") + "ZEHNOX Admin";
  }
  window.addEventListener("beforeunload", (e) => { if (isDirty()) { e.preventDefault(); e.returnValue = ""; } });

  /* ---------- rendering: simple fields ---------- */
  function fillSimpleFields() {
    $$("[data-path]", el.main).forEach((input) => {
      const path = input.dataset.path;
      if (/^(team|work|posts)\./.test(path)) return; // list items render themselves
      const v = getPath(path);
      if (input.type === "checkbox") input.checked = !!v; else input.value = v == null ? "" : String(v);
    });
  }

  /* ---------- rendering: lists ---------- */
  const numberOf = (i) => String(i + 1).padStart(2, "0");
  const tools = (list, i, count) =>
    '<div class="item__tools">' +
    '<button class="btn btn--icon" type="button" data-act="up" data-list="' + list + '" data-index="' + i + '" aria-label="Move up"' + (i === 0 ? " disabled" : "") + '>↑</button>' +
    '<button class="btn btn--icon" type="button" data-act="down" data-list="' + list + '" data-index="' + i + '" aria-label="Move down"' + (i === count - 1 ? " disabled" : "") + '>↓</button>' +
    '<button class="btn btn--icon btn--danger" type="button" data-act="remove" data-list="' + list + '" data-index="' + i + '" aria-label="Remove">✕</button>' +
    "</div>";
  const options = (list, current) => list.map((v) => '<option value="' + attr(v) + '"' + (v === current ? " selected" : "") + ">" + esc(v) + "</option>").join("") +
    (list.includes(current) || !current ? "" : '<option value="' + attr(current) + '" selected>' + esc(current) + "</option>");
  /* Discipline is an open list: the built-ins plus anything the team already uses. Free text is allowed. */
  const disciplineList = () => Array.from(new Set(DISCIPLINES.concat((content && content.team ? content.team : []).map((m) => String(m.discipline || "").trim())).filter(Boolean)));
  const datalist = (id, list) => '<datalist id="' + id + '">' + list.map((v) => '<option value="' + attr(v) + '"></option>').join("") + "</datalist>";
  const refreshDisciplines = () => { const dl = $("#disciplineOptions", el.main); if (dl) dl.innerHTML = disciplineList().map((v) => '<option value="' + attr(v) + '"></option>').join(""); };

  function photoSrc(p) {
    if (!p) return "";
    if (previews[p]) return previews[p];
    if (/^(https?:)?\/\//i.test(p) || /^data:/i.test(p)) return p;
    return "/" + p.replace(/^\/+/, "").replace(/^src\//, "");
  }
  const initialsOf = (name) => (name ? name.trim().split(/\s+/).map((w) => w[0]).join("").slice(0, 2).toUpperCase() : "—");
  function photoFrame(m) {
    return m.photo
      ? '<div class="photo__frame has-photo"><img src="' + attr(photoSrc(m.photo)) + '" alt=""></div>'
      : '<div class="photo__frame">' + esc(initialsOf(m.name)) + "</div>";
  }

  function renderTeam() {
    const list = content.team;
    const cards = list.length ? list.map((m, i) => {
      const p = "team." + i + ".";
      const placeholder = !m.name.trim();
      return '<article class="item' + (placeholder ? " is-placeholder" : "") + '" data-list="team" data-index="' + i + '">' +
        '<div class="item__bar"><span class="item__num">' + numberOf(i) + '</span><span class="item__title">' + esc(m.name.trim() || m.role || "Unnamed") + "</span>" +
        '<span class="badge badge--placeholder"' + (placeholder ? "" : " hidden") + '>Placeholder slot</span>' +
        '<span class="badge badge--founder"' + (m.founder ? "" : " hidden") + ">Founder</span>" + tools("team", i, list.length) + "</div>" +
        '<div class="item__body item__body--photo">' +
          '<div class="photo">' + photoFrame(m) +
            '<div class="photo__btns"><label class="btn btn--outline btn--sm">Upload photo<input type="file" accept="image/*" data-upload="' + p + 'photo"></label>' +
            '<button class="btn btn--ghost btn--sm" type="button" data-act="clear-photo" data-list="team" data-index="' + i + '"' + (m.photo ? "" : " hidden") + '>Remove photo</button></div>' +
          "</div>" +
          '<div class="item__fields">' +
            '<label class="field"><span>Name</span><input type="text" data-path="' + p + 'name" value="' + attr(m.name) + '" placeholder="Leave empty to keep this slot as a placeholder"></label>' +
            '<label class="field"><span>Role</span><input type="text" data-path="' + p + 'role" value="' + attr(m.role) + '" placeholder="Lead, AI Automation"></label>' +
            '<label class="field"><span>Discipline</span><input type="text" data-path="' + p + 'discipline" list="disciplineOptions" value="' + attr(m.discipline) + '" placeholder="AI Automation" autocomplete="off" spellcheck="false"><small>Pick a suggestion or type a new discipline.</small></label>' +
            '<label class="field"><span>Photo path or URL <em>optional</em></span><input type="text" data-path="' + p + 'photo" value="' + attr(m.photo) + '" placeholder="uploads/name.jpg"></label>' +
            '<label class="field field--wide"><span>Bio</span><textarea rows="3" data-path="' + p + 'bio" placeholder="One or two sentences.">' + esc(m.bio) + "</textarea></label>" +
            '<label class="field field--wide"><span>Quote <em>optional</em></span><input type="text" data-path="' + p + 'quote" value="' + attr(m.quote) + '"></label>' +
            '<label class="check field--wide"><input type="checkbox" data-path="' + p + 'founder"' + (m.founder ? " checked" : "") + "><span>Founder</span></label>" +
            '<p class="hint field--wide team__note"' + (placeholder ? "" : " hidden") + '>This slot has no name, so the site shows a dashed “to be announced” card with the role above. Add a name to publish the person.</p>' +
          "</div>" +
        "</div>" +
      "</article>";
    }).join("") : '<div class="empty">No team members yet. Add the founder first.</div>';
    el.teamList.innerHTML = cards + datalist("disciplineOptions", disciplineList());
  }

  function renderWork() {
    const list = content.work;
    el.workList.innerHTML = list.length ? list.map((w, i) => {
      const p = "work." + i + ".";
      return '<article class="item" data-list="work" data-index="' + i + '">' +
        '<div class="item__bar"><span class="item__num">' + numberOf(i) + '</span><span class="item__title">' + esc(w.title.trim() || "Untitled project") + "</span>" + tools("work", i, list.length) + "</div>" +
        '<div class="item__body"><div class="item__fields">' +
          '<label class="field"><span>Title</span><input type="text" data-path="' + p + 'title" value="' + attr(w.title) + '"></label>' +
          '<label class="field"><span>Slug</span><input type="text" data-path="' + p + 'slug" value="' + attr(w.slug) + '" spellcheck="false" placeholder="auto from title"><small>Lowercase letters, digits and hyphens. Fills itself from the title until you edit it.</small></label>' +
          '<label class="field"><span>Vertical</span><select data-path="' + p + 'vertical">' + options(VERTICALS, w.vertical) + "</select></label>" +
          '<label class="field"><span>Year</span><input type="text" data-path="' + p + 'year" value="' + attr(w.year) + '" inputmode="numeric" placeholder="' + new Date().getFullYear() + '"></label>' +
          '<label class="field field--wide"><span>Summary</span><textarea rows="3" data-path="' + p + 'summary">' + esc(w.summary) + "</textarea></label>" +
          '<label class="field"><span>Tags <em>comma-separated</em></span><input type="text" data-path="' + p + 'tags" data-kind="tags" value="' + attr(w.tags.join(", ")) + '" placeholder="Live, Case study"><small>A tag named “Live” is highlighted on the site.</small></label>' +
          '<label class="field"><span>URL <em>optional</em></span><input type="url" data-path="' + p + 'url" value="' + attr(w.url) + '" inputmode="url" placeholder="https://…"></label>' +
        "</div></div>" +
      "</article>";
    }).join("") : '<div class="empty">No projects yet. The Work page shows “No work published yet.” until you add one.</div>';
  }

  function renderPosts() {
    const list = content.posts;
    el.postList.innerHTML = list.length ? list.map((post, i) => {
      const p = "posts." + i + ".";
      return '<article class="item" data-list="posts" data-index="' + i + '">' +
        '<div class="item__bar"><span class="item__num">' + numberOf(i) + '</span><span class="item__title">' + esc(post.title.trim() || "Untitled insight") + "</span>" + tools("posts", i, list.length) + "</div>" +
        '<div class="item__body"><div class="item__fields">' +
          '<label class="field"><span>Title</span><input type="text" data-path="' + p + 'title" value="' + attr(post.title) + '"></label>' +
          '<label class="field"><span>Slug</span><input type="text" data-path="' + p + 'slug" value="' + attr(post.slug) + '" spellcheck="false" placeholder="auto from title"><small>Becomes <code>insights/' + esc(post.slug || "slug") + '.html</code>. Fills itself from the title until you edit it.</small></label>' +
          '<label class="field"><span>Date</span><input type="date" data-path="' + p + 'date" value="' + attr(post.date) + '" placeholder="YYYY-MM-DD"></label>' +
          '<label class="field"><span>Tags <em>comma-separated</em></span><input type="text" data-path="' + p + 'tags" data-kind="tags" value="' + attr(post.tags.join(", ")) + '" placeholder="AI Automation, Operations"><small>The first tag is shown in lists.</small></label>' +
          '<label class="field field--wide"><span>Description</span><textarea rows="2" data-path="' + p + 'description" placeholder="One or two sentences shown in the index and as the meta description.">' + esc(post.description) + "</textarea></label>" +
          '<div class="editor">' +
            '<label class="field"><span>Body</span><textarea class="code" rows="18" data-path="' + p + 'body" data-preview="1">' + esc(post.body) + "</textarea>" +
              '<small>Blank line = new paragraph · <code>## Heading</code> · <code>### Subheading</code> · <code>- bullet</code> · <code>1. numbered</code> · <code>&gt; quote</code> · <code>**bold**</code> · <code>*italic*</code></small></label>' +
            '<div><span class="preview__label">Preview</span><div class="preview">' + previewHtml(post.body) + "</div></div>" +
          "</div>" +
        "</div></div>" +
      "</article>";
    }).join("") : '<div class="empty">No insights yet. The Insights page shows “No insights published yet.” until you add one.</div>';
  }
  const previewHtml = (body) => (String(body || "").trim() ? textToHtml(body) : '<span class="placeholder">Nothing to preview yet</span>');

  function renderAll() {
    fillSimpleFields();
    renderTeam();
    renderWork();
    renderPosts();
    updateDirty();
  }

  /* ---------- rendering: inquiries ---------- */
  function fmtWhen(v) {
    if (!v) return "—";
    const d = typeof v === "number" ? new Date(v) : new Date(String(v));
    if (isNaN(d)) return String(v);
    return d.toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
  }
  const whenOf = (q) => q.receivedAt || q.createdAt || q.created || q.date || q.time || q.at || q.ts || q.timestamp || "";
  const KNOWN = ["id", "receivedAt", "createdAt", "created", "date", "time", "at", "ts", "timestamp", "name", "email", "phone", "company", "brief", "message", "iam", "services", "service", "method", "page", "ip", "userAgent"];

  /* The fetched list is kept here so filtering and marking read repaint from memory
     instead of going back to the server for every keystroke. */
  let inquiriesData = [];

  const servicesOf = (q) => Array.isArray(q.services) ? q.services : (q.services || q.service ? [q.services || q.service] : []);
  const repliesOf = (q) => Array.isArray(q.replies) ? q.replies : [];

  function renderInquiries(items) {
    inquiriesData = arr(items && !Array.isArray(items) ? (items.inquiries || items.items || items.data) : items).slice();
    inquiriesData.sort((a, b) => (Date.parse(whenOf(b)) || 0) - (Date.parse(whenOf(a)) || 0));
    fillServiceFilter();
    paintInquiries();
  }

  function fillServiceFilter() {
    if (!el.inquiriesService) return;
    const seen = [];
    inquiriesData.forEach((q) => servicesOf(q).forEach((s) => {
      const v = String(s).trim();
      if (v && seen.indexOf(v) === -1) seen.push(v);
    }));
    seen.sort();
    const current = el.inquiriesService.value;
    el.inquiriesService.innerHTML = '<option value="">All services</option>' +
      seen.map((s) => '<option value="' + attr(s) + '">' + esc(s) + "</option>").join("");
    if (seen.indexOf(current) !== -1) el.inquiriesService.value = current;
  }

  function matchesFilters(q) {
    if (el.inquiriesUnread && el.inquiriesUnread.checked && q.read) return false;
    const service = el.inquiriesService ? el.inquiriesService.value : "";
    if (service && servicesOf(q).indexOf(service) === -1) return false;
    const term = el.inquiriesSearch ? el.inquiriesSearch.value.trim().toLowerCase() : "";
    if (!term) return true;
    const hay = [q.name, q.email, q.company, q.phone, q.brief || q.message, q.iam, servicesOf(q).join(" ")]
      .filter(Boolean).join(" ").toLowerCase();
    return hay.indexOf(term) !== -1;
  }

  function paintInquiries() {
    const list = inquiriesData.filter(matchesFilters);
    const unread = inquiriesData.filter((q) => !q.read).length;
    const bits = [];
    if (inquiriesData.length) bits.push(inquiriesData.length + (inquiriesData.length === 1 ? " enquiry" : " enquiries"));
    if (unread) bits.push(unread + " unread");
    if (list.length !== inquiriesData.length) bits.push("showing " + list.length);
    el.inquiriesCount.textContent = bits.join(" · ");

    if (!inquiriesData.length) { el.inquiries.innerHTML = '<div class="empty">No enquiries yet. Submissions from the contact form appear here when the site posts to this server.</div>'; return; }
    if (!list.length) { el.inquiries.innerHTML = '<div class="empty">No enquiries match these filters.</div>'; return; }
    el.inquiries.innerHTML = '<table class="tbl"><thead><tr><th>Received</th><th>From</th><th>Enquiry</th><th></th></tr></thead><tbody>' +
      list.map(inquiryRow).join("") + "</tbody></table>";
  }

  function inquiryRow(q) {
    const services = servicesOf(q);
    const meta = [].concat(q.iam ? ["I am: " + q.iam] : [], services, q.method ? ["Prefers " + q.method] : []);
    const extra = Object.keys(q).filter((k) => !KNOWN.includes(k) && q[k] != null && String(q[k]).trim() !== "" && typeof q[k] !== "object");
    const replies = repliesOf(q);
    return '<tr' + (q.read ? "" : ' class="is-unread"') + ' data-row="' + attr(q.id) + '">' +
      '<td class="when">' + esc(fmtWhen(whenOf(q))) + "</td>" +
      '<td class="from"><strong>' + esc(q.name || "—") + "</strong>" +
        (q.email ? '<a href="mailto:' + attr(q.email) + '">' + esc(q.email) + "</a>" : "") +
        (q.phone ? "<span>" + esc(q.phone) + "</span>" : "") +
        (q.company ? "<span>" + esc(q.company) + "</span>" : "") + "</td>" +
      '<td><div class="msg">' + esc(q.brief || q.message || "—") + "</div>" +
        (meta.length || extra.length ? '<div class="meta">' + meta.map((m) => "<span>" + esc(m) + "</span>").join("") + extra.map((k) => "<span>" + esc(k + ": " + q[k]) + "</span>").join("") + "</div>" : "") +
        (q.page ? '<div class="meta"><span>' + esc(String(q.page).replace(/^https?:\/\/[^/]+/, "") || "/") + "</span></div>" : "") +
        (replies.length ? '<div class="replies">' + replies.map((r) =>
          '<div class="replies__item"><div class="replies__meta">Replied ' + esc(fmtWhen(r.at)) + (r.by ? " by " + esc(r.by) : "") + "</div>" +
          '<div class="replies__body">' + esc(r.body || "") + "</div></div>").join("") + "</div>" : "") +
        '<div class="replybox" data-box hidden>' +
          '<input type="text" data-subject value="Re: your enquiry to ZEHNOX">' +
          '<textarea data-message rows="5" placeholder="Write your reply…"></textarea>' +
          '<div class="replybox__err" data-err hidden></div>' +
          '<div class="replybox__row">' +
            '<button class="btn btn--sm btn--lime" type="button" data-send="' + attr(q.id) + '">Send reply</button>' +
            '<button class="btn btn--sm btn--text" type="button" data-cancel="1">Cancel</button>' +
          "</div>" +
        "</div>" +
      "</td>" +
      '<td class="act">' +
        (q.email ? '<button class="btn btn--sm btn--outline" type="button" data-reply="' + attr(q.id) + '">Reply</button>' : "") +
        '<button class="btn btn--sm btn--ghost" type="button" data-read="' + attr(q.id) + '">' + (q.read ? "Mark unread" : "Mark read") + "</button>" +
        '<button class="btn btn--sm btn--danger" type="button" data-del="' + attr(q.id) + '">Delete</button>' +
      "</td>" +
    "</tr>";
  }

  async function loadInquiries(silent) {
    el.inquiries.innerHTML = '<div class="empty">Loading…</div>';
    try {
      const data = await api("GET", "/api/inquiries");
      renderInquiries(data);
      inquiriesLoaded = true;
      if (!silent) toast("Inquiries refreshed");
    } catch (e) {
      if (!e.auth) el.inquiries.innerHTML = '<div class="empty">' + esc(e.message) + "</div>";
    }
  }

  /* ---------- validation ---------- */
  function validate() {
    const c = toJSON();
    const problems = [];
    const add = (panel, path, msg) => problems.push({ panel, path, msg });
    const urlCheck = (panel, path, label) => { const v = getPath(path); if (v && !isUrl(v)) add(panel, path, label + " must start with http:// or https://"); };

    urlCheck("site", "site.url", "Site URL");
    urlCheck("site", "site.contactEndpoint", "Contact form endpoint");
    urlCheck("site", "site.inquiryWebhook", "Inquiry webhook");
    /* Checked against the normalised value from toJSON(), so pasting the whole <iframe>
       is fine. https only, because that is all site.js will put in the frame. */
    if (c.contact.mapEmbed && !/^https:\/\/\S+$/i.test(c.contact.mapEmbed)) {
      add("site", "contact.mapEmbed", "Map embed must be the https:// link from Google Maps → Share → Embed a map (pasting the whole <iframe> snippet works too)");
    }
    if (!/^\d*$/.test(c.contact.whatsapp)) add("site", "contact.whatsapp", "WhatsApp number must contain digits only (no +, spaces or dashes)");
    else if (c.contact.whatsapp && (c.contact.whatsapp.length < 8 || c.contact.whatsapp.length > 15)) add("site", "contact.whatsapp", "WhatsApp number should be 8–15 digits including the country code");
    if (c.contact.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(c.contact.email)) add("site", "contact.email", "Email does not look valid");
    if (c.site.inquiryEmail && !/^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/.test(c.site.inquiryEmail)) add("site", "site.inquiryEmail", "Forward inquiries to must be one email address, like info@zehnox.com");
    SOCIAL_KEYS.forEach((k) => urlCheck("social", "social." + k, k.charAt(0).toUpperCase() + k.slice(1) + " URL"));

    c.team.forEach((m, i) => {
      if (!m.discipline.trim()) add("team", "team." + i + ".discipline", "Team #" + (i + 1) + ": discipline is required (pick a suggestion or type your own)");
      if (!m.role) add("team", "team." + i + ".role", "Team #" + (i + 1) + ": role is required (it is shown even for placeholder slots)");
      if (m.photo && !/^(https?:\/\/|\/?(src\/)?uploads\/)/i.test(m.photo)) add("team", "team." + i + ".photo", "Team #" + (i + 1) + ": photo must be an uploads/ path or a full URL");
    });

    const seenWork = {};
    c.work.forEach((w, i) => {
      const n = "Project #" + (i + 1) + ": ";
      if (!w.title) add("work", "work." + i + ".title", n + "title is required");
      if (!w.slug) add("work", "work." + i + ".slug", n + "slug is required");
      else if (!isSlug(w.slug)) add("work", "work." + i + ".slug", n + "slug may only use lowercase letters, digits and single hyphens");
      else if (seenWork[w.slug] != null) add("work", "work." + i + ".slug", n + "slug “" + w.slug + "” is already used by project #" + (seenWork[w.slug] + 1));
      else seenWork[w.slug] = i;
      if (!VERTICALS.includes(w.vertical)) add("work", "work." + i + ".vertical", n + "choose a vertical");
      if (w.year && !/^\d{4}$/.test(w.year)) add("work", "work." + i + ".year", n + "year must be four digits");
      if (w.url && !isUrl(w.url)) add("work", "work." + i + ".url", n + "URL must start with http:// or https://");
    });

    const seenPost = {};
    c.posts.forEach((p, i) => {
      const n = "Insight #" + (i + 1) + ": ";
      if (!p.title) add("insights", "posts." + i + ".title", n + "title is required");
      if (!p.slug) add("insights", "posts." + i + ".slug", n + "slug is required");
      else if (!isSlug(p.slug)) add("insights", "posts." + i + ".slug", n + "slug may only use lowercase letters, digits and single hyphens");
      else if (seenPost[p.slug] != null) add("insights", "posts." + i + ".slug", n + "slug “" + p.slug + "” is already used by insight #" + (seenPost[p.slug] + 1));
      else seenPost[p.slug] = i;
      if (!isIsoDate(p.date)) add("insights", "posts." + i + ".date", n + "date must be a real date in YYYY-MM-DD form");
      if (!p.description) add("insights", "posts." + i + ".description", n + "description is required");
      if (!p.body) add("insights", "posts." + i + ".body", n + "body is empty");
    });
    return problems;
  }

  function showProblems(problems) {
    $$(".is-invalid", el.main).forEach((n) => n.classList.remove("is-invalid"));
    if (!problems.length) { el.problems.hidden = true; return; }
    problems.forEach((p) => { const f = $('[data-path="' + p.path + '"]', el.main); if (f) f.classList.add("is-invalid"); });
    el.problemsList.innerHTML = problems.map((p, i) => '<li><button type="button" data-problem="' + i + '">' + esc(p.msg) + "</button></li>").join("");
    el.problems.hidden = false;
    el.problems._items = problems;
    goTo(problems[0].panel);
    el.problems.scrollIntoView({ block: "start", behavior: "smooth" });
  }
  function focusProblem(p) {
    goTo(p.panel);
    const f = $('[data-path="' + p.path + '"]', el.main);
    if (f) { f.scrollIntoView({ block: "center", behavior: "smooth" }); setTimeout(() => f.focus({ preventScroll: true }), 300); }
  }

  /* ---------- actions ---------- */
  let busy = false;
  function setBusy(on, label) {
    busy = on;
    $("#btnSave").disabled = on;
    $("#btnRebuild").disabled = on;
    $("#btnSave").textContent = on && label === "save" ? "Saving…" : "Save";
    $("#btnRebuild").textContent = on && label === "build" ? "Building…" : "Rebuild";
  }

  async function save() {
    if (busy) return;
    const problems = validate();
    showProblems(problems);
    if (problems.length) { toast(problems.length + (problems.length === 1 ? " problem" : " problems") + " to fix before saving", "error"); return; }
    const payload = toJSON();
    setBusy(true, "save");
    try {
      await api("PUT", "/api/content", payload);
      savedJson = JSON.stringify(payload);
      updateDirty();
      toast("Saved. The site has been rebuilt.", "ok");
    } catch (e) {
      if (e.data && e.data.saved) { savedJson = JSON.stringify(payload); updateDirty(); }
      if (!e.auth) toast("Save failed: " + e.message, "error");
    } finally { setBusy(false); }
  }

  async function rebuild() {
    if (busy) return;
    setBusy(true, "build");
    try {
      await api("POST", "/api/build", {});
      toast(isDirty() ? "Rebuilt from the last saved content. You still have unsaved changes." : "Site rebuilt.", "ok");
    } catch (e) {
      if (!e.auth) toast("Rebuild failed: " + e.message, "error");
    } finally { setBusy(false); }
  }

  async function upload(input) {
    const file = input.files && input.files[0];
    const path = input.dataset.upload;
    if (!file || !path) return;
    if (!/^image\//.test(file.type)) { toast("Choose an image file (JPG, PNG, WebP, SVG).", "error"); input.value = ""; return; }
    if (file.size > MAX_UPLOAD) { toast("Image is larger than 5 MB. Resize it first.", "error"); input.value = ""; return; }
    const card = input.closest(".item");
    const dataUrl = await new Promise((resolve, reject) => { const r = new FileReader(); r.onload = () => resolve(r.result); r.onerror = () => reject(new Error("Could not read the file")); r.readAsDataURL(file); });
    const frame = card && $(".photo__frame", card);
    if (frame) { frame.className = "photo__frame has-photo"; frame.innerHTML = '<img src="' + attr(dataUrl) + '" alt="">'; frame.style.opacity = ".5"; }
    try {
      const res = await api("POST", "/api/upload", { name: file.name, dataUrl });
      const saved = res && (res.path || res.url || res.file);
      if (!saved) throw new Error("The server did not return a path");
      previews[saved] = dataUrl;
      setPath(path, saved);
      const pathInput = card && $('[data-path="' + path + '"]', card);
      if (pathInput) pathInput.value = saved;
      const clear = card && $('[data-act="clear-photo"]', card);
      if (clear) clear.hidden = false;
      if (frame) frame.style.opacity = "";
      updateDirty();
      toast("Photo uploaded. Save to publish it.", "ok");
    } catch (e) {
      if (frame) { const idx = +card.dataset.index; frame.outerHTML = photoFrame(content.team[idx]); }
      if (!e.auth) toast("Upload failed: " + e.message, "error");
    } finally { input.value = ""; }
  }

  function addItem(list) {
    if (list === "team") content.team.push({ name: "", role: "", discipline: "AI Automation", bio: "", quote: "", photo: "", founder: false });
    if (list === "work") content.work.push({ slug: "", title: "", vertical: "Web & Digital", year: String(new Date().getFullYear()), summary: "", tags: [], url: "" });
    if (list === "posts") content.posts.push({ slug: "", title: "", date: today(), tags: [], description: "", body: "" });
    rerender(list);
    const cards = $$('.item[data-list="' + list + '"]', el.main);
    const last = cards[cards.length - 1];
    if (last) { last.scrollIntoView({ block: "start", behavior: "smooth" }); const first = $("input[type=text]", last); if (first) setTimeout(() => first.focus({ preventScroll: true }), 300); }
    updateDirty();
  }
  function rerender(list) { if (list === "team") renderTeam(); else if (list === "work") renderWork(); else if (list === "posts") renderPosts(); }
  const labelOf = (list, item) => (list === "team" ? (item.name.trim() || item.role || "this placeholder slot") : (item.title.trim() || "this item"));

  function listAction(act, list, index) {
    const items = content[list];
    const i = +index;
    if (!items || !items[i]) return;
    if (act === "remove") {
      if (!confirm("Remove " + labelOf(list, items[i]) + "? This takes effect when you save.")) return;
      items.splice(i, 1);
    } else if (act === "up" && i > 0) {
      [items[i - 1], items[i]] = [items[i], items[i - 1]];
    } else if (act === "down" && i < items.length - 1) {
      [items[i + 1], items[i]] = [items[i], items[i + 1]];
    } else if (act === "clear-photo") {
      items[i].photo = "";
    } else return;
    rerender(list);
    updateDirty();
  }

  /* ---------- input handling ---------- */
  function onInput(e) {
    const t = e.target;
    const path = t.dataset && t.dataset.path;
    if (!path || t.readOnly) return;
    const old = getPath(path);
    let value;
    if (t.type === "checkbox") value = t.checked;
    else if (t.dataset.kind === "tags") value = splitTags(t.value);
    else value = t.value;
    setPath(path, value);
    t.classList.remove("is-invalid");

    const card = t.closest(".item");
    let m;
    if ((m = path.match(/^(work|posts)\.(\d+)\.title$/))) {
      const item = content[m[1]][+m[2]];
      if (item && (item.slug === "" || item.slug === slugify(old))) {
        item.slug = slugify(value);
        const slugInput = card && $('[data-path="' + m[1] + "." + m[2] + '.slug"]', card);
        if (slugInput) slugInput.value = item.slug;
      }
      const title = card && $(".item__title", card);
      if (title) title.textContent = value.trim() || (m[1] === "work" ? "Untitled project" : "Untitled insight");
    } else if ((m = path.match(/^team\.(\d+)\.name$/))) {
      const item = content.team[+m[1]];
      const placeholder = !value.trim();
      if (card) {
        card.classList.toggle("is-placeholder", placeholder);
        const badge = $(".badge--placeholder", card); if (badge) badge.hidden = !placeholder;
        const note = $(".team__note", card); if (note) note.hidden = !placeholder;
        const title = $(".item__title", card); if (title) title.textContent = value.trim() || item.role || "Unnamed";
        if (!item.photo) { const frame = $(".photo__frame", card); if (frame) frame.textContent = initialsOf(value); }
      }
    } else if ((m = path.match(/^team\.(\d+)\.role$/))) {
      const item = content.team[+m[1]];
      if (card && !item.name.trim()) { const title = $(".item__title", card); if (title) title.textContent = value.trim() || "Unnamed"; }
    } else if ((m = path.match(/^team\.(\d+)\.discipline$/))) {
      refreshDisciplines();
    } else if ((m = path.match(/^team\.(\d+)\.founder$/))) {
      const badge = card && $(".badge--founder", card); if (badge) badge.hidden = !value;
    } else if ((m = path.match(/^team\.(\d+)\.photo$/))) {
      const item = content.team[+m[1]];
      const frame = card && $(".photo__frame", card);
      if (frame) frame.outerHTML = photoFrame(item);
      const clear = card && $('[data-act="clear-photo"]', card); if (clear) clear.hidden = !value.trim();
    } else if ((m = path.match(/^posts\.(\d+)\.slug$/))) {
      const small = card && $('[data-path="' + path + '"] + small', card);
      if (small) small.innerHTML = "Becomes <code>insights/" + esc(value || "slug") + ".html</code>. Fills itself from the title until you edit it.";
    }
    if (t.dataset.preview) {
      const preview = card && $(".preview", card);
      if (preview) preview.innerHTML = previewHtml(value);
    }
    updateDirty();
  }

  function onClick(e) {
    const btn = e.target.closest("button");
    if (!btn) return;
    if (btn.dataset.act) { listAction(btn.dataset.act, btn.dataset.list, btn.dataset.index); return; }
    if (btn.dataset.add) { addItem(btn.dataset.add); return; }
    if (btn.dataset.problem != null) { const p = el.problems._items && el.problems._items[+btn.dataset.problem]; if (p) focusProblem(p); return; }
    if (btn.dataset.reply != null) { openReply(btn); return; }
    if (btn.dataset.cancel != null) { closeReply(btn); return; }
    if (btn.dataset.send != null) { sendReply(btn.dataset.send, btn); return; }
    if (btn.dataset.read != null) { toggleRead(btn.dataset.read, btn); return; }
    if (btn.dataset.del != null) { deleteInquiry(btn.dataset.del, btn); }
  }

  const boxFor = (btn) => { const row = btn.closest("tr"); return row && $("[data-box]", row); };

  function openReply(btn) {
    const box = boxFor(btn);
    if (!box) return;
    box.hidden = !box.hidden;
    if (!box.hidden) { const t = $("[data-message]", box); if (t) t.focus(); }
  }

  function closeReply(btn) {
    const box = boxFor(btn);
    if (box) box.hidden = true;
  }

  async function sendReply(id, btn) {
    const box = boxFor(btn);
    if (!box) return;
    const subject = ($("[data-subject]", box).value || "").trim();
    const message = ($("[data-message]", box).value || "").trim();
    const err = $("[data-err]", box);
    const showErr = (m) => { if (err) { err.textContent = m; err.hidden = !m; } };
    if (!message) return showErr("Write a message before sending.");
    showErr("");
    btn.disabled = true;
    const label = btn.textContent;
    btn.textContent = "Sending…";
    try {
      const out = await api("POST", "/api/inquiries/" + encodeURIComponent(id) + "/reply", { subject, message });
      const record = inquiriesData.find((q) => q && q.id === id);
      if (record) {
        if (!Array.isArray(record.replies)) record.replies = [];
        record.replies.push(out.reply);
        record.read = true;
      }
      paintInquiries();
      toast("Reply sent");
    } catch (e) {
      btn.disabled = false;
      btn.textContent = label;
      // The server reports a real send failure rather than a silent success, so surface it
      // next to the box the message is still sitting in.
      if (!e.auth) showErr(e.message);
    }
  }

  async function toggleRead(id, btn) {
    const record = inquiriesData.find((q) => q && q.id === id);
    if (!record) return;
    const next = !record.read;
    btn.disabled = true;
    try {
      await api("PATCH", "/api/inquiries/" + encodeURIComponent(id), { read: next });
      record.read = next;
      paintInquiries();
    } catch (e) {
      btn.disabled = false;
      if (!e.auth) toast("Could not update: " + e.message, "error");
    }
  }

  async function deleteInquiry(id, btn) {
    if (!confirm("Delete this enquiry permanently?")) return;
    btn.disabled = true;
    try {
      await api("DELETE", "/api/inquiries/" + encodeURIComponent(id));
      inquiriesData = inquiriesData.filter((q) => !q || q.id !== id);
      paintInquiries();
      toast("Enquiry deleted");
    } catch (e) {
      btn.disabled = false;
      if (!e.auth) toast("Delete failed: " + e.message, "error");
    }
  }

  /* ---------- navigation ---------- */
  function goTo(panel) {
    if (!PANELS.includes(panel)) panel = "site";
    currentPanel = panel;
    $$(".panel", el.main).forEach((p) => { p.hidden = p.dataset.panel !== panel; });
    $$("[data-nav]").forEach((a) => { a.classList.toggle("is-active", a.dataset.nav === panel); if (a.dataset.nav === panel) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
    if (location.hash !== "#" + panel) history.replaceState(null, "", "#" + panel);
    if (panel === "inquiries" && !inquiriesLoaded && content) loadInquiries(true);
    const active = $('[data-nav="' + panel + '"]');
    if (active && active.scrollIntoView) active.scrollIntoView({ block: "nearest", inline: "center" });
  }

  /* ---------- boot ---------- */
  async function load() {
    show("loading");
    try {
      const data = await api("GET", "/api/content");
      content = normalize(data);
      savedJson = JSON.stringify(toJSON());
      inquiriesLoaded = false;
      renderAll();
      el.problems.hidden = true;
      show("app");
      whoAmI();
      goTo((location.hash || "#site").slice(1));
    } catch (e) {
      if (e.auth) return;
      el.failMessage.textContent = e.message;
      show("fail");
    }
  }

  function signOut() {
    const old = token;
    try { localStorage.removeItem(TOKEN_KEY); } catch (e) { /* ignore */ }
    token = "";
    content = null;
    if (old) fetch("/api/logout", { method: "POST", headers: { Authorization: "Bearer " + old } }).catch(() => {});
    showAuth();
  }

  async function signIn(username, password) {
    let res;
    try {
      res = await fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify({ username, password }), cache: "no-store" });
    } catch (e) {
      throw new Error("Could not reach the server at " + location.origin + ". Is `node server.js` running on this port?");
    }
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (!res.ok || !data || !data.session) {
      let msg = (data && data.error) || "Sign-in failed (" + res.status + ")";
      if (data && typeof data.remaining === "number") msg += data.remaining > 0 ? " " + data.remaining + (data.remaining === 1 ? " attempt" : " attempts") + " left before a 15-minute lock." : " Too many failed attempts: locked for 15 minutes.";
      throw new Error(msg);
    }
    return data;
  }

  const authToggle = $("#authToggle");
  if (authToggle) authToggle.addEventListener("click", () => {
    const showing = el.authPass.type === "text";
    el.authPass.type = showing ? "password" : "text";
    authToggle.textContent = showing ? "Show" : "Hide";
    authToggle.setAttribute("aria-pressed", String(!showing));
    authToggle.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    el.authPass.focus();
  });

  el.authForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = el.authUser.value.trim(), password = el.authPass.value;
    if (!username || !password) { el.authError.textContent = "Enter your username and password."; el.authError.hidden = false; return; }
    const btn = el.authForm.querySelector("[type=submit]");
    btn.disabled = true;
    try {
      const data = await signIn(username, password);
      token = data.session;
      try { localStorage.setItem(TOKEN_KEY, token); } catch (err) { /* private mode: keep it for this page only */ }
      el.authError.hidden = true;
      el.authPass.value = "";
      if (el.whoami) el.whoami.textContent = data.username;
      load();
    } catch (err) {
      el.authError.textContent = err.message;
      el.authError.hidden = false;
      el.authPass.value = "";
      el.authPass.focus();
    } finally { btn.disabled = false; }
  });

  /* Account: change username and/or password (current password required) */
  if (el.accountForm) el.accountForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = el.accountForm;
    const current = f.elements.currentPassword.value;
    const username = f.elements.newUsername.value.trim();
    const p1 = f.elements.newPassword.value, p2 = f.elements.confirmPassword.value;
    const showErr = (m) => { el.accountError.textContent = m; el.accountError.hidden = !m; };
    if (!current) return showErr("Enter your current password.");
    if (!username && !p1) return showErr("Enter a new username, a new password, or both.");
    if (p1 && p1.length < 8) return showErr("The new password must be at least 8 characters.");
    if (p1 !== p2) return showErr("The new password and its confirmation do not match.");
    const btn = f.querySelector("[type=submit]");
    btn.disabled = true;
    try {
      const data = await api("POST", "/api/account", { currentPassword: current, username: username || undefined, newPassword: p1 || undefined });
      showErr("");
      f.reset();
      if (el.whoami && data && data.username) el.whoami.textContent = data.username;
      toast("Account updated. Use the new details next time you sign in.", "", 5000);
    } catch (err) {
      if (!err.auth) showErr(err.message);
    } finally { btn.disabled = false; }
  });

  async function whoAmI() {
    try { const me = await api("GET", "/api/me"); if (el.whoami && me && me.username) el.whoami.textContent = me.username; } catch (e) { /* handled by api() */ }
  }
  $("#btnRetry").addEventListener("click", load);
  $("#btnFailSignOut").addEventListener("click", signOut);
  $("#btnSignOut").addEventListener("click", () => { if (!isDirty() || confirm("You have unsaved changes. Sign out anyway?")) signOut(); });
  $("#sideSignOut").addEventListener("click", (e) => { e.preventDefault(); if (!isDirty() || confirm("You have unsaved changes. Sign out anyway?")) signOut(); });
  $("#btnSave").addEventListener("click", save);
  $("#btnRebuild").addEventListener("click", rebuild);
  $("#btnInquiriesRefresh").addEventListener("click", () => loadInquiries(false));
  if (el.inquiriesSearch) el.inquiriesSearch.addEventListener("input", paintInquiries);
  if (el.inquiriesService) el.inquiriesService.addEventListener("change", paintInquiries);
  if (el.inquiriesUnread) el.inquiriesUnread.addEventListener("change", paintInquiries);
  el.main.addEventListener("input", onInput);
  el.main.addEventListener("change", (e) => {
    if (e.target.matches("input[type=file][data-upload]")) upload(e.target);
    else if (e.target.matches("select[data-path], input[type=checkbox][data-path]")) onInput(e);
  });
  el.main.addEventListener("click", onClick);
  $$("[data-nav]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); goTo(a.dataset.nav); }));
  window.addEventListener("hashchange", () => { if (content) goTo((location.hash || "#site").slice(1)); });
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s" && content) { e.preventDefault(); save(); }
  });

  if (token) load(); else showAuth();
})();
