/* ZEHNOX — shared runtime for every page.
   Loaded after gsap, ScrollTrigger, lenis (CDN script tags) and js/content.js (generated from content.json).
   Responsibilities: content binding, smooth scroll, nav, cursor, scroll reveals, team roster, contact form. */
(function () {
  "use strict";
  const html = document.documentElement;
  html.classList.add("js");
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const fine = matchMedia("(hover: hover) and (pointer: fine)").matches;
  const hasGsap = typeof gsap !== "undefined";
  const hasST = hasGsap && typeof ScrollTrigger !== "undefined";
  if (hasST) gsap.registerPlugin(ScrollTrigger);
  if (reduce || !hasGsap) document.body.classList.add("reduce");
  const C = window.CONTENT || {};
  const ROOT = document.body.dataset.root || "";
  const yearEl = document.getElementById("year");
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  /* ---------- helpers ---------- */
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const get = (path) => String(path).split(".").reduce((o, k) => (o == null ? undefined : o[k]), C);
  const inline = (s) => esc(s).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/\*(.+?)\*/g, "<em>$1</em>");
  /* Minimal text → HTML: blank-line paragraphs, ## / ### headings, - and 1. lists, **bold**, *italic*. */
  const textToHtml = (text) => String(text || "").replace(/\r/g, "").trim().split(/\n\s*\n/).map((block) => {
    const lines = block.split("\n");
    if (/^###\s/.test(lines[0])) return "<h3>" + inline(lines[0].replace(/^###\s+/, "")) + "</h3>";
    if (/^##\s/.test(lines[0])) return "<h2>" + inline(lines[0].replace(/^##\s+/, "")) + "</h2>";
    if (lines.every((l) => /^[-*]\s/.test(l))) return "<ul>" + lines.map((l) => "<li>" + inline(l.replace(/^[-*]\s+/, "")) + "</li>").join("") + "</ul>";
    if (lines.every((l) => /^\d+[.)]\s/.test(l))) return "<ol>" + lines.map((l) => "<li>" + inline(l.replace(/^\d+[.)]\s+/, "")) + "</li>").join("") + "</ol>";
    if (/^>\s/.test(lines[0])) return "<blockquote>" + inline(lines.map((l) => l.replace(/^>\s?/, "")).join(" ")) + "</blockquote>";
    return "<p>" + lines.map(inline).join("<br>") + "</p>";
  }).join("\n");
  const fmtDate = (iso) => { const d = new Date(iso); return isNaN(d) ? esc(iso) : d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }); };
  const waNumber = (C.contact && C.contact.whatsapp) ? String(C.contact.whatsapp).replace(/\D/g, "") : "923435441132";
  const waLink = (text) => "https://wa.me/" + waNumber + (text ? "?text=" + encodeURIComponent(text) : "");

  /* ---------- content binding ---------- */
  document.querySelectorAll("[data-field]").forEach((el) => {
    const v = get(el.dataset.field);
    if (v != null && String(v).trim() !== "") { el.textContent = v; el.classList.remove("ph"); }
    else { el.textContent = el.dataset.ph || "[Insert " + el.dataset.field.split(".").pop() + "]"; el.classList.add("ph"); }
  });
  document.querySelectorAll("[data-href]").forEach((el) => {
    const v = get(el.dataset.href);
    if (v != null && String(v).trim() !== "") { el.setAttribute("href", (el.dataset.prefix || "") + v); el.classList.remove("is-empty"); }
    else { el.removeAttribute("href"); el.classList.add("is-empty"); }
  });
  document.querySelectorAll("[data-html]").forEach((el) => {
    const v = get(el.dataset.html);
    if (v != null && String(v).trim() !== "") { el.innerHTML = textToHtml(v); el.classList.remove("placeholder-block"); }
    else { el.innerHTML = '<span class="mono">' + esc(el.dataset.ph || "[Insert " + el.dataset.html + "]") + "</span>"; el.classList.add("placeholder-block"); }
  });
  document.querySelectorAll("a[data-wa]").forEach((a) => { a.href = waLink(a.dataset.wa); });
  document.querySelectorAll("[data-wa-display]").forEach((el) => { el.textContent = (C.contact && C.contact.whatsappDisplay) || "+92 343 5441132"; });

  /* ---------- lists ---------- */
  const SOCIAL = [["instagram", "Instagram"], ["linkedin", "LinkedIn"], ["youtube", "YouTube"], ["facebook", "Facebook"], ["tiktok", "TikTok"], ["x", "X"]];
  document.querySelectorAll('[data-list="social"]').forEach((el) => {
    el.innerHTML = SOCIAL.map(([k, label]) => {
      const v = C.social && C.social[k];
      return v ? '<a href="' + esc(v) + '" target="_blank" rel="noopener">' + label + "</a>" : '<span class="ph">' + label + "</span>";
    }).join("");
  });
  document.querySelectorAll('[data-list="posts"]').forEach((el) => {
    const limit = parseInt(el.dataset.limit || "0", 10) || Infinity;
    const exclude = el.dataset.exclude || "";
    const posts = (C.posts || []).filter((p) => !exclude || p.slug !== exclude).sort((a, b) => String(b.date).localeCompare(String(a.date))).slice(0, limit);
    el.innerHTML = posts.map((p) =>
      '<a class="row reveal" href="' + ROOT + "insights/" + esc(p.slug) + '" data-cursor="Read">' +
      '<span class="mono">' + fmtDate(p.date) + "</span><h3>" + esc(p.title) + "</h3>" +
      '<span class="row__tag">' + esc((p.tags || [])[0] || "Insight") + '</span><span class="row__arrow" aria-hidden="true">→</span></a>').join("") ||
      '<p class="placeholder-block"><span class="mono">No insights published yet.</span></p>';
  });
  document.querySelectorAll('[data-list="work"]').forEach((el) => {
    const filter = el.dataset.vertical;
    const items = (C.work || []).filter((w) => !filter || w.vertical === filter);
    el.innerHTML = items.map((w) => {
      const tags = [w.vertical].concat(w.tags || []).map((t, i) => '<span class="row__tag' + (i && /live/i.test(t) ? " row__tag--live" : "") + '">' + esc(t) + "</span>").join("");
      const inner = '<span class="mono">' + esc(w.year || "") + "</span><div><h3>" + esc(w.title) + "</h3>" + (w.summary ? '<p class="row__desc">' + esc(w.summary) + "</p>" : "") + '</div><span class="row__tags">' + tags + '</span><span class="row__arrow" aria-hidden="true">\u2192</span>';
      /* Every entry stays reachable: the external case study when one is set, the
         work index otherwise, so a row is never a dead end. */
      return w.url ? '<a class="row row--feature reveal" href="' + esc(w.url) + '" target="_blank" rel="noopener" data-cursor="View" data-vertical="' + esc(w.vertical) + '">' + inner + "</a>"
                   : '<a class="row row--feature reveal" href="' + ROOT + 'work" data-cursor="View" data-vertical="' + esc(w.vertical) + '">' + inner + "</a>";
    }).join("") || '<p class="placeholder-block"><span class="mono">No work published yet.</span></p>';

    /* Vertical filters. One entry needs no filter bar, so it stays hidden until
       a second vertical exists and then appears on its own. */
    const bar = document.querySelector("[data-work-filters]");
    const verticals = [...new Set(items.map((w) => w.vertical).filter(Boolean))];
    if (bar && items.length > 1 && verticals.length > 1) {
      bar.hidden = false;
      bar.innerHTML = ["All"].concat(verticals).map((v, i) =>
        '<button type="button" class="chip' + (i ? "" : " is-active") + '" data-v="' + esc(v) + '">' + esc(v) + "</button>").join("");
      bar.addEventListener("click", (e) => {
        const chip = e.target.closest(".chip");
        if (!chip) return;
        bar.querySelectorAll(".chip").forEach((c) => c.classList.toggle("is-active", c === chip));
        const v = chip.dataset.v;
        el.querySelectorAll(".row").forEach((r) => { r.hidden = v !== "All" && r.dataset.vertical !== v; });
        if (hasST) ScrollTrigger.refresh();
      });
    }
  });

  /* ---------- team roster + stage ---------- */
  const HUES = { "AI Automation": "#16e9d8", "Creative Studio": "#b57bff", "Web & Digital": "#cefd21", "Software Solutions": "#6c9cff", "Training": "#ff8a5b", "Leadership": "#cefd21" };
  /* Disciplines are an open list (admin allows custom ones): unknown names get a stable colour of their own. */
  const hueOf = (d) => HUES[d] || (d ? "hsl(" + String(d).split("").reduce((h, ch) => (h * 31 + ch.charCodeAt(0)) % 360, 7) + " 88% 62%)" : "#cefd21");
  const initialsOf = (m) => m.name ? m.name.trim().split(/\s+/).map((w) => w[0]).join("").slice(0, 2).toUpperCase() : "—";
  document.querySelectorAll('[data-list="team"]').forEach((roster) => {
    const TEAM = (C.team || []).map((m) => Object.assign({}, m, { placeholder: !m.name }));
    const stage = document.getElementById(roster.dataset.stage || "stage");
    const filters = document.getElementById(roster.dataset.filters || "teamFilters");
    const photo = (m) => m.photo ? (/^(https?:)?\//.test(m.photo) ? m.photo : ROOT + m.photo) : "";
    const members = TEAM.map((m) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "member" + (m.placeholder ? " is-placeholder" : "");
      b.style.setProperty("--hue", hueOf(m.discipline));
      b.dataset.discipline = m.discipline || "";
      b.setAttribute("data-cursor", "View");
      b.innerHTML =
        '<span class="member__avatar">' + (photo(m) ? '<img src="' + esc(photo(m)) + '" alt="" loading="lazy" decoding="async">' : esc(initialsOf(m))) + "</span>" +
        '<span><span class="member__name">' + esc(m.placeholder ? "[Insert team member]" : m.name) + '</span><span class="member__role">' + esc(m.role || "") + "</span></span>" +
        '<span class="member__disc">' + esc(m.discipline || "") + "</span>" +
        '<span class="member__more"><p>' + esc(m.placeholder ? "[Insert bio]" : (m.bio || "")) + "</p></span>";
      roster.appendChild(b);
      return b;
    });
    let active = -1;
    const show = (i, animate) => {
      if (i === active || !stage) { active = i; members.forEach((b, j) => b.classList.toggle("is-active", j === i)); return; }
      active = i;
      const m = TEAM[i];
      members.forEach((b, j) => b.classList.toggle("is-active", j === i));
      const markup =
        '<div class="stage__frame">' + (photo(m) ? '<img src="' + esc(photo(m)) + '" alt="' + esc(m.name) + '">' :
          '<div class="stage__ph"><span class="stage__initials">' + esc(initialsOf(m)) + '</span><span class="mono">' + (m.placeholder ? "Insert team member" : "Insert portrait") + "</span></div>") +
        '<span class="stage__tag">' + esc(m.discipline || "") + "</span></div>" +
        '<div class="stage__body"><span class="stage__role">' + esc(m.role || "") + '</span><h3 class="stage__name">' + esc(m.placeholder ? "[Insert name]" : m.name) + "</h3>" +
        '<p class="stage__bio">' + esc(m.placeholder ? "[Insert bio]" : (m.bio || "")) + "</p>" +
        '<p class="stage__quote">' + (m.quote ? "“" + esc(m.quote) + "”" : "") + "</p></div>";
      const paint = () => { stage.innerHTML = markup; };
      if (animate && hasGsap && !reduce) {
        gsap.to(stage, { opacity: 0, y: 8, duration: .2, ease: "power2.in", onComplete: () => { paint(); gsap.fromTo(stage, { opacity: 0, y: 12 }, { opacity: 1, y: 0, duration: .5, ease: "power3.out" }); } });
      } else paint();
    };
    if (TEAM.length) show(0, false);
    const mobile = () => matchMedia("(max-width: 860px)").matches;
    members.forEach((b, i) => {
      if (fine) b.addEventListener("mouseenter", () => { if (!mobile()) show(i, true); });
      b.addEventListener("focus", () => { if (!mobile()) show(i, true); });
      b.addEventListener("click", () => {
        show(i, true);
        if (mobile() || !stage) {
          const more = b.querySelector(".member__more"), open = b.classList.toggle("is-open");
          if (hasGsap) gsap.to(more, { height: open ? more.firstElementChild.offsetHeight : 0, duration: .45, ease: "power3.inOut", onComplete: () => hasST && ScrollTrigger.refresh() });
          else more.style.height = open ? "auto" : "0";
        }
      });
    });
    if (filters) {
      const disciplines = ["All", ...new Set(TEAM.map((m) => m.discipline).filter(Boolean))];
      disciplines.forEach((d, i) => {
        const c = document.createElement("button");
        c.type = "button"; c.className = "chip" + (i === 0 ? " is-active" : ""); c.textContent = d;
        c.addEventListener("click", () => {
          filters.querySelectorAll(".chip").forEach((x) => x.classList.toggle("is-active", x === c));
          let first = -1;
          members.forEach((b, j) => { const hide = d !== "All" && b.dataset.discipline !== d; b.classList.toggle("is-hidden", hide); if (!hide && first < 0) first = j; });
          if (first >= 0 && members[active] && members[active].classList.contains("is-hidden")) show(first, true);
          if (hasST) ScrollTrigger.refresh();
        });
        filters.appendChild(c);
      });
    }
  });

  /* ---------- smooth scroll (Lenis) ---------- */
  let lenis = null;
  if (!reduce && typeof Lenis !== "undefined" && hasGsap) {
    lenis = new Lenis({ lerp: 0.08, smoothWheel: true });
    lenis.on("scroll", () => hasST && ScrollTrigger.update());
    gsap.ticker.add((t) => lenis.raf(t * 1000));
    gsap.ticker.lagSmoothing(0);
  }
  const scrollTo = (target, offset) => { lenis ? lenis.scrollTo(target, { offset: offset == null ? -60 : offset, duration: 1.5 }) : target.scrollIntoView({ behavior: reduce ? "auto" : "smooth" }); };

  /* ---------- nav ---------- */
  const nav = document.getElementById("nav"), burger = document.querySelector(".burger"), top = document.getElementById("top");
  const closeNav = () => { if (nav) nav.classList.remove("is-open"); if (burger) burger.setAttribute("aria-expanded", "false"); };
  if (burger && nav) burger.addEventListener("click", () => burger.setAttribute("aria-expanded", String(nav.classList.toggle("is-open"))));
  if (top) { const onScroll = () => top.classList.toggle("is-scrolled", scrollY > 40); addEventListener("scroll", onScroll, { passive: true }); onScroll(); }
  document.querySelectorAll('a[href^="#"]').forEach((a) => a.addEventListener("click", (e) => {
    const id = a.getAttribute("href"); if (id.length < 2) return;
    const t = document.querySelector(id); if (!t) return;
    e.preventDefault(); closeNav(); scrollTo(t);
  }));
  // Mark the current page in the nav (inner pages); the homepage marks sections itself.
  /* Pages are served at extensionless routes (/services), so compare normalised paths: a
     legacy .html suffix, a trailing slash and /index all mean the same page. A section
     link stays lit on its children, so /services is active on /services/ai-automation. */
  const norm = (p) => p.replace(/\.html$/, "").replace(/\/index$/, "/").replace(/(.)\/$/, "$1") || "/";
  const here = norm(location.pathname);
  document.querySelectorAll(".nav a").forEach((a) => {
    const href = a.getAttribute("href"); if (!href || href.startsWith("#")) return;
    const path = norm(new URL(href, location.href).pathname);
    if (path === here || (path !== "/" && here.startsWith(path + "/"))) a.classList.add("is-active");
  });

  /* ---------- cursor ---------- */
  const cursor = document.querySelector(".cursor");
  if (!fine && cursor) cursor.remove();
  if (fine && cursor) {
    const label = cursor.querySelector(".cursor__label");
    const pos = { x: innerWidth / 2, y: innerHeight / 2 }, cur = { x: pos.x, y: pos.y };
    /* GSAP is a progressive enhancement here, not a requirement: without it the dot
       still follows the pointer, it just runs off a plain rAF loop. */
    const set = hasGsap ? gsap.quickSetter(cursor, "css")
      : (p) => { cursor.style.transform = "translate3d(" + p.x + "px, " + p.y + "px, 0)"; };
    let live = false;
    addEventListener("mousemove", (e) => {
      pos.x = e.clientX; pos.y = e.clientY;
      if (live) return;
      /* First move: we finally know where the pointer is, so snap the dot to it,
         show it, and only now let the native cursor be hidden. */
      live = true; cur.x = pos.x; cur.y = pos.y; set({ x: cur.x, y: cur.y });
      cursor.classList.add("is-live");
      document.documentElement.classList.add("has-cursor");
    }, { passive: true });
    const tick = () => { cur.x += (pos.x - cur.x) * 0.22; cur.y += (pos.y - cur.y) * 0.22; set({ x: cur.x, y: cur.y }); };
    if (hasGsap) gsap.ticker.add(tick);
    else (function loop() { tick(); requestAnimationFrame(loop); })();
    document.addEventListener("mouseover", (e) => {
      const el = e.target.closest("[data-cursor], a, button, h1, h2, .founder__quote, .stage__quote");
      cursor.classList.remove("is-hover", "is-label", "is-text");
      if (!el) return;
      const text = el.getAttribute("data-cursor");
      if (text) { label.textContent = text; cursor.classList.add("is-label"); }
      else if (el.matches("h1, h2, .founder__quote, .stage__quote")) cursor.classList.add("is-text");
      else cursor.classList.add("is-hover");
    });
  }

  /* ---------- contact form ---------- */
  document.querySelectorAll("form[data-contact]").forEach((form) => {
    const err = form.querySelector(".form__err"), brief = form.elements.brief, count = form.querySelector(".count");
    const done = form.parentElement.querySelector(".form__done");
    /* "0 / 50" read as a 50-character limit when it is actually a minimum, and nothing said
       so until the form refused to send. Count down to the threshold instead, and go lime
       once it is met. */
    const MIN_BRIEF = 50;
    function paintCount() {
      if (!brief || !count) return;
      const short = MIN_BRIEF - brief.value.trim().length;
      count.textContent = short > 0 ? short + (short === 1 ? " more character" : " more characters") : "ready to send";
      count.classList.toggle("is-met", short <= 0);
    }
    if (brief && count) { brief.addEventListener("input", paintCount); paintCount(); }
    const flag = (el, bad) => { const box = el && el.closest(".field, .check"); if (box) box.classList.toggle("is-invalid", bad); };
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const d = new FormData(form), problems = [];
      const name = (d.get("name") || "").trim(); flag(form.elements.name, !name); if (!name) problems.push("your name");
      const email = (d.get("email") || "").trim(); const okE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); flag(form.elements.email, !okE); if (!okE) problems.push("a valid email");
      const phone = (d.get("phone") || "").trim(); const okP = /^\+?[0-9 ()-]{7,20}$/.test(phone); flag(form.elements.phone, !okP); if (!okP) problems.push("a phone or WhatsApp number");
      const iam = d.get("iam"); flag(form.elements.iam, !iam); if (!iam) problems.push("who you are");
      const services = d.getAll("service"); const sv = form.querySelector("[data-services]"); if (sv) sv.classList.toggle("is-invalid", !services.length); if (!services.length) problems.push("at least one service");
      const briefV = brief ? brief.value.trim() : ""; flag(brief, briefV.length < 50); if (briefV.length < 50) problems.push("a brief of at least 50 characters");
      const method = d.get("method"); const mt = form.querySelector("[data-method]"); if (mt) mt.classList.toggle("is-invalid", !method); if (!method) problems.push("a preferred contact method");
      const consent = form.elements.consent && form.elements.consent.checked; flag(form.elements.consent, !consent); if (!consent) problems.push("your consent");
      if (problems.length) {
        if (err) { err.hidden = false; err.textContent = "Please add " + problems.join(", ") + "."; }
        const first = form.querySelector(".is-invalid"); if (first) scrollTo(first, -120);
        return;
      }
      if (err) err.hidden = true;
      const company = (d.get("company") || "").trim();
      const text = "Hello ZEHNOX, new enquiry from " + location.host + "\n\nName: " + name + "\nEmail: " + email + "\nPhone / WhatsApp: " + phone + "\nCompany: " + (company || "-") + "\nI am a: " + iam + "\nService of interest: " + services.join(", ") + "\nPreferred contact: " + method + "\n\nBrief:\n" + briefV;
      const wa = waLink(text);
      const btn = form.querySelector("[type=submit]"); btn.disabled = true; btn.textContent = "Sending…";
      /* Default to this site's own API. Leaving the setting empty used to mean "post
         nowhere and just open WhatsApp", which silently dropped every enquiry before it
         reached the admin or the forwarding email. On a static deployment with no server
         the POST 404s, sent stays false, and the WhatsApp fallback below still runs. */
      const endpoint = (C.site && C.site.contactEndpoint) || form.dataset.endpoint || "/api/contact";
      let sent = false;
      if (endpoint) {
        try {
          const r = await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify({ name, email, phone, company, iam, services, brief: briefV, method, page: location.href }) });
          sent = r.ok;
        } catch (_) { sent = false; }
      }
      if (!sent) window.open(wa, "_blank", "noopener");
      if (done) {
        /* Two different outcomes, so two different messages: the enquiry reached the
           server, or it did not and WhatsApp is carrying it instead. Saying "your brief is
           ready" for both told the sender nothing about which had happened. */
        const link = done.querySelector("a");
        if (link) { link.href = wa; link.textContent = sent ? "Also send on WhatsApp" : "Open in WhatsApp"; }
        const okState = done.querySelector('[data-done="sent"]'); if (okState) okState.hidden = !sent;
        const waState = done.querySelector('[data-done="wa"]'); if (waState) waState.hidden = sent;
        form.hidden = true; done.hidden = false;
        if (hasGsap) gsap.from(done, { opacity: 0, y: 20, duration: .8, ease: "power3.out" });
      }
      if (hasST) ScrollTrigger.refresh();
    });
  });

  /* ---------- reveals ---------- */
  const heroRises = gsap.utils ? gsap.utils.toArray(".phero .rise, .phero .reveal") : [];
  if (hasGsap && !reduce) {
    const tl = gsap.timeline({ defaults: { ease: "power4.out" }, onComplete: () => document.body.classList.remove("is-loading") });
    if (heroRises.length) tl.to(heroRises, { y: 0, opacity: 1, duration: 1.1, stagger: .1 }, .15);
    else tl.call(() => document.body.classList.remove("is-loading"));
  } else document.body.classList.remove("is-loading");

  if (hasST && !reduce) {
    gsap.utils.toArray(".mask .rise").forEach((el) => {
      if (el.closest(".hero, .phero")) return;
      gsap.to(el, { y: 0, duration: 1.2, ease: "power4.out", scrollTrigger: { trigger: el, start: "top 88%" } });
    });
    ScrollTrigger.batch(".reveal:not(.phero .reveal)", { start: "top 90%", onEnter: (els) => gsap.to(els, { opacity: 1, y: 0, duration: 1, ease: "power3.out", stagger: .08, overwrite: true }) });
    ScrollTrigger.addEventListener("refreshInit", () => gsap.utils.toArray(".reveal, .mask .rise").forEach((el) => { if (el.getBoundingClientRect().top < 0) gsap.set(el, { opacity: 1, y: 0 }); }));
    gsap.utils.toArray("[data-parallax-y]").forEach((el) => {
      const d = parseFloat(el.dataset.parallaxY);
      gsap.fromTo(el, { y: -d }, { y: d, ease: "none", scrollTrigger: { trigger: el.closest("section") || el, start: "top bottom", end: "bottom top", scrub: true } });
    });
    addEventListener("load", () => ScrollTrigger.refresh());
  } else if (hasGsap) {
    gsap.set(".rise", { y: 0 }); gsap.set(".reveal", { opacity: 1, y: 0 });
  }

  /* ---------- FAQ (details) : animate open/close ---------- */
  document.querySelectorAll("details.faq__item").forEach((d) => {
    const body = d.querySelector(".faq__body"); if (!body || !hasGsap || reduce) return;
    d.querySelector("summary").addEventListener("click", (e) => {
      e.preventDefault();
      if (d.open) gsap.to(body, { height: 0, opacity: 0, duration: .35, ease: "power3.inOut", onComplete: () => { d.open = false; body.style.height = ""; hasST && ScrollTrigger.refresh(); } });
      else { d.open = true; gsap.from(body, { height: 0, opacity: 0, duration: .45, ease: "power3.out", clearProps: "height", onComplete: () => hasST && ScrollTrigger.refresh() }); }
    });
  });

  /* ---------- contact page: office map (guarded; runs only where .map-frame exists) ----------
     Fills the frame from contact.mapEmbed (an iframe src URL or a pasted <iframe> snippet, edited in the admin).
     When the value is empty the frame renders a visible dashed placeholder instead of an invented map. */
  document.querySelectorAll(".map-frame").forEach((frame) => {
    const raw = C.contact && C.contact.mapEmbed ? String(C.contact.mapEmbed).trim() : "";
    const pasted = raw.match(/src=["']([^"']+)["']/);
    let src = pasted ? pasted[1] : raw;
    if (!/^https:\/\//i.test(src)) src = "";
    frame.innerHTML = "";
    if (src) {
      const iframe = document.createElement("iframe");
      iframe.src = src;
      iframe.title = "ZEHNOX office location";
      iframe.loading = "lazy";
      iframe.referrerPolicy = "no-referrer-when-downgrade";
      iframe.setAttribute("allowfullscreen", "");
      frame.appendChild(iframe);
    } else {
      const block = document.createElement("div");
      block.className = "placeholder-block";
      const label = document.createElement("span");
      label.className = "mono";
      label.textContent = frame.dataset.ph || "[Insert embedded map link]";
      block.appendChild(label);
      frame.appendChild(block);
    }
  });

  window.ZX = { C, ROOT, hasGsap, hasST, reduce, fine, lenis, esc, textToHtml, fmtDate, waLink, scrollTo };
})();

/* ---------- Work / Insights: filter chips + featured post (guarded; runs only where the markup exists) ----------
   <div class="filters" data-filter-for="<listId>" [data-filter-from="tags"]> … chips with data-filter …</div>
   Rows inside the list carry data-vertical (work) or data-tags (posts, stamped here). "all" shows everything.
   <p data-filter-empty="<listId>" hidden> is shown when a filter matches nothing.
   <div data-featured-post> renders the newest post as one large editorial row. */
(function () {
  "use strict";
  const ZX = window.ZX; if (!ZX) return;
  const { C, ROOT, esc, fmtDate, hasGsap, hasST, reduce } = ZX;
  const sortedPosts = () => (C.posts || []).slice().sort((a, b) => String(b.date).localeCompare(String(a.date)));
  const postHref = (p) => ROOT + "insights/" + esc(p.slug);

  document.querySelectorAll("[data-featured-post]").forEach((el) => {
    const p = sortedPosts()[0];
    if (!p) { el.innerHTML = '<p class="placeholder-block"><span class="mono">No insights published yet.</span></p>'; return; }
    const tags = (p.tags || []).map((t) => '<span class="row__tag">' + esc(t) + "</span>").join("") || '<span class="row__tag">Insight</span>';
    el.innerHTML = '<a class="row row--feature" href="' + postHref(p) + '" data-cursor="Read">' +
      '<span class="mono">' + fmtDate(p.date) + "</span><div><h3>" + esc(p.title) + "</h3>" +
      (p.description ? '<p class="row__desc">' + esc(p.description) + "</p>" : "") + "</div>" +
      '<span class="row__tags">' + tags + "</span></a>";
    if (hasST && !reduce) gsap.from(el.firstElementChild, { opacity: 0, y: 24, duration: 1, ease: "power3.out", scrollTrigger: { trigger: el, start: "top 90%" } });
  });

  document.querySelectorAll(".filters[data-filter-for]").forEach((bar) => {
    const list = document.getElementById(bar.dataset.filterFor); if (!list) return;
    const empty = document.querySelector('[data-filter-empty="' + bar.dataset.filterFor + '"]');
    const rows = () => Array.from(list.children).filter((r) => r.classList.contains("row"));
    const keys = (row) => (row.dataset.vertical ? [row.dataset.vertical] : []).concat(row.dataset.tags ? row.dataset.tags.split("|") : []);
    if (bar.dataset.filterFrom === "tags") {
      const limit = parseInt(list.dataset.limit || "0", 10) || Infinity;
      const posts = sortedPosts().slice(0, limit);
      rows().forEach((row, i) => { if (posts[i]) row.dataset.tags = (posts[i].tags || []).join("|"); });
      const tags = [...new Set(posts.flatMap((p) => p.tags || []))];
      bar.innerHTML = '<button type="button" class="chip is-active" data-filter="all">All</button>' +
        tags.map((t) => '<button type="button" class="chip" data-filter="' + esc(t) + '">' + esc(t) + "</button>").join("");
      if (!tags.length) bar.hidden = true;
    }
    bar.addEventListener("click", (e) => {
      const chip = e.target.closest(".chip[data-filter]"); if (!chip || !bar.contains(chip)) return;
      bar.querySelectorAll(".chip").forEach((x) => x.classList.toggle("is-active", x === chip));
      const f = chip.dataset.filter; let shown = 0;
      rows().forEach((row) => {
        const show = f === "all" || keys(row).includes(f);
        row.hidden = !show;
        if (show) { shown++; if (hasGsap) gsap.set(row, { opacity: 1, y: 0 }); }
      });
      if (empty) empty.hidden = shown > 0;
      if (hasST) ScrollTrigger.refresh();
    });
  });
})();
