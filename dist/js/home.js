/* ZEHNOX — homepage-only behaviour: loader, hero, horizontal capabilities, why, process, section-aware nav.
   Runs after site.js (window.ZX). */
(function () {
  "use strict";
  const Z = window.ZX || {};
  const { hasGsap, hasST, reduce, fine } = Z;
  if (!hasGsap) { document.body.classList.remove("is-loading"); return; }

  /* Hero headline: split into words so weight can react to the cursor */
  const heroWords = [];
  document.querySelectorAll(".hero__h1 .rise").forEach((line) => {
    const target = line.querySelector("em") || line;
    const parts = target.textContent.trim().split(/\s+/);
    target.textContent = "";
    parts.forEach((w, i) => {
      const s = document.createElement("span"); s.className = "hw"; s.textContent = w; target.appendChild(s); heroWords.push(s);
      if (i < parts.length - 1) target.appendChild(document.createTextNode(" "));
    });
  });

  /* Wire mark: prepare stroke drawing */
  const marks = gsap.utils.toArray(".mk");
  marks.forEach((p) => { const len = p.getTotalLength(); p.style.strokeDasharray = len; p.style.strokeDashoffset = reduce ? 0 : len; });

  /* Loader → hero */
  const words = gsap.utils.toArray(".loader__word span");
  const intro = gsap.timeline({ defaults: { ease: "power3.out" }, onComplete: () => document.body.classList.remove("is-loading") });
  if (!reduce) {
    words.forEach((w, i) => intro.fromTo(w, { opacity: 0, y: 30 }, { opacity: 1, y: 0, duration: .35 }, i * 0.3).to(w, { opacity: 0, y: -30, duration: .3 }, i * 0.3 + 0.3));
    intro.to(".loader__bar i", { scaleX: 1, duration: 1.2, ease: "power2.inOut" }, 0)
      .to(".loader", { yPercent: -100, duration: .9, ease: "power4.inOut" }, 1.3)
      .from(".sun", { scale: .6, opacity: 0, duration: 1.8, ease: "power2.out" }, 1.5)
      .fromTo(".mk--top", { y: -40 }, { y: 0, duration: 1.6, ease: "power3.out" }, 1.5)
      .fromTo(".mk--bot", { y: 40 }, { y: 0, duration: 1.6, ease: "power3.out" }, 1.5)
      .to(marks, { strokeDashoffset: 0, duration: 1.8, ease: "power2.inOut" }, 1.5)
      .to(marks, { fillOpacity: .16, duration: 1, ease: "power2.out" }, 2.6)
      .to(".hero .rise", { y: 0, duration: 1.2, stagger: .12, ease: "power4.out" }, 1.7)
      .from(".hero__sub, .hero__cta > *, .hero__meta > span, .marquee", { opacity: 0, y: 16, duration: .8, stagger: .08 }, 2.3)
      .from(".top", { opacity: 0, y: -10, duration: .8, clearProps: "transform" }, 2.3);
  } else {
    gsap.set(".hero .rise", { y: 0 });
    gsap.set(marks, { fillOpacity: .16 });
    document.body.classList.remove("is-loading");
  }

  /* Hero interaction: sun follows the mouse, the mark tilts as one object, words gain weight near the cursor */
  const heroEl = document.querySelector(".hero");
  if (fine && !reduce && heroEl) {
    const sun = document.querySelector(".sun");
    const mouse = { x: innerWidth / 2, y: innerHeight / 2 };
    addEventListener("mousemove", (e) => {
      mouse.x = e.clientX; mouse.y = e.clientY;
      const nx = e.clientX / innerWidth - .5, ny = e.clientY / innerHeight - .5;
      gsap.to(sun, { xPercent: nx * 12, yPercent: ny * 12, duration: 1.6, ease: "power2.out" });
      gsap.to(".hero__mark svg", { rotateY: nx * 16, rotateX: -ny * 12, transformPerspective: 1400, duration: 1.6, ease: "power2.out" });
    }, { passive: true });
    gsap.to(".hero__mark", { y: 10, duration: 3.4, yoyo: true, repeat: -1, ease: "sine.inOut" });
    const weights = heroWords.map(() => 0);
    gsap.ticker.add(() => {
      if (heroEl.getBoundingClientRect().bottom < 0) return;
      heroWords.forEach((w, i) => {
        const r = w.getBoundingClientRect();
        const d = Math.hypot(r.left + r.width / 2 - mouse.x, r.top + r.height / 2 - mouse.y);
        const t = Math.max(0, 1 - d / 260);
        weights[i] += (t - weights[i]) * .12;
        const base = w.parentElement.tagName === "EM" ? 300 : 320;
        w.style.setProperty("--w", (base + weights[i] * 220).toFixed(1));
      });
    });
  }
  if (hasST && !reduce) {
    gsap.to(".sun", { y: 240, ease: "none", scrollTrigger: { trigger: ".hero", start: "top top", end: "bottom top", scrub: true } });
    gsap.to(".hero__h1", { y: 120, opacity: 0, ease: "none", scrollTrigger: { trigger: ".hero", start: "top top", end: "bottom top", scrub: true } });
    gsap.to(".hero__mark", { yPercent: 30, rotate: 8, opacity: 0, ease: "none", scrollTrigger: { trigger: ".hero", start: "top top", end: "bottom top", scrub: true } });
  }

  if (!hasST || reduce) return;

  /* Section-aware nav on the homepage: highlight the page link for the section in view */
  const map = { "#services": "/services", "#solutions": "/solutions", "#work": "/work", "#insights": "/insights", "#team": "/about", "#contact": "/contact" };
  Object.entries(map).forEach(([id, page]) => {
    const sec = document.querySelector(id), a = document.querySelector('.nav a[href="' + page + '"]');
    if (sec && a) ScrollTrigger.create({ trigger: sec, start: "top 50%", end: "bottom 50%", onToggle: (s) => a.classList.toggle("is-active", s.isActive) });
  });
  const homeLink = document.querySelector('.nav a[href="/"]');
  if (homeLink) { homeLink.classList.remove("is-active"); ScrollTrigger.create({ trigger: ".hero", start: "top top", end: "bottom 50%", onToggle: (s) => homeLink.classList.toggle("is-active", s.isActive) }); }

  /* Capabilities: pinned horizontal scroll with counter */
  const mm = gsap.matchMedia();
  /* Pinning needs both width and height to work with. Below either threshold the
     CSS falls back to a vertical stack, so these breakpoints must match it. */
  mm.add("(min-width: 861px) and (min-height: 620px)", () => {
    const caps = document.querySelector(".caps");
    const track = document.querySelector(".caps__track");
    const cards = gsap.utils.toArray(".cap");
    const counter = document.querySelector(".caps__counter b");
    const rail = document.querySelector(".caps__rail i");
    /* Chrome leaves the end padding out of scrollWidth, so the track's right gutter
       has to be added back by hand or the last card stops flush against the edge.
       clientWidth (not innerWidth) keeps the scrollbar out of the measurement. */
    const getDist = () => Math.max(0, track.scrollWidth - document.documentElement.clientWidth + parseFloat(getComputedStyle(track).paddingRight));
    const tween = gsap.to(track, {
      x: () => -getDist(), ease: "none",
      scrollTrigger: {
        trigger: ".caps", start: "top top", end: () => "+=" + getDist(), pin: ".caps__pin", scrub: .8, anticipatePin: 1, invalidateOnRefresh: true,
        onUpdate: (self) => {
          if (counter) counter.textContent = String(Math.min(cards.length, 1 + Math.round(self.progress * (cards.length - 1)))).padStart(2, "0");
          if (rail) rail.style.setProperty("--p", self.progress.toFixed(4));
          if (caps) caps.classList.toggle("is-scrolling", self.progress > .01);
        },
      },
    });
    cards.forEach((c) => {
      gsap.from(c, { scale: .92, opacity: .4, ease: "none", scrollTrigger: { containerAnimation: tween, trigger: c, start: "left 95%", end: "left 55%", scrub: true } });
      /* Number and title drift against the travel across the whole pass, which gives
         the row depth without touching the properties the entrance tween owns. */
      gsap.fromTo(c.querySelectorAll(".cap__n, h3"), { x: 32 }, { x: -32, ease: "none", scrollTrigger: { containerAnimation: tween, trigger: c, start: "left right", end: "right left", scrub: true } });
    });
  });
  mm.add("(max-width: 860px), (max-height: 619px)", () => {
    gsap.utils.toArray(".cap").forEach((c) => gsap.from(c, { opacity: 0, y: 30, scrollTrigger: { trigger: c, start: "top 85%" } }));
  });

  /* Why: line-draw dividers */
  gsap.utils.toArray(".why__item").forEach((item) => {
    gsap.fromTo(item, { "--x": 0 }, { "--x": 1, duration: 1.2, ease: "power3.inOut", scrollTrigger: { trigger: item, start: "top 80%" } });
    gsap.from(item.children, { opacity: 0, y: 24, stagger: .1, duration: 1, ease: "power3.out", scrollTrigger: { trigger: item, start: "top 85%" } });
  });

  /* Process: draw the line, light the dots */
  const line = document.querySelector(".timeline__line");
  if (line) gsap.fromTo(line, { attr: { y2: 0 } }, { attr: { y2: 1000 }, ease: "none", scrollTrigger: { trigger: ".timeline", start: "top 70%", end: "bottom 70%", scrub: true } });
  gsap.utils.toArray(".tl").forEach((tl) => {
    ScrollTrigger.create({ trigger: tl, start: "top 70%", onEnter: () => tl.classList.add("is-on"), onLeaveBack: () => tl.classList.remove("is-on") });
    gsap.from(tl.children, { opacity: 0, x: -20, stagger: .08, duration: 1, ease: "power3.out", scrollTrigger: { trigger: tl, start: "top 85%" } });
  });
})();
