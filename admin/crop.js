/* ZEHNOX Admin — portrait cropper and compressor. No dependencies, no build step.

   Browser:  ZXCrop.open(file) -> Promise<{name, dataUrl, bytes, width, height} | null>
             (null when the editor is cancelled)
   Node:     require("./crop.js") exposes the pure helpers the tests exercise.

   Why it exists: uploads used to travel at whatever size the camera produced — a 5 MB
   shot went up as a 6.7 MB base64 body and then out to every visitor unchanged, which is
   what made adding a photo feel slow. Cropping to one fixed 4:5 frame here makes every
   portrait line up on the site, and re-encoding at 900px wide turns that 5 MB shot into
   roughly 150 KB. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.ZXCrop = api;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  /* 4:5 — the ratio .stage__frame on the site and .photo__frame in the admin already use. */
  const OUT_W = 900, OUT_H = 1125;
  const SOFT_W = 480;                 // below this a portrait starts to look soft on a retina screen
  const MAX_ZOOM = 4;
  const BYTE_BUDGET = 220 * 1024;
  const QUALITIES = [0.86, 0.78, 0.7, 0.62, 0.54, 0.46];
  const TYPES = ["image/webp", "image/jpeg"];

  /* ---------- geometry (pure, unit tested) ---------- */

  /* Smallest scale at which the image still covers the whole crop frame. */
  function coverScale(iw, ih, fw, fh) {
    if (!(iw > 0 && ih > 0 && fw > 0 && fh > 0)) return 1;
    return Math.max(fw / iw, fh / ih);
  }

  /* Keep the drawn image pinned over the frame so no empty gutter can ever appear. */
  function clampOffset(off, drawn, frame) {
    if (!(drawn > frame)) return (frame - drawn) / 2;
    return Math.min(0, Math.max(frame - drawn, off));
  }

  function viewState(state, zoom, x, y) {
    const s = coverScale(state.iw, state.ih, state.fw, state.fh) * zoom;
    const w = state.iw * s, h = state.ih * s;
    return {
      iw: state.iw, ih: state.ih, fw: state.fw, fh: state.fh, zoom: zoom,
      x: clampOffset(x, w, state.fw), y: clampOffset(y, h, state.fh),
    };
  }

  /* The image rectangle in frame coordinates: where it sits and how big it is drawn. */
  function viewOf(state) {
    const s = coverScale(state.iw, state.ih, state.fw, state.fh) * state.zoom;
    const w = state.iw * s, h = state.ih * s;
    return { x: clampOffset(state.x, w, state.fw), y: clampOffset(state.y, h, state.fh), w: w, h: h };
  }

  function panBy(state, dx, dy) {
    return viewState(state, state.zoom, state.x + dx, state.y + dy);
  }

  /* Zoom around a fixed point — the pointer, or the frame centre — so the picture grows
     under the finger instead of jumping away from it. */
  function zoomAbout(state, nextZoom, px, py) {
    const z = Math.min(MAX_ZOOM, Math.max(1, nextZoom || 1));
    const v = viewOf(state);
    const ux = (px - v.x) / v.w, uy = (py - v.y) / v.h;
    const s = coverScale(state.iw, state.ih, state.fw, state.fh) * z;
    return viewState(state, z, px - ux * state.iw * s, py - uy * state.ih * s);
  }

  /* Open on the centre of the shot, which is where people frame a face anyway. */
  function initialState(iw, ih) {
    const base = { iw: iw, ih: ih, fw: OUT_W, fh: OUT_H, zoom: 1, x: 0, y: 0 };
    const s = coverScale(iw, ih, OUT_W, OUT_H);
    return viewState(base, 1, (OUT_W - iw * s) / 2, (OUT_H - ih * s) / 2);
  }

  /* The visible frame mapped back onto the original pixels — what we actually crop out. */
  function sourceRect(state) {
    const v = viewOf(state);
    const s = v.w / state.iw;
    return { x: -v.x / s, y: -v.y / s, w: state.fw / s, h: state.fh / s };
  }

  /* Never upscale: a 400px source stays 400px wide rather than being blown up to 900. */
  function outputSize(srcW) {
    const w = Math.max(1, Math.min(OUT_W, Math.round(srcW)));
    return { w: w, h: Math.round(w * OUT_H / OUT_W) };
  }

  /* Step the quality down until the encoded image fits the budget. If nothing fits we keep
     the smallest result: a slightly soft 900px portrait still beats sending megabytes. */
  async function encodeWithin(encode, types, budget, qualities) {
    let best = null;
    for (const type of types) {
      for (const q of qualities) {
        const out = await encode(type, q);
        if (!out) break;                       // this browser cannot encode that type at all
        if (!best || out.bytes < best.bytes) best = out;
        if (out.bytes <= budget) return out;
      }
    }
    return best;
  }

  function outputName(name, type) {
    const ext = type === "image/webp" ? ".webp" : ".jpg";
    const stem = String(name || "photo").replace(/\.[a-z0-9]+$/i, "").slice(0, 60).trim() || "photo";
    return stem + ext;
  }

  const kb = (n) => (n < 1024 * 1024 ? Math.round(n / 1024) + " KB" : (n / 1048576).toFixed(1) + " MB");

  /* ---------- browser: decoding ---------- */

  function viaElement(file) {
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(file);
      const img = new Image();
      /* The object URL stays alive on purpose: revoking it here blanks the decoded image
         in Safari when we later draw it to a canvas. It dies with the page. */
      img.onload = () => resolve(img);
      img.onerror = () => { URL.revokeObjectURL(url); reject(new Error("That file is not an image we can read")); };
      img.src = url;
    });
  }

  function loadImage(file) {
    if (typeof createImageBitmap === "function") {
      /* "from-image" applies the EXIF orientation phones write, so a portrait shot
         sideways arrives upright instead of lying on its side. */
      return createImageBitmap(file, { imageOrientation: "from-image" })
        .catch(() => createImageBitmap(file))
        .catch(() => viaElement(file));
    }
    return viaElement(file);
  }

  /* ---------- browser: drawing ---------- */

  function ctx2d(canvas) {
    const c = canvas.getContext("2d");
    c.imageSmoothingEnabled = true;
    c.imageSmoothingQuality = "high";
    return c;
  }

  /* One drawImage from a 4000px original down to 900px throws away detail on several
     browsers, so halve first and land the final step from close to the target size. */
  function drawCrop(canvas, img, src, ow, oh) {
    let cur = img, sx = src.x, sy = src.y, cw = src.w, ch = src.h;
    while (cw > ow * 2 && ch > oh * 2) {
      const nw = Math.max(ow, Math.round(cw / 2)), nh = Math.max(oh, Math.round(ch / 2));
      const step = document.createElement("canvas");
      step.width = nw; step.height = nh;
      ctx2d(step).drawImage(cur, sx, sy, cw, ch, 0, 0, nw, nh);
      cur = step; sx = 0; sy = 0; cw = nw; ch = nh;
    }
    canvas.width = ow; canvas.height = oh;
    ctx2d(canvas).drawImage(cur, sx, sy, cw, ch, 0, 0, ow, oh);
    return canvas;
  }

  function toDataUrl(canvas, type, quality) {
    const url = canvas.toDataURL(type, quality);
    /* A browser that cannot encode this type quietly hands back a PNG instead. */
    const head = "data:" + type + ";base64,";
    if (url.slice(0, head.length) !== head) return null;
    const b64 = url.slice(head.length);
    const pad = b64.endsWith("==") ? 2 : b64.endsWith("=") ? 1 : 0;
    return { type: type, quality: quality, dataUrl: url, bytes: Math.floor(b64.length * 3 / 4) - pad };
  }

  /* ---------- browser: the editor ---------- */

  const HTML =
    '<div class="crop__panel" role="document">' +
      '<div class="crop__head"><h3>Position the photo</h3>' +
        '<p class="hint">Drag to move, scroll or pinch to zoom. Whatever sits inside the frame is exactly what the site shows.</p></div>' +
      '<div class="crop__stage"><canvas class="crop__canvas"></canvas><div class="crop__grid" aria-hidden="true"></div></div>' +
      '<label class="crop__zoom"><span class="mono">Zoom</span>' +
        '<input type="range" min="1" max="4" step="0.005" value="1" aria-label="Zoom"></label>' +
      '<div class="crop__foot"><span class="crop__meta mono"></span>' +
        '<span class="crop__btns">' +
          '<button class="btn btn--ghost btn--sm" type="button" data-crop="cancel">Cancel</button>' +
          '<button class="btn btn--lime btn--sm" type="button" data-crop="use">Use photo</button>' +
        "</span></div>" +
    "</div>";

  function open(file) {
    if (typeof document === "undefined") return Promise.reject(new Error("ZXCrop.open needs a browser"));
    return loadImage(file).then((img) => new Promise((resolve, reject) => {
      const iw = img.naturalWidth || img.width, ih = img.naturalHeight || img.height;
      if (!iw || !ih) return reject(new Error("That image has no size we can read"));

      const dlg = document.createElement("dialog");
      dlg.className = "crop";
      dlg.setAttribute("aria-label", "Position the photo");
      dlg.innerHTML = HTML;
      document.body.appendChild(dlg);

      const stage = dlg.querySelector(".crop__stage");
      const canvas = dlg.querySelector(".crop__canvas");
      const range = dlg.querySelector(".crop__zoom input");
      const meta = dlg.querySelector(".crop__meta");
      const useBtn = dlg.querySelector('[data-crop="use"]');

      let state = initialState(iw, ih);
      let settled = false;

      function teardown() {
        window.removeEventListener("resize", onResize);
        try { dlg.close(); } catch (_) { /* already closed */ }
        dlg.remove();
        /* A decoded 4000x3000 bitmap is ~48 MB of GPU memory; hand it back rather than
           waiting for the collector, or a few uploads in a row make the tab crawl. */
        if (typeof ImageBitmap !== "undefined" && img instanceof ImageBitmap) img.close();
      }

      function finish(value) {
        if (settled) return;
        settled = true;
        teardown();
        resolve(value);
      }

      /* Crop state lives in output-pixel space (900x1125) so a window resize never disturbs
         it; pointer deltas are converted through this factor. */
      const perCss = () => OUT_W / (stage.getBoundingClientRect().width || OUT_W);
      function toFrame(clientX, clientY) {
        const r = stage.getBoundingClientRect(), k = OUT_W / (r.width || OUT_W);
        return { x: (clientX - r.left) * k, y: (clientY - r.top) * k };
      }

      function paint() {
        const r = stage.getBoundingClientRect();
        const dpr = Math.min(2, window.devicePixelRatio || 1);
        const cw = Math.max(1, Math.round(r.width * dpr)), ch = Math.max(1, Math.round(r.height * dpr));
        if (canvas.width !== cw || canvas.height !== ch) { canvas.width = cw; canvas.height = ch; }
        const k = cw / OUT_W, v = viewOf(state), c = ctx2d(canvas);
        c.clearRect(0, 0, cw, ch);
        c.drawImage(img, v.x * k, v.y * k, v.w * k, v.h * k);
        range.value = String(state.zoom);
      }

      const shown = outputSize(sourceRect(state).w);
      meta.textContent = iw + " × " + ih + "  →  " + shown.w + " × " + shown.h;
      if (shown.w < SOFT_W) { meta.textContent += "  ·  small original, may look soft"; meta.classList.add("is-warn"); }

      /* ---- pointer: drag to pan, two fingers to pinch ---- */
      const pointers = new Map();
      let drag = null, pinch = null;
      const spread = () => { const a = Array.from(pointers.values()); return Math.hypot(a[0].x - a[1].x, a[0].y - a[1].y) || 1; };
      const centre = () => { let x = 0, y = 0; pointers.forEach((p) => { x += p.x; y += p.y; }); return { x: x / pointers.size, y: y / pointers.size }; };

      stage.addEventListener("pointerdown", (e) => {
        stage.setPointerCapture(e.pointerId);
        pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
        if (pointers.size === 2) {
          const c = centre();
          pinch = { dist: spread(), zoom: state.zoom, at: toFrame(c.x, c.y) };
          drag = null;
        } else {
          drag = { id: e.pointerId, x: e.clientX, y: e.clientY, sx: state.x, sy: state.y };
        }
        e.preventDefault();
      });
      stage.addEventListener("pointermove", (e) => {
        if (!pointers.has(e.pointerId)) return;
        pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
        if (pinch && pointers.size === 2) {
          state = zoomAbout(state, pinch.zoom * (spread() / pinch.dist), pinch.at.x, pinch.at.y);
        } else if (drag && drag.id === e.pointerId) {
          const k = perCss();
          state = viewState(state, state.zoom, drag.sx + (e.clientX - drag.x) * k, drag.sy + (e.clientY - drag.y) * k);
        } else return;
        paint();
      });
      function release(e) {
        pointers.delete(e.pointerId);
        if (pointers.size < 2) pinch = null;
        if (drag && drag.id === e.pointerId) drag = null;
        /* Lifting one finger of a pinch hands control back to the finger still down. */
        if (pointers.size === 1) {
          const only = Array.from(pointers.entries())[0];
          drag = { id: only[0], x: only[1].x, y: only[1].y, sx: state.x, sy: state.y };
        }
      }
      stage.addEventListener("pointerup", release);
      stage.addEventListener("pointercancel", release);

      stage.addEventListener("wheel", (e) => {
        e.preventDefault();
        const at = toFrame(e.clientX, e.clientY);
        state = zoomAbout(state, state.zoom * Math.exp(-e.deltaY * (e.deltaMode === 1 ? 0.02 : 0.0015)), at.x, at.y);
        paint();
      }, { passive: false });

      range.addEventListener("input", () => {
        state = zoomAbout(state, parseFloat(range.value), OUT_W / 2, OUT_H / 2);
        paint();
      });

      dlg.addEventListener("click", (e) => {
        const act = e.target.closest && e.target.closest("[data-crop]");
        if (act && act.dataset.crop === "cancel") return finish(null);
        if (act && act.dataset.crop === "use") return commit();
        if (e.target === dlg) finish(null);                    // click on the backdrop
      });
      dlg.addEventListener("cancel", (e) => { e.preventDefault(); finish(null); });   // Esc

      async function commit() {
        useBtn.disabled = true;
        useBtn.textContent = "Preparing…";
        try {
          const src = sourceRect(state), size = outputSize(src.w);
          const shot = drawCrop(document.createElement("canvas"), img, src, size.w, size.h);
          const best = await encodeWithin((type, q) => toDataUrl(shot, type, q), TYPES, BYTE_BUDGET, QUALITIES);
          if (!best) throw new Error("This browser could not compress the image");
          finish({
            name: outputName(file && file.name, best.type), dataUrl: best.dataUrl,
            bytes: best.bytes, width: size.w, height: size.h, label: kb(best.bytes),
          });
        } catch (err) {
          useBtn.disabled = false;
          useBtn.textContent = "Use photo";
          if (settled) return;
          settled = true;
          teardown();
          reject(err);
        }
      }

      function onResize() { paint(); }
      window.addEventListener("resize", onResize);

      dlg.showModal();
      paint();
      requestAnimationFrame(paint);      // the stage reaches its final width only after layout
    }));
  }

  return {
    OUT_W, OUT_H, MAX_ZOOM, BYTE_BUDGET, QUALITIES, TYPES, SOFT_W,
    coverScale, clampOffset, viewOf, viewState, panBy, zoomAbout, initialState,
    sourceRect, outputSize, encodeWithin, outputName, open,
  };
});
