/* Tests for admin/crop.js — the geometry and the size-budget encoder.
   The DOM half (dialog, pointers, canvas) is not covered here; these are the parts that
   decide what actually lands on disk, so they are the parts worth pinning down.
   Run: node tools/test-crop.js */
"use strict";
const assert = require("assert");
const C = require("../admin/crop.js");

let pass = 0, fail = 0;
function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => { pass++; console.log("  ok   " + name); })
    .catch((e) => { fail++; console.log("  FAIL " + name + "\n       " + e.message); });
}
const near = (a, b, eps) => Math.abs(a - b) <= (eps == null ? 1e-6 : eps);

(async () => {
  console.log("crop geometry + compression");

  await test("a landscape shot is scaled until it covers the 4:5 frame", () => {
    // 4000x3000 into 900x1125: height is the tight side, so scale by 1125/3000.
    assert.ok(near(C.coverScale(4000, 3000, 900, 1125), 1125 / 3000));
  });

  await test("a portrait taller than 4:5 is scaled on width instead", () => {
    assert.ok(near(C.coverScale(1000, 2000, 900, 1125), 900 / 1000));
  });

  await test("the opening view is centred and leaves no gutter", () => {
    const s = C.initialState(4000, 3000);
    const v = C.viewOf(s);
    assert.ok(v.w >= C.OUT_W - 1e-9 && v.h >= C.OUT_H - 1e-9, "image must cover the frame");
    assert.ok(v.x <= 0 && v.y <= 0, "top-left must sit at or outside the frame");
    assert.ok(near(v.x, (C.OUT_W - v.w) / 2, 1e-6), "horizontally centred");
    assert.ok(near(v.y, (C.OUT_H - v.h) / 2, 1e-6), "vertically centred");
  });

  await test("panning past the edge is clamped, never leaving empty space", () => {
    let s = C.initialState(4000, 3000);
    s = C.panBy(s, 99999, 99999);
    const v = C.viewOf(s);
    assert.ok(near(v.x, 0), "cannot drag the left edge inside the frame");
    assert.ok(near(v.y, 0), "cannot drag the top edge inside the frame");
    s = C.panBy(s, -99999, -99999);
    const w = C.viewOf(s);
    assert.ok(near(w.x, C.OUT_W - w.w), "cannot drag the right edge inside the frame");
    assert.ok(near(w.y, C.OUT_H - w.h), "cannot drag the bottom edge inside the frame");
  });

  await test("zoom stays between 1 (cover) and the maximum", () => {
    const s = C.initialState(4000, 3000);
    assert.strictEqual(C.zoomAbout(s, 0.2, 450, 562).zoom, 1);
    assert.strictEqual(C.zoomAbout(s, 99, 450, 562).zoom, C.MAX_ZOOM);
  });

  await test("zooming holds the point under the pointer still", () => {
    const s = C.initialState(4000, 3000);
    const px = 300, py = 800;
    const before = C.viewOf(s);
    const u = { x: (px - before.x) / before.w, y: (py - before.y) / before.h };
    const after = C.viewOf(C.zoomAbout(s, 2.5, px, py));
    // Same fraction of the image should still sit under (px, py) — up to the edge clamp,
    // which cannot bite here because the anchor is well inside a 2.5x view.
    assert.ok(near((px - after.x) / after.w, u.x, 1e-6), "x anchor drifted");
    assert.ok(near((py - after.y) / after.h, u.y, 1e-6), "y anchor drifted");
  });

  await test("the crop rectangle stays inside the original pixels", () => {
    for (const [iw, ih] of [[4000, 3000], [1000, 2500], [900, 1125], [640, 480]]) {
      for (const zoom of [1, 1.7, 4]) {
        const s = C.zoomAbout(C.panBy(C.initialState(iw, ih), 500, -700), zoom, 100, 100);
        const r = C.sourceRect(s);
        assert.ok(r.x >= -1e-6 && r.y >= -1e-6, iw + "x" + ih + " @" + zoom + ": crop starts outside the image");
        assert.ok(r.x + r.w <= iw + 1e-6, iw + "x" + ih + " @" + zoom + ": crop runs past the right edge");
        assert.ok(r.y + r.h <= ih + 1e-6, iw + "x" + ih + " @" + zoom + ": crop runs past the bottom edge");
        assert.ok(near(r.w / r.h, C.OUT_W / C.OUT_H, 1e-6), "crop is not 4:5");
      }
    }
  });

  await test("zooming in crops a smaller piece of the original", () => {
    const s = C.initialState(4000, 3000);
    assert.ok(C.sourceRect(C.zoomAbout(s, 2, 450, 562)).w < C.sourceRect(s).w);
  });

  await test("output is 4:5 and never upscaled beyond the source", () => {
    assert.deepStrictEqual(C.outputSize(4000), { w: 900, h: 1125 });
    assert.deepStrictEqual(C.outputSize(900), { w: 900, h: 1125 });
    assert.deepStrictEqual(C.outputSize(400), { w: 400, h: 500 });
  });

  await test("the file keeps its name but takes the encoder's extension", () => {
    assert.strictEqual(C.outputName("Hamza Riaz.HEIC", "image/webp"), "Hamza Riaz.webp");
    assert.strictEqual(C.outputName("shot.png", "image/jpeg"), "shot.jpg");
    assert.strictEqual(C.outputName("", "image/jpeg"), "photo.jpg");
  });

  await test("quality steps down only until the image fits the budget", async () => {
    const tried = [];
    // Fits from q=0.54 down; the walk must stop there and not burn the last step.
    const encode = (type, q) => { tried.push(q); return { type, quality: q, bytes: Math.round(400 * 1024 * q) }; };
    const out = await C.encodeWithin(encode, ["image/webp"], 220 * 1024, C.QUALITIES);
    assert.ok(out.bytes <= 220 * 1024, "picked a result over budget");
    assert.deepStrictEqual(tried, [0.86, 0.78, 0.7, 0.62, 0.54]);
    assert.strictEqual(out.quality, 0.54, "did not stop at the first quality that fits");
  });

  await test("an image that never fits keeps the smallest attempt rather than nothing", async () => {
    const encode = (type, q) => ({ type, quality: q, bytes: 5 * 1024 * 1024 * q });
    const out = await C.encodeWithin(encode, ["image/webp"], 220 * 1024, C.QUALITIES);
    assert.ok(out, "returned nothing");
    assert.strictEqual(out.quality, 0.46, "did not keep the smallest attempt");
  });

  await test("a browser that cannot make WebP falls straight through to JPEG", () => {
    const seen = [];
    const encode = (type, q) => {
      seen.push(type);
      if (type === "image/webp") return null;      // toDataURL handed back a PNG instead
      return { type, quality: q, bytes: 100 * 1024 };
    };
    return C.encodeWithin(encode, C.TYPES, 220 * 1024, C.QUALITIES).then((out) => {
      assert.strictEqual(out.type, "image/jpeg");
      assert.strictEqual(seen.filter((t) => t === "image/webp").length, 1, "kept retrying an unsupported type");
    });
  });

  await test("a source smaller than the frame is still covered, not letterboxed", () => {
    const s = C.initialState(200, 200);           // square, smaller than 900x1125
    const v = C.viewOf(s);
    assert.ok(v.w >= C.OUT_W - 1e-9 && v.h >= C.OUT_H - 1e-9);
    const r = C.sourceRect(s);
    assert.ok(r.x >= -1e-6 && r.x + r.w <= 200 + 1e-6);
    assert.deepStrictEqual(C.outputSize(r.w), { w: 160, h: 200 });
  });

  /* The cropper is only worth anything if every frame that shows the result is the shape
     it cropped to. A stray aspect-ratio override crops the photo a second time and the
     site quietly shows a tighter picture than the one that was framed. */
  await test("every photo frame is 4:5, at every viewport size", () => {
    const fs = require("fs"), path = require("path");
    const root = path.join(__dirname, "..");
    const frames = { "src/css/style.css": ".stage__frame", "admin/admin.css": ".photo__frame" };
    for (const [file, sel] of Object.entries(frames)) {
      const css = fs.readFileSync(path.join(root, file), "utf8");
      const rules = css.split("\n").filter((l) => l.includes(sel) && l.includes("aspect-ratio"));
      assert.ok(rules.length, file + ": no aspect-ratio declared on " + sel);
      for (const line of rules) {
        const ratios = line.match(/aspect-ratio:\s*([^;}]+)/g).map((m) => m.split(":")[1].trim());
        for (const r of ratios) assert.strictEqual(r, "4 / 5", file + ": " + sel + " is " + r + ", not 4 / 5 — " + line.trim().slice(0, 90));
      }
    }
    const stage = fs.readFileSync(path.join(root, "src/css/style.css"), "utf8");
    assert.ok(/\.stage__frame img \{[^}]*object-fit: cover/.test(stage), "the stage must fill its frame, not letterbox");
  });

  console.log("\n" + pass + " passed, " + fail + " failed");
  process.exit(fail ? 1 : 0);
})();
