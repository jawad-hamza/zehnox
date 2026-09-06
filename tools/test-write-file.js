/* Unit tests for writeFileAtomic — run: node tools/test-write-file.js
   Focus: a single-file Docker bind mount cannot be replaced by rename (EBUSY),
   which is what broke PUT /api/content on the deployed site. */
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { writeFileAtomic } = require("../write-file.js");

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zx-writefile-"));
let passed = 0;
function test(name, fn) {
  const target = path.join(dir, "t-" + (passed + 1) + ".json");
  const realRename = fs.renameSync;
  try { fn(target); fs.renameSync = realRename; passed++; console.log("  ok   " + name); }
  catch (e) { fs.renameSync = realRename; console.error("  FAIL " + name + "\n       " + e.message); process.exitCode = 1; }
}
const stubRename = (code) => { fs.renameSync = () => { throw Object.assign(new Error(code + ": simulated"), { code }); }; };

test("writes contents and leaves no .tmp behind", (target) => {
  writeFileAtomic(target, "hello\n");
  assert.strictEqual(fs.readFileSync(target, "utf8"), "hello\n");
  assert.ok(!fs.existsSync(target + ".tmp"), ".tmp should be cleaned up");
});

test("overwrites an existing file", (target) => {
  fs.writeFileSync(target, "old");
  writeFileAtomic(target, "new");
  assert.strictEqual(fs.readFileSync(target, "utf8"), "new");
});

for (const code of ["EBUSY", "EXDEV", "EPERM"]) {
  test("falls back to in-place write when rename throws " + code, (target) => {
    fs.writeFileSync(target, "old");                 // the bind-mounted file already exists
    stubRename(code);
    writeFileAtomic(target, "new content\n");
    assert.strictEqual(fs.readFileSync(target, "utf8"), "new content\n");
    assert.ok(!fs.existsSync(target + ".tmp"), ".tmp should be cleaned up after fallback");
  });
}

test("preserves the target's inode on the fallback path (bind mount must not be replaced)", (target) => {
  fs.writeFileSync(target, "old");
  const before = fs.statSync(target).ino;
  stubRename("EBUSY");
  writeFileAtomic(target, "new");
  assert.strictEqual(fs.statSync(target).ino, before, "in-place write must keep the same inode");
});

test("rethrows unexpected rename errors instead of masking them", (target) => {
  stubRename("EACCES");
  assert.throws(() => writeFileAtomic(target, "x"), (e) => e.code === "EACCES");
});

test("applies mode when creating a new file", (target) => {
  writeFileAtomic(target, "secret", { mode: 0o600 });
  assert.strictEqual(fs.readFileSync(target, "utf8"), "secret");
});

fs.rmSync(dir, { recursive: true, force: true });
console.log(passed + " passed");
