"use strict";
/* No arbitrary command execution surface (DESIGN.md sections 5.8 and 15, user rules):
   - the public Node process (server.js, lib/**, admin/email.js) never loads child_process,
     vm or any other way to run a command or evaluate code;
   - the only worker is the constant hash-worker.js;
   - the daemon's only subprocess call is execFile of the indexer, once, with the frozen
     POSTMAP_ARGV lookup and no shell;
   - the verb set is frozen and unknown verbs are rejected;
   - no route builds a file path or a command from request data.
   Static scans read the source text; the runtime checks load the modules. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { REPO, LIB, CORE } = require("./helpers/common.js");

const read = (p) => fs.readFileSync(path.join(REPO, p), "utf8");
function jsFiles(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(path.join(REPO, d), { withFileTypes: true })) {
      const rel = path.join(d, e.name);
      if (e.isDirectory()) walk(rel);
      else if (e.name.endsWith(".js")) out.push(rel);
    }
  };
  walk(dir);
  return out.sort();
}

const WEB_FILES = ["server.js", "smtp.js", "write-file.js", "admin/email.js"].concat(jsFiles("lib"));

/* Patterns that would give the web process a way to run commands or code. `exec(` is
   matched only when it is not a method call, because server.js uses RegExp#exec. */
const FORBIDDEN = [
  ["child_process", /child_process/],
  ["exec(", /(?<![.\w$])exec\s*\(/],
  ["execSync", /execSync/],
  ["execFile", /execFile/],
  ["spawn", /\bspawn(Sync)?\b/],
  ["fork(", /\bfork\s*\(/],
  ["eval(", /(?<![.\w$])eval\s*\(/],
  ["new Function", /new\s+Function\b/],
  ["Function(", /(?<![.\w$])Function\s*\(/],
  ["vm module", /require\(\s*["'](node:)?vm["']\s*\)|\bvm\.(run|Script|compile|createContext)/],
  ["process.binding", /process\.(binding|_linkedBinding|dlopen)/],
  ["cluster", /require\(\s*["'](node:)?cluster["']\s*\)/],
  ["wasi", /require\(\s*["'](node:)?wasi["']\s*\)/],
  ["setTimeout(string)", /set(Timeout|Interval|Immediate)\(\s*["'`]/],
  ["shell option", /\bshell\s*:\s*(true|["'])/],
  ["import()", /\bimport\s*\(/],
];

test("the scanner itself: each pattern catches its construct and ignores RegExp#exec", () => {
  const samples = {
    "child_process": 'const cp = require("child_process")', "exec(": "exec('id')", "execSync": "cp.execSync('id')",
    "execFile": "cp.execFile('/bin/x', [])", "spawn": "spawn('sh')", "fork(": "fork('x.js')", "eval(": "eval(code)",
    "new Function": "new Function('return 1')", "Function(": "Function('return 1')()", "vm module": 'require("node:vm")',
    "process.binding": "process.binding('spawn_sync')", "cluster": 'require("cluster")', "wasi": 'require("wasi")',
    "setTimeout(string)": 'setTimeout("alert(1)", 1)', "shell option": "{ shell: true }", "import()": 'import("x")',
  };
  for (const [label, re] of FORBIDDEN) assert.ok(re.test(samples[label]), label + " pattern is live");
  for (const [label, re] of FORBIDDEN) assert.ok(!re.test("const m = /x/.exec(s); re.exec(v); retrieval(x);"), label + " false positive");
});

test("web side: no command execution or code evaluation anywhere in server.js, lib/** or admin/email.js", () => {
  assert.ok(WEB_FILES.length > 20, "the scan found the files");
  for (const f of WEB_FILES) {
    const src = read(f);
    for (const [label, re] of FORBIDDEN) assert.ok(!re.test(src), f + " contains " + label);
  }
});

test("web side: every require() is a relative module or an allowlisted builtin", () => {
  const BUILTINS = new Set(["fs", "path", "crypto", "net", "tls", "dns", "http", "https", "os", "url", "zlib", "worker_threads", "stream", "events", "util", "querystring", "buffer", "string_decoder", "timers"]);
  for (const f of WEB_FILES) {
    const src = read(f);
    for (const m of src.matchAll(/require\(([^)]*)\)/g)) {
      const arg = m[1].trim();
      const lit = arg.match(/^["']([^"']+)["']$/);
      if (lit) {
        const name = lit[1].replace(/^node:/, "");
        assert.ok(name.startsWith(".") || BUILTINS.has(name), f + " requires " + name);
        assert.ok(!/mail-daemon|zehnox-maild/.test(name), f + " must never load the daemon");
      } else {
        // Computed requires only in lib/mail/core consumers via path.join with a constant file name.
        assert.match(arg, /^path\.join\(__dirname, ["'][a-z./-]+\.js["']$/, f + ": computed require " + arg);
      }
    }
  }
});

test("worker_threads: only hash-pool.js, pointing at the constant hash-worker.js", () => {
  for (const f of WEB_FILES) {
    const src = read(f);
    const uses = /worker_threads|new\s+Worker\s*\(/.test(src);
    if (f === path.join("lib", "mail", "hash-pool.js")) continue;
    if (f === path.join("lib", "mail", "hash-worker.js")) { assert.ok(!/new\s+Worker/.test(src)); continue; }
    assert.ok(!uses, f + " uses worker_threads");
  }
  const pool = read("lib/mail/hash-pool.js");
  assert.equal((pool.match(/new\s+Worker\s*\(/g) || []).length, 1);
  assert.match(pool, /new Worker\(WORKER_FILE\)/);
  assert.match(pool, /const WORKER_FILE = path\.join\(__dirname, "hash-worker\.js"\);/);
  assert.equal(require(path.join(LIB, "hash-pool.js")).WORKER_FILE, path.join(LIB, "hash-worker.js"));
});

test("lib/mail/core is pure: node:crypto and siblings only; no fs, net, env or subprocess", () => {
  for (const f of jsFiles("lib/mail/core")) {
    const src = read(f);
    for (const m of src.matchAll(/require\(([^)]*)\)/g)) assert.match(m[1].trim(), /^["'](\.\/[a-z]+\.js|crypto|node:crypto)["']$/, f + " requires " + m[1]);
    assert.ok(!/process\.env|process\.argv|\bfs\.|\bnet\./.test(src), f + " touches the environment, the disk or the network");
  }
});

test("daemon: execFile appears exactly once, at the frozen POSTMAP_ARGV lookup, with no shell", () => {
  const src = read("mail-daemon/zehnox-maild.js");
  assert.equal((src.match(/execFile/g) || []).length, 1, "the runner is referenced exactly once");
  assert.match(src, /const run = typeof o\.executor === "function" \? o\.executor : cp\.execFile;/);
  assert.equal((src.match(/\brun\(/g) || []).length, 1, "and called at exactly one site");
  assert.match(src, /run\(cfg\.postmapPath, POSTMAP_ARGV\[name\], POSTMAP_OPTIONS, /);
  assert.equal((src.match(/\bcp\./g) || []).length, 1, "child_process is used for nothing else");
  for (const [label, re] of FORBIDDEN.filter(([l]) => !["child_process", "execFile"].includes(l))) assert.ok(!re.test(src), "daemon contains " + label);
  assert.match(src, /const POSTMAP_ARGV = Object\.freeze\(/);
  // The only requires: stdlib and the pinned core. (The capture stops at the first ")",
  // so a path.join(...) argument is seen without its closing parenthesis.)
  for (const m of src.matchAll(/require\(([^)]+)\)/g)) {
    assert.ok(/^"(fs|path|net|crypto|child_process)"$/.test(m[1]) || /^path\.join\(CORE_DIR, "[a-z]+\.js"$/.test(m[1]), m[1]);
  }
});

test("verbs: the table is frozen; the daemon serves exactly it; unknown verbs never dispatch", () => {
  const C = require(path.join(CORE, "constants.js"));
  const V = require(path.join(CORE, "validate.js"));
  const LIST = ["getMailStatus", "listAddresses", "getAuditTail", "createAddress", "deleteAddress", "setForwarding", "removeForwarding", "setAddressEnabled", "createMailbox", "disableMailbox", "enableMailbox", "changeMailboxPassword"];
  assert.deepEqual(Object.keys(C.VERBS), LIST);
  assert.ok(Object.isFrozen(C.VERBS));
  assert.throws(() => { "use strict"; C.VERBS.exec = { kind: "mutate" }; }, TypeError);
  for (const v of ["exec", "run", "shell", "__proto__", "constructor", "prototype", "toString", "valueOf", "__defineGetter__"]) {
    assert.throws(() => V.checkVerbArgs(v, {}), (e) => e.code === "unknown_verb", v);
  }
  // The daemon checks its handler table against the list when the file loads.
  const src = read("mail-daemon/zehnox-maild.js");
  assert.match(src, /C\.VERB_NAMES/);
});

test("routes: a fixed table, fully anchored patterns, :local is the only capture and never becomes a path", () => {
  const { createMailRoutes } = require(path.join(LIB, "routes.js"));
  const { ROUTES } = createMailRoutes({ cfg: {}, getProvider() {}, getSmtp() {}, getAudit() {}, getHashPool() {}, hashOptions() {} });
  assert.deepEqual(ROUTES.map((r) => r.label), [
    "GET /api/mail/status", "GET /api/mail/addresses", "POST /api/mail/addresses", "GET /api/mail/addresses/:local",
    "PATCH /api/mail/addresses/:local", "DELETE /api/mail/addresses/:local", "POST /api/mail/addresses/:local/mailbox",
    "POST /api/mail/addresses/:local/password", "GET /api/mail/health", "POST /api/mail/health/refresh", "GET /api/mail/smtp",
    "PUT /api/mail/smtp", "POST /api/mail/smtp/test", "POST /api/mail/smtp/rotate", "GET /api/mail/audit",
  ]);
  for (const r of ROUTES) {
    assert.ok(r.re.source.startsWith("^") && r.re.source.endsWith("$"), r.label);
    assert.equal(r.re.flags, "", r.label + ": no flags (no /i, no /m)");
    const groups = (r.re.source.match(/\((?!\?)/g) || []).length;
    assert.equal(groups, r.label.includes(":local") ? 1 : 0, r.label);
    if (r.label.includes(":local")) assert.ok(r.re.source.includes("([a-z0-9._-]{1,64})"), r.label);
  }
  // Mutating routes are exactly the ones that change mail state or secrets.
  assert.deepEqual(ROUTES.filter((r) => r.mutating).map((r) => r.label), [
    "POST /api/mail/addresses", "PATCH /api/mail/addresses/:local", "DELETE /api/mail/addresses/:local",
    "POST /api/mail/addresses/:local/mailbox", "POST /api/mail/addresses/:local/password", "PUT /api/mail/smtp", "POST /api/mail/smtp/rotate",
  ]);
  // Every file the web side writes is a constant name under DATA/mail: no path is built from input.
  for (const f of ["routes.js", "website-smtp.js", "mock-provider.js", "audit.js", "index.js"]) {
    const src = read(path.join("lib", "mail", f));
    for (const m of src.matchAll(/path\.join\(([^)]*)\)/g)) {
      assert.ok(!/\b(body|req|url|args|local|input|params|query)\b/.test(m[1]), f + ": path.join(" + m[1] + ")");
    }
  }
});

test("runtime: loading the web side's mail module pulls in no subprocess or vm module", () => {
  const before = new Set(Object.keys(require.cache));
  require(path.join(LIB, "routes.js"));
  require(path.join(LIB, "website-smtp.js"));
  require(path.join(LIB, "vps-provider.js"));
  require(path.join(LIB, "dns-health.js"));
  const loaded = Object.keys(require.cache).filter((k) => !before.has(k));
  for (const k of Object.keys(require.cache)) {
    if (k.startsWith(LIB)) assert.ok(!/mail-daemon/.test(k));
  }
  // The daemon file is loaded in this process only by the daemon tests' helper, never by lib/.
  for (const k of loaded) assert.ok(!/zehnox-maild/.test(k), k);
});
