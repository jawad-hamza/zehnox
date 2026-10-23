"use strict";
/* Repository hygiene for the mail module (DESIGN.md section 15, user rule: secrets never
   in git). Scans the mail code, the daemon and its install files, the admin panel, the
   docs, the deploy files and this test suite for anything that looks like committed key
   material: private key blocks, 64-hex keys, full crypt hashes, and secret variables
   assigned a value. Test fixtures are generated at run time, so none of this may appear
   in the source text. The published SHA-512 crypt vectors in tests/crypt.test.js are the
   one allowed exception (they are public test data, split so no full hash is written). */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { REPO } = require("./helpers/common.js");

function walk(rel, filter) {
  const out = [];
  const abs = path.join(REPO, rel);
  if (!fs.existsSync(abs)) return out;
  if (fs.statSync(abs).isFile()) return [rel];
  for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
    const r = path.join(rel, e.name);
    if (e.isDirectory()) out.push(...walk(r, filter));
    else if (!filter || filter(e.name)) out.push(r);
  }
  return out;
}

const TEXT = (n) => /\.(js|json|md|ext|socket|service|ya?ml|example|txt|html|css)$/.test(n) || /^(Dockerfile|\.env\.example|\.dockerignore|\.gitignore)$/.test(n);
const FILES = [].concat(
  walk("lib/mail", TEXT), walk("mail-daemon", TEXT), walk("tests/mail", TEXT), walk("test", TEXT), walk("docs", TEXT), walk("tools", TEXT),
  ["admin/email.js", "admin/email.css", "server.js", "smtp.js", "lib/portal-intake.js", ".env.example", "compose.yaml", "Dockerfile", "README.md", ".github/workflows/deploy.yml"].filter((f) => fs.existsSync(path.join(REPO, f))),
);

const RULES = [
  ["private key block", /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ["64-hex key", /(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])/],
  ["full SHA-512 crypt hash", /\$6\$(rounds=\d+\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}/],
  ["argon2 hash", /\$argon2id\$v=19\$m=\d+,t=\d+,p=\d\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}/],
  /* A value that is a bare ALL_CAPS identifier names something built at run time (see
     FAKE_PASS in tools/test-*.js); a literal secret still trips the rule. */
  ["secret env assignment", /^[ \t]*(export[ \t]+)?(MAIL_SERVICE_KEY|MAIL_SECRETS_KEY|MAIL_SECRET_KEY|SMTP_PASS|PORTAL_INTAKE_SECRET)[ \t]*[=:][ \t]*(?![A-Z][A-Z0-9_]*[\s,;)]*$)["']?[^\s"'#$<{][^\s"']*/m],
  ["AWS-style key", /AKIA[0-9A-Z]{16}/],
];

test("no committed key material, hashes or secret values in the mail-related files", () => {
  assert.ok(FILES.length > 40, "the scan found the files (" + FILES.length + ")");
  const hits = [];
  for (const f of FILES) {
    const text = fs.readFileSync(path.join(REPO, f), "utf8");
    for (const [label, re] of RULES) {
      const m = text.match(re);
      if (m) hits.push(f + ": " + label + " (" + m[0].slice(0, 16) + "...)");
    }
  }
  assert.deepEqual(hits, []);
});

test("the scanner itself: each rule catches a sample", () => {
  const samples = [
    "-----BEGIN " + "PRIVATE KEY-----", "a".repeat(32) + "b".repeat(32), "$" + "6$rounds=5000$saltsalt$" + "x".repeat(86),
    "$argon2id$v=19$m=65536,t=3,p=1$" + "A".repeat(22) + "$" + "B".repeat(43), "SMTP_PASS=" + "hunter2", "AKIA" + "ABCDEFGHIJKLMNOP",
  ];
  RULES.forEach(([label, re], i) => assert.ok(re.test(samples[i]), label));
  // Empty placeholders are fine.
  assert.ok(!RULES[4][1].test("SMTP_PASS=\nMAIL_SERVICE_KEY=\n"));
  // A reference to a value generated at run time is not a committed secret; a literal is.
  assert.ok(!RULES[4][1].test("      SMTP_PASS: FAKE_PASS,"));
  assert.ok(RULES[4][1].test('      SMTP_PASS: "hunter2",'));
});

test("git ignores the places secrets and runtime data live", () => {
  const gi = fs.readFileSync(path.join(REPO, ".gitignore"), "utf8").split(/\r?\n/);
  // *.key and *.pem without a slash match at any depth, so a key dropped in lib/mail/ or
  // mail-daemon/keys/ during local testing can never be committed.
  for (const needed of ["/data/", "/secrets/", "secrets/", ".env", "*.key", "*.pem"]) assert.ok(gi.includes(needed), needed);
});

test("the image never gets the tests, the daemon, the docs or key material", () => {
  const di = fs.readFileSync(path.join(REPO, ".dockerignore"), "utf8").split(/\r?\n/).map((l) => l.trim());
  // tests/ holds process-starting helpers and fake servers; the web image follows the
  // no-exec rule. In .dockerignore a bare *.key only matches at the context root, so the
  // **/ forms are required for key material anywhere else.
  for (const needed of ["test", "tests/mail", "docs", "mail-daemon", "tools/mail-manifest.js", "secrets", "**/secrets", "*.key", "**/*.key", "*.pem", "**/*.pem", ".env", ".env.*", "data"]) {
    assert.ok(di.includes(needed), ".dockerignore lacks " + needed);
  }
});

test("CI runs the whole tests/ suite, and there is no second suite it would skip", () => {
  const wf = fs.readFileSync(path.join(REPO, ".github/workflows/deploy.yml"), "utf8");
  assert.ok(wf.includes('node --test "tests/**/*.test.js"'), "deploy.yml runs tests/");
  assert.ok(!/node --test "test\//.test(wf), "deploy.yml no longer runs only test/");
  assert.match(wf, /deploy:\s*\n\s*needs: test\b/, "the deploy job waits for the tests");
  // A test/ directory next to tests/ would be a suite that CI does not run (the CI step
  // also refuses it).
  assert.equal(fs.existsSync(path.join(REPO, "test")), false, "test/ must be merged into tests/");
  const readme = fs.readFileSync(path.join(REPO, "README.md"), "utf8");
  assert.ok(!readme.includes('node --test "test/**'), "README points at the right suite");
  // The guards this suite exists for must be in it.
  /* api.test.js is deliberately not ported: it sandboxes the server by running it from a
     temporary working directory, and this server resolves its paths from its own location,
     so it would read the real data instead. routes.test.js covers the same handlers. */
  for (const f of ["repo-hygiene.test.js", "no-exec-surface.test.js", "routes.test.js", "maild.test.js", "daemon.test.js"]) {
    assert.ok(fs.existsSync(path.join(REPO, "tests/mail", f)), f);
  }
});

test("CI actions are pinned to commit SHAs (the deploy action receives the SSH key)", () => {
  const wf = fs.readFileSync(path.join(REPO, ".github/workflows/deploy.yml"), "utf8");
  const uses = Array.from(wf.matchAll(/^\s*uses:\s*(\S+)/gm)).map((m) => m[1]);
  assert.ok(uses.length >= 3, "found the uses: lines");
  for (const u of uses) assert.match(u, /^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/, u);
});

test("the deploy log tail masks IP and email addresses before printing them", () => {
  const wf = fs.readFileSync(path.join(REPO, ".github/workflows/deploy.yml"), "utf8");
  const calls = wf.split(/\r?\n/).filter((l) => /docker logs\b/.test(l));
  assert.ok(calls.length >= 1);
  for (const l of calls) assert.match(l, /\|\s*sed -E/, "every docker logs call is piped through the masking sed: " + l.trim());
  assert.ok(wf.includes("<ip>") && wf.includes("<ip6>") && wf.includes("<email>"));
});
