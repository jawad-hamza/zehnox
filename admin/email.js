/* ZEHNOX Admin — the Email panel.

   Talks to /api/mail/* (lib/mail/routes.js). It deliberately keeps its own state and never
   touches the content document: mail settings are not part of content.json, so nothing here
   may mark the page dirty or write a localStorage draft.

   Every mutation carries the rev it was based on and a fresh Idempotency-Key. If the rev is
   stale the server answers conflict_rev, and we reload the list and ask the admin to retry
   rather than guessing which change should win. */
(function () {
  "use strict";

  const A = window.ZXAdmin;                 // bridge exposed by admin.js
  if (!A) return;
  const { api, toast, esc, attr, $, $$ } = A;

  const DOMAIN = "zehnox.com";
  const TYPES = [
    ["forward", "Forwarding only", "Mail arrives and is passed straight on to other inboxes. Nothing is stored here."],
    ["mailbox", "Mailbox only", "Mail is stored here and read with a mail app or webmail. Nothing is forwarded."],
    ["mailbox+forward", "Mailbox and forwarding", "Mail is stored here and a copy is passed on."],
  ];

  let state = { rev: 0, addresses: [], status: null, smtp: null, health: null, loaded: false, busy: false };
  let adding = false;

  const uuid = () => (crypto.randomUUID ? crypto.randomUUID()
    : "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0; return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
      }));

  /* Mutations need the key header; reads do not. */
  const mutate = (method, path, body) => api(method, path, body, { "Idempotency-Key": uuid() });

  const el = () => $('[data-panel="email"]');
  const box = (name) => $('[data-mail="' + name + '"]', el());

  /* ---------- loading ---------- */

  async function load(force) {
    if (state.loaded && !force) return;
    const root = el();
    if (!root) return;
    box("rows").innerHTML = '<p class="hint">Loading…</p>';
    try {
      const [status, list, smtp] = await Promise.all([
        api("GET", "/api/mail/status"),
        api("GET", "/api/mail/addresses"),
        api("GET", "/api/mail/smtp"),
      ]);
      state.status = status;
      state.rev = typeof list.rev === "number" ? list.rev : status.rev;
      state.addresses = Array.isArray(list.addresses) ? list.addresses : [];
      state.smtp = smtp;
      state.loaded = true;
      paintStatus();
      paintRows();
      paintSmtp();
      loadHealth();
    } catch (e) {
      if (e.auth) return;
      state.loaded = false;
      paintOffline(e);
    }
  }

  async function loadHealth() {
    try {
      state.health = await api("GET", "/api/mail/health");
      paintHealth();
    } catch (e) { if (!e.auth) paintHealth(e); }
  }

  /* The panel is useful even when the mail service is not connected: it explains what is
     missing instead of showing an empty list that looks like "no addresses". */
  function paintOffline(e) {
    const why = (e && e.data && e.data.code) || "";
    const human = {
      not_connected: "The mail service is not connected to this site yet.",
      unavailable: "The mail service is not answering.",
      domain_mismatch: "The mail service is configured for a different domain.",
      not_ready: "The mail service is repairing its files. Try again shortly.",
    }[why] || (e && e.message) || "The mail service could not be reached.";
    box("status").innerHTML = '<div class="mail-note"><strong>Email management is not available yet.</strong>' +
      '<p class="hint">' + esc(human) + '</p></div>';
    box("rows").innerHTML = "";
    box("smtp").innerHTML = "";
    box("health").innerHTML = "";
  }

  /* ---------- status and DNS health ---------- */

  const WORD = { online: "Online", degraded: "Degraded", offline: "Offline", not_connected: "Not connected" };

  function paintStatus() {
    const s = state.status || {};
    const svc = (s.service && s.service.state) || "not_connected";
    const good = svc === "online";
    box("status").innerHTML =
      '<div class="mail-tiles">' +
        tile("Service", WORD[svc] || svc, good ? "ok" : svc === "degraded" ? "warn" : "bad",
          s.mock ? "Practice mode — no real mail is touched" : "Live mail server") +
        tile("Addresses", String(state.addresses.length), "", "of " + ((s.capabilities && s.capabilities.maxAddresses) || 200) + " allowed") +
        tile("Mailboxes", String(state.addresses.filter((a) => a.mailbox).length), "",
          (s.capabilities && s.capabilities.mailboxes) ? "Mailboxes are enabled" : "Mailboxes are not enabled yet") +
      "</div>";
  }

  const tile = (label, value, kind, sub) =>
    '<div class="mail-tile' + (kind ? " is-" + kind : "") + '">' +
      '<span class="mono mail-tile__l">' + esc(label) + "</span>" +
      '<strong class="mail-tile__v">' + esc(value) + "</strong>" +
      (sub ? '<span class="mail-tile__s">' + esc(sub) + "</span>" : "") +
    "</div>";

  function paintHealth(err) {
    const h = state.health;
    if (err || !h) { box("health").innerHTML = '<p class="hint">DNS checks are unavailable right now.</p>'; return; }
    const kind = (st) => (st === "pass" ? "ok" : st === "warn" ? "warn" : "bad");
    const word = (st) => (st === "pass" ? "OK" : st === "warn" ? "Check" : "Problem");
    box("health").innerHTML =
      '<div class="panel__head panel__head--sub"><h3>Domain records</h3>' +
        '<p>What the internet must know about ' + esc(DOMAIN) + ' for mail to arrive and be trusted. ' +
        'These are read from public DNS; changing them is done at your DNS provider, not here.</p></div>' +
      '<div class="mail-tiles">' + (h.checks || []).map((c) =>
        tile(c.label, word(c.status), kind(c.status), c.note || (c.observed && c.observed[0]) || "")).join("") + "</div>" +
      '<p class="hint">Last checked ' + esc(when(h.checkedAt)) + '. <button class="btn btn--text btn--sm" type="button" data-mail-act="refresh-health">Check again</button></p>';
  }

  /* ---------- the address list ---------- */

  function paintRows() {
    const rows = state.addresses.slice().sort((a, b) => a.local.localeCompare(b.local));
    box("rows").innerHTML = rows.length
      ? '<table class="tbl mail-tbl"><thead><tr><th>Address</th><th>What it does</th><th>Status</th><th class="act">Actions</th></tr></thead><tbody>' +
          rows.map((a) => row(a) + editor(a)).join("") + "</tbody></table>"
      : '<div class="empty">No addresses yet.</div>';
  }

  /* Editing happens in a row under the address rather than in a browser prompt: the admin
     can see what they are changing, and a mistyped confirmation never costs a mailbox. */
  function editor(a) {
    if (!open.local || open.local !== a.local) return "";
    const body =
      open.kind === "forwards" ? (
        '<label class="field field--wide"><span>Forward ' + esc(a.address) + " to</span>" +
          '<textarea rows="2" data-edit="value" placeholder="owner@example.com, second@example.com">' + esc(a.forwards.join(", ")) + "</textarea>" +
          "<small>Separate several with commas. Leave empty to stop forwarding" +
          (a.mailbox ? " — mail will still arrive in the mailbox." : ", which leaves this address with nowhere to deliver.") + "</small></label>"
      ) : open.kind === "password" ? (
        '<label class="field field--wide"><span>' + (a.mailbox ? "New password for " : "Mailbox password for ") + esc(a.address) + "</span>" +
          '<input type="password" data-edit="value" autocomplete="new-password">' +
          "<small>At least 12 characters. It cannot be read back afterwards, so pass it on straight away.</small></label>"
      ) : (
        '<p class="mail-warn">' + (a.mailbox
          ? "This mailbox and every message stored in it will be removed."
          : "Mail sent here will bounce instead of being forwarded.") + "</p>" +
        '<label class="field field--wide"><span>Type <code>' + esc(a.address) + "</code> to confirm</span>" +
          '<input type="text" data-edit="value" autocomplete="off" spellcheck="false"></label>'
      );
    const label = open.kind === "forwards" ? "Save forwarding" : open.kind === "password" ? (a.mailbox ? "Change password" : "Create mailbox") : "Delete for good";
    const cls = open.kind === "delete" ? "btn--danger" : "btn--lime";
    return '<tr class="mail-editor"><td colspan="4"><div class="item__fields">' + body + "</div>" +
      '<div class="mail-actions">' +
        '<button class="btn btn--sm ' + cls + '" type="button" data-mail-act="commit" data-local="' + attr(a.local) + '">' + label + "</button>" +
        '<button class="btn btn--ghost btn--sm" type="button" data-mail-act="cancel-edit">Cancel</button>' +
      "</div></td></tr>";
  }

  function row(a) {
    const type = a.mailbox && a.forwards.length ? "Mailbox and forwarding" : a.mailbox ? "Mailbox" : "Forwarding";
    const dest = a.forwards.length
      ? '<span class="mail-dest">→ ' + a.forwards.map((f) => esc(f)).join(", ") + "</span>"
      : (a.mailbox ? '<span class="hint">Stored in its own mailbox</span>' : '<span class="hint">Nowhere</span>');
    return '<tr' + (a.enabled ? "" : ' class="is-off"') + ' data-local="' + attr(a.local) + '">' +
      '<td><strong>' + esc(a.address) + "</strong>" +
        (a.protected ? ' <span class="badge">Required</span>' : "") + "</td>" +
      "<td>" + esc(type) + "<br>" + dest + "</td>" +
      "<td>" + (a.enabled ? '<span class="mail-dot is-ok"></span>Active' : '<span class="mail-dot is-off"></span>Paused') + "</td>" +
      '<td class="act">' + actions(a) + "</td></tr>";
  }

  function actions(a) {
    const b = (act, label, cls) => '<button class="btn btn--sm ' + (cls || "btn--outline") + '" type="button" data-mail-act="' + act + '" data-local="' + attr(a.local) + '">' + label + "</button>";
    let out = b("edit", "Forwarding");
    /* postmaster@ and abuse@ must always deliver somewhere and may never become mailboxes
       (that would add a sign-in nobody asked for), so they only offer re-pointing. */
    if (a.mailbox) out += b("password", "New password");
    else if (!a.protected) out += b("add-mailbox", "Add mailbox");
    if (!a.protected) {
      out += b(a.enabled ? "disable" : "enable", a.enabled ? "Pause" : "Resume");
      out += b("delete", "Delete", "btn--danger");
    }
    return out;
  }

  /* ---------- website sending ---------- */

  function paintSmtp() {
    const s = state.smtp || {};
    const ready = s.ready;
    box("smtp").innerHTML =
      '<div class="panel__head panel__head--sub"><h3>How the website sends email</h3>' +
        '<p>Used for the enquiry emails the contact form sends. ' +
        (ready ? "Configured and ready." : "Not configured yet — enquiries are still saved in Inquiries either way.") + "</p></div>" +
      (s.locked ? '<p class="hint">These settings are managed on the server and cannot be changed here.</p>' : "") +
      '<div class="grid">' +
        f("Mail server", "host", s.host || "", "mail." + DOMAIN, s.locked) +
        security(s) +
        f("Port", "port", String(s.port || 587), "587", s.locked) +
        f("Sign-in name", "username", s.username || "", "info@" + DOMAIN, s.locked) +
        f("Password", "password", "", s.passwordSet ? "Saved — type to replace it" : "Not set", s.locked, "password") +
        f("Sender name", "fromName", s.fromName || "", "ZEHNOX", s.locked) +
        /* Only the part before @ is editable: the domain is fixed to zehnox.com. */
        '<label class="field"><span>Sends as</span><span class="mail-local">' +
          '<input type="text" data-smtp="fromLocal" value="' + attr(s.fromLocal || "") + '" placeholder="info"' + (s.locked ? " disabled" : "") + ">" +
          "<em>@" + esc(DOMAIN) + "</em></span></label>" +
      "</div>" +
      '<div class="mail-actions">' +
        (s.locked ? "" : '<button class="btn btn--lime btn--sm" type="button" data-mail-act="save-smtp">Save sending settings</button>') +
        '<label class="field mail-test"><span class="sr-only">Send a test email to</span>' +
          '<input type="email" data-smtp="testTo" placeholder="you@example.com" value="' + attr(s.fromAddress || "") + '"' + (ready ? "" : " disabled") + "></label>" +
        '<button class="btn btn--outline btn--sm" type="button" data-mail-act="test-smtp"' + (ready ? "" : " disabled") + '>Send a test email</button>' +
        '<span class="hint">' + (s.passwordUpdatedAt ? "Password last changed " + esc(when(s.passwordUpdatedAt)) : "") + "</span>" +
      "</div>";
  }

  const security = (s) =>
    '<label class="field"><span>Security</span><select data-smtp="tlsMode"' + (s.locked ? " disabled" : "") + ">" +
      '<option value="starttls"' + (s.tlsMode === "implicit" ? "" : " selected") + ">STARTTLS (port 587)</option>" +
      '<option value="implicit"' + (s.tlsMode === "implicit" ? " selected" : "") + ">TLS (port 465)</option>" +
    "</select></label>";

  const f = (label, name, value, placeholder, locked, type) =>
    '<label class="field"><span>' + esc(label) + "</span>" +
      '<input type="' + (type || "text") + '" data-smtp="' + attr(name) + '" value="' + attr(value) + '"' +
      ' placeholder="' + attr(placeholder || "") + '"' + (locked ? " disabled" : "") +
      (type === "password" ? ' autocomplete="new-password"' : "") + "></label>";

  /* ---------- the add form ---------- */

  function paintAdd() {
    const host = box("add");
    if (!adding) { host.innerHTML = ""; return; }
    host.innerHTML =
      '<article class="item">' +
        '<div class="item__bar"><span class="item__title">New email address</span></div>' +
        '<div class="item__body"><div class="item__fields">' +
          '<label class="field"><span>Address</span>' +
            '<span class="mail-local"><input type="text" data-new="local" placeholder="sales" autocomplete="off" spellcheck="false">' +
            '<em>@' + esc(DOMAIN) + "</em></span>" +
            "<small>Lowercase letters, digits, dot, dash or underscore.</small></label>" +
          '<label class="field"><span>What it does</span><select data-new="type">' +
            TYPES.map(([v, l]) => '<option value="' + attr(v) + '">' + esc(l) + "</option>").join("") +
          "</select><small data-new-help>" + esc(TYPES[0][2]) + "</small></label>" +
          '<label class="field field--wide" data-new-row="forwards"><span>Forward to</span>' +
            '<textarea rows="2" data-new="forwards" placeholder="owner@example.com, second@example.com"></textarea>' +
            "<small>One or more inboxes, separated by commas. At most 10.</small></label>" +
          '<label class="field field--wide" data-new-row="password" hidden><span>Mailbox password</span>' +
            '<input type="password" data-new="password" autocomplete="new-password">' +
            "<small>At least 12 characters. Not the company name, not the address itself.</small></label>" +
        "</div></div>" +
        '<div class="mail-actions">' +
          '<button class="btn btn--lime btn--sm" type="button" data-mail-act="create">Create address</button>' +
          '<button class="btn btn--ghost btn--sm" type="button" data-mail-act="cancel-add">Cancel</button>' +
        "</div>" +
      "</article>";
    syncAddForm();
  }

  function syncAddForm() {
    const host = box("add");
    const type = ($('[data-new="type"]', host) || {}).value || "forward";
    const help = $("[data-new-help]", host);
    const t = TYPES.find((x) => x[0] === type);
    if (help && t) help.textContent = t[2];
    const fwd = $('[data-new-row="forwards"]', host), pw = $('[data-new-row="password"]', host);
    if (fwd) fwd.hidden = type === "mailbox";
    if (pw) pw.hidden = type === "forward";
  }

  /* ---------- actions ---------- */

  const splitList = (s) => String(s || "").split(/[,\n]/).map((x) => x.trim()).filter(Boolean);

  async function guard(fn) {
    if (state.busy) return;
    state.busy = true;
    try { await fn(); }
    catch (e) {
      if (e.auth) return;
      const code = e.data && e.data.code;
      if (code === "conflict_rev") { await load(true); toast("Someone else changed the mail settings. The list has been reloaded — try again.", "error"); }
      else if (code === "not_found" && e.about === "smtp") toast("The address in “Sends as” does not exist yet. Create it above first, then save these settings.", "error", 7000);
      else toast(e.message || "That did not work.", "error");
    }
    finally { state.busy = false; }
  }

  async function create() {
    const host = box("add");
    const v = (n) => (($('[data-new="' + n + '"]', host) || {}).value || "").trim();
    const type = v("type") || "forward";
    const body = { rev: state.rev, local: v("local").toLowerCase(), type };
    if (type !== "mailbox") body.forwards = splitList(v("forwards"));
    if (type !== "forward") body.password = v("password");
    await guard(async () => {
      const res = await mutate("POST", "/api/mail/addresses", body);
      adding = false;
      paintAdd();
      await load(true);
      toast(res.address.address + " created.", "ok");
    });
  }

  /* One editor open at a time, so there is never a half-finished change hidden off screen. */
  let open = { local: "", kind: "" };

  function openEditor(local, kind) {
    open = { local: local, kind: kind };
    paintRows();
    const i = $('[data-edit="value"]', box("rows"));
    if (i) { i.focus(); if (i.select) i.select(); }
  }

  async function commit(local) {
    const a = state.addresses.find((x) => x.local === local);
    const input = $('[data-edit="value"]', box("rows"));
    if (!a || !input) return;
    const value = input.value;
    const kind = open.kind;
    await guard(async () => {
      if (kind === "forwards") {
        await mutate("PATCH", "/api/mail/addresses/" + encodeURIComponent(local), { rev: state.rev, forwards: splitList(value) });
        toast("Forwarding updated.", "ok");
      } else if (kind === "password") {
        const path = "/api/mail/addresses/" + encodeURIComponent(local) + (a.mailbox ? "/password" : "/mailbox");
        await mutate("POST", path, { rev: state.rev, password: value });
        toast(a.mailbox ? "Password changed." : "Mailbox created. Pass the password on now — it cannot be read back.", "ok", 7000);
      } else {
        await mutate("DELETE", "/api/mail/addresses/" + encodeURIComponent(local), { rev: state.rev, confirm: value.trim() });
        toast(a.address + " deleted.", "ok");
      }
      open = { local: "", kind: "" };
      await load(true);
    });
  }

  async function setEnabled(local, enabled) {
    await guard(async () => {
      await mutate("PATCH", "/api/mail/addresses/" + encodeURIComponent(local), { rev: state.rev, enabled: enabled });
      await load(true);
      toast(local + "@" + DOMAIN + (enabled ? " resumed." : " paused."), "ok");
    });
  }

  /* The server checks the sender against the real addresses, so a missing one comes back
     as not_found. On its own that reads as "no such address" with no hint which. */
  async function saveSmtp() {
    const host = box("smtp");
    const v = (n) => (($('[data-smtp="' + n + '"]', host) || {}).value || "").trim();
    const body = {
      host: v("host"), port: parseInt(v("port"), 10) || 587, tlsMode: v("tlsMode") || "starttls",
      username: v("username"), fromLocal: v("fromLocal"), fromName: v("fromName"),
    };
    const pw = ($('[data-smtp="password"]', host) || {}).value || "";
    if (pw) body.password = pw;
    await guard(async () => {
      const res = await mutate("PUT", "/api/mail/smtp", body).catch((err) => { err.about = "smtp"; throw err; });
      state.smtp = await api("GET", "/api/mail/smtp");
      paintSmtp();
      const warn = (res && res.warnings) || [];
      toast(warn.length ? "Saved. " + warn.join(" ") : "Sending settings saved.", warn.length ? "error" : "ok", warn.length ? 7000 : undefined);
    });
  }

  /* The test send takes its recipient from a field in the panel rather than a browser
     prompt: the server only accepts a short allowlist of addresses, so the admin needs to
     see and correct what they typed. */
  async function testSmtp() {
    const host = box('smtp');
    const input = $('[data-smtp="testTo"]', host);
    const to = ((input && input.value) || "").trim();
    if (!to) { if (input) input.focus(); return void toast("Type the address to send the test to.", "error"); }
    await guard(async () => {
      const res = await mutate("POST", "/api/mail/smtp/test", { to: to });
      toast(res.delivered === false ? "The server accepted it but did not confirm delivery." : "Test email sent to " + to + ".", "ok");
    });
  }

  /* ---------- events ---------- */

  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-mail-act]");
    if (!btn) return;
    const act = btn.dataset.mailAct, local = btn.dataset.local;
    if (act === "add") { adding = true; paintAdd(); const i = $('[data-new="local"]', box("add")); if (i) i.focus(); return; }
    if (act === "cancel-add") { adding = false; paintAdd(); return; }
    if (act === "create") return void create();
    if (act === "edit") return void openEditor(local, "forwards");
    if (act === "add-mailbox" || act === "password") return void openEditor(local, "password");
    if (act === "cancel-edit") { open = { local: "", kind: "" }; return void paintRows(); }
    if (act === "commit") return void commit(local);
    if (act === "disable") return void setEnabled(local, false);
    if (act === "enable") return void setEnabled(local, true);
    if (act === "delete") return void openEditor(local, "delete");
    if (act === "save-smtp") return void saveSmtp();
    if (act === "test-smtp") return void testSmtp();
    if (act === "refresh-health") {
      btn.disabled = true;
      api("POST", "/api/mail/health/refresh", {}, { "Idempotency-Key": uuid() })
        .then(() => loadHealth())
        .catch((err) => { if (!err.auth) toast(err.message, "error"); })
        .finally(() => { btn.disabled = false; });
    }
  });

  document.addEventListener("change", (e) => {
    if (e.target.matches('[data-new="type"]')) syncAddForm();
  });

  function when(iso) {
    if (!iso) return "never";
    const d = new Date(iso);
    return isNaN(d) ? String(iso) : d.toLocaleString();
  }

  window.ZXMail = { show: () => load(false), reload: () => load(true) };
})();
