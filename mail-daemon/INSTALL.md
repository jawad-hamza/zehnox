# zehnox-maild: install, verify, operate, uninstall

The privileged mail-management service for zehnox.com. The design is
`docs/mail/DESIGN.md` (sections 5, 13 and 16); this file is the owner's runbook for the
daemon itself. Everything here is done **by the owner, by hand, with sudo**, on the VPS.
Nothing in the deploy pipeline installs, upgrades or restarts the daemon.

Files in this directory:

| File | Goes to |
|---|---|
| `zehnox-maild.js` | `/usr/local/lib/zehnox-mail/zehnox-maild.js` (root:root 0644) |
| `../lib/mail/core/*.js` | `/usr/local/lib/zehnox-mail/core/` (root:root 0644) |
| `config.example.json` | template for `/etc/zehnox-mail/config.json` (root:zehnox-mail 0640) |
| `systemd/zehnox-maild.socket`, `.service` | `/etc/systemd/system/` (root 0644) |
| `dovecot/auth-zehnox-2.{3,4}.conf.ext` | Phase B only, see the file header |
| `postfix/README-snippets.md` | the Postfix commands for Phases A and B |
| `INSTALL.md` | optional copy to `/usr/local/lib/zehnox-mail/INSTALL.md` (the units link to it) |

## 0. Before you start

Do Phase 0 of section 16 (discovery and backup) first, and check the assumptions in
section 17. You need Node 18 or later on the host (`node -v`) and the host's
`postconf -h default_database_type` (`hash` or `lmdb`).

## 1. Users, groups and directories

```sh
adduser --system --group --no-create-home --home /nonexistent --shell /usr/sbin/nologin zehnox-mail
groupadd --system zehnox-mail-client          # note its gid (getent group zehnox-mail-client)

install -d -o root -g zehnox-mail -m 0750 /etc/zehnox-mail /etc/zehnox-mail/keys
install -d -o zehnox-mail -g zehnox-mail -m 0751 /var/lib/zehnox-mail
install -d -o zehnox-mail -g postfix -m 2750 /var/lib/zehnox-mail/postfix
install -d -o zehnox-mail -g dovecot -m 2750 /var/lib/zehnox-mail/dovecot
install -d -o zehnox-mail -g zehnox-mail-client -m 0750 /var/lib/zehnox-mail/sock
install -d -o root -g root -m 0700 /srv/zehnox/secrets
```

The `postfix` and `dovecot` groups must exist (Postfix and Dovecot installed), even for
Phase A: the self-check requires both setgid directories and reports `group_missing`
otherwise. A host without Dovecot is outside this design; stop and revisit it.

The daemon never creates these directories itself on the VPS (it could not give them the
`postfix` or `dovecot` group). Its self-check (`selfCheck` in the admin panel and in
`--status`) refuses every change until they are exactly as above:

| Code | Meaning |
|---|---|
| `dir_missing` | one of the four directories is missing |
| `dir_mode` | wrong mode (note the setgid `2` on `postfix/` and `dovecot/`) |
| `dir_owner` / `dir_group` | wrong owner, or not the `postfix` / `dovecot` / `zehnox-mail-client` group |
| `group_missing` | that group does not exist on the host |
| `file_mode` / `file_owner` | a state or rendered file is not 0600/0640 or not owned by zehnox-mail |
| `state_missing` | `hashes.json` exists but `state.json` does not: restore both from backup |
| `state_invalid` | `state.json` or `hashes.json` does not parse or fails validation |

## 2. Copy the reviewed code and check the manifest

On the VPS, from a checkout of the **reviewed git tag** (not the live deploy directory):

```sh
install -d -o root -g root -m 0755 /usr/local/lib/zehnox-mail /usr/local/lib/zehnox-mail/core
install -o root -g root -m 0644 mail-daemon/zehnox-maild.js /usr/local/lib/zehnox-mail/
install -o root -g root -m 0644 lib/mail/core/*.js /usr/local/lib/zehnox-mail/core/
node tools/mail-manifest.js --check /usr/local/lib/zehnox-mail     # must say: installed files match
node /usr/local/lib/zehnox-mail/zehnox-maild.js --print-manifest # same lines as node tools/mail-manifest.js
```

The daemon is **never** run from `/srv/zehnox/app`: every deploy runs `git reset --hard`
there.

## 3. Keys

The same 32-byte HMAC key goes to the daemon and to the website container. Generate it on
the host, never in git, never in `.env`:

```sh
umask 077
T=$(mktemp -d)                                  # a private scratch dir, removed below
openssl rand -hex 32 > "$T/k1.tmp"
install -o root -g zehnox-mail -m 0440 "$T/k1.tmp" /etc/zehnox-mail/keys/k1.key
install -o root -g root -m 0400 "$T/k1.tmp" /srv/zehnox/secrets/mail-service.key
shred -u "$T/k1.tmp" && rmdir "$T"
openssl rand -hex 32 > /srv/zehnox/secrets/mail-secrets.key && chmod 0400 /srv/zehnox/secrets/mail-secrets.key
```

The daemon refuses a key file that other users can read, and one that is not exactly 64
hex characters. It never prints a key.

**Rotation**: add `"k2": "/etc/zehnox-mail/keys/k2.key"` to `keys`, restart the daemon,
switch the website to `MAIL_SERVICE_KEY_ID=k2` with the new key file, redeploy, then remove
`k1` from the config and restart again.

## 4. Configuration

```sh
install -o root -g zehnox-mail -m 0640 mail-daemon/config.example.json /etc/zehnox-mail/config.json
editor /etc/zehnox-mail/config.json
sudo -u zehnox-mail node /usr/local/lib/zehnox-mail/zehnox-maild.js --config /etc/zehnox-mail/config.json --check-config
```

Settings the daemon enforces at start (it exits non-zero otherwise):

- `domain` is `zehnox.com`; `stateDir` is `/var/lib/zehnox-mail`;
  `postmapPath` is `/usr/sbin/postmap`; `mailboxes.homeBase` is `/var/vmail/zehnox.com`.
- `mapType` is `hash` or `lmdb` and must equal `postconf -h default_database_type`.
- `bootstrapForward` is an external address: postmaster@ and abuse@ forward there on first start.
- `mailboxes.minRounds` is raised to at least 50000 whatever the file says.
- `mailboxes.enabled: true` has no effect until **both** `gate` flags are true (D10); the
  journal then says `event=mailbox_gate_closed`.
- `dkim.publicFile` holds only the public `p=` value (Phase C), under `/etc/zehnox-mail/`.
  The daemon refuses any path under OpenDKIM and any file that contains "PRIVATE".
- `keys` files live under `/etc/zehnox-mail/keys/`.
- No forward may target `hostname` or a subdomain of it (a forward to `root@<hostname>`
  would be delivered locally through `/etc/aliases`). `forwardDenyDomains` (optional, up to
  20 lowercase host names) adds more such domains, typically the other domains hosted on the
  same MTA, for example `["strategicbhm.com"]`, so a compromised website cannot route
  zehnox.com mail into their mailboxes. Leave a domain out only if zehnox.com
  addresses really must forward there. It cannot list `zehnox.com` or a parent of it.
- Unknown settings are refused.

## 5. Start

```sh
install -o root -g root -m 0644 mail-daemon/systemd/zehnox-maild.socket mail-daemon/systemd/zehnox-maild.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now zehnox-maild.socket
ls -l /var/lib/zehnox-mail/sock/mail.sock      # srw-rw---- zehnox-mail zehnox-mail-client
systemctl start zehnox-maild.service           # optional: first start now instead of on first connection
sudo -u zehnox-mail node /usr/local/lib/zehnox-mail/zehnox-maild.js --config /etc/zehnox-mail/config.json --status
```

On first start (no `state.json`) the daemon creates postmaster@ and abuse@ as protected
forwards to `bootstrapForward`, renders all five files and indexes the four maps. Check in
`--status`: `selfCheck: "ok"`, `mapsInSync: true`, every map `indexFresh: true`, and that
`postfix/virtual` and its `.db` (or `.lmdb`) exist. Postfix is not using these maps yet:
that is Phase A (`postfix/README-snippets.md`).

## 6. Operating it

- **Diagnosis without the website**: `--status` (read-only, works while the service runs)
  and `journalctl -u zehnox-maild`. Journal lines are `event=<name> key=value`; they never
  contain destinations, hashes, keys or request bodies. Useful events: `self_check_failed`,
  `reconcile_mismatch`, `postmap_failed`, `restore_failed`, `auth_failures`, `mutation`.
- **Reconcile**: runs at start and every 60 s. To run one by hand, stop the service first
  (the socket stays up and restarts it on the next request):
  `systemctl stop zehnox-maild.service` then
  `sudo -u zehnox-mail node ... --config ... --reconcile` (add `--dry-run` to only report).
  The one-shot modes take the same lock as the service and refuse while it runs.
- **Adopting hand-made entries** (`--import --postfix-map <virtual source> [--passwd-file <f>] [--dry-run]`):
  reads only `@zehnox.com` keys and counts the others; every entry goes through the
  same rules as the admin panel. Run it with `--dry-run` first. Existing addresses are
  skipped, except that postmaster@ and abuse@ take the imported forwarding.
- **Deleted addresses**: the maildir is never deleted by the daemon. After removing it by
  hand (`rm -r /var/vmail/zehnox.com/<local>/`), forget the tombstone with
  `--purge-tombstone <local>` (service stopped, as for `--reconcile`).
- **Kill switch**: `MAIL_PROVIDER=none` on the website, and/or
  `systemctl stop zehnox-maild.socket zehnox-maild.service`. Mail keeps flowing with
  the last rendered maps.
- **Upgrades**: copy the files from a newer reviewed tag (step 2, including the manifest
  check), then `systemctl restart zehnox-maild`.
- **Backups**: `/var/lib/zehnox-mail` (`state.json` and `hashes.json` rebuild everything
  else), `/etc/zehnox-mail`, and separately `/srv/zehnox/secrets`.

## 7. Uninstall

Undo the Postfix and Dovecot phases first (their rollbacks are in `postfix/README-snippets.md`
and section 16), and switch the website to `MAIL_PROVIDER=none` and remove its socket mount
**before** removing the directories: the deploy rollback reuses `compose.yaml`, and a missing
mounted directory would make Docker create a root-owned placeholder.

```sh
systemctl disable --now zehnox-maild.socket zehnox-maild.service
rm /etc/systemd/system/zehnox-maild.socket /etc/systemd/system/zehnox-maild.service
systemctl daemon-reload
tar czf /root/sbhm/zehnox-mail-final-$(date +%F).tgz /var/lib/zehnox-mail /etc/zehnox-mail
rm -r /usr/local/lib/zehnox-mail /etc/zehnox-mail /var/lib/zehnox-mail
# Maildirs under /var/vmail/zehnox.com/ are left alone: remove them deliberately, if at all.
userdel zehnox-mail; groupdel zehnox-mail-client
```

## 8. Rehearsing without a mail server (sandbox)

For development only, never on the VPS. `--sandbox` accepts any absolute `stateDir`, a
stand-in indexer (`postmapPath` plus `postmapPreArgs`), creates the directory layout
itself and skips the owner and group checks; `--no-postmap` skips indexing entirely.
`--listen <path>` (a Unix socket path, or `\\.\pipe\<name>` on Windows) needs `--sandbox`.

```sh
node mail-daemon/zehnox-maild.js --config /tmp/sbhm-sandbox/config.json --sandbox --no-postmap --listen /tmp/sbhm-sandbox/mail.sock
```

with a config like `config.example.json` but `"stateDir": "/tmp/sbhm-sandbox/state"`,
`"dkim": { "selector": "sbhm1", "publicFile": null }` and a key file generated for the
rehearsal (`openssl rand -hex 32`). The test suite (`tests/maild.test.js`, `tests/daemon.test.js`,
`tests/daemon-hardening.test.js`) runs the daemon this way with `tests/helpers/*fake-postmap.js`
as the indexer.
