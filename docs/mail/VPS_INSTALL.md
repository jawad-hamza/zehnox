# Installing the mail module on the VPS

Everything in this file needs `sudo` on `srv1957725` and touches live mail for two domains.
None of it has been run. `mail-daemon/INSTALL.md` is the generic daemon install; this file
is the zehnox-specific plan, written against the server as it actually is.

## What is already there (observed 2026-10-23, read-only)

| | |
|---|---|
| `myhostname` | `mail.zehnox.com` |
| zehnox.com | `virtual_alias_domains` — **forwarding only, no mailboxes** |
| zehnox.com aliases | `/etc/postfix/virtual`, 89 bytes, two entries (`info@`, `bot@` → one Gmail address) |
| strategicbhm.com | `virtual_mailbox_domains`, mailboxes managed by `strategic-maild` |
| Website sending | port 587, Cyrus SASL (`/etc/sasldb2`) |
| strategicbhm mailboxes | port 465 + IMAPS 993, Dovecot **2.4.2** |
| Ports listening | 25, 465, 587, 993 |
| DNS | MX → mail.zehnox.com; SPF `v=spf1 ip4:187.53.134.192 ~all`; DMARC `p=none`; DKIM selector `mail` present; reverse DNS → mail.zehnox.com |
| IP agreement | A record, SPF and reverse DNS all point at 187.53.134.192 ✓ |

Two consequences worth stating plainly:

- **The import is tiny.** Only two addresses exist. Nothing large is being migrated.
- **Dovecot is 2.4**, so use `mail-daemon/dovecot/auth-zehnox-2.4.conf.ext`, not the 2.3 one.

## The one structural change

Postfix will not let a domain be in both `virtual_alias_domains` and
`virtual_mailbox_domains`. Giving zehnox.com mailboxes therefore **moves** it:

```
virtual_alias_domains   = (zehnox.com removed)
virtual_mailbox_domains = strategicbhm.com, zehnox.com
```

Forwarding still works after the move, because `virtual_alias_maps` is consulted for every
domain and is expanded before the mailbox lookup. But the order matters: **every existing
address must exist in the daemon's rendered files before the move**, or mail to it is
rejected at RCPT with 550. That is why Phase A comes first and is verified before Phase B.

## Order

| Phase | Does | Mail flow changes? |
|---|---|---|
| 1 | Install the daemon, keys, config, systemd units | no |
| A | Import the two aliases; add the daemon's alias map | no (same destinations) |
| W | Point the website at the daemon and its own SMTP settings | no |
| B | Move zehnox.com to a mailbox domain; create mailboxes | **yes — the risky one** |
| C | Confirm DKIM signs `d=zehnox.com` from the new path | yes, outbound only |

Stop after any phase. Each one is useful on its own.

### Phase 1 — install the daemon

Follow `mail-daemon/INSTALL.md` sections 1–5, with these zehnox values:

- user and group `zehnox-mail`, state in `/var/lib/zehnox-mail`
- socket `/var/lib/zehnox-mail/sock/mail.sock` (the unit sets it; it is kept out of `/run`
  so the container's bind mount cannot go stale), units `mail-daemon/systemd/zehnox-maild.*`
- the container reaches the socket through the `zehnox-mail-client` group
- restriction class `zehnox_sender` (the other domain already uses `strategic_sender`)

After copying the code into place, run the manifest check — it needs the install directory,
and prints only usage without it:

```sh
node tools/mail-manifest.js --check /usr/local/lib/zehnox-mail
```

It proves the daemon's copy of the rules is byte-for-byte the one the website runs.

The Dovecot snippet is **not** part of this phase: it is only needed once mailboxes exist,
in Phase B.

Nothing about mail changes in this phase: the daemon writes its own files under
`/var/lib/zehnox-mail`, which no Postfix setting points at yet.

### Phase A — import the two aliases, then let the daemon own them

```bash
sudo cp -a /etc/postfix/virtual /etc/postfix/virtual.bak-$(date +%F)
sudo tar czf /root/postfix-dovecot-backup-$(date +%F).tgz /etc/postfix /etc/dovecot
```

The admin panel cannot do this yet — it is not connected until Phase W. The daemon adopts
the existing entries itself, and will show you what it would do first:

```sh
sudo -u zehnox-mail zehnox-maild --import --postfix-map /etc/postfix/virtual --dry-run
sudo -u zehnox-mail zehnox-maild --import --postfix-map /etc/postfix/virtual
```

Then compare what it rendered against what is live today:

```sh
sudo cat /var/lib/zehnox-mail/postfix/virtual   # what the daemon rendered
sudo cat /etc/postfix/virtual                   # what is live today
```

They must list the same addresses going to the same places. Only then:

```sh
# append the daemon's map; the hand-written file stays first and still wins
sudo postconf -e 'virtual_alias_maps = hash:/etc/postfix/virtual, hash:/var/lib/strategic-mail/postfix/virtual, hash:/var/lib/zehnox-mail/postfix/virtual'
sudo systemctl reload postfix
```
Verify with a real delivery to `info@zehnox.com` before going further.

### Phase W — the website uses the daemon

Keys stay out of `.env`. They are written to files in Phase 1 and the site reads them by
path, so a key is never an environment variable anyone can print:

```
MAIL_PROVIDER=vps
MAIL_SERVICE_SOCKET=/var/lib/zehnox-mail/sock/mail.sock
MAIL_SERVICE_KEY_FILE=/srv/zehnox/secrets/mail-service.key
MAIL_SECRETS_KEY_FILE=/srv/zehnox/secrets/mail-secrets.key
MAIL_SMTP_HOST_ALLOWLIST=mail.zehnox.com
```
The socket directory and both key files must be bind-mounted into the container in
`/opt/zehnox/compose.yaml`, the key files read-only. Until
this phase the Email panel says "Email management is not available yet", which is correct.

### Phase B — mailboxes (the risky one)

This is the phase that moves zehnox.com between domain classes. Do it when you can watch
mail for an hour, and not on a Friday.

Required decisions before starting, both now settled:

- **`info@` is being recreated in the new system.** It becomes a managed address; keep the
  Gmail forward on it as `mailbox+forward` if you still want a copy there.
- **The Cyrus login on 587 is retired** once the website sends as the managed mailbox on
  465. Until then the two must not both claim `info@zehnox.com`.

The `zehnox-fromcheck` milter and the sender-login class are scoped per domain, so the
strategicbhm rules stay exactly as they are.

### Phase C — DKIM

Selector `mail` already publishes a key for zehnox.com and OpenDKIM already signs. After
Phase B, confirm a message sent from a zehnox mailbox on 465 is signed `d=zehnox.com` and
not `d=strategicbhm.com`, because OpenDKIM picks the key from the `From:` header.

## Rollback

Each phase is reversible on its own:

- **A**: `postconf -e` the old `virtual_alias_maps` back, reload Postfix.
- **W**: remove the `MAIL_*` lines from `.env`, `docker compose up -d`. The site keeps
  working with mail management switched off.
- **B**: move zehnox.com back to `virtual_alias_domains`, restore
  `/etc/postfix/virtual.bak-*`, reload. Mailbox contents under `/var/vmail/zehnox.com`
  survive the move.

The full backup from Phase A restores `/etc/postfix` and `/etc/dovecot` wholesale.

## Not done here

- Rewriting the published git history to remove `data/admin-auth.json`,
  `data/initial-password.txt` and the stored enquiry. Untracking them stopped the bleeding;
  what is already published is still published.
- Hardening SPF. `~all` (softfail) is lenient; `-all` is the stricter form, and the panel's
  DNS check reports on it.
