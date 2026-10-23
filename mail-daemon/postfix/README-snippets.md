# Postfix changes for zehnox.com (owner, by hand, with sudo)

Copied from `docs/mail/DESIGN.md` section 16. That document is the authority; if they ever
differ, follow the design. Nothing here is run by the website, the container or
zehnox-maild: the daemon only writes its own maps under `/var/lib/zehnox-mail/postfix/`
and runs `postmap` on them. It never edits `main.cf` or `master.cf` and never reloads Postfix.

Every step is additive and has a rollback. Stop at the first failed check.

## Phase 0: record the current state first

```sh
mkdir -p /root/sbhm
postconf -n > /root/sbhm/postconf-n.before; postconf -M > /root/sbhm/postconf-M.before
postconf -h default_database_type; postconf -m
postconf virtual_alias_domains virtual_alias_maps virtual_mailbox_domains virtual_mailbox_maps \
  virtual_transport transport_maps smtpd_sasl_type smtpd_sender_login_maps smtpd_sender_restrictions \
  smtpd_relay_restrictions smtpd_recipient_restrictions smtpd_restriction_classes recipient_delimiter \
  milter_default_action mail_version > /root/sbhm/saved-postconf.txt
tar czf /root/sbhm/mail-config-$(date +%F).tgz /etc/postfix /etc/dovecot /etc/opendkim*
```

`mapType` in `/etc/zehnox-mail/config.json` must equal `postconf -h default_database_type`
(`hash` or `lmdb`).

## Safe append helper

`postconf -h` shows the unexpanded value, including defaults such as `$virtual_alias_maps`.
This helper avoids a leading comma when the value is empty.

```sh
append() { cur="$(postconf -h "$1")"; if [ -z "$cur" ]; then postconf -e "$1 = $2"; else postconf -e "$1 = $cur, $2"; fi; }
T=$(postconf -h default_database_type)
```

## Phase A: forwarding only

Decide on SRS first (section 16, Phase A): forwarding without SRS breaks SPF at the
destinations. Record the decision.

```sh
append virtual_alias_maps "$T:/var/lib/zehnox-mail/postfix/virtual"     # appended LAST: strategicbhm keys always win
append virtual_alias_domains "zehnox.com"                             # Phase A only; never also in virtual_mailbox_domains
postconf -n | diff /root/sbhm/postconf-n.before -     # must show only these two lines changed
postfix check && postfix reload
```

Verify:

- `postmap -q test1@zehnox.com $T:/var/lib/zehnox-mail/postfix/virtual` after
  creating `test1@` in the admin panel; external mail to it is delivered.
- Change its forwarding in the panel; the next message follows the new destination
  **without a reload** (the mail log shows "table ... has changed -- restarting").
- No warnings about table ownership or location, no chroot open errors.
- An unknown `@zehnox.com` address gets 550 at RCPT.
- From outside, an unauthenticated RCPT to a foreign domain gets 554 "Relay access denied".
- An `@strategicbhm.com` round trip still works; existing strategicbhm lookups return what they did before.

Rollback A: restore the two saved lines with `postconf -e "<line from saved-postconf.txt>"`,
then `postfix reload`.

## Phase B: mailboxes and SASL (gated)

Only if Dovecot exists, `smtpd_sasl_type=dovecot`, Postfix is 2.11 or later, and
`auth_username_format` does not strip the domain.

```sh
# 1. Domain switch: never in both lists.
postconf -e "virtual_alias_domains = <saved value from saved-postconf.txt>"
append virtual_mailbox_domains zehnox.com
append virtual_mailbox_maps "$T:/var/lib/zehnox-mail/postfix/vmailbox"   # appended last

# 2. Delivery: only if virtual_transport is NOT already Dovecot LMTP. The transport map is a
#    one-line file the owner writes by hand (the daemon does not render it):
#      zehnox.com lmtp:unix:private/dovecot-lmtp
#    then: postmap $T:<that file>
# append transport_maps "$T:<that file>"

# 4. Sender-login enforcement, scoped to zehnox logins (gate flag 1).
append smtpd_sender_login_maps "$T:/var/lib/zehnox-mail/postfix/sender_login"
append smtpd_restriction_classes zehnox_sender
postconf -e "zehnox_sender = reject_authenticated_sender_login_mismatch, check_policy_service <policy endpoint>"
# Put  check_sasl_access $T:/var/lib/zehnox-mail/postfix/sasl_access  FIRST in the
# submission service's smtpd_sender_restrictions (master.cf -o if submission overrides it,
# otherwise main.cf). Only logins listed in sasl_access enter the class.

# 5. Per-SASL-user outbound rate limit (gate flag 2): a policy service bound to 127.0.0.1
#    (for example postfwd), matching sasl_username=~/@zehnox\.com$/, 100/hour and
#    500/day per user, referenced only inside zehnox_sender.

postfix check && postfix reload
```

Step 3 (Dovecot) is in `mail-daemon/dovecot/`. Verify: a strategicbhm login still sends as its
usual From; a zehnox login sending `From: x@strategicbhm.com` is rejected; the rate limit
trips in a controlled test. Then open the gate: `mailboxes.enabled: true` and both
`gate` flags `true` in `/etc/zehnox-mail/config.json`, and
`systemctl restart zehnox-maild`.

Rollback B: restore the saved value of every appended parameter, remove the Dovecot
include, set `mailboxes.enabled: false`, `postfix reload`, `systemctl reload dovecot`.
