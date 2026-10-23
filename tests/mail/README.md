# Mail module tests

Run them with:

```
node --test tests/mail/
```

These use `node:test` rather than the `tools/test-*.js` scripts the rest of the site uses,
because they are ported from the STRATEGIC mail module and kept close to their originals so
fixes can travel between the two projects. The site's own suites are unchanged.

## What is covered so far

| File | Covers |
|---|---|
| `core.test.js` | the pure state machine: every verb, its rules and its refusals |
| `validate.test.js` | local parts, forwarding destinations, hash formats, request schemas, password policy |
| `render.test.js` | the Postfix and Dovecot files rendered from state, and the checks that refuse a tampered one |
| `protocol.test.js` | the signed frames the web process and the daemon exchange |

## Porting notes

The two projects are mirror images. STRATEGIC is pinned to `strategicbhm.com` and uses
`zehnox.com` as its example of "a domain that is not ours"; here it is the other way round.
A blind rename would turn those foreign-domain cases into our own domain and quietly gut the
test, so the port swaps them deliberately — `strategicbhm.com` appearing in these files is a
foreign domain on purpose, and happens to be the other domain on the same mail server.

Two rules had to be re-pinned rather than renamed:

- the Postfix restriction class is `zehnox_sender`, because `strategic_sender` already exists
  on that Postfix for the other domain;
- the password policy rejects passwords containing `zehnox`, not the old company name.

To prove the suite still has teeth, change `PINNED_DOMAIN` in `lib/mail/core/constants.js` to
something else: 21 of the 46 tests should fail.
