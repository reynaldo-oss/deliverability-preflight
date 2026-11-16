# deliverability-preflight

Check a sending domain before you send on it.

Cold email infrastructure rarely fails loudly. It fails because an SPF record
quietly exceeded its DNS lookup budget, or DMARC sat at `p=none` for a year, or
a click-tracking CNAME ended up on the same subdomain as live MX records. None
of these throw an error. They just cost you the inbox.

This checks the things that actually bite, grades each one, and says what to fix.

```
$ python3 preflight.py go.example.com

go.example.com
==============
  [PASS] MX                   2 record(s)
  [FAIL] SPF lookups          12 DNS lookups (limit is 10)
         -> Over the limit SPF returns permerror and is treated as no SPF.
            Flatten or drop includes.
  [WARN] SPF policy           ~all (soft fail)
         -> Move to -all once you trust the record.
  [WARN] DMARC policy         p=none (monitor only)
         -> Fine while you collect reports. Does not protect the domain yet.
  [PASS] DKIM                 selector(s) found: selector1, selector2
  [FAIL] Tracking collision   go.example.com is a CNAME but also carries MX/SPF
         -> Move open/click tracking to a dedicated subdomain that never sends.
```

---

## What it checks

**SPF lookup budget.** RFC 7208 caps an SPF evaluation at 10 DNS lookups. Go
over and the record returns `permerror`, which most receivers treat as *no SPF
at all*. The counter here follows `include:` chains recursively, because the
budget is consumed by everything downstream, not just the mechanisms you can see
in your own record. This is the single most common silent failure in a stack
that's accumulated vendors over time.

**SPF policy.** `-all`, `~all`, `?all`, `+all` — graded by how much they
actually assert.

**DMARC.** Presence, policy strength, `pct` sampling, and whether `rua` is set.
A policy with no aggregate reporting address means nobody is watching
authentication failures.

**DKIM.** Probes common selectors. Requires a plausible key (`v=DKIM1` or
`k=rsa`, plus a long base64 `p=` value) rather than any TXT record containing
`p=` — domains with wildcard DNS answer every selector name and will otherwise
report a full set of keys that don't exist.

**Tracking collision.** A subdomain carrying live MX or SPF should not also be
the open/click tracking host. Sharing them ties sending reputation to tracking
redirects, which are far more likely to end up on a blocklist. This one comes
from finding it in production.

---

## Usage

```bash
python3 preflight.py example.com
python3 preflight.py go.example.com hi.example.com use.example.com
python3 preflight.py --json example.com        # machine-readable
```

Exit code is `2` if anything failed, `0` otherwise, so it drops into CI or a
pre-send gate.

No dependencies. Uses `dig`, which ships with macOS and most Linux.

---

## What it does not do

- **No inbox placement testing.** DNS is necessary, not sufficient. Seed-list
  testing is a different tool.
- **No reputation or blocklist lookups.** Check Google Postmaster Tools and
  Microsoft SNDS directly.
- **DKIM probing is best-effort.** Selectors are vendor-chosen and there is no
  way to enumerate them. A WARN here often means "ask your ESP", not "broken".
- **No content or engagement signals**, which matter at least as much as
  authentication once the basics are right.

---

## Why it exists

Written after spending too long diagnosing a sending setup where every record
looked individually correct and placement was still poor. The problem was the
tracking subdomain sharing a host with live mail records — invisible unless you
check for it specifically, which no commercial tool I tried did.

Built by [Reynaldo Espanola](https://github.com/reynaldo-oss).
