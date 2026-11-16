#!/usr/bin/env python3
"""
Deliverability preflight — check a sending domain before you send on it.

Most cold-email infrastructure fails for boring reasons: SPF that silently
exceeds its DNS lookup budget, DMARC left at p=none, a tracking CNAME sharing
a subdomain with live MX records. None of these throw an error. They just
quietly cost you inbox placement.

This checks the things that actually bite, grades them, and says what to fix.

Usage:
    python3 preflight.py example.com
    python3 preflight.py go.example.com hi.example.com use.example.com
    python3 preflight.py --json example.com

No dependencies. Uses `dig`, which ships with macOS and most Linux.
"""
import subprocess, sys, re, json, shutil

COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "mail",
    "dkim", "s1", "s2", "mandrill", "sendgrid", "pm", "zoho", "mailjet",
]

# SPF mechanisms that each cost one DNS lookup. RFC 7208 caps the total at 10.
LOOKUP_MECHANISMS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


def dig(name, rrtype="TXT"):
    if not shutil.which("dig"):
        sys.exit("error: `dig` not found. Install bind-utils / dnsutils.")
    try:
        out = subprocess.run(
            ["dig", "+short", rrtype, name],
            capture_output=True, text=True, timeout=12
        ).stdout
    except subprocess.TimeoutExpired:
        return []
    return [l.strip().strip('"') for l in out.splitlines() if l.strip()]


def spf_lookup_count(domain, seen=None, depth=0):
    """Count DNS-querying mechanisms in an SPF record, following includes."""
    if seen is None:
        seen = set()
    if depth > 5 or domain in seen:
        return 0
    seen.add(domain)

    records = [r for r in dig(domain) if r.lower().startswith("v=spf1")]
    if not records:
        return 0

    count = 0
    for token in records[0].split():
        low = token.lower()
        if low.startswith("include:"):
            count += 1
            count += spf_lookup_count(token.split(":", 1)[1], seen, depth + 1)
        elif low.startswith(("a:", "mx:", "exists:", "redirect=")) or low in ("a", "mx", "ptr"):
            count += 1
    return count


def check(domain):
    findings = []

    def add(level, label, detail, fix=None):
        findings.append({"level": level, "label": label, "detail": detail, "fix": fix})

    # --- MX -----------------------------------------------------------------
    mx = dig(domain, "MX")
    if mx:
        add("ok", "MX", f"{len(mx)} record(s)")
    else:
        add("warn", "MX", "none found",
            "A sending domain with no MX cannot receive replies or bounces.")

    # --- SPF ----------------------------------------------------------------
    txt = dig(domain)
    spf = [r for r in txt if r.lower().startswith("v=spf1")]
    if not spf:
        add("fail", "SPF", "no record",
            "Publish a v=spf1 record authorising your sending platform.")
    elif len(spf) > 1:
        add("fail", "SPF", f"{len(spf)} records published",
            "More than one SPF record is a permanent error. Merge into one.")
    else:
        rec = spf[0]
        n = spf_lookup_count(domain)
        if n > 10:
            add("fail", "SPF lookups", f"{n} DNS lookups (limit is 10)",
                "Over the limit SPF returns permerror and is treated as no SPF. "
                "Flatten or drop includes.")
        elif n >= 8:
            add("warn", "SPF lookups", f"{n} of 10 used", "Little headroom for another vendor.")
        else:
            add("ok", "SPF lookups", f"{n} of 10 used")

        if rec.rstrip().endswith("-all"):
            add("ok", "SPF policy", "-all (hard fail)")
        elif rec.rstrip().endswith("~all"):
            add("warn", "SPF policy", "~all (soft fail)", "Move to -all once you trust the record.")
        elif "?all" in rec or rec.rstrip().endswith("+all"):
            add("fail", "SPF policy", "neutral or pass-all",
                "This authorises the whole internet to send as you.")

    # --- DMARC --------------------------------------------------------------
    dmarc = [r for r in dig(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        add("fail", "DMARC", "no record",
            "Gmail and Yahoo require DMARC for bulk senders. Start at p=none with rua.")
    else:
        rec = dmarc[0]
        pol = re.search(r"\bp\s*=\s*(\w+)", rec)
        pol = pol.group(1).lower() if pol else "?"
        if pol == "none":
            add("warn", "DMARC policy", "p=none (monitor only)",
                "Fine while you collect reports. Does not protect the domain yet.")
        elif pol in ("quarantine", "reject"):
            add("ok", "DMARC policy", f"p={pol}")
        else:
            add("fail", "DMARC policy", f"unrecognised p={pol}")

        pct = re.search(r"\bpct\s*=\s*(\d+)", rec)
        if pct and int(pct.group(1)) < 100:
            add("warn", "DMARC pct", f"pct={pct.group(1)} — policy applies to a sample only")
        if "rua=" not in rec.lower():
            add("warn", "DMARC rua", "no aggregate report address",
                "Without rua you are flying blind on authentication failures.")

    # --- DKIM ---------------------------------------------------------------
    # Match a real key, not just any TXT containing "p=". Domains with wildcard
    # DNS answer every subdomain, which otherwise reports all selectors present.
    def is_dkim(rec):
        r = rec.lower().replace(" ", "")
        key = re.search(r"\bp=([A-Za-z0-9+/=]+)", rec)
        return ("v=dkim1" in r or "k=rsa" in r) and key and len(key.group(1)) > 80

    found = [s for s in COMMON_DKIM_SELECTORS
             if any(is_dkim(r) for r in dig(f"{s}._domainkey.{domain}"))]
    if len(found) > 6:
        add("warn", "DKIM", f"{len(found)} selectors answered — likely wildcard DNS",
            "A domain answering every selector is not publishing real keys. Verify manually.")
    elif found:
        add("ok", "DKIM", f"selector(s) found: {', '.join(found)}")
    else:
        add("warn", "DKIM", "no common selector found",
            "Selectors are vendor-specific, so this may be a false negative. Verify manually.")

    # --- Tracking CNAME collision -------------------------------------------
    # A subdomain carrying live MX/SPF should not also be the open/click
    # tracking host. Sharing them ties your sending reputation to tracking
    # redirects, which are far more likely to be blocklisted.
    cname = dig(domain, "CNAME")
    if cname and (mx or spf):
        add("fail", "Tracking collision",
            f"{domain} is a CNAME ({cname[0].rstrip('.')}) but also carries MX/SPF",
            "Move open/click tracking to a dedicated subdomain that never sends.")
    elif cname:
        add("ok", "Tracking collision", "CNAME present, no mail records on the same host")

    return findings


ICON = {"ok": "PASS", "warn": "WARN", "fail": "FAIL"}


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    if not args:
        sys.exit(__doc__.strip())

    report = {}
    worst = 0
    for d in args:
        f = check(d)
        report[d] = f
        worst = max(worst, max((0, 1, 2)[["ok", "warn", "fail"].index(x["level"])] for x in f))

        if not as_json:
            print(f"\n{d}")
            print("=" * len(d))
            for x in f:
                print(f"  [{ICON[x['level']]}] {x['label']:<20} {x['detail']}")
                if x["fix"] and x["level"] != "ok":
                    print(f"         -> {x['fix']}")

    if as_json:
        print(json.dumps(report, indent=2))

    sys.exit(worst if worst == 2 else 0)


if __name__ == "__main__":
    main()
