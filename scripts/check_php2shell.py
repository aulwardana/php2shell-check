#!/usr/bin/env python3
"""
Multi-layer, passive PHP fingerprinting tool.

Checks a URL (and, optionally, its subdomains) for signals that the target
is running PHP, and tries to narrow down the version, using only ordinary,
non-intrusive HTTP requests and passive subdomain discovery (certificate
transparency logs, DNS resolution of a common-name wordlist). No malformed
input, no error-triggering, no port scanning, no exploitation.

Usage:
    python3 check_php2shell.py <url> [options]

Options:
    --json                  Output raw JSON only
    --scan-subdomains       Auto-discover subdomains (crt.sh + common
                             wordlist) and scan each one that resolves
    --subdomains LIST       Manually supply subdomains to scan instead of
                             auto-discovery: comma-separated hostnames, or
                             a path to a file with one hostname per line
    --max-subdomains N      Cap how many discovered subdomains get scanned
                             (default 15, ignored for --subdomains)
    --no-subdomains         Explicit no-op flag for clarity in scripts/docs
                             (this is the default; scanning subdomains is
                             always opt-in)

Exit behavior is informational only; this never attempts exploitation.
"""
import sys
import re
import json
import socket
import argparse
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    print("This script requires the 'requests' package: pip install requests --break-system-packages", file=sys.stderr)
    sys.exit(1)

USER_AGENT = "Mozilla/5.0 (compatible; PHPFingerprint/1.0; passive-detection)"
TIMEOUT = 8

# Common subdomains where organizations park PHP-based services
# (webmail/SSO/portal software is very often PHP even when the main
# marketing site is not).
COMMON_SUBDOMAIN_WORDLIST = [
    "mail", "webmail", "owa", "autodiscover",
    "sso", "login", "portal", "auth", "account",
    "admin", "cpanel", "whm", "plesk",
    "vpn", "remote", "intranet",
    "support", "helpdesk", "ticket",
    "wiki", "crm", "status",
]

# Common, well-known PHP app paths. Fetching these is equivalent to a normal
# visitor browsing to a login page -- not a vulnerability probe.
COMMON_PATHS = [
    "wp-login.php",
    "wp-admin/",
    "administrator/index.php",   # Joomla
    "user/login",                # Drupal (not PHP-extension based, but PHP cookie-detectable)
    "index.php",
]

# PHP2Shell (CVE-2026-109618 / CVE-2026-109619), disclosed 2026-10-21.
# Fixed releases per branch, per the PHP project's upstream advisory.
# This is used ONLY for a passive version-string comparison -- never for
# active probing or exploit confirmation.
PHP2SHELL_FIXED_VERSIONS = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}
PHP2SHELL_ADVISORY_URL = "https://www.php.net/ChangeLog-8.php"  # point users to the official advisory/changelog

GENERATOR_PATTERNS = [
    (re.compile(r"WordPress\s*([\d.]+)?", re.I), "WordPress (PHP-based)"),
    (re.compile(r"Joomla!?\s*([\d.]+)?", re.I), "Joomla (PHP-based)"),
    (re.compile(r"Drupal\s*([\d.]+)?", re.I), "Drupal (PHP-based)"),
    (re.compile(r"MediaWiki\s*([\d.]+)?", re.I), "MediaWiki (PHP-based)"),
]


def fetch(url, method="GET", allow_redirects=True):
    try:
        resp = requests.request(
            method, url,
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT,
            allow_redirects=allow_redirects,
            verify=True,
        )
        return resp
    except requests.exceptions.RequestException as e:
        return None


def normalize_base_url(url):
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}/"


def layer_headers(resp, evidence, score):
    if resp is None:
        return
    xpb = resp.headers.get("X-Powered-By", "")
    if xpb:
        m = re.search(r"PHP/([\d.]+)", xpb, re.I)
        if m:
            evidence.append({
                "layer": "headers",
                "signal": f"X-Powered-By header reports PHP/{m.group(1)}",
                "weight": "strong",
                "version_hint": m.group(1),
            })
            score["strong"] += 1
        else:
            evidence.append({
                "layer": "headers",
                "signal": f"X-Powered-By header present but no PHP version string: {xpb}",
                "weight": "weak",
            })
            score["weak"] += 1

    server = resp.headers.get("Server", "")
    if server:
        m = re.search(r"PHP/([\d.]+)", server, re.I)
        if m:
            evidence.append({
                "layer": "headers",
                "signal": f"Server header reports PHP/{m.group(1)}",
                "weight": "strong",
                "version_hint": m.group(1),
            })
            score["strong"] += 1
        elif any(s in server for s in ("Apache", "nginx", "LiteSpeed")):
            evidence.append({
                "layer": "headers",
                "signal": f"Server header: {server} (consistent with common PHP hosting, not conclusive alone)",
                "weight": "neutral",
            })


def layer_cookies(resp, evidence, score):
    if resp is None:
        return
    set_cookie_headers = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers, "get_all") else None
    cookie_str = ""
    if set_cookie_headers:
        cookie_str = " ; ".join(set_cookie_headers)
    else:
        cookie_str = resp.headers.get("Set-Cookie", "") or " ; ".join(f"{k}={v}" for k, v in resp.cookies.items())

    if re.search(r"PHPSESSID", cookie_str, re.I):
        evidence.append({
            "layer": "cookies",
            "signal": "PHPSESSID cookie present",
            "weight": "strong",
        })
        score["strong"] += 1


def layer_paths(base_url, evidence, score):
    for path in COMMON_PATHS:
        url = urljoin(base_url, path)
        resp = fetch(url, method="GET")
        if resp is None:
            continue
        final_url = resp.url
        if final_url.lower().endswith(".php") and resp.status_code < 500:
            evidence.append({
                "layer": "paths",
                "signal": f"Request to /{path} resolved to a .php URL ({final_url}, status {resp.status_code})",
                "weight": "moderate",
            })
            score["moderate"] += 1
            layer_headers(resp, evidence, score)
            layer_cookies(resp, evidence, score)


def layer_markup(resp, evidence, score):
    if resp is None or not resp.text:
        return
    text = resp.text[:200000]  # cap how much we scan
    for pattern, label in GENERATOR_PATTERNS:
        m = pattern.search(text)
        if m:
            version = m.group(1) if m.lastindex else None
            sig = f"Page markup indicates {label}"
            if version:
                sig += f" version {version}"
            evidence.append({
                "layer": "markup",
                "signal": sig,
                "weight": "moderate",
            })
            score["moderate"] += 1

    if re.search(r'action="[^"]*\.php', text, re.I):
        evidence.append({
            "layer": "markup",
            "signal": "Form action attribute points to a .php endpoint",
            "weight": "weak",
        })
        score["weak"] += 1


def parse_version_tuple(version_str):
    parts = re.findall(r"\d+", version_str)
    if not parts:
        return None
    nums = tuple(int(p) for p in parts[:3])
    while len(nums) < 3:
        nums = nums + (0,)
    return nums


def check_php2shell_version_flag(version_hints):
    """Passive version-string comparison against PHP2Shell's fixed releases.
    This NEVER sends anything to the target beyond the normal requests
    already made elsewhere in this script -- it only compares a version
    string that was already observed. It does not confirm exploitability."""
    if not version_hints:
        return None

    results = []
    for v in version_hints:
        parsed = parse_version_tuple(v)
        if not parsed:
            continue
        branch = parsed[:2]
        major = parsed[0]

        if branch in PHP2SHELL_FIXED_VERSIONS:
            fixed = PHP2SHELL_FIXED_VERSIONS[branch]
            if parsed < fixed:
                results.append({
                    "version": v,
                    "status": "version string is older than the patched release for its branch",
                    "fixed_version_for_branch": ".".join(map(str, fixed)),
                })
            else:
                results.append({
                    "version": v,
                    "status": "version string meets or exceeds the patched release for its branch",
                    "fixed_version_for_branch": ".".join(map(str, fixed)),
                })
        else:
            # Any branch not in the fixed-version table (including very old
            # 5.x/7.x/8.0/8.1 branches) predates the patched releases above
            # and should not be assumed safe just because it's "too old to
            # be in the table" -- researchers explicitly warn against that.
            results.append({
                "version": v,
                "status": f"PHP {major}.x branch is not one of the officially patched branches (8.2-8.5) -- do not assume this is unaffected",
                "fixed_version_for_branch": None,
            })

    if not results:
        return None

    return {
        "php2shell_version_check": results,
        "disclaimer": (
            "This is a version-STRING comparison only, not confirmation of "
            "exploitability. Distribution vendors (RHEL, Debian, Ubuntu, etc.) "
            "frequently backport security fixes without changing the "
            "upstream-looking version number, which can make this check both "
            "under- and over-report. The header seen here also only reflects "
            "the web-facing PHP runtime, which is the one that actually "
            "matters for this vulnerability -- but it cannot see whether "
            "FPM/mod_php workers have been restarted after a binary update. "
            f"Verify server-side and consult the official PHP advisory ({PHP2SHELL_ADVISORY_URL}) "
            "before concluding anything about actual exposure."
        ),
    }


def summarize(evidence, score):
    total_strong = score["strong"]
    total_moderate = score["moderate"]
    total_weak = score["weak"]

    version_hints = sorted({e["version_hint"] for e in evidence if "version_hint" in e})

    if total_strong >= 1:
        verdict = "Likely running PHP (confirmed by a strong signal, e.g. header or cookie)."
        confidence = "high"
    elif total_moderate >= 2:
        verdict = "Probably running PHP (multiple moderate signals, no direct confirmation)."
        confidence = "medium"
    elif total_moderate == 1 or total_weak >= 2:
        verdict = "Possibly running PHP (weak/limited signals only)."
        confidence = "low"
    else:
        verdict = "No PHP signals detected. This does NOT confirm the site isn't running PHP -- many servers deliberately hide this (stripped headers, rewritten URLs, non-PHP-looking frontends)."
        confidence = "inconclusive"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "version_hints_found": version_hints,
        "evidence_count": {
            "strong": total_strong,
            "moderate": total_moderate,
            "weak": total_weak,
        },
    }


def scan_one(url):
    """Run all layers against a single host and return its result dict."""
    base_url = normalize_base_url(url)
    evidence = []
    score = {"strong": 0, "moderate": 0, "weak": 0}

    home_resp = fetch(base_url)
    layer_headers(home_resp, evidence, score)
    layer_cookies(home_resp, evidence, score)
    layer_markup(home_resp, evidence, score)
    layer_paths(base_url, evidence, score)

    summary = summarize(evidence, score)
    php2shell_flag = check_php2shell_version_flag(summary["version_hints_found"])

    return {
        "target": base_url,
        "summary": summary,
        "evidence": evidence,
        "php2shell_flag": php2shell_flag,
    }


def discover_subdomains_crtsh(root_domain):
    """Passive discovery via certificate transparency logs (crt.sh).
    This only queries a public log -- it never contacts the target."""
    found = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{root_domain}&output=json",
            headers={"User-Agent": USER_AGENT},
            timeout=15,
        )
        if resp.status_code == 200 and resp.text.strip():
            entries = json.loads(resp.text)
            for entry in entries:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(root_domain) and name != root_domain and "*" not in name:
                        found.add(name)
    except (requests.exceptions.RequestException, json.JSONDecodeError, ValueError):
        pass  # crt.sh being unreachable just means fewer results, not an error state
    return found


def discover_subdomains_wordlist(root_domain):
    """Passive discovery via plain DNS resolution of a common-name wordlist.
    A DNS lookup is not a request to the host; nothing is sent to the
    target's web/mail server by this step."""
    found = set()
    for word in COMMON_SUBDOMAIN_WORDLIST:
        candidate = f"{word}.{root_domain}"
        try:
            socket.gethostbyname(candidate)
            found.add(candidate)
        except socket.gaierror:
            continue
    return found


def parse_manual_subdomains(arg_value):
    import os
    if os.path.isfile(arg_value):
        with open(arg_value) as f:
            return [line.strip() for line in f if line.strip()]
    return [s.strip() for s in arg_value.split(",") if s.strip()]


def run(url, scan_subdomains=False, manual_subdomains=None, max_subdomains=15):
    root_result = scan_one(url)
    root_domain = urlparse(root_result["target"]).netloc

    subdomain_results = []
    discovery_note = None

    if manual_subdomains:
        targets = manual_subdomains
        discovery_note = f"Scanning {len(targets)} manually supplied subdomain(s)."
    elif scan_subdomains:
        discovered = discover_subdomains_crtsh(root_domain) | discover_subdomains_wordlist(root_domain)
        discovered.discard(root_domain)
        targets = sorted(discovered)[:max_subdomains]
        discovery_note = (
            f"Passively discovered {len(discovered)} candidate subdomain(s) via certificate "
            f"transparency logs and a common-name wordlist; scanning {len(targets)} "
            f"(capped at {max_subdomains})."
        )
    else:
        targets = []

    for sub in targets:
        subdomain_results.append(scan_one(sub))

    return {
        "root": root_result,
        "subdomains": subdomain_results,
        "subdomain_discovery_note": discovery_note,
        "note": (
            "This is passive fingerprinting only (headers, cookies, markup, "
            "common page paths, certificate-transparency / DNS-based subdomain "
            "discovery). It does not probe for or exploit any vulnerability, "
            "and never port-scans or brute-forces the target. Absence of "
            "signals does not prove a host is PHP-free -- many admins "
            "intentionally hide this. For a ground-truth answer on a host you "
            "control, check server-side (php -v / hosting panel)."
        ),
    }


def host_risk_level(host_result):
    """Classify a single host's result into a traffic-light risk level for
    non-technical reporting. This reflects what's worth a closer look, not
    a confirmed vulnerability status."""
    flag = host_result.get("php2shell_flag")
    confidence = host_result["summary"]["confidence"]

    if flag:
        for r in flag["php2shell_version_check"]:
            if r["status"].startswith("version string is older"):
                return "high", "PHP version detected is older than the patched release"
            if "not one of the officially patched branches" in r["status"]:
                return "high", "PHP version is on a branch not covered by the official fix -- do not assume safe"
        # every hint matched or exceeded the fixed version
        return "ok", "Detected PHP version meets or exceeds the patched release"

    if confidence in ("high", "medium"):
        return "medium", "PHP detected but version could not be confirmed from outside -- verify with IT"

    return "ok", "No signals requiring action from this check"


RISK_ICON = {"high": "\U0001F534", "medium": "\U0001F7E1", "ok": "\U0001F7E2"}
RISK_LABEL = {"high": "High", "medium": "Medium", "ok": "OK"}


def generate_management_report(result, scan_date=None, org_label=None):
    import datetime
    scan_date = scan_date or datetime.date.today().isoformat()
    all_hosts = [result["root"]] + result["subdomains"]
    org_label = org_label or urlparse(result["root"]["target"]).netloc

    rows = []
    for h in all_hosts:
        level, reason = host_risk_level(h)
        host_name = urlparse(h["target"]).netloc
        rows.append((host_name, level, reason))

    high = [r for r in rows if r[1] == "high"]
    medium = [r for r in rows if r[1] == "medium"]
    ok = [r for r in rows if r[1] == "ok"]

    if high:
        overall = f"{RISK_ICON['high']} ACTION NEEDED"
    elif medium:
        overall = f"{RISK_ICON['medium']} REVIEW RECOMMENDED"
    else:
        overall = f"{RISK_ICON['ok']} NO ACTION NEEDED"

    lines = []
    lines.append("=" * 47)
    lines.append(" PHP EXPOSURE & PATCH STATUS -- SUMMARY REPORT")
    lines.append("=" * 47)
    lines.append(f"Organization scope:  {org_label}" + (f" + {len(all_hosts) - 1} related subdomains" if len(all_hosts) > 1 else ""))
    lines.append(f"Scan date:            {scan_date}")
    lines.append("Prepared for:         Management / IT leadership")
    lines.append("")
    lines.append(f"OVERALL RISK:  {overall}")
    lines.append("")
    lines.append("-" * 47)
    lines.append("WHAT WE FOUND")
    lines.append("-" * 47)
    if high:
        lines.append(
            f"Of {len(all_hosts)} web propert{'y' if len(all_hosts)==1 else 'ies'} checked, {len(high)} "
            f"appear to run PHP in a state older than, or outside, the official security "
            f"fix for a critical, actively-discussed vulnerability (PHP2Shell, Oct 2026)."
        )
        lines.append("")
        lines.append(
            "This does not confirm those systems have been or can be attacked -- it means "
            "they should be verified and prioritized for patching."
        )
    elif medium:
        lines.append(
            f"Of {len(all_hosts)} web propert{'y' if len(all_hosts)==1 else 'ies'} checked, none showed a "
            f"confirmed outdated PHP version, but {len(medium)} showed signs of running PHP without "
            f"a version visible from outside. Worth a quick internal confirmation."
        )
    else:
        lines.append(
            f"Checked {len(all_hosts)} web propert{'y' if len(all_hosts)==1 else 'ies'}. No signals "
            f"requiring action were found."
        )
    lines.append("")
    lines.append("-" * 47)
    lines.append("SITES NEEDING ATTENTION" if (high or medium) else "SITES CHECKED")
    lines.append("-" * 47)
    display_rows = high + medium if (high or medium) else ok
    if display_rows:
        for host_name, level, reason in display_rows:
            icon = RISK_ICON[level]
            lines.append(f" {icon} {RISK_LABEL[level]:<6} {host_name}")
            lines.append(f"        -> {reason}")
    if ok and (high or medium):
        lines.append(f" {RISK_ICON['ok']} {len(ok)} other host(s) showed no signals requiring action.")
    lines.append("")
    lines.append("-" * 47)
    lines.append("RECOMMENDED NEXT STEPS")
    lines.append("-" * 47)
    if high:
        lines.append(" 1. Share this report with whoever manages hosting/IT for the flagged sites.")
        lines.append(" 2. Ask them to confirm the actual PHP version running in production")
        lines.append("    (not just the installed binary -- workers must be restarted after patching).")
        lines.append(" 3. Prioritize patching based on sensitivity (login/SSO/mail systems first).")
        lines.append(" 4. Re-run this check after patching to confirm.")
    elif medium:
        lines.append(" 1. Ask IT to confirm PHP version on the listed site(s) directly.")
        lines.append(" 2. No urgent action otherwise -- this is a visibility gap, not a confirmed issue.")
    else:
        lines.append(" No action required based on this check. Re-run periodically as good practice.")
    lines.append("")
    lines.append("-" * 47)
    lines.append("IMPORTANT CAVEATS")
    lines.append("-" * 47)
    lines.append("- This is an outside, non-intrusive check -- it reads only what a normal")
    lines.append("  visitor's browser would see. It cannot guarantee a system is safe OR unsafe;")
    lines.append("  it flags things worth a closer look by IT.")
    lines.append("- A green/OK result does not prove a system doesn't run PHP -- some servers")
    lines.append("  deliberately hide this information, which is actually good security practice.")
    lines.append("- Distribution vendors sometimes patch security issues without changing the")
    lines.append("  visible version number, so a flagged host may already be patched internally.")
    lines.append("")
    lines.append("(Full technical evidence available in the JSON report for your IT team.)")
    lines.append("=" * 47)
    return "\n".join(lines)


def print_host_result(result, indent=""):
    print(f"{indent}Target: {result['target']}")
    print(f"{indent}Verdict: {result['summary']['verdict']}")
    print(f"{indent}Confidence: {result['summary']['confidence']}")
    if result["summary"]["version_hints_found"]:
        print(f"{indent}Version hint(s): {', '.join(result['summary']['version_hints_found'])}")
    if result["evidence"]:
        print(f"{indent}Evidence:")
        for e in result["evidence"]:
            tag = f"[{e['weight']}]"
            print(f"{indent}  {tag:<12} {e['layer']:<8} {e['signal']}")
    else:
        print(f"{indent}Evidence: (none found)")

    flag = result.get("php2shell_flag")
    if flag:
        print(f"{indent}PHP2Shell (CVE-2026-109618/109619) version check:")
        for r in flag["php2shell_version_check"]:
            print(f"{indent}  - PHP {r['version']}: {r['status']}"
                  + (f" (fixed: {r['fixed_version_for_branch']})" if r["fixed_version_for_branch"] else ""))
        print(f"{indent}  Note: {flag['disclaimer']}")


def main():
    parser = argparse.ArgumentParser(
        description="Passive, multi-layer PHP fingerprinting, with optional subdomain scanning"
    )
    parser.add_argument("url", help="Target URL or domain, e.g. example.com")
    parser.add_argument("--json", action="store_true", help="Output raw JSON only (shorthand for --report json)")
    parser.add_argument("--report", choices=["text", "json", "management"], default="text",
                         help="Output format: 'text' (default, per-host detail for IT), "
                              "'json' (raw data for tooling), "
                              "'management' (plain-language risk summary for non-technical stakeholders)")
    parser.add_argument("--org-label", help="Display name for the organization/scope in the management report (defaults to the root domain)")
    parser.add_argument("--scan-subdomains", action="store_true",
                         help="Auto-discover subdomains (crt.sh + common wordlist) and scan each")
    parser.add_argument("--subdomains", metavar="LIST_OR_FILE",
                         help="Comma-separated hostnames, or a path to a file (one per line), to scan instead of auto-discovery")
    parser.add_argument("--max-subdomains", type=int, default=15,
                         help="Cap on auto-discovered subdomains to scan (default 15)")
    parser.add_argument("--no-subdomains", action="store_true",
                         help="Explicit no-op: subdomain scanning is opt-in by default anyway")
    args = parser.parse_args()

    manual = parse_manual_subdomains(args.subdomains) if args.subdomains else None
    scan_subs = args.scan_subdomains and not args.no_subdomains

    result = run(
        args.url,
        scan_subdomains=scan_subs,
        manual_subdomains=manual,
        max_subdomains=args.max_subdomains,
    )

    report_mode = "json" if args.json else args.report

    if report_mode == "json":
        print(json.dumps(result, indent=2))
        return

    if report_mode == "management":
        print(generate_management_report(result, org_label=args.org_label))
        return

    print("=== Root target ===")
    print_host_result(result["root"])

    if result["subdomain_discovery_note"]:
        print()
        print(result["subdomain_discovery_note"])

    for sub_result in result["subdomains"]:
        print()
        print(f"=== {sub_result['target']} ===")
        print_host_result(sub_result, indent="  ")

    print()
    print(result["note"])


if __name__ == "__main__":
    main()
