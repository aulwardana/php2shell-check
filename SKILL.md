---
name: php2shell-check
description: Check whether a website (and optionally its subdomains) runs PHP, confirm its version, and flag exposure to the PHP2Shell vulnerabilities (CVE-2026-109618 / CVE-2026-109619), given just a URL. Use whenever the user asks to check/detect/fingerprint PHP on a site, asks "does this site use PHP" or "is this site vulnerable to PHP2Shell", wants to know a site's PHP version, or wants a multi-layer / multi-signal confidence check rather than a single header lookup. Combines HTTP headers, cookies, common PHP app paths, and page markup into one scored verdict, plus a version-string comparison against PHP2Shell's patched releases. Passive and non-intrusive only — does not probe for or attempt to exploit any vulnerability, including PHP2Shell itself; never use this skill to help someone attack or exploit a target they don't own or have authorization to test.
---

# PHP2Shell Check

Determine whether a target site is running PHP, and ideally which version, using several independent passive signals combined into one confidence-scored verdict — rather than relying on any single header that could be stripped or spoofed.

## Before running anything

This tool only does passive reconnaissance (reading headers/cookies/markup a browser would see anyway, and requesting a handful of well-known public page paths like `wp-login.php`). It never sends malformed input, never tries to trigger stack traces, and never touches known CVEs or exploitation techniques.

If the user's framing suggests they want to *find and exploit* vulnerable servers at scale, or specifically wants to chain this into exploiting PHP2Shell or another CVE on a target they don't control, decline that framing and offer only the defensive/informational use (checking their own site, or general due-diligence fingerprinting) instead.

## How to run it

1. Get the target URL or domain from the user (bare domains like `example.com` are fine, the script normalizes them).
2. Decide whether subdomains should be included — see the CLI options below — based on what the user asked for. **Default to NOT scanning subdomains** unless the user said something like "check subdomains too", "include mail/SSO/webmail", or gave you a list.
3. Run the bundled script:

```bash
python3 scripts/check_php2shell.py "<url>" --json
```

4. The script performs these layers against each host it checks, each adding weighted evidence:
   - **Headers** — `X-Powered-By: PHP/x.y.z`, `Server:` banner version strings (strong signal when a version is present)
   - **Cookies** — `PHPSESSID` presence (strong signal, survives header-stripping)
   - **Common paths** — ordinary requests to well-known PHP app entry points (`wp-login.php`, `administrator/index.php`, etc.) and whether the final URL resolves to `.php` (moderate signal); re-runs the header/cookie checks against whichever of these responds
   - **Markup** — `<meta name="generator">` tags for PHP-based CMSs (WordPress, Joomla, Drupal, MediaWiki), and `.php` form action attributes (moderate/weak signal)

5. The script returns, per host, an overall verdict (`high` / `medium` / `low` / `inconclusive` confidence) plus the full evidence list and any PHP/CMS version numbers it found.

## CLI options (like a normal Linux command)

```
check_php2shell.py <url> [options]

  --json                    Output raw JSON only (shorthand for --report json)
  --report {text,json,management}
                             Output format (default: text):
                               text       per-host technical detail, for IT/engineers
                               json       raw structured data, for tooling/pipelines
                               management plain-language, traffic-light risk summary
                                          for non-technical stakeholders (see below)
  --org-label NAME           Display name for the scope in the management report
                              (defaults to the root domain)
  --scan-subdomains         Auto-discover subdomains and scan each one that resolves
  --subdomains LIST_OR_FILE Manually supply subdomains instead of auto-discovery:
                             comma-separated hostnames ("mail.x.com,sso.x.com")
                             or a path to a file, one hostname per line
  --max-subdomains N        Cap how many auto-discovered subdomains get scanned
                             (default 15; ignored when --subdomains is used)
  --no-subdomains           Explicit no-op — subdomain scanning is opt-in by
                             default anyway, this flag exists just for clarity
                             when the user wants to be explicit about it
```

### Choosing a report format

Ask yourself who's going to read the output, and default accordingly if the user doesn't say:
- Talking to an engineer/IT person, or they want to pipe results somewhere → `text` (default) or `--report json`
- The user says something like "for my boss," "for management," "a summary for the team," "non-technical," or similar → use `--report management`. This collapses all the per-layer evidence into one risk level per host (🔴/🟡/🟢), a one-paragraph finding, and a short action list — present that output directly rather than re-summarizing the raw evidence yourself, since the report is already written for that audience.

Map the user's phrasing to flags, e.g.:
- "just check example.com" → `python3 scripts/check_php2shell.py "example.com" --json`
- "also check their subdomains, mail server, SSO portal" → `python3 scripts/check_php2shell.py "example.com" --scan-subdomains --json`
- "check example.com, mail.example.com, and sso.example.com" → `python3 scripts/check_php2shell.py "example.com" --subdomains "mail.example.com,sso.example.com" --json`
- "check subdomains but only the first 5" → add `--max-subdomains 5`

### How subdomain discovery works (still fully passive)

With `--scan-subdomains`, the script finds candidates two ways, **neither of which contacts the target's infrastructure**:
- **Certificate Transparency logs** (crt.sh) — a public log of issued SSL/TLS certificates; querying it is a request to crt.sh, not to the target
- **Plain DNS resolution** of a built-in list of common service names (`mail`, `webmail`, `sso`, `portal`, `owa`, `autodiscover`, `admin`, `vpn`, `helpdesk`, etc.) — a DNS lookup doesn't send anything to the host itself

Only subdomains that actually resolve get scanned, and each is scanned with the exact same passive layers as the root domain — no port scanning, no brute-forcing paths beyond the same small common-path list, no probing beyond what a normal visitor's browser would trigger.

## Presenting results to the user

- Lead with the verdict and confidence level, not a raw evidence dump.
- List the evidence that drove the verdict (2-5 bullet points is usually enough; the full JSON is there if they want it).
- If confidence is `inconclusive` or `low`, say plainly that this doesn't prove PHP is absent — many production servers deliberately hide this — and that `php -v` or a hosting control panel is the only ground-truth source if it's their own server.
- If a version number was found, you can mention in passing whether it looks current, but don't frame this as a vulnerability assessment — this skill fingerprints, it doesn't scan for or confirm CVEs. For that, point the user to patching their PHP install and checking official advisories, not to this tool.

## PHP2Shell (CVE-2026-109618 / CVE-2026-109619) version flag

When a PHP version is detected, the script compares the version **string** against the officially patched releases (8.5.12, 8.4.27, 8.3.36, 8.2.35) and reports whether it's older, at/above the fix, or on a branch (5.x/7.x/8.0/8.1) outside the patched table — in which case it explicitly does NOT assume safety, since researchers have warned old branches shouldn't be treated as unaffected.

This is a **passive version-string comparison only** — nothing beyond the requests already made elsewhere in this script. It is not exploit confirmation, and the output always carries a disclaimer covering:
- distro vendors (RHEL/Debian/Ubuntu/etc.) backport fixes without bumping the upstream-looking version string, so this check can both over- and under-report
- the header only reflects the web-facing runtime, which can still be running old code in memory until workers are restarted even after a binary update
- a link to the official PHP advisory/changelog as the authoritative source

When relaying this to the user, keep that framing — report it as "update and verify," not as a yes/no vulnerability confirmation.

## Scope of use — read before scanning anything you don't own

Passive technique lowers *technical* risk but doesn't remove the need for a legitimate reason to check a target, especially once subdomain discovery is involved. Three common scenarios, roughly in order of how settled they are:

1. **Your own site/domain** — no issue.
2. **A client's site under a contract or engagement** — fine if the engagement's scope covers it. Scoped pentest/bug-bounty agreements often define exactly which techniques and which subdomains are in scope; passive subdomain discovery can still turn up vendor-hosted or out-of-scope infrastructure the client didn't intend to include, so check scope before scanning discovered subdomains, not just the root domain.
3. **A third party's site with no relationship to you** — the gray area. A single read-only request to a public homepage (what a browser or search engine does) is very unlikely to raise concern. Enumerating an org's subdomains — especially internal-sounding ones (admin/VPN/SSO/mail) — starts to resemble reconnaissance even when every individual request stays passive, and laws like the US CFAA (and equivalents elsewhere) turn on "unauthorized access," which some courts/regulators have read broadly. This skill doesn't make that determination for you, and Claude using it isn't legal advice.

If the user's request suggests scanning a third party's infrastructure without a stated relationship to it (no "my site," "our client," "we have permission," etc.), surface this ambiguity to them rather than silently proceeding — a short reminder is enough, not a refusal, unless something about the request suggests intent to attack rather than assess.

## Requirements

- Python 3 with the `requests` package (`pip install requests --break-system-packages` if missing)
- Outbound network access to the target URL
