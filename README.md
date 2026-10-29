# PHP2Shell Check — Claude Skill

A Claude Skill that passively checks whether a website (and optionally its subdomains) runs PHP, confirms the version where possible, and flags exposure to **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619) — using only ordinary, non-intrusive HTTP requests. No exploitation, no malformed input, no port scanning, no fuzzing.

Works inside Claude conversations (Claude.ai, Claude Code, Cowork) once installed — just ask in plain language, e.g. *"check example.com for PHP2Shell exposure"*.

> **This is a defensive/awareness tool, not an exploit.** It compares version strings against official patch data — it never attempts to trigger or confirm the underlying vulnerability. See [Scope & limitations](#scope--limitations) and [Ethics & authorization](#️-ethics--authorization--read-before-scanning-anything-you-dont-own) before pointing it at anything you don't own.

## What it checks

Each signal is weighted and combined into a scored verdict (`high` / `medium` / `low` / `inconclusive`) rather than trusting any single header:

| Layer | Signal | Weight |
|---|---|---|
| Headers | `X-Powered-By: PHP/x.y.z`, `Server:` banner | Strong |
| Cookies | `PHPSESSID` present | Strong |
| Common paths | `wp-login.php`, `administrator/index.php`, etc. resolve to `.php` | Moderate |
| Markup | `<meta name="generator">` for WordPress/Joomla/Drupal/MediaWiki | Moderate |
| Markup | `.php` form action attributes | Weak |

Optionally extends the same checks to subdomains, discovered passively via:
- **Certificate Transparency logs** (crt.sh) — queries a public cert log, never touches the target
- **DNS resolution** of a built-in wordlist (`mail`, `webmail`, `sso`, `portal`, `owa`, `autodiscover`, `admin`, `vpn`, `helpdesk`, etc.) — a DNS lookup doesn't contact the target's server
- A **manual list** you supply yourself

## PHP2Shell version flag (CVE-2026-109618 / CVE-2026-109619)

When a PHP version is detected, the tool compares the version **string** against the officially patched releases:

| Branch | Fixed in |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 5.x / 7.x / 8.0 / 8.1 | *Not in the officially patched table — not assumed safe* |

This is a **version-string comparison only**, not exploit confirmation — no crafted or malformed requests are ever sent, and no attempt is made to actually trigger or confirm the vulnerability. Every result ships with this disclaimer:

> This is a version-STRING comparison only, not confirmation of exploitability. Distribution vendors (RHEL, Debian, Ubuntu, etc.) frequently backport security fixes without changing the upstream-looking version number, which can make this check both under- and over-report. The header seen here also only reflects the web-facing PHP runtime, which is the one that actually matters for this vulnerability — but it cannot see whether FPM/mod_php workers have been restarted after a binary update. Verify server-side and consult the official PHP advisory before concluding anything about actual exposure.

Treat a flagged result as "update and verify," never as a confirmed vulnerability.

## Requirements

- Python 3.7+
- [`requests`](https://pypi.org/project/requests/)
- A Claude product that supports Skills (Claude.ai, Claude Code, or Cowork) with code execution enabled

## Installation

### Option 1 — Claude.ai / Cowork (`.skill` file)

1. Download `php2shell-check.skill` from this repo.
2. In Claude, open **Settings → Capabilities → Skills** (or the relevant Skills/Capabilities panel for your product).
3. Upload / import the `.skill` file, or drag it into a chat and click **Save skill** on the file card.
4. Confirm it appears in your enabled skills list.

This runs entirely inside Claude's own sandboxed code-execution environment — nothing is installed on your device, and Python/`requests` are set up automatically if missing.

### Option 2 — Claude Code

1. Clone this repo (or copy the `php2shell-check/` folder) into your skills directory, e.g.:
   ```bash
   git clone <this-repo-url> ~/.claude/skills/php2shell-check
   ```
2. Make sure the folder contains:
   ```
   php2shell-check/
   ├── SKILL.md
   └── scripts/
       └── check_php2shell.py
   ```
3. Install the Python dependency:
   ```bash
   pip install requests --break-system-packages
   ```
4. Restart/reload Claude Code so it picks up the new skill.

### Option 3 — Run the script standalone (no Claude needed)

```bash
git clone <this-repo-url>
cd php2shell-check
pip install requests --break-system-packages
python3 scripts/check_php2shell.py example.com
```

## Usage

### Inside Claude (natural language)

Just ask — Claude maps your request to the right CLI flags automatically:

- *"Check example.com for PHP2Shell exposure"*
- *"Check example.com and scan their subdomains, mail and SSO included"*
- *"Check example.com, mail.example.com, and sso.example.com"*
- *"Check subdomains but only the first 5 found"*
- *"Give me a summary for my manager"* / *"a non-technical report for the team"*

No CLI menu is shown to you — it's all conversational. Claude follows `SKILL.md`'s instructions to pick the right flags from what you said, and defaults to a sensible choice (no subdomain scanning, technical report format) when you don't specify.

### Command line

```
check_php2shell.py <url> [options]

  --json                     Output raw JSON only (shorthand for --report json)
  --report {text,json,management}
                              Output format (default: text):
                                text        per-host technical detail, for IT/engineers
                                json        raw structured data, for tooling/pipelines
                                management  plain-language, traffic-light risk summary
                                            for non-technical stakeholders
  --org-label NAME            Display name for the scope in the management report
                               (defaults to the root domain)
  --scan-subdomains          Auto-discover subdomains (crt.sh + wordlist) and scan each
  --subdomains LIST_OR_FILE  Comma-separated hostnames, or a file (one per line)
  --max-subdomains N         Cap auto-discovered subdomains scanned (default 15)
  --no-subdomains            Explicit no-op — subdomain scanning is opt-in anyway
```

**Examples:**

```bash
# Basic check
python3 scripts/check_php2shell.py example.com

# JSON output (for piping into other tools)
python3 scripts/check_php2shell.py example.com --json

# Include auto-discovered subdomains
python3 scripts/check_php2shell.py example.com --scan-subdomains

# Limit to 5 discovered subdomains
python3 scripts/check_php2shell.py example.com --scan-subdomains --max-subdomains 5

# Manually specify subdomains
python3 scripts/check_php2shell.py example.com --subdomains "mail.example.com,sso.example.com"

# From a file
python3 scripts/check_php2shell.py example.com --subdomains hosts.txt

# Plain-language summary for management, with a friendly org name
python3 scripts/check_php2shell.py example.com --scan-subdomains --report management --org-label "Acme Corp"
```

### Sample output — technical (`--report text`, default)

```
=== Root target ===
Target: https://example.com/
Verdict: Likely running PHP (confirmed by a strong signal, e.g. header or cookie).
Confidence: high
Version hint(s): 8.2.12
Evidence:
  [strong]      headers  X-Powered-By header reports PHP/8.2.12
  [strong]      cookies  PHPSESSID cookie present
  [moderate]    markup   Page markup indicates WordPress (PHP-based) version 6.4
PHP2Shell (CVE-2026-109618/109619) version check:
  - PHP 8.2.12: version string is older than the patched release for its branch (fixed: 8.2.35)
  Note: This is a version-STRING comparison only, not confirmation of exploitability. ...

Passively discovered 6 candidate subdomain(s) via certificate transparency
logs and a common-name wordlist; scanning 6 (capped at 15).

=== https://mail.example.com/ ===
  Target: https://mail.example.com/
  Verdict: Probably running PHP (multiple moderate signals, no direct confirmation).
  Confidence: medium
  ...
```

### Sample output — management summary (`--report management`)

```
===============================================
 PHP EXPOSURE & PATCH STATUS -- SUMMARY REPORT
===============================================
Organization scope:  Acme Corp + 4 related subdomains
Scan date:            2026-10-29
Prepared for:         Management / IT leadership

OVERALL RISK:  🔴 ACTION NEEDED

-----------------------------------------------
WHAT WE FOUND
-----------------------------------------------
Of 5 web properties checked, 2 appear to run PHP in a state
older than, or outside, the official security fix for a
critical, actively-discussed vulnerability (PHP2Shell, Oct 2026).

This does not confirm those systems have been or can be
attacked -- it means they should be verified and prioritized
for patching.

-----------------------------------------------
SITES NEEDING ATTENTION
-----------------------------------------------
 🔴 High   example.com
        -> PHP version detected is older than the patched release
 🔴 High   mail.example.com
        -> PHP version is on a branch not covered by the official fix
           -- do not assume safe
 🟡 Medium sso.example.com
        -> PHP detected but version could not be confirmed from
           outside -- verify with IT
 🟢 2 other host(s) showed no signals requiring action.

-----------------------------------------------
RECOMMENDED NEXT STEPS
-----------------------------------------------
 1. Share this report with whoever manages hosting/IT for the
    flagged sites.
 2. Ask them to confirm the actual PHP version running in
    production (not just the installed binary -- workers must
    be restarted after patching).
 3. Prioritize patching based on sensitivity (login/SSO/mail
    systems first).
 4. Re-run this check after patching to confirm.

-----------------------------------------------
IMPORTANT CAVEATS
-----------------------------------------------
- This is an outside, non-intrusive check -- it reads only
  what a normal visitor's browser would see. It cannot
  guarantee a system is safe OR unsafe; it flags things worth
  a closer look by IT.
- A green/OK result does not prove a system doesn't run PHP
  -- some servers deliberately hide this information, which is
  actually good security practice.
- Distribution vendors sometimes patch security issues without
  changing the visible version number, so a flagged host may
  already be patched internally.

(Full technical evidence available in the JSON report for
your IT team.)
===============================================
```

## Choosing a report format

| Situation | Use |
|---|---|
| Debugging, piping into other tools, CI | `--report json` / `--json` |
| Talking to engineers/IT directly | `--report text` (default) |
| Reporting to management, a client, or anyone non-technical | `--report management` |

Risk levels in the management report:
- 🔴 **High** — version confirmed older than the PHP2Shell fix, *or* on a branch (5.x/7.x/8.0/8.1) outside the officially patched table (treated as "don't assume safe," never silently marked OK)
- 🟡 **Medium** — PHP detected but version not visible from outside; worth confirming internally
- 🟢 **OK** — no actionable signal found (covers both "confirmed patched" and "no PHP detected")

## Scope & limitations

- **Passive only.** No malformed input, no error-triggering, no port scanning, no fuzzing, no exploitation of any kind (including the PHP2Shell CVEs themselves).
- **Not a vulnerability scanner in the active sense.** The PHP2Shell check is a version-string comparison, not exploit confirmation — it cannot tell you with certainty whether a specific host is actually exploitable, and it should never be treated as proof either way.
- **Absence ≠ proof.** Many production servers deliberately strip identifying headers and rewrite URLs. A low/inconclusive or "OK" result does not mean a target is PHP-free, and a "patched" version string does not guarantee the running workers have actually picked up the fix.

## ⚖️ Ethics & authorization — read before scanning anything you don't own

**"Passive" lowers technical risk. It does not remove the need for a legitimate reason to check a target**, and it does not substitute for authorization. Three common scenarios:

### 1. Your own site or domain
No issue — you're the owner, there's no authorization question.

### 2. A client's site under a contract or engagement
Fine if the signed engagement scope covers it. Watch `--scan-subdomains` specifically: passive discovery can surface infrastructure the client doesn't actually control — third-party-hosted portals, SaaS subdomains, acquired-company domains not yet folded into scope. Scanning those is outside authorization even though the technique itself is passive. **Check discovered subdomains against the written scope before scanning them** — "it resolved under their domain" is not the same as "it's in scope."

### 3. A third party with no relationship to you
This is genuinely unsettled, not just a hedge:
- A single passive request to a public homepage is what every browser and search-engine crawler already does, continuously, to every site on the internet.
- Enumerating an organization's subdomain footprint — especially internal-sounding names like `admin`/`vpn`/`sso`/`mail` — can resemble the reconnaissance phase of an attack to the party on the receiving end, even when every individual request is technically passive. Laws like the US CFAA (and equivalents elsewhere) turn on "unauthorized access," and some courts/prosecutors have read that broadly — intent and pattern have mattered in some cases, not just the specific technique used.
- Many organizations' security policies and terms of service explicitly prohibit scanning of any kind, regardless of technique. Violating a ToS isn't necessarily criminal, but it's a real exposure (civil claims, access termination, vendor relationship damage) separate from criminal law.

**This tool does not make that determination for you, and using it is not legal advice.** If you don't have a stated relationship to a target (ownership, contract, written permission), treat subdomain enumeration against it as something to think carefully about, not a default action — and when in doubt, consult a lawyer, especially before doing this at any scale.

## Repository structure

```
php2shell-check/
├── SKILL.md              # Claude Skill definition (name, trigger description, usage instructions)
├── README.md              # This file
└── scripts/
    └── check_php2shell.py # The detection script
```

## License

Add your preferred license here (e.g. MIT).
