# Open Redirect in Pagekit CMS 1.0.18 (CVE-2018-14381 Fix Bypass)

## Overview

| Field | Details |
|-------|---------|
| **Affected Software** | [Pagekit CMS](https://github.com/pagekit/pagekit) (5,454★) |
| **Tested Version** | 1.0.18 (all versions since CVE-2018-14381 fix) |
| **CWE** | CWE-601 (URL Redirection to Untrusted Site) |
| **CVSS 3.1** | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N — **6.1 (Medium)** |
| **Authentication** | None required |
| **Discovered by** | Marxabo Keldibekova |
| **Coordinated by** | [VulnCheck](https://vulncheck.com/) — validated as CVE-eligible, declined assignment due to 7+ year abandonment |

## Summary

Pagekit CMS's authentication controller sanitizes the `redirect` parameter to prevent open redirects — this was the fix for CVE-2018-14381. However, the regex only strips `http://host`, `https://host`, and `//host` prefixes. It does not handle backslash-prefixed hosts like `/\evil.com`.

All major browsers normalize backslashes to forward slashes per the WHATWG URL Standard, so `/\evil.com/phish` resolves as `//evil.com/phish` — a cross-origin redirect.

## Vulnerable Code

`app/system/modules/user/src/Controller/AuthController.php`:

```php
protected function redirect($url)
{
    do {
        $url = preg_replace('#^(https?:)?//[^/]+#', '', $url, 1, $count);
    } while ($count);

    return App::redirect($url);
}
```

The regex does not account for `\/` or `/\` patterns that browsers normalize to `//`.

## Reachable Sinks

- `GET /index.php/user/logout?redirect=/\<host>/<path>` — **unauthenticated**, immediate 302
- `POST /index.php/user/authenticate` (redirect field) — fires after successful login
- `GET /index.php/user/login?redirect=/\<host>/<path>` — echoed into login form, carried through to POST

## Proof of Concept

```bash
# Bypass — backslash prefix (NOT stripped):
curl -i "http://TARGET/index.php/user/logout?redirect=/%5Cevil.com/phish"
# Response: Location: /\evil.com/phish — browser resolves to //evil.com/phish

# Control — confirms sanitizer works for intended cases:
curl -i "http://TARGET/index.php/user/logout?redirect=http://evil.com/phish"
# Response: Location: /phish (correctly stripped)

curl -i "http://TARGET/index.php/user/logout?redirect=//evil.com/phish"
# Response: Location: /phish (correctly stripped)
```

Browser confirmation: headless Chromium navigated to `evil.com`'s actual page after following the redirect.

## Impact

Attacker crafts login link to the real Pagekit domain. Victim sees the genuine domain, logs in with real credentials, then gets silently bounced to the attacker's phishing page. Useful for credential-harvesting, fake update pages, or OAuth token theft.

## Remediation

Replace the strip-known-prefixes regex with a strict check:

```php
protected function redirect($url)
{
    if ($url === '' || $url[0] !== '/' || (isset($url[1]) && ($url[1] === '/' || $url[1] === '\\'))) {
        $url = '/';
    }
    return App::redirect($url);
}
```

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-09-09 | Vulnerability discovered and verified |
| 2026-09-09 | Submitted to VulnCheck + GitHub Security Advisory (GHSA) |
| 2026-09-16 | VulnCheck validates as CVE-eligible but declines — repo 7+ years without commits |
| 2026-09-27 | Public disclosure via GitHub |

## References

- [Pagekit Repository](https://github.com/pagekit/pagekit)
- [CVE-2018-14381 — Original Open Redirect](https://www.cve.org/CVERecord?id=CVE-2018-14381)
- [VulnCheck](https://vulncheck.com/)
