# Gitleaks Secret Scan Report

**Repository:** adjustTheBed
**Scanned on:** 2025-09-19 08:29:05
**Command:** `gitleaks detect --source /tmp/repo_scan_agqdyff3/adjustTheBed --report-format json --report-path /work/reports/adjustTheBed/adjustTheBed_gitleaks.json --verbose --no-git`

## Found 1 potential secrets

### Secret 1
- **File:** `/tmp/repo_scan_agqdyff3/adjustTheBed/adjustTheBed-main.php`
- **Line:** 321
- **Rule ID:** generic-api-key
- **Description:** N/A
- **Secret:** `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`
- **Match:** `keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'`
- **Commit:** 
- **Author:**  ()
- **Date:** 

---

