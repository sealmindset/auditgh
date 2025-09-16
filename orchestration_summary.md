# Orchestration Summary
Generated: 2025-09-15T17:57:51.479114

Profile: deep
Parallel scanners: 2
Organization: sealmindset
Token detected: yes


## Results

| Scanner | Status | Exit Code | Duration | Log | Key Reports |
|---------|--------|-----------:|---------:|-----|------------|
| gitleaks | success | 0 | 0:00:53.803424 | [gitleaks.log](logs/gitleaks.log) | [secrets_scan_summary.md](secrets_reports/secrets_scan_summary.md) |
| cicd | findings | 1 | 0:04:48.234910 | [cicd.log](logs/cicd.log) | [ci_summary.md](ci_reports/ci_summary.md) |
| hardcoded_ips | success | 0 | 0:00:54.952433 | [hardcoded_ips.log](logs/hardcoded_ips.log) | [HARDCODED_IPS_SUMMARY.md](hardcoded_ips_reports/HARDCODED_IPS_SUMMARY.md) |
| oss | success | 0 | 0:01:23.664763 | [oss.log](logs/oss.log) | [oss_summary.md](oss_reports/oss_summary.md) |
| terraform | success | 0 | 0:01:03.248596 | [terraform.log](logs/terraform.log) | [terraform_scan_summary.md](terraform_reports/terraform_scan_summary.md) |
| codeql | success | 0 | 0:31:32.234417 | [codeql.log](logs/codeql.log) | [codeql_summary.md](codeql_reports/codeql_summary.md) |
| contributors | success | 0 | 0:01:13.120053 | [contributors.log](logs/contributors.log) | [contributors_reports](contributors_reports) |
