# Docker Guide: Running AuditGH Scanners with Docker Compose

This guide explains how to build and run the complete AuditGH toolchain using Docker Compose. It covers running all scanners in one pass, running a single scanner, discovering which scanners are available, understanding each scanner’s scope, and inspecting arguments and logs.

## Prerequisites

- Docker Desktop (macOS, Windows, or Linux)
- Docker Compose v2 (bundled with modern Docker Desktop)
- A GitHub Personal Access Token with the necessary scopes
  - Required: `repo` (for private repos) and `read:org`

## Environment Setup

Create a `.env` file at the project root or export environment variables in your shell:

```bash
# .env (preferred) or shell exports
GITHUB_TOKEN=ghp_xxx...
GITHUB_ORG=your-org
# Optional (defaults to https://api.github.com)
GITHUB_API=https://api.github.com
```

On macOS zsh:

```bash
export GITHUB_TOKEN=ghp_xxx...
export GITHUB_ORG=your-org
```

## Build the Image

The Dockerfile installs all scanner dependencies (Semgrep, Gitleaks, Trivy, Syft, Grype, OSV-Scanner, CodeQL CLI, govulncheck, bundler-audit, Dependency-Check, plus runtimes: Java/Go/Ruby/npm).

```bash
# Build the image
docker compose build --no-cache
```

Notes:
- On Apple Silicon, `docker-compose.yml` sets `platform: linux/amd64` to ensure consistent tool availability.
- Installer scripts are used for some tools (e.g., Trivy) to avoid flaky APT repositories.

## Run the Orchestrator (Balanced Profile)

The container entrypoint runs the orchestrator by default. The balanced profile is a good starting point.

```bash
docker compose up --build
```

This will:
- Read your `.env` for `GITHUB_TOKEN` and `GITHUB_ORG`
- Run multiple scanners in a sensible sequence
- Write per-scanner reports into mounted local folders
- Create a high-level orchestration summary in `markdown/orchestration_summary.md`

Before running, ensure host bind paths exist (they must be directories):

```bash
mkdir -p ci_reports codeql_reports oss_reports secrets_reports \
         hardcoded_ips_reports terraform_reports contributors_reports \
         binaries_reports linecount_reports markdown logs
```

## Where Reports and Logs Are Written

- Per-scanner reports (mounted to host):
  - `ci_reports/`
  - `codeql_reports/`
  - `oss_reports/`
  - `secrets_reports/`
  - `hardcoded_ips_reports/`
  - `terraform_reports/`
  - `contributors_reports/`
  - `binaries_reports/`
  - `linecount_reports/`
  - `markdown/` (orchestration summary, etc.)
- Logs:
  - `logs/` (including `versions.log` with tool versions for every run)

Inspect versions:

```bash
cat logs/versions.log
```

## Run a Single Scanner

Use the `--only` flag with the orchestrator to run a subset.

```bash
# Example: run only the hardcoded IP/hostname scanner
# (filters to ignore common noise)
docker compose run --rm auditgh \
  --only hardcoded_ips \
  --ignore-private --ignore-localhost --ignore-example \
  -v
```

More examples:

```bash
# Only CodeQL and OSS
docker compose run --rm auditgh --only codeql,oss -v

# Only CI/CD
docker compose run --rm auditgh --only cicd -v
```

## Run Multiple Scanners at Once

Use `--only` with a comma-separated list, and optionally increase parallelization of scanner windows with `--scanners-parallel`.

```bash
# CodeQL + Terraform + OSS, two scanners concurrently
docker compose run --rm auditgh \
  --only codeql,terraform,oss \
  --scanners-parallel 2 \
  -vv
```

## Profiles

- `--profile fast` – lightweight, faster, fewer heavy steps
- `--profile balanced` – default, well-rounded coverage
- `--profile deep` – maximum coverage (heavier, slower)

```bash
# Deep profile with 2 scanners at a time
docker compose run --rm auditgh --profile deep --scanners-parallel 2 -vv
```

## Available Scanners and Coverage

The orchestrator supports the following scanner keys (use with `--only`):

- `cicd` – Discover CI/CD config and metadata (e.g., GitHub Actions YAML)
- `gitleaks` – Secrets detection on current content
- `hardcoded_ips` – Matches IPv4/IPv6/FQDN/hostnames (classification + context)
- `oss` – Open source dependency vulnerabilities (pip-audit, safety, OSV; SBOM via Syft; Grype)
- `terraform` – IaC scanning/enrichment (Trivy FS optional in deep profile; KEV/EPSS refresh)
- `codeql` – SAST using CodeQL CLI across multiple languages; SARIF + Markdown
- `contributors` – Contributors metadata, churn/PR metrics, permissions, and cross-attribution with secrets
- `binaries` – Inventories binary-like and executable files; reports counts and details per repo and an org-level summary
- `linecount` – Tallies SAST-relevant lines of code with language/file breakdown and an org-level summary

Notes:
- Some scanners are heavier by design (CodeQL, deep Terraform). Prefer `--profile balanced` before running `--profile deep`.
- The orchestrator will auto-enable Syft/Grype if installed (they are installed in the image).

## Common Orchestrator Arguments

- `--only <list>` – Limit to a subset (e.g., `--only codeql,oss`)
- `--skip <list>` – Skip specific scanners
- `--profile {fast|balanced|deep}` – Coverage level
- `--include-forks --include-archived` – Include more repos
- `--scanners-parallel N` – Run up to N scanners at a time (default 1)
- `-v/-vv/-vvv` – Increase verbosity (repeatable)
- `--dry-run` – Print planned commands without executing

### Scanner-Specific Highlights

- Hardcoded IPs (`hardcoded_ips`):
  - `--ignore-private` – Filter private-scope IPs
  - `--ignore-localhost` – Filter localhost/loopback/unspecified
  - `--ignore-example` – Filter documentation/example ranges (`example.com`, RFC 5737/3849)
  - Output includes: `Type`, `Scope`, exact `Indicator`, `File`, `Line`, `Key`, `Message`, plus context code fences

- CodeQL (`codeql`):
  - `--max-workers N` – repo-level parallelism
  - `--query-suite <pack>` – query pack (default `code-scanning`)
  - `--top-n <N>` – limit findings in Markdown
  - `--timeout-seconds <sec>` – timeout per repo
  - Optional flags exist for DB recreate/build (in deep profile); check `scan_codeql.py` `--help` for full list

- Terraform (`terraform`):
  - `--refresh-kev --refresh-epss` – update threat intel indices
  - `--with-trivy-fs` (deep profile) – file-system scan for misconfigs/vulns

- OSS (`oss`):
  - `--tools` – choose sub-tools (pip-audit, safety, osv-scanner)
  - `--parse-osv-cvss` – parse CVSS from OSV
  - Auto-enables Syft/Grype when present

- CI/CD (`cicd`), Secrets (`gitleaks`), Contributors (`contributors`):
  - Support the common org/repo selection and verbosity

## Binaries/Executables Scanner

The `binaries` scanner inventories binary-like and executable files in repositories and writes per-repo JSON/Markdown reports into `binaries_reports/<repo>/` and an org-level summary at `binaries_reports/binaries_scan_summary.md`.

Heuristics include executable bit checks, magic headers (ELF/PE/Mach-O), archive signatures (zip/gzip), Windows executable/script extensions, shebangs, and a generic binary content heuristic.

Examples:

```bash
# Run only the binaries scanner via orchestrator
docker compose run --rm auditgh --only binaries -v

# Apply filters in direct script mode inside the container
docker compose run --rm auditgh python scan_binaries.py \
  --org "$GITHUB_ORG" \
  --min-size-bytes 4096 \
  --ignore-glob 'dist/**' --ignore-glob 'build/**' --ignore-glob '*.map' -v
```

## Discover Arguments and Help

You can inspect each scanner’s CLI help from inside the container:

```bash
# Example: discover CodeQL scanner CLI
docker compose run --rm auditgh python scan_codeql.py --help

# Hardcoded IPs help
docker compose run --rm auditgh python scan_hardcoded_ips.py --help
```

To see the orchestrator’s help:

```bash
docker compose run --rm auditgh --help
```

## Troubleshooting

- SSL interception breaks bundler-audit install (Option B)

  Some corporate networks (for example, Zscaler) perform TLS inspection which can cause SSL verification failures when installing Ruby gems. The Dockerfile now implements a resilient install path for `bundler-audit`:

  - It first attempts a normal `gem install bundler-audit` using the system CA bundle.
  - If that fails due to SSL, it automatically retries using the HTTP RubyGems source as a last resort:
    - `gem sources --remove https://rubygems.org/`
    - `gem sources --add http://rubygems.org/`
    - `gem install bundler-audit --clear-sources --source http://rubygems.org/`

  Build normally; the fallback is automatic when needed:

  ```bash
  docker compose build --no-cache
  ```

  Note: HTTP is insecure. Prefer providing a corporate root CA (Option A) when possible.

- **Build interrupted (exit 130):** Rerun `docker compose build --no-cache`.
- **Trivy APT repo ‘stable’ Release file error:** The Dockerfile uses Trivy’s official installer; rebuild to pick up the fix.
- **Debconf Readline error during apt:** Noninteractive debconf is enabled in the Dockerfile; rebuilding should avoid this.
- **Apple Silicon:** The Compose file pins `platform: linux/amd64`. Docker Desktop translates transparently.
- **Tool versions:** Check `logs/versions.log` generated by the orchestrator on every run.

## Examples

```bash
# Balanced profile (default entrypoint via docker compose up)
docker compose up --build

# Deep profile, 2 scanners concurrently
docker compose run --rm auditgh --profile deep --scanners-parallel 2 -vv

# Only hardcoded IPs, with ignore filters
docker compose run --rm auditgh --only hardcoded_ips --ignore-private --ignore-localhost --ignore-example -v

# Only CodeQL and OSS
docker compose run --rm auditgh --only codeql,oss -v
```
