# AuditGH UI/UX Context

This document provides the essential context for an LLM or engineering team to understand the AuditGH project’s purpose and how a UI/UX should interact with it. The UI will orchestrate security scans against one or more GitHub repositories by invoking Docker Compose commands exposed by this repo.

## Purpose

AuditGH is a modular, multi-scanner toolkit that audits GitHub organizations and repositories for a broad set of security and hygiene signals. It centralizes discovery, scanning, reporting, and orchestration across tools (SAST, secrets, OSS vulns, IaC, CI/CD, etc.).

Key goals:
- Inventory and scan many repos consistently with sensible defaults.
- Normalize outputs (Markdown + JSON) into predictable, host-mounted directories.
- Provide a single orchestrator to run scanners and produce an aggregate summary.
- Run reliably in air-gapped/corporate environments using Docker Compose.

## High-Level Architecture

- CLI scripts (e.g., `scan_codeql.py`, `scan_gitleaks.py`, `scan_terraform.py`, `scan_binaries.py`, `scan_linecount.py`, etc.) implement per-domain scans.
- Orchestrator (`orchestrate_scans.py`) coordinates multiple scanners, collects logs, and writes a Markdown summary to `markdown/orchestration_summary.md`
- Shared GitHub API layer with rate-limit handling (`src/github/rate_limit.py`) ensures polite pacing, exponential backoff, and stable operation.
- Docker Compose encapsulates tools and dependencies. Host bind mounts surface reports and logs for the UI to present.

## Primary Interaction Model (UI → Docker Compose)

The UI should treat Docker Compose as the execution boundary:
- Prepare bind directories on the host (or prompt the user to run `./prepare_bind_dirs.sh`).
- Ensure `.env` includes `GITHUB_TOKEN` and `GITHUB_ORG` (UI can help users author or validate this file). Never log secrets.
- Build (first run) and execute scans by calling Docker Compose with appropriate arguments.

Common flows:
- Balanced profile (default orchestrator entrypoint):
  - `docker compose up --build`
- Run a subset of scanners:
  - `docker compose run --rm auditgh --only codeql,oss -v`
- Increase scan depth:
  - `docker compose run --rm auditgh --profile deep -vv`
- Run a single scanner (examples):
  - `docker compose run --rm auditgh --only gitleaks -v`
  - `docker compose run --rm auditgh --only binaries -v`
  - `docker compose run --rm auditgh --only linecount -v`

The container entrypoint runs `orchestrate_scans.py`. Flags are passed directly to that script.

## Inputs

- Environment variables (via `.env` or Compose environment):
  - `GITHUB_TOKEN` (required): PAT with `repo` and `read:org` scopes.
  - `GITHUB_ORG` (required): Org/user name to scan.
  - `GITHUB_API` (optional; default `https://api.github.com`).
  - Optional per-scanner report dir overrides (all have sensible defaults).
  - Optional rate-limit tuning:
    - `GITHUB_REQ_DELAY` (default 0.35s)
    - `GITHUB_REQ_MAX_ATTEMPTS` (default 6)
    - `GITHUB_REQ_BACKOFF_BASE` (default 1.7)

- Orchestrator flags the UI can expose:
  - `--only <comma,list>` / `--skip <comma,list>`
  - `--profile {fast|balanced|deep}`
  - `--include-forks`, `--include-archived`
  - `--scanners-parallel N` (how many scanners run concurrently)
  - `-v/-vv/-vvv` for verbosity
  - Scanner-specific flags (see below)

## Outputs (host-mounted)

The following directories are bind-mounted to the host for UI consumption:
- `markdown/` — high-level orchestration summary (`orchestration_summary.md`)
- `logs/` — logs per scanner and `versions.log`
- Per-scanner report folders:
  - `ci_reports/`
  - `codeql_reports/`
  - `oss_reports/`
  - `secrets_reports/`
  - `hardcoded_ips_reports/`
  - `terraform_reports/`
  - `contributors_reports/`
  - `binaries_reports/`
  - `linecount_reports/`

UI should read these folders to surface:
- Per-scanner summaries and links.
- Orchestration summary table (status, duration, links).
- Notable totals (e.g., total LOC, secret findings summary, etc.).

## Scanners (Overview for UI)

Each scanner writes per-repo Markdown/JSON plus its own summary (when applicable). Key ones:

- CI/CD (`cicd`) — Enumerates GitHub Actions workflows/runs/artifacts; flags potential deployment targets.
- Gitleaks (`gitleaks`) — Secrets detection; reports to `secrets_reports/` and summary.
- Hardcoded IPs/Hostnames (`hardcoded_ips`) — Semgrep-based detection with filters for private/localhost/example.
- OSS (`oss`) — Dependency vulnerabilities via `pip-audit`, `safety`, `osv-scanner`; SBOM (Syft) and Grype when present.
- Terraform (`terraform`) — IaC scanning; can use Trivy FS in deep profile; includes KEV/EPSS enrichment.
- CodeQL (`codeql`) — Multi-language SAST; emits SARIF + Markdown.
- Contributors (`contributors`) — Metadata, churn/PR metrics, permissions; can crosslink secrets.
- Binaries (`binaries`) — Inventories binary/executable files; filters by size and ignore globs.
- Linecount (`linecount`) — SAST-relevant line-of-code tally with language/file breakdown.

## Scanner-Specific Flags (UI Surface)

Examples the UI can translate to CLI args:
- Binaries: `--min-size-bytes`, `--ignore-glob` (repeatable)
- Linecount: `--include-ext`, `--exclude-dir`, `--exclude-glob`, `--no-exclude-minified`, `--max-file-bytes`
- Hardcoded IPs: `--ignore-private`, `--ignore-localhost`, `--ignore-example`
- CodeQL: `--max-workers`, `--query-suite`, `--top-n`, `--timeout-seconds`
- Terraform: `--refresh-kev`, `--refresh-epss`, `--with-trivy-fs` (deep)

The UI should conditionally expose flags based on selected scanners to avoid overwhelming users.

## UX Considerations

- Wizard for first-run setup:
  - Validate `.env` presence and required keys.
  - Offer to create required bind directories or run `./prepare_bind_dirs.sh`.
- Scan planner:
  - Let users choose org, subset of scanners, profile, and filters.
  - Show the effective Compose command before execution.
- Run view:
  - Stream orchestrator logs and per-scanner logs.
  - Progress states per scanner (queued, running, done), durations, and exit codes.
- Results view:
  - Render `markdown/orchestration_summary.md`.
  - List available per-scanner summary files and per-repo reports.
  - Surface key totals (e.g., total LOC, total secrets, #repos scanned).
- Export/Share:
  - Allow exporting summaries as a bundle or link to the workspace folder.

## Security & Reliability

- Authentication via `GITHUB_TOKEN` in env; never print tokens to logs or UI.
- Central rate-limit handling (delays, backoff, sleep-until-reset) reduces API errors.
- Docker isolates toolchains and ensures reproducibility across environments.
- No persistent git credential helpers are configured; cloning uses HTTPS token injection.

## Extensibility

- New scanners follow the same pattern: discover repos, clone, scan, write reports.
- Orchestrator can add them to the default set and summary links.
- The UI should not need to change drastically—surface new report folders and summaries dynamically.

## Minimal UI/UX Contract

- Inputs:
  - `.env` with `GITHUB_TOKEN` and `GITHUB_ORG`.
  - Scanner selections and flags (optional, with sensible defaults).
- Action:
  - Run Docker Compose commands and stream results.
- Outputs:
  - Files in mounted report directories + `markdown/orchestration_summary.md` to render.

## Example Compose Invocations (for UI)

- Balanced, default set:
  - `docker compose up --build`
- Deep + two parallel scanners:
  - `docker compose run --rm auditgh --profile deep --scanners-parallel 2 -vv`
- Only secrets + hardcoded IPs with filters:
  - `docker compose run --rm auditgh --only gitleaks,hardcoded_ips --ignore-private --ignore-localhost -v`
- Only linecount:
  - `docker compose run --rm auditgh --only linecount -v`


