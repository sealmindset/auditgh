# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `README.md` with setup and usage instructions.
- `requirements.txt` for Python dependencies.
- `.gitignore` to exclude sensitive files and development artifacts.
- `--repo` CLI argument to scan a single repository (e.g., `--repo owner/repo` or `--repo repo` defaulting to `--org`). If omitted, all repositories in `--org` are scanned.
- Optional Dagda integration for container image analysis:
  - Flags: `--dagda-url`, `--docker-image`
  - Outputs: `{repo}_dagda.json`, `{repo}_dagda.md`
- Optional Syft integration for SBOM generation:
  - Runs on cloned repo directory; if `--docker-image` is provided, also runs on the image
  - Flag: `--syft-format` (default: `cyclonedx-json`)
  - Outputs: `{repo}_syft_repo.json`/`.md` and (if image) `{repo}_syft_image.json`/`.md`

### Planned
- Add structured, parseable output (e.g., SARIF/JSON) and a consolidated summary report.
- Add CI workflow and containerized execution (Docker) with pinned tool versions.
- Add `--dry-run` mode and additional dependency discovery (Pipenv, setup.cfg/py, requirements.in).

## [0.3.0] - 2025-09-11

### Added
- Bandit and Trivy FS scanners integrated:
  - Bandit: writes `<repo>_bandit.json` and `<repo>_bandit.md` with summaries and sample findings.
  - Trivy (fs): writes `<repo>_trivy_fs.json` and `<repo>_trivy_fs.md` with severity summaries.
- Semgrep taint-mode optional pass (`--semgrep-taint`) and exploitable flows section.
- Gitleaks integration with secrets findings section.
- Policy gate and `policy.yaml` link surfaced in summary.
- Threat intel enrichment (KEV/EPSS) for Grype and Top 5 ranking:
  - Added KEV/EPSS badges and an explicit `Exploitability` column to "Top 5 Vulnerabilities".
  - New "Threat Intel" counts block and a "Threat Intel Diagnostics" subsection.
- VEX support passthrough for Grype (`--vex <file>`) and sample VEX file `struts2_exploitable.vex.json` (CVE-2017-5638 set to exploitable for Struts2).
- Summary now lists Bandit and Trivy report links in "Detailed Reports" when present.
- `install_dependencies.sh` expanded to install all scanners on macOS/Linux/Windows.
  - Optional flags: `--no-java`, `--no-go`, `--sanity-only`.
  - Post-install sanity check prints versions for all tools.

### Changed
- Summary table status for Bandit/Trivy is derived from JSON results rather than exit codes (avoids "success" when findings exist).
- Top 5 now considers Trivy FS vulnerabilities in addition to Grype to avoid empty results when VEX suppresses Grype findings.
- Improved repository information with contributors, languages, activity, and enhanced Top 5 ranking (KEV > EPSS > severity).

### Fixed
- Resolved `IndentationError` in `run_pip_audit_scan()` and removed placeholder lines.
- Hardened summary generation with additional try/except blocks around sections to ensure the summary always writes.

### Notes
- For Grype + VEX, best results occur when scanning an SBOM with bom-refs matching the VEX `affects` entries.

## [0.2.0] - 2025-09-10

### Added
- CLI options via `argparse` for org, API base, report directory, inclusion flags, worker count, and verbosity (`-v`, `-vv`).
- Logging with levels and timestamps; scanner outputs are captured and written to files.
- Parallel processing using `ThreadPoolExecutor` with configurable `--max-workers`.

### Changed
- GitHub authentication now uses `Authorization: Bearer <token>` and validates token presence at startup.
- HTTP calls use a `requests.Session` with retries/backoff and timeouts.
- Repository cloning is shallow (`--depth=1 --filter=blob:none`) and prefers `ssh_url` when available.
- Repositories that are forked or archived are skipped by default (override with `--include-forks` and `--include-archived`).
- Dependency discovery expanded to PEP 621 (`project.dependencies`) and Poetry (`tool.poetry.dependencies`).
- Temporary requirement files created from `pyproject.toml` are cleaned up after scanning.
- `safety` and `pip-audit` invocations now capture stdout/stderr and return codes; results saved to per-repo files.

## [0.1.0] - 2025-09-10

### Added
- Initial Python script `scan_repos.py` that:
  - Fetches repositories from a GitHub organization via the REST v3 API with pagination.
  - Clones repositories into a temporary working directory.
  - Detects Python dependencies via `requirements.txt` or PEP 621 `pyproject.toml` (`project.dependencies`).
  - Runs `safety` and `pip-audit` against discovered dependencies.
  - Writes per-repo vulnerability reports into `vulnerability_reports/`.
  - Cleans up temporary clone directories on completion.

### Known Issues
- `GITHUB_TOKEN` may be `None`, resulting in an invalid `Authorization` header. Token should be required and validated at startup.
- `clone_url` often requires credentials for private repos; support for `ssh_url` or embedded token over HTTPS is needed.
- `requests.get` calls lack timeouts and retry/backoff; risk of hangs and rate-limit failures.
- `safety` flags may not be correct for current versions (`--save-html` with `--output text` mismatch). Pin `safety` version and adjust CLI accordingly.
- Only PEP 621 dependencies are parsed from `pyproject.toml`; Poetry (`tool.poetry.dependencies`) and other ecosystems are not handled.
- Temporary requirements file created from `pyproject.toml` is not explicitly cleaned per repo.
- No aggregated summary across repos; reports are individual text/markdown files.
- Limited error handling: subprocess failures for scanners are ignored (`check=False`) without surfacing status.

### Security Notes
- Avoid echoing tokens. Consider using `Bearer` scheme for the header and validate presence.
- Prefer least-privilege tokens; document required scopes.

[Unreleased]: https://example.com/compare/v0.2.0...HEAD
[0.3.0]: https://example.com/compare/v0.2.0...v0.3.0
[0.2.0]: https://example.com/compare/v0.1.0...v0.2.0
[0.1.0]: https://example.com/releases/tag/v0.1.0
