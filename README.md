# AuditGH: GitHub Repository Security Scanner

A modular and extensible security scanning tool that checks GitHub repositories for security vulnerabilities across multiple programming languages.

## Features

- **Modular Architecture**: Easy to extend with new scanners and report formats
- **Multi-language Support**: 
  - Python: `safety` and `pip-audit` for dependency scanning
  - More language scanners coming soon!
- **Comprehensive Scanning**:
  - Dependency vulnerability scanning
  - Static code analysis
  - License compliance checking (planned)
  - Secrets detection (planned)
- **Parallel Processing**: Fast scanning of multiple repositories
- **Detailed Reporting**: Multiple report formats (Markdown, HTML, JSON, Console)
- **Extensible**: Easy to add support for new security tools and languages
- **Cross-Platform**: Works on macOS, Linux, and Windows

## Prerequisites

- Python 3.9+
- Git
- pip (Python package manager)
- (Optional) Virtual environment (recommended)

## Installation

### Using Docker Compose (Recommended)

The easiest way to run AuditGH is using Docker Compose, which handles all dependencies automatically.

1. Copy the example environment file and update with your GitHub token:
   ```bash
   cp .env.example .env
   # Edit .env and set your GitHub token and organization
   ```

2. Build and run the container:
   ```bash
   docker-compose up --build
   ```

### Using pip

```bash
# Install from PyPI (coming soon)
# pip install auditgh

# Or install directly from GitHub
pip install git+https://github.com/your-username/auditgh.git
```

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/auditgh.git
   cd auditgh
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -e .
   ```

4. Install required tools:
   ```bash
   # Python dependency scanners
   pip install safety pip-audit
   
   # Other tools will be added as more scanners are implemented
   ```

## Usage

### Docker Compose Usage

1. Basic run (orchestrator, balanced profile):
   ```bash
   docker compose up --build
   ```

2. Prepare host bind paths (must be directories):
   These directories are mounted into the container for reports and logs. Ensure they exist on the host to avoid permission or ownership surprises.
   ```bash
   mkdir -p ci_reports codeql_reports oss_reports secrets_reports \
            hardcoded_ips_reports terraform_reports contributors_reports \
            binaries_reports linecount_reports markdown logs
   ```

3. Run with custom orchestrator parameters:
   ```bash
   docker compose run --rm auditgh \
     --org your-org-name \
     --profile deep \
     --include-forks --include-archived \
     --scanners-parallel 2 -vv
   ```

4. View reports:
   ```bash
   # Reports are written to per-scanner folders mounted from the host
   ls -l codeql_reports/
   ls -l oss_reports/
   ls -l secrets_reports/
   ls -l hardcoded_ips_reports/
   ls -l terraform_reports/
   ls -l ci_reports/
   ls -l contributors_reports/
   ls -l binaries_reports/
   ls -l linecount_reports/
   ls -l markdown/
   ```

5. Sanity check toolchain versions:
   ```bash
   # Each orchestrator run writes a versions log
   cat logs/versions.log
   ```

Authentication note:
- GitHub authentication uses `GITHUB_TOKEN` and `GITHUB_ORG` environment variables. There is no need to mount a `.git-credentials` file into the container.

### Orchestrator (multi-scanner)

Use the top-level orchestrator to run multiple scanners with one command and produce a single summary.

Prereqs:
- Ensure `.env` contains `GITHUB_TOKEN` and `GITHUB_ORG` (or pass `--org/--token`).
- Some scanners rely on external tools (e.g., CodeQL, Semgrep, Gitleaks, Syft, Grype, Trivy). The orchestrator will skip optional integrations when tools are not present.

Examples:

```bash
# Balanced profile (default)
./orchestrate_scans.py -v

# Fast profile (lighter scans)
./orchestrate_scans.py --profile fast -v

# Deep profile (maximum coverage) with 2 scanners running in parallel
./orchestrate_scans.py --profile deep --scanners-parallel 2 -vv

# Run only CodeQL and OSS scanners
./orchestrate_scans.py --only codeql,oss -v
```

Outputs:
- Summary: `markdown/orchestration_summary.md`
- Per-scanner reports are written to their respective folders (e.g., `codeql_reports/`, `oss_reports/`, `terraform_reports/`, `ci_reports/`, `secrets_reports/`, `hardcoded_ips_reports/`, `contributors_reports/`).
- Per-scanner reports are written to their respective folders (e.g., `codeql_reports/`, `oss_reports/`, `terraform_reports/`, `ci_reports/`, `secrets_reports/`, `hardcoded_ips_reports/`, `contributors_reports/`, `binaries_reports/`).
- Per-scanner reports are written to their respective folders (e.g., `codeql_reports/`, `oss_reports/`, `terraform_reports/`, `ci_reports/`, `secrets_reports/`, `hardcoded_ips_reports/`, `contributors_reports/`, `binaries_reports/`, `linecount_reports/`).

### Binaries/Executables Scanner

The `binaries` scanner inventories binary-like and executable files in repositories and writes per-repo JSON/Markdown reports into `binaries_reports/<repo>/` and an org-level summary at `binaries_reports/binaries_scan_summary.md`.

Heuristics include executable bit checks, magic headers (ELF/PE/Mach-O), archive signatures (zip/gzip), Windows executable/script extensions, shebangs, and a generic binary content heuristic.

Examples:

```bash
# Run only the binaries scanner via orchestrator
./orchestrate_scans.py --only binaries -v

# Direct usage: scan a single repo
python scan_binaries.py --repo owner/repo -v

# Apply filters: skip files smaller than 4 KB and ignore build artifacts
python scan_binaries.py --org your-org \
  --min-size-bytes 4096 \
  --ignore-glob 'dist/**' --ignore-glob 'build/**' --ignore-glob '*.map' -v
```

### Linecount (SAST-Relevant LOC) Scanner

The `linecount` scanner tallies lines of code that a typical SAST tool (e.g., Sonar/Snyk) would scan, with sensible defaults for included extensions and excluded vendor/build artifacts. Per-repo reports are written to `linecount_reports/<repo>/` and an org-level summary to `linecount_reports/linecount_scan_summary.md`.

Examples:

```bash
# Run only the linecount scanner via orchestrator
./orchestrate_scans.py --only linecount -v

# Direct usage: scan a single repo
python scan_linecount.py --repo owner/repo -v

# Customize filters: add extensions, exclude dirs/globs, include minified code
python scan_linecount.py --org your-org \
  --include-ext .proto --include-ext .vue \
  --exclude-dir dist --exclude-dir build \
  --exclude-glob '*.min.js' \
  --no-exclude-minified -v
```

### Local Usage

### Basic Usage

```bash
# Set your GitHub token
export GITHUB_TOKEN=your_github_token

# Scan an organization
python -m auditgh --org your-org-name

# Scan a specific repository
python -m auditgh --repo owner/repo-name
```

### Advanced Options

```bash
# Include forked and archived repositories
python -m auditgh --org your-org-name --include-forks --include-archived

# Specify number of parallel workers (default: 4)
python -m auditgh --org your-org-name --max-workers 8

# Change report format (markdown, html, json, console)
python -m auditgh --org your-org-name --format html

# Specify scanners to run
python -m auditgh --org your-org-name --scanners safety pip-audit

# Keep temporary files after scanning
python -m auditgh --org your-org-name --keep-temp
```

## Output

Reports are saved in the `reports` directory by default (configurable with `--output-dir`). For each repository, you'll find:

- `security_report_{repo_name}_{timestamp}.{md|html|json|txt}`: Detailed security report
- Scanner-specific output files in the repository's subdirectory

### Report Formats

- **Markdown** (default): Human-readable format with detailed findings
- **HTML**: Interactive HTML report with filtering and search
- **JSON**: Machine-readable format for further processing
- **Console**: Simple text output to the terminal

## Command-Line Options

```
usage: python -m auditgh [-h] [--org ORG] [--repo REPO] [--token TOKEN]
                        [--include-forks] [--include-archived]
                        [--scanners {all,safety,pip-audit} ...]
                        [--max-workers MAX_WORKERS] [--output-dir OUTPUT_DIR]
                        [--format {markdown,html,json,console}] [--keep-temp]
                        [-v] [--debug] [--version]

Audit GitHub repositories for security vulnerabilities.

options:
  -h, --help            show this help message and exit
  --org ORG             GitHub organization name
  --repo REPO           Specific repository to scan (format: owner/name)
  --token TOKEN         GitHub token (or set GITHUB_TOKEN env var)
  --include-forks       Include forked repositories (default: False)
  --include-archived    Include archived repositories (default: False)
  --scanners {all,safety,pip-audit} ...
                        Scanners to run (default: safety pip-audit)
  --max-workers MAX_WORKERS
                        Maximum number of parallel scans (default: 4)
  --output-dir OUTPUT_DIR
                        Output directory for reports (default: reports)
  --format {markdown,html,json,console}
                        Report format (default: markdown)
  --keep-temp           Keep temporary files after scanning (default: False)
  -v, --verbose         Enable verbose output
  --debug               Enable debug output
  --version             Show version and exit
```

## Examples

### Scan an organization with verbose output
```bash
python -m auditgh --org your-org-name -v
```

### Scan a specific repository with HTML output
```bash
python -m auditgh --repo owner/repo-name --format html
```

### Include forked and archived repositories
```bash
python -m auditgh --org your-org-name --include-forks --include-archived
```

### Use a custom report directory and increase concurrency
```bash
python -m auditgh --org your-org-name --output-dir my_reports --max-workers 8
```

### Run only specific scanners
```bash
python -m auditgh --org your-org-name --scanners safety
```

## Output

Reports are saved in the `vulnerability_reports` directory (or custom directory if specified) with the following naming convention:
- `{repo_name}_safety.txt` - Output from safety
- `{repo_name}_pip_audit.md` - Output from pip-audit

## GitHub Token

Create a personal access token with the following scopes:
- `repo` - Required to access private repositories
- `read:org` - Required to list organization repositories

Set the token as an environment variable:
```bash
export GITHUB_TOKEN=your_github_token  # Linux/macOS
set GITHUB_TOKEN=your_github_token    # Windows Command Prompt
$env:GITHUB_TOKEN="your_github_token" # PowerShell
```

Or pass it directly to the command:
```bash
python -m auditgh --org your-org-name --token your_github_token
```

## Development

### Adding a New Scanner

1. Create a new Python file in `src/scanners/` (or appropriate subdirectory for the language)
2. Create a class that inherits from `BaseScanner`
3. Implement the required methods:
   - `is_applicable()`: Check if the scanner is applicable to the repository
   - `scan()`: Perform the actual scan and return a `ScanResult`
4. Add the scanner to the appropriate `__init__.py` file
5. Update the scanner registry in the main application

### Running Tests

```bash
# Install test dependencies
pip install -e ".[test]"

# Run tests
pytest
```

### Building the Package

```bash
# Install build tools
pip install build

# Build the package
python -m build
```

## License

MIT
