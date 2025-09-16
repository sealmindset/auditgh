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

1. Basic scan of an organization:
   ```bash
   docker-compose up --build
   ```

2. Scan with custom parameters:
   ```bash
   docker-compose run --rm auditgh \
     --org your-org-name \
     --include-forks \
     --include-archived \
     --max-workers 4
   ```

3. View reports:
   ```bash
   # Reports are available in the vulnerability_reports directory
   ls -l vulnerability_reports/
   ```

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
