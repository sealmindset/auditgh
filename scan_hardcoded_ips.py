#!/usr/bin/env python3
"""
Scan GitHub repositories for hardcoded IP addresses and hostnames using Semgrep.
"""
import os
import sys
import json
import logging
import subprocess
import argparse
import tempfile
import shutil
import requests
import re
import ipaddress
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin

# Load environment variables
from dotenv import load_dotenv
load_dotenv(override=True)

# Configure GitHub API
GITHUB_API = os.getenv('GITHUB_API', 'https://api.github.com')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_ORG = os.getenv('GITHUB_ORG')

if not GITHUB_TOKEN or not GITHUB_ORG:
    print("Error: GITHUB_TOKEN and GITHUB_ORG must be set in environment or .env file")
    sys.exit(1)

def setup_logging(verbosity: int = 1, quiet: bool = False, level_name: Optional[str] = None):
    """Configure logging based on verbosity or explicit level name."""
    if quiet:
        verbosity = 0
    # Default mapping for verbosity
    level = logging.INFO
    if level_name:
        level_name = str(level_name).upper()
        level = getattr(logging, level_name, logging.INFO)
    else:
        if verbosity > 1:
            level = logging.DEBUG
        elif verbosity == 0:
            level = logging.WARNING

    # Reconfigure root logger
    for h in logging.root.handlers[:]:
        logging.root.removeHandler(h)
    try:
        os.makedirs('logs', exist_ok=True)
    except Exception:
        pass
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('logs/hardcoded_ips_scan.log')
        ]
    )

logger = logging.getLogger(__name__)

class GitHubRepositoryManager:
    """Manages GitHub repository operations."""
    
    def __init__(self, github_token: str, github_org: str, api_url: str = GITHUB_API):
        """Initialize with GitHub credentials."""
        self.github_token = github_token
        self.github_org = github_org
        self.api_url = api_url
        self.headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
    
    def get_repositories(self, include_forks: bool = False, include_archived: bool = False) -> List[Dict]:
        """Fetch all repositories from the organization with fallback to user account.

        Tries /orgs/{name}/repos first. If the first request returns 404, falls back to
        /users/{name}/repos and continues pagination using Link headers.
        """
        # Start with orgs endpoint
        url = f"{self.api_url}/orgs/{self.github_org}/repos?per_page=100"
        repos: List[Dict] = []
        tried_user_fallback = False

        while url:
            response = requests.get(url, headers=self.headers)
            # If org not found on the first hit, retry as user
            if response.status_code == 404 and not tried_user_fallback:
                logger.info(f"Organization '{self.github_org}' not found or inaccessible. Retrying as a user account...")
                tried_user_fallback = True
                url = f"{self.api_url}/users/{self.github_org}/repos?per_page=100"
                continue

            response.raise_for_status()

            for repo in response.json():
                if not include_forks and repo.get('fork'):
                    continue
                if not include_archived and repo.get('archived'):
                    continue
                repos.append({
                    'name': repo['name'],
                    'clone_url': repo['clone_url'],
                    'ssh_url': repo['ssh_url'],
                    'default_branch': repo['default_branch'],
                    'archived': repo.get('archived', False),
                    'fork': repo.get('fork', False)
                })

            # Handle pagination via Link headers
            if 'next' in response.links:
                url = response.links['next']['url']
            else:
                url = None

        return repos
    
    def clone_repository(self, repo: Dict, target_dir: Path) -> Optional[Path]:
        """Clone a repository to the target directory."""
        try:
            repo_name = repo['name']
            clone_dir = target_dir / repo_name
            clone_url = repo.get('clone_url') or ''
            # If we have a token and https URL, inject the token for auth to support private repos
            if self.github_token and clone_url.startswith('https://'):
                # Avoid leaking token in logs; only use for the command argument
                # Format: https://TOKEN:x-oauth-basic@github.com/owner/repo.git
                auth_url = clone_url.replace('https://', f"https://{self.github_token}:x-oauth-basic@", 1)
            else:
                auth_url = clone_url
            
            if clone_dir.exists():
                logger.info(f"Repository {repo_name} already exists, pulling latest changes...")
                try:
                    # Ensure remote fetch uses auth_url if needed
                    if self.github_token and clone_url.startswith('https://'):
                        subprocess.run(
                            ['git', '-C', str(clone_dir), 'remote', 'set-url', 'origin', auth_url],
                            check=True,
                            capture_output=True,
                            text=True
                        )
                    subprocess.run(
                        ['git', '-C', str(clone_dir), 'pull'],
                        check=True,
                        capture_output=True,
                        text=True
                    )
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to update repository {repo_name}: {e.stderr}")
                    return None
            else:
                logger.info(f"Cloning {repo_name}...")
                try:
                    subprocess.run(
                        ['git', 'clone', '--depth', '1', auth_url, str(clone_dir)],
                        check=True,
                        capture_output=True,
                        text=True
                    )
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to clone repository {repo_name}: {e.stderr}")
                    return None
            
            return clone_dir
            
        except Exception as e:
            logger.error(f"Error processing repository {repo.get('name', 'unknown')}: {e}")
            return None


class HardcodedIPScanner:
    """Scanner for detecting hardcoded IP addresses and hostnames in repositories."""
    
    def __init__(self, output_dir: str = "hardcoded_ips_reports", github_token: str = None, github_org: str = None,
                 ignore_private: bool = False, ignore_localhost: bool = False, ignore_example: bool = False):
        """Initialize the scanner with output directory and GitHub credentials."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.rules_file = Path(__file__).parent / "semgrep-rules" / "hardcoded-ips-hostnames.yaml"
        self.github_token = github_token or GITHUB_TOKEN
        self.github_org = github_org or GITHUB_ORG
        self.ignore_private = ignore_private
        self.ignore_localhost = ignore_localhost
        self.ignore_example = ignore_example
        
        if not self.rules_file.exists():
            raise FileNotFoundError(f"Rules file not found: {self.rules_file}")
            
        if self.github_token and self.github_org:
            self.github = GitHubRepositoryManager(self.github_token, self.github_org)
    
    def run_semgrep(self, target_dir: Path) -> Dict[str, Any]:
        """Run Semgrep on the target directory and return results."""
        try:
            cmd = [
                "semgrep",
                "--config", str(self.rules_file),
                "--json",
                "--no-git-ignore",  # Scan all files, including those in .gitignore
                "--metrics", "off",
                "--error",  # Return non-zero exit code on findings
                str(target_dir)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False  # Don't raise exception on non-zero exit code
            )
            
            if result.stderr:
                logger.warning(f"Semgrep stderr: {result.stderr}")
                
            if result.returncode not in (0, 1):  # 0: no findings, 1: findings found
                logger.error(f"Semgrep failed with return code {result.returncode}")
                return {"results": [], "errors": [f"Semgrep failed: {result.stderr}"]}
                
            return json.loads(result.stdout) if result.stdout else {"results": []}
            
        except Exception as e:
            logger.error(f"Error running Semgrep: {e}")
            return {"results": [], "errors": [str(e)]}
    
    def process_repository(self, repo_path: Path) -> Dict[str, Any]:
        """Process a single repository and return findings."""
        repo_name = repo_path.name
        logger.info(f"Scanning repository: {repo_name}")
        
        # Check if the path exists
        if not repo_path.exists():
            logger.error(f"Repository path does not exist: {repo_path}")
            return {
                "repository": repo_name,
                "path": str(repo_path),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "findings": [],
                "findings_count": 0,
                "errors": [f"Repository path does not exist: {repo_path}"]
            }
            
        results = self.run_semgrep(repo_path)

        # Process and format the results
        findings = []
        # Classification regexes
        ipv4_re = re.compile(r"(?<![0-9])((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9])")
        # Simplified IPv6 matcher (covers most forms, not fully RFC 4291 exhaustive)
        ipv6_re = re.compile(r"\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
        # FQDN (must contain a dot and end with TLD >=2 chars)
        fqdn_re = re.compile(r"\b(?=.{1,253}\b)([a-zA-Z0-9](?:[-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}\b")
        # Hostname (single label allowed, RFC 1123 subset)
        hostname_re = re.compile(r"\b[a-zA-Z0-9](?:[-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?\b")

        def classify_indicator(text: str) -> str:
            t = text.strip()
            if not t:
                return "unknown"
            if ipv4_re.search(t):
                return "ipv4"
            if ipv6_re.search(t):
                return "ipv6"
            # Distinguish FQDN vs hostname: prefer FQDN when a dot is present and matches fqdn pattern
            if '.' in t and fqdn_re.fullmatch(t):
                return "fqdn"
            # Avoid classifying purely numeric strings as hostname
            if hostname_re.fullmatch(t) and not t.isdigit():
                return "hostname"
            return "unknown"

        def classify_scope(indicator_type: str, value: str) -> str:
            """Return scope for IP addresses using ipaddress; otherwise 'n/a'.
            Values: private, loopback, link-local, multicast, reserved, unspecified, global, n/a.
            """
            if indicator_type not in ("ipv4", "ipv6"):
                return "n/a"
            try:
                ip = ipaddress.ip_address(value.strip())
            except Exception:
                # Fallback: try stripping brackets (e.g., [::1]) or ports (host:port)
                v = value.strip().lstrip('[').rstrip(']')
                v = v.split('%')[0]  # drop zone index
                v = v.split(':')[0] if indicator_type == 'ipv4' and ':' in v else v
                try:
                    ip = ipaddress.ip_address(v)
                except Exception:
                    return "unknown"
            if ip.is_private:
                return "private"
            if ip.is_loopback:
                return "loopback"
            if ip.is_link_local:
                return "link-local"
            if ip.is_multicast:
                return "multicast"
            if ip.is_reserved:
                return "reserved"
            if ip.is_unspecified:
                return "unspecified"
            # global/public
            return "global"

        # Ignoring helpers
        example_v4 = [
            ipaddress.ip_network('192.0.2.0/24'),
            ipaddress.ip_network('198.51.100.0/24'),
            ipaddress.ip_network('203.0.113.0/24'),
        ]
        example_v6 = [ipaddress.ip_network('2001:db8::/32')]

        def is_example_ip(val: str) -> bool:
            try:
                ip = ipaddress.ip_address(val.strip())
            except Exception:
                return False
            if isinstance(ip, ipaddress.IPv4Address):
                return any(ip in net for net in example_v4)
            return any(ip in net for net in example_v6)

        def is_localhost(val: str, indicator_type: str, scope: str) -> bool:
            if scope == 'loopback':
                return True
            v = val.strip().lower()
            if v in ('localhost',):
                return True
            if indicator_type == 'ipv4' and v in ('127.0.0.1', '0.0.0.0'):
                return True
            if indicator_type == 'ipv6' and v in ('::1',):
                return True
            return False

        def is_example_host(val: str) -> bool:
            v = val.strip().lower().strip('.')
            return v.endswith('example.com') or v.endswith('example.org') or v.endswith('example.net')
        for result in results.get("results", []):
            file_path = result.get("path", "")
            start = result.get("start", {}) or {}
            end = result.get("end", {}) or {}
            s_line = int(start.get("line")) if start.get("line") else 0
            e_line = int(end.get("line")) if end.get("line") else 0
            s_col = int(start.get("col")) if start.get("col") else 0
            e_col = int(end.get("col")) if end.get("col") else 0

            # Attempt to extract exact matched value from source
            matched_value = ""
            try:
                if file_path and os.path.exists(file_path) and s_line > 0 and e_line > 0:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as sf:
                        lines_src = sf.readlines()
                    if s_line == e_line and s_line <= len(lines_src):
                        line_txt = lines_src[s_line-1]
                        if 0 < s_col <= len(line_txt) and 0 < e_col <= len(line_txt) and e_col > s_col:
                            matched_value = line_txt[s_col-1:e_col-1].strip()
                        else:
                            matched_value = line_txt.strip()
                    else:
                        # Multi-line match; join slice
                        chunk = lines_src[s_line-1:e_line]
                        if chunk:
                            chunk[0] = chunk[0][s_col-1:] if s_col>0 and s_col-1 < len(chunk[0]) else chunk[0]
                            chunk[-1] = chunk[-1][:e_col-1] if e_col>0 and e_col-1 <= len(chunk[-1]) else chunk[-1]
                            matched_value = ''.join(chunk).strip()
                if not matched_value:
                    # Fallback: derive from semgrep extra.lines content using regexes
                    extra_lines = result.get("extra", {}).get("lines", "") or ""
                    if not isinstance(extra_lines, str):
                        try:
                            extra_lines = ' '.join(extra_lines)
                        except Exception:
                            extra_lines = str(extra_lines)
                    m = ipv4_re.search(extra_lines) or ipv6_re.search(extra_lines) or fqdn_re.search(extra_lines) or hostname_re.search(extra_lines)
                    matched_value = m.group(0) if m else extra_lines.strip()
            except Exception:
                matched_value = ""

            # Infer key name, if present on the same line
            key_name = ""
            try:
                if file_path and os.path.exists(file_path) and s_line > 0:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as sf:
                        line_txt = sf.readlines()[s_line-1]
                    # Common key patterns: key: value, key = value, "key": value
                    key_match = re.search(r"[\"']?([A-Za-z0-9_\-\.]+)[\"']?\s*[:=]", line_txt)
                    if key_match:
                        key_name = key_match.group(1)
            except Exception:
                key_name = ""

            indicator_type = classify_indicator(matched_value)
            scope = classify_scope(indicator_type, matched_value)

            # Apply ignore filters
            if self.ignore_private and scope == 'private':
                continue
            if self.ignore_localhost and is_localhost(matched_value, indicator_type, scope):
                continue
            if self.ignore_example:
                if indicator_type in ('ipv4', 'ipv6') and is_example_ip(matched_value):
                    continue
                if indicator_type in ('fqdn', 'hostname') and is_example_host(matched_value):
                    continue
            # Build a precise, value-first message while preserving the original rule message
            original_msg = (result.get("extra", {}) or {}).get("message", "")
            precise_msg = f"Matched {indicator_type}: {matched_value}" if matched_value else (original_msg or f"Matched {indicator_type}")
            finding = {
                "check_id": result.get("check_id", ""),
                "path": file_path,
                "start_line": s_line,
                "end_line": e_line,
                "message": precise_msg,
                "severity": result.get("extra", {}).get("severity", "INFO"),
                "lines": result.get("extra", {}).get("lines", []),
                "metadata": {
                    **(result.get("extra", {}).get("metadata", {}) or {}),
                    "original_message": original_msg,
                },
                "key": key_name,
                "value": matched_value,
                "indicator_type": indicator_type,
                "scope": scope
            }
            findings.append(finding)
        
        return {
            "repository": repo_name,
            "path": str(repo_path),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "findings": findings,
            "findings_count": len(findings),
            "errors": results.get("errors", [])
        }
    
    def generate_markdown_report(self, report_data: Dict[str, Any], output_file: Path):
        """Generate a markdown report from the scan results."""
        with open(output_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("# Hardcoded IPs and Hostnames Scan Report\n\n")
            f.write(f"**Generated on:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
            
            # Summary
            f.write("## Summary\n\n")
            f.write(f"- **Repository:** {report_data.get('repository', 'N/A')}\n")
            f.write(f"- **Path:** `{report_data.get('path', 'N/A')}`\n")
            f.write(f"- **Total Findings:** {report_data.get('findings_count', 0)}\n")
            
            # Findings by severity
            severities = {}
            types_count = {"ipv4": 0, "ipv6": 0, "fqdn": 0, "hostname": 0, "unknown": 0}
            for finding in report_data.get('findings', []):
                severity = finding.get('severity', 'UNKNOWN')
                severities[severity] = severities.get(severity, 0) + 1
                t = (finding.get('indicator_type') or 'unknown').lower()
                if t not in types_count:
                    types_count[t] = 0
                types_count[t] += 1
            
            if severities:
                f.write("\n## Findings by Severity\n\n")
                for severity, count in sorted(severities.items()):
                    f.write(f"- **{severity}:** {count}\n")
            
            # Detailed Findings
            if report_data.get('findings'):
                f.write("\n## Detailed Findings\n\n")
                # Make the actual indicator front-and-center; drop the legacy Value column to avoid confusion
                f.write("| Severity | Type | Scope | Indicator | File | Line | Key | Message |\n")
                f.write("|----------|------|-------|-----------|------|------|-----|---------|\n")

                for finding in report_data.get('findings', []):
                    # Get relative path for display
                    file_path = finding.get('path', '')
                    try:
                        file_path = str(Path(file_path).relative_to(report_data['path']))
                    except ValueError:
                        pass

                    # Prepare key/value proof
                    key_disp = finding.get('key', '') or '—'
                    message_disp = finding.get('message', '')
                    typ_disp = finding.get('indicator_type', '') or ''
                    f.write(
                        f"| {finding.get('severity', '')} "
                        f"| {typ_disp} "
                        f"| {finding.get('scope','') or ''} "
                        f"| `{finding.get('value','') or ''}` "
                        f"| `{file_path}` "
                        f"| {finding.get('start_line', '')} "
                        f"| `{key_disp}` "
                        f"| {message_disp} |\n"
                    )

                    # Append source context code block (±2 lines around the match)
                    try:
                        base = Path(report_data.get('path', '') or '.')
                        src_path = Path(finding.get('path') or '')
                        abs_path = src_path if src_path.is_absolute() else (base / src_path)
                        # Read file contents safely
                        context_lines: List[str] = []
                        if abs_path.exists() and abs_path.is_file():
                            with open(abs_path, 'r', encoding='utf-8', errors='ignore') as sf:
                                lines_all = sf.readlines()
                            s_line = int(finding.get('start_line') or 1)
                            e_line = int(finding.get('end_line') or s_line)
                            start_idx = max(1, s_line - 2)
                            end_idx = min(len(lines_all), e_line + 2)
                            # Slice (1-indexed to 0-indexed)
                            snippet = lines_all[start_idx - 1:end_idx]
                            # Best-guess language from extension
                            ext = abs_path.suffix.lower()
                            lang_map = {
                                '.py': 'python', '.js': 'javascript', '.ts': 'typescript', '.java': 'java',
                                '.rb': 'ruby', '.go': 'go', '.c': 'c', '.h': 'c', '.cpp': 'cpp', '.hpp': 'cpp',
                                '.sh': 'bash', '.bash': 'bash', '.yaml': 'yaml', '.yml': 'yaml', '.json': 'json',
                                '.tf': 'hcl', '.ini': 'ini', '.cfg': 'ini', '.toml': 'toml', '.md': 'markdown'
                            }
                            lang = lang_map.get(ext, '')
                            f.write("\n<details><summary>Source context</summary>\n\n")
                            fence = f"```{lang}\n" if lang else "```\n"
                            f.write(fence)
                            # Write snippet with simple line prefixes
                            cur_line = start_idx
                            for line in snippet:
                                # Trim trailing newlines; preserve indentation
                                f.write(f"{line}")
                                cur_line += 1
                            f.write("```\n\n")
                            # Add an annotation for the match position
                            f.write(f"Match at line {s_line}, columns {finding.get('start_line') and (s_col) or '?'}-{finding.get('end_line') and (e_col) or '?'}\n\n")
                            f.write("</details>\n\n")
                    except Exception:
                        # Do not fail report on context issues
                        pass
            
            # Errors
            if report_data.get('errors'):
                f.write("\n## Errors\n\n")
                for error in report_data.get('errors', []):
                    f.write(f"- {error}\n")
            
            f.write("\n---\n")
            f.write("*This report was automatically generated by scan_hardcoded_ips.py*\n")
    
    def scan_repository(self, repo_path: Path) -> Optional[Path]:
        """Scan a single repository and return the path to the report."""
        try:
            if not repo_path.exists() or not repo_path.is_dir():
                logger.error(f"Repository path does not exist or is not a directory: {repo_path}")
                return None
            
            # Process the repository
            report_data = self.process_repository(repo_path)
            
            # Generate output files to per-repo directory without timestamps
            repo_name = repo_path.name
            repo_out_dir = self.output_dir / repo_name
            repo_out_dir.mkdir(parents=True, exist_ok=True)

            json_report = repo_out_dir / f"{repo_name}_hardcoded_ips.json"
            with open(json_report, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)

            md_report = repo_out_dir / f"{repo_name}_hardcoded_ips.md"
            self.generate_markdown_report(report_data, md_report)
            
            logger.info(f"Report generated: {md_report}")
            return md_report
            
        except Exception as e:
            logger.error(f"Error scanning repository {repo_path}: {e}")
            return None


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Scan GitHub repositories for hardcoded IPs and hostnames.')
    
    # GitHub specific arguments
    github_group = parser.add_argument_group('GitHub Options')
    github_group.add_argument('--org', default=GITHUB_ORG,
                           help=f'GitHub organization (default: {GITHUB_ORG})')
    github_group.add_argument('--token', default=GITHUB_TOKEN,
                           help=f'GitHub access token (default: from GITHUB_TOKEN env var)')
    github_group.add_argument('--include-forks', action='store_true',
                           help='Include forked repositories in the scan')
    github_group.add_argument('--include-archived', action='store_true',
                           help='Include archived repositories in the scan')
    github_group.add_argument('--repo',
                           help='Scan a specific repository instead of all repositories')
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('--output-dir', '-o', default='hardcoded_ips_reports',
                         help='Output directory for reports (default: hardcoded_ips_reports)')
    scan_group.add_argument('--cleanup', action='store_true',
                         help='Clean up cloned repositories after scanning')
    
    # General options
    general_group = parser.add_argument_group('General')
    general_group.add_argument('-v', '--verbose', action='count', default=1,
                            help='Increase verbosity (can be specified multiple times)')
    general_group.add_argument('-q', '--quiet', action='store_true',
                            help='Suppress output (overrides --verbose)')
    general_group.add_argument('--loglevel', choices=['DEBUG','INFO','WARNING','ERROR','CRITICAL'],
                            help='Set explicit log level (overrides --verbose/--quiet)')
    general_group.add_argument('--parallel', '-p', type=int, default=1,
                           help='Number of parallel scans to run (default: 1)')

    # Ignore filters
    general_group.add_argument('--ignore-private', action='store_true', help='Ignore private-scope IP addresses')
    general_group.add_argument('--ignore-localhost', action='store_true', help='Ignore localhost/loopback/unspecified endpoints')
    general_group.add_argument('--ignore-example', action='store_true', help='Ignore example IP ranges and example.* domains')
    
    return parser.parse_args()


def scan_repository(scanner: HardcodedIPScanner, repo: Dict, output_dir: Path, cleanup: bool = False) -> Optional[Path]:
    """Clone and scan a single repository."""
    try:
        # Create a temporary directory for cloning
        with tempfile.TemporaryDirectory(prefix=f"{repo['name']}_") as temp_dir:
            temp_path = Path(temp_dir)
            
            # Clone the repository
            clone_dir = scanner.github.clone_repository(repo, temp_path)
            if not clone_dir:
                logger.error(f"Failed to clone repository: {repo['name']}")
                return None
            
            # Scan the repository
            report_path = scanner.scan_repository(clone_dir)
            
            # If the report is already inside the desired output_dir tree, return as-is
            if report_path and report_path.exists():
                try:
                    if report_path.resolve().is_relative_to(output_dir.resolve()):
                        return report_path
                except AttributeError:
                    # Python < 3.9 fallback
                    if str(report_path.resolve()).startswith(str(output_dir.resolve())):
                        return report_path
                # Otherwise move into output_dir root (back-compat), though per-repo path is preferred
                target_path = output_dir / report_path.name
                shutil.move(str(report_path), str(target_path))
                return target_path
            
            return None
            
    except Exception as e:
        logger.error(f"Error scanning repository {repo.get('name', 'unknown')}: {e}")
        return None


def main():
    """Main entry point for the script."""
    args = parse_arguments()
    
    # Configure logging (verbosity/quiet or explicit level)
    setup_logging(verbosity=args.verbose, quiet=args.quiet, level_name=args.loglevel)
    
    # Validate GitHub credentials
    if not args.token:
        logger.error("GitHub token is required. Set GITHUB_TOKEN environment variable or use --token")
        return 1
    
    if not args.org:
        logger.error("GitHub organization is required. Set GITHUB_ORG environment variable or use --org")
        return 1
    
    # logger level already set by setup_logging
    
    try:
        # Initialize the scanner with GitHub credentials
        scanner = HardcodedIPScanner(
            output_dir=args.output_dir,
            github_token=args.token,
            github_org=args.org,
            ignore_private=args.ignore_private,
            ignore_localhost=args.ignore_localhost,
            ignore_example=args.ignore_example,
        )
        
        # Check if Semgrep is installed
        try:
            subprocess.run(
                ["semgrep", "--version"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.error("Semgrep is not installed. Please install it with 'pip install semgrep'")
            return 1
        
        # Create output directory if it doesn't exist
        output_path = Path(args.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Get repositories to scan
        if args.repo:
            # Scan a specific repository
            logger.info(f"Fetching repository: {args.repo}")
            try:
                url = f"{GITHUB_API}/repos/{args.org}/{args.repo}"
                response = requests.get(url, headers={
                    'Authorization': f'token {args.token}',
                    'Accept': 'application/vnd.github.v3+json'
                })
                response.raise_for_status()
                repo_data = response.json()
                
                if not args.include_forks and repo_data.get('fork'):
                    logger.info(f"Skipping forked repository: {args.repo}")
                    return 0
                    
                if not args.include_archived and repo_data.get('archived'):
                    logger.info(f"Skipping archived repository: {args.repo}")
                    return 0
                
                repositories = [{
                    'name': repo_data['name'],
                    'clone_url': repo_data['clone_url'],
                    'ssh_url': repo_data['ssh_url'],
                    'default_branch': repo_data['default_branch'],
                    'archived': repo_data.get('archived', False),
                    'fork': repo_data.get('fork', False)
                }]
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to fetch repository {args.repo}: {e}")
                return 1
        else:
            # Scan all repositories in the organization
            logger.info(f"Fetching repositories from organization: {args.org}")
            try:
                github = GitHubRepositoryManager(args.token, args.org)
                repositories = github.get_repositories(
                    include_forks=args.include_forks,
                    include_archived=args.include_archived
                )
                logger.info(f"Found {len(repositories)} repositories to scan")
            except Exception as e:
                logger.error(f"Failed to fetch repositories: {e}")
                return 1
        
        # Process repositories
        reports = []
        
        if args.parallel > 1:
            # Parallel processing
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            with ThreadPoolExecutor(max_workers=args.parallel) as executor:
                future_to_repo = {
                    executor.submit(
                        scan_repository,
                        scanner,
                        repo,
                        output_path,
                        args.cleanup
                    ): repo for repo in repositories
                }
                
                for future in as_completed(future_to_repo):
                    repo = future_to_repo[future]
                    try:
                        report_path = future.result()
                        if report_path:
                            reports.append(report_path)
                            logger.info(f"Completed scan for {repo['name']}: {report_path}")
                    except Exception as e:
                        logger.error(f"Error processing {repo.get('name', 'unknown')}: {e}")
        else:
            # Sequential processing
            for repo in repositories:
                try:
                    report_path = scan_repository(
                        scanner,
                        repo,
                        output_path,
                        args.cleanup
                    )
                    if report_path:
                        reports.append(report_path)
                        logger.info(f"Completed scan for {repo['name']}: {report_path}")
                except Exception as e:
                    logger.error(f"Error processing {repo.get('name', 'unknown')}: {e}")
        
        # Generate summary report
        if reports:
            summary_report = output_path / "HARDCODED_IPS_SUMMARY.md"
            
            # Count total findings
            total_findings = 0
            findings_by_severity = {}
            
            # Collect data from all reports
            report_data = []
            for report_path in reports:
                try:
                    with open(report_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Extract repo name from parent directory (new per-repo layout)
                    repo_name = report_path.parent.name or report_path.stem.split('_hardcoded_ips_')[0]
                    findings = 0
                    
                    # Parse findings count (robust to markdown formatting)
                    m_total = re.search(r"-\s*\*\*Total Findings:\*\*\s*(\d+)", content)
                    if m_total:
                        findings = int(m_total.group(1))
                        total_findings += findings
                    
                    # Parse findings by severity
                    in_severity_section = False
                    severities = {}
                    
                    for line in content.split('\n'):
                        if line.startswith("## Findings by Severity"):
                            in_severity_section = True
                            continue
                        elif line.startswith('##') and in_severity_section:
                            in_severity_section = False
                            continue
                        if in_severity_section:
                            m = re.match(r"-\s*\*\*([^*]+):\*\*\s*(\d+)", line.strip())
                            if m:
                                severity = m.group(1).strip()
                                count = int(m.group(2))
                                severities[severity] = count
                                # Update global severity counts
                                findings_by_severity[severity] = findings_by_severity.get(severity, 0) + count
                    
                    report_data.append({
                        'name': repo_name,
                        'path': str(report_path.relative_to(output_path)),
                        'findings': findings,
                        'severities': severities
                    })
                    
                except Exception as e:
                    logger.error(f"Error processing report {report_path}: {e}")
            
            # Sort by number of findings (descending)
            report_data.sort(key=lambda x: x['findings'], reverse=True)
            
            # Write summary report
            with open(summary_report, 'w', encoding='utf-8') as f:
                # Header
                f.write("# Hardcoded IPs and Hostnames - Scan Summary\n\n")
                f.write(f"**Organization:** {args.org}\n")
                f.write(f"**Generated on:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                f.write(f"**Total Repositories Scanned:** {len(reports)}\n")
                f.write(f"**Total Findings:** {total_findings}\n\n")
                
                # Summary by Severity
                if findings_by_severity:
                    f.write("## Findings by Severity\n\n")
                    for severity, count in sorted(findings_by_severity.items(), key=lambda x: x[1], reverse=True):
                        f.write(f"- **{severity}:** {count}\n")
                    f.write("\n")
                
                # Repository Summary
                f.write("## Repository Summary\n\n")
                f.write("| Repository | Findings | Severities | Report |\n")
                f.write("|------------|----------|------------|--------|\n")
                
                for repo in report_data:
                    # Format severities
                    severity_str = ", ".join(
                        f"{s}:{c}" for s, c in sorted(repo['severities'].items(), 
                                                     key=lambda x: x[1], 
                                                     reverse=True)
                    )
                    
                    f.write(
                        f"| {repo['name']} | "
                        f"{repo['findings']} | "
                        f"{severity_str} | "
                        f"[{os.path.basename(repo['path'])}]({repo['path']}) |\n"
                    )
                
                # Footer
                f.write("\n---\n")
                f.write("*This report was automatically generated by scan_hardcoded_ips.py*\n")
                f.write("*For detailed findings, please refer to individual repository reports*\n")
            
            logger.info(f"\n{'='*80}")
            logger.info(f"Scan completed successfully!")
            logger.info(f"Total repositories scanned: {len(reports)}")
            logger.info(f"Total findings: {total_findings}")
            logger.info(f"Summary report: {summary_report}")
            logger.info(f"{'='*80}")
        
        return 0 if reports else 1
        
    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=args.verbose)
        return 1

if __name__ == "__main__":
    sys.exit(main())
