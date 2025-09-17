#!/usr/bin/env python3
"""
Scan GitHub repositories that contain Terraform for misconfigurations and vulnerabilities
using Checkov and Trivy. Modeled on scan_gitleaks_fixed.py for consistency.

What it does per repo (if Terraform is detected):
- Runs Checkov (IaC misconfigurations): checkov -d <repo>
- Runs Trivy config (IaC misconfigurations): trivy config <repo>
- Optionally runs Trivy filesystem scan for vulnerabilities in dependencies/binaries: trivy fs <repo>

Outputs per repo into terraform_reports/<repo_name>/:
- <repo>_checkov.json, <repo>_checkov.md
- <repo>_trivy_config.json, <repo>_trivy_config.md
- (optional) <repo>_trivy_fs.json, <repo>_trivy_fs.md

Generates a summary at terraform_reports/terraform_scan_summary.md
"""

import argparse
import concurrent.futures
import datetime
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import csv
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from src.github.rate_limit import make_rate_limited_session, request_with_rate_limit
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(override=True)


class TFConfig:
    """Configuration for the Terraform scanner."""

    def __init__(self):
        self.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        self.ORG_NAME = os.getenv("GITHUB_ORG")
        if not self.GITHUB_TOKEN:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        if not self.ORG_NAME:
            raise ValueError("GITHUB_ORG environment variable is required")
        self.GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com")
        self.REPORT_DIR = os.path.abspath(os.getenv("TERRAFORM_REPORT_DIR", "terraform_reports"))
        self.KEV_CACHE = os.path.abspath(os.getenv("KEV_CACHE", ".cache/kev.json"))
        self.EPSS_CACHE = os.path.abspath(os.getenv("EPSS_CACHE", ".cache/epss.csv"))
        self.CLONE_DIR = None
        self.HEADERS = {
            "Authorization": f"token {self.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "auditgh-scan-terraform",
        }


config: Optional[TFConfig] = None


def setup_logging(verbosity: int = 1):
    level = logging.INFO
    if verbosity > 1:
        level = logging.DEBUG
    elif verbosity == 0:
        level = logging.WARNING
    try:
        os.makedirs('logs', exist_ok=True)
    except Exception:
        pass
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(), logging.FileHandler('logs/terraform_scan.log')],
    )


def make_session() -> requests.Session:
    return make_rate_limited_session(config.GITHUB_TOKEN, user_agent="auditgh-terraform")


def _filter_page_repos(page_repos: List[Dict[str, Any]], include_forks: bool, include_archived: bool) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for repo in page_repos or []:
        if (not include_forks and repo.get('fork')) or (not include_archived and repo.get('archived')):
            continue
        out.append(repo)
    return out


def get_all_repos(session: requests.Session, include_forks: bool = False, include_archived: bool = False) -> List[Dict[str, Any]]:
    repos: List[Dict[str, Any]] = []
    page = 1
    per_page = 100
    is_user_fallback = False
    while True:
        base = "users" if is_user_fallback else "orgs"
        url = f"{config.GITHUB_API}/{base}/{config.ORG_NAME}/repos"
        params = {"type": "all", "per_page": per_page, "page": page}
        try:
            resp = request_with_rate_limit(session, 'GET', url, params=params, timeout=30, logger=logging.getLogger('terraform.api'))
            if not is_user_fallback and page == 1 and resp.status_code == 404:
                logging.info(f"Organization '{config.ORG_NAME}' not found or inaccessible. Retrying as a user account...")
                is_user_fallback = True
                page = 1
                repos.clear()
                continue
            resp.raise_for_status()
            page_repos = resp.json() or []
            if not page_repos:
                break
            repos.extend(_filter_page_repos(page_repos, include_forks, include_archived))
            if len(page_repos) < per_page:
                break
            page += 1
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching repositories: {e}")
            break
    return repos


def get_single_repo(session: requests.Session, repo_identifier: str) -> Optional[Dict[str, Any]]:
    if '/' in repo_identifier:
        owner, repo_name = repo_identifier.split('/', 1)
    else:
        owner = config.ORG_NAME
        repo_name = repo_identifier
    url = f"{config.GITHUB_API}/repos/{owner}/{repo_name}"
    try:
        response = request_with_rate_limit(session, 'GET', url, timeout=30, logger=logging.getLogger('terraform.api'))
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching repository {repo_identifier}: {e}")
        return None


def clone_repo(repo: Dict[str, Any]) -> Optional[str]:
    if not config.CLONE_DIR:
        config.CLONE_DIR = tempfile.mkdtemp(prefix="repo_scan_tf_")
    repo_name = repo['name']
    clone_url = repo['clone_url']
    if not config.GITHUB_TOKEN and 'ssh_url' in repo:
        clone_url = repo['ssh_url']
    elif config.GITHUB_TOKEN and clone_url.startswith('https://'):
        if '@' not in clone_url:
            clone_url = clone_url.replace('https://', f'https://x-access-token:{config.GITHUB_TOKEN}@')
    repo_path = os.path.join(config.CLONE_DIR, repo_name)
    try:
        if os.path.exists(repo_path):
            logging.info(f"Updating existing repository: {repo_name}")
            subprocess.run(['git', '-C', repo_path, 'fetch', '--all'], check=True, capture_output=True, text=True)
            subprocess.run(['git', '-C', repo_path, 'reset', '--hard', 'origin/HEAD'], check=True, capture_output=True, text=True)
        else:
            logging.info(f"Cloning repository: {repo_name}")
            subprocess.run(['git', 'clone', '--depth', '1', clone_url, repo_path], check=True, capture_output=True, text=True)
        return repo_path
    except subprocess.CalledProcessError as e:
        logging.error(f"Error cloning/updating repository {repo_name}: {e.stderr}")
        return None


def repo_has_terraform(repo_path: str) -> bool:
    for root, _dirs, files in os.walk(repo_path):
        if any(fn.endswith('.tf') for fn in files):
            return True
    return False


# -----------------------------
# Enrichment helpers (Phase 1)
# -----------------------------
def load_kev(cache_path: str) -> Dict[str, Dict[str, Any]]:
    """Load CISA KEV JSON cache into a dict keyed by CVE."""
    try:
        if not os.path.exists(cache_path):
            return {}
        with open(cache_path, 'r') as f:
            data = json.load(f)
        items = []
        if isinstance(data, dict) and 'vulnerabilities' in data:
            items = data.get('vulnerabilities') or []
        elif isinstance(data, dict) and 'data' in data:
            items = data.get('data') or []
        elif isinstance(data, list):
            items = data
        kev: Dict[str, Dict[str, Any]] = {}
        for it in items:
            cve = it.get('cveID') or it.get('cve') or it.get('CVE')
            if cve:
                kev[str(cve).upper()] = it
        return kev
    except Exception:
        return {}


def load_epss(cache_path: str) -> Dict[str, Dict[str, Any]]:
    """Load EPSS CSV cache into a dict keyed by CVE."""
    epss: Dict[str, Dict[str, Any]] = {}
    try:
        if not os.path.exists(cache_path):
            return epss
        with open(cache_path, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve = (row.get('cve') or '').upper()
                if not cve:
                    continue
                epss[cve] = {
                    'epss': float(row.get('epss') or 0.0),
                    'percentile': float(row.get('percentile') or 0.0),
                    'date': row.get('date') or ''
                }
    except Exception:
        return epss
    return epss


def refresh_kev(cache_path: str) -> bool:
    """Fetch KEV JSON and write to cache. Returns True on success."""
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        logging.info("Refreshing KEV cache from CISA")
        import urllib.request
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = resp.read()
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, 'wb') as f:
            f.write(data)
        return True
    except Exception as e:
        logging.warning(f"Failed to refresh KEV: {e}")
        return False


def refresh_epss(cache_path: str) -> bool:
    """Fetch EPSS CSV bulk and write to cache. Returns True on success."""
    try:
        url = "https://api.first.org/data/v1/epss?download=true"
        logging.info("Refreshing EPSS cache from FIRST")
        import urllib.request
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = resp.read()
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, 'wb') as f:
            f.write(data)
        return True
    except Exception as e:
        logging.warning(f"Failed to refresh EPSS: {e}")
        return False


def check_tooling() -> None:
    """Log presence and versions of required external tools."""
    tools = [
        ("git", ["git", "--version"]),
        ("checkov", ["checkov", "--version"]),
        ("trivy", ["trivy", "--version"]),
    ]
    for name, cmd in tools:
        path = shutil.which(name)
        if not path:
            logging.warning(f"Tool not found on PATH: {name}")
            continue
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            ver = (res.stdout or res.stderr or '').strip().splitlines()[0] if (res.stdout or res.stderr) else ''
            logging.info(f"{name}: {ver}")
        except Exception:
            logging.info(f"{name}: present at {path}")


def run_checkov(repo_path: str, repo_name: str, report_dir: str, *, no_guidelines: bool = True, download_external_modules: bool = True,
                guidelines_path: Optional[str] = None) -> Dict[str, Any]:
    os.makedirs(report_dir, exist_ok=True)
    out_json = os.path.join(report_dir, f"{repo_name}_checkov.json")
    out_md = os.path.join(report_dir, f"{repo_name}_checkov.md")
    if not shutil.which('checkov'):
        msg = "Checkov is not installed. Install: pipx install checkov or pip install checkov"
        logging.error(msg)
        with open(out_md, 'w') as f:
            f.write(f"# Checkov Error\n\n{msg}\n")
        return {"success": False, "error": msg, "report_file": out_md}
    try:
        modules_path = os.path.join(report_dir, ".checkov_modules")
        os.makedirs(modules_path, exist_ok=True)
        cmd = ['checkov', '-d', repo_path, '--output', 'json', '--framework', 'terraform', '--quiet', '--output-file', out_json]
        if download_external_modules:
            cmd += ['--download-external-modules', 'true', '--external-modules-download-path', modules_path]
        logging.info(f"Running Checkov on {repo_name}")
        # Environment: skip guidelines fetch to avoid SSL errors to Bridgecrew public endpoint
        env = dict(os.environ)
        if no_guidelines:
            env['CHECKOV_SKIP_GUIDELINES'] = '1'
        # Add extra offline/env hardening to avoid any network lookups for guidelines/mappings
        env.setdefault('BC_SKIP_MAPPING', '1')
        env.setdefault('CHECKOV_SKIP_MAPPING', '1')
        env.setdefault('CHECKOV_OFFLINE', '1')
        env.setdefault('BC_RUN_LOCAL', '1')
        env.setdefault('REQUESTS_CA_BUNDLE', '')  # ensure no custom CA breaks offline expectations
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_path, env=env)
        # If Checkov failed due to guidelines fetch, try once more with stricter flags
        if result.returncode != 0 and (result.stderr or '').lower().find('guidelines') != -1:
            logging.warning("Checkov failed due to guidelines fetch; retrying in strict offline mode")
            env['CHECKOV_SKIP_GUIDELINES'] = '1'
            env['BC_SKIP_MAPPING'] = '1'
            env['CHECKOV_SKIP_MAPPING'] = '1'
            env['CHECKOV_OFFLINE'] = '1'
            env['BC_RUN_LOCAL'] = '1'
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_path, env=env)
        # Load JSON output (prefer file/dir written by --output-file; fallback to stdout)
        parsed: Dict[str, Any] = {}
        # Some Checkov versions create a directory at the output path and place files like results_json.json inside
        if os.path.isdir(out_json):
            candidate = os.path.join(out_json, 'results_json.json')
            if os.path.exists(candidate):
                try:
                    with open(candidate, 'r') as jf:
                        parsed = json.load(jf)
                except Exception:
                    parsed = {}
        elif os.path.exists(out_json) and os.path.getsize(out_json) > 0:
            try:
                with open(out_json, 'r') as jf:
                    parsed = json.load(jf)
            except Exception:
                parsed = {}
        if not parsed:
            try:
                parsed = json.loads(result.stdout or '{}')
                # Persist for downstream steps
                with open(out_json, 'w') as jf:
                    json.dump(parsed, jf, indent=2)
            except json.JSONDecodeError:
                parsed = {}
        # Write MD summary
        with open(out_md, 'w') as f:
            f.write(f"# Checkov Report\n\n")
            f.write(f"**Repository:** {repo_name}\n\n")
            # Simple TOC for navigation
            f.write("- [Failed Checks](#failed-checks)\n\n")
            # Determine local guidelines presence early for messaging
            gp = guidelines_path or 'guidelines'
            has_local_guidelines = bool(gp and os.path.exists(gp))
            if no_guidelines:
                if has_local_guidelines:
                    f.write(f"- Guidelines fetch skipped (CHECKOV_SKIP_GUIDELINES=1). Using local guidelines at `{gp}`.\n")
                else:
                    f.write("- Guidelines fetch skipped (CHECKOV_SKIP_GUIDELINES=1) to avoid external API dependency. BC_* mapping not enriched.\n")
            if download_external_modules:
                f.write(f"- External modules will be downloaded to: `{modules_path}`\n")
            if result.returncode in (0, 1):
                # Checkov uses exit code 0 even when findings exist by default
                try:
                    failed = 0
                    passed = 0
                    if isinstance(parsed, dict):
                        failed = len(parsed.get('results', {}).get('failed_checks', []) or [])
                        passed = len(parsed.get('results', {}).get('passed_checks', []) or [])
                    f.write(f"- Failed Checks: {failed}\n")
                    f.write(f"- Passed Checks: {passed}\n")
                    # If local guidelines JSON exists, enrich with a table
                    guideline_map = {}
                    if has_local_guidelines:
                        try:
                            with open(gp, 'r') as gf:
                                gl = json.load(gf)
                            # Build a map for fast lookup. Support common shapes.
                            if isinstance(gl, dict) and 'data' in gl:
                                items = gl.get('data') or []
                            elif isinstance(gl, list):
                                items = gl
                            else:
                                items = []
                            for it in items:
                                # Try several keys for BC id
                                key = it.get('id') or it.get('bc_id') or it.get('bcId') or it.get('guideline_id')
                                if key:
                                    guideline_map[str(key)] = {
                                        'title': it.get('title') or it.get('name') or '',
                                        'description': it.get('description') or it.get('guideline') or ''
                                    }
                        except Exception:
                            guideline_map = {}
                    failed_checks = (parsed.get('results', {}) or {}).get('failed_checks', []) if isinstance(parsed, dict) else []
                    if failed_checks:
                        f.write("\n## Failed Checks\n\n")
                        f.write("| Severity | Check ID | Check | Resource | File | Description | Guideline | Doc | Remediation |\n")
                        f.write("|---------:|---------|-------|----------|------|-------------|-----------|-----|------------|\n")
                        for fc in failed_checks:
                            check_id = fc.get('check_id') or ''
                            check_name = fc.get('check_name') or ''
                            bc_id = fc.get('bc_id') or fc.get('guideline') or ''
                            file_path = fc.get('file_path') or fc.get('file_abs_path') or ''
                            resource = fc.get('resource') or fc.get('resource_address') or ''
                            severity = fc.get('severity') or ''
                            guide = ''
                            remediation = ''
                            description = ''
                            doc_url = ''
                            # Prefer local guidelines when BC id maps
                            if bc_id and guideline_map:
                                g = guideline_map.get(str(bc_id))
                                if g:
                                    title = g.get('title') or ''
                                    desc = g.get('description') or ''
                                    remediation = g.get('remediation') or ''
                                    guide = title or (desc[:120] + '…' if desc else '')
                                    description = desc or ''
                                    # Try guideline references/urls if provided by local guidelines
                                    for ref_key in ('url', 'link', 'reference'):
                                        if not doc_url and g.get(ref_key):
                                            doc_url = g.get(ref_key)
                                    if not doc_url:
                                        refs = g.get('references') or []
                                        if isinstance(refs, list) and refs:
                                            doc_url = refs[0]
                            # Fall back to Checkov-provided fields
                            if not description:
                                description = fc.get('description') or fc.get('guideline') or ''
                            # Derive doc link from finding if present
                            if not doc_url:
                                cand = fc.get('guideline') or fc.get('url') or ''
                                if isinstance(cand, str) and cand.startswith('http'):
                                    doc_url = cand
                            # Truncate long fields for table readability
                            if remediation:
                                remediation = (remediation[:80] + '…') if len(remediation) > 80 else remediation
                            if description:
                                description = (description[:120] + '…') if len(description) > 120 else description
                            doc_cell = f"[link]({doc_url})" if doc_url else ""
                            f.write(f"| {severity} | {check_id} | {check_name} | {resource} | `{file_path}` | {description} | {guide} | {doc_cell} | {remediation} |\n")
                except Exception:
                    f.write("- Parsed results not available; see JSON output.\n")
            else:
                f.write(f"- Non-zero exit code: {result.returncode}\n")
                if result.stderr:
                    # Suppress known guideline SSL noise lines
                    filtered = []
                    for line in (result.stderr or '').splitlines():
                        low = line.lower()
                        if 'guidelines' in low or 'api0.prismacloud.io' in low:
                            continue
                        filtered.append(line)
                    if filtered:
                        f.write("\n````\n" + "\n".join(filtered) + "\n````\n")
        # Also emit a compact summary markdown from parsed JSON for quick consumption
        try:
            sum_md = os.path.join(report_dir, f"{repo_name}_checkov_summary.md")
            total_failed = len((parsed.get('results', {}) or {}).get('failed_checks', []) or []) if isinstance(parsed, dict) else 0
            total_passed = len((parsed.get('results', {}) or {}).get('passed_checks', []) or []) if isinstance(parsed, dict) else 0
            total_skipped = len((parsed.get('results', {}) or {}).get('skipped_checks', []) or []) if isinstance(parsed, dict) else 0
            # Aggregate by rule and by file
            by_rule: Dict[str, int] = {}
            by_file: Dict[str, int] = {}
            for fc in ((parsed.get('results', {}) or {}).get('failed_checks', []) or []):
                rid = fc.get('check_id') or 'UNKNOWN'
                by_rule[rid] = by_rule.get(rid, 0) + 1
                fp = fc.get('file_path') or fc.get('file_abs_path') or 'UNKNOWN'
                by_file[fp] = by_file.get(fp, 0) + 1
            with open(sum_md, 'w') as sf:
                sf.write(f"# Checkov Summary (Parsed JSON)\n\n")
                sf.write(f"**Repository:** {repo_name}\n\n")
                sf.write(f"- Failed: {total_failed}\n")
                sf.write(f"- Passed: {total_passed}\n")
                sf.write(f"- Skipped: {total_skipped}\n\n")
                if by_rule:
                    sf.write("## Top Rules by Failures\n\n")
                    sf.write("| Rule | Failures |\n")
                    sf.write("|------|---------:|\n")
                    for rid, cnt in sorted(by_rule.items(), key=lambda x: (-x[1], x[0]))[:50]:
                        sf.write(f"| {rid} | {cnt} |\n")
                if by_file:
                    sf.write("\n## Top Files by Failures\n\n")
                    sf.write("| File | Failures |\n")
                    sf.write("|------|---------:|\n")
                    for fp, cnt in sorted(by_file.items(), key=lambda x: (-x[1], x[0]))[:50]:
                        sf.write(f"| `{fp}` | {cnt} |\n")
        except Exception:
            pass
        return {"success": True, "returncode": result.returncode, "output_file": out_json, "report_file": out_md}
    except Exception as e:
        msg = f"Error running Checkov: {e}"
        logging.error(msg)
        return {"success": False, "error": msg, "report_file": out_md}


def run_trivy_config(repo_path: str, repo_name: str, report_dir: str) -> Dict[str, Any]:
    os.makedirs(report_dir, exist_ok=True)
    out_json = os.path.join(report_dir, f"{repo_name}_trivy_config.json")
    out_md = os.path.join(report_dir, f"{repo_name}_trivy_config.md")
    if not shutil.which('trivy'):
        msg = "Trivy is not installed. Install: brew install trivy or see https://aquasecurity.github.io/trivy/"
        logging.error(msg)
        with open(out_md, 'w') as f:
            f.write(f"# Trivy Config Error\n\n{msg}\n")
        return {"success": False, "error": msg, "report_file": out_md}
    try:
        cmd = [
            'trivy', 'config', '--scanners', 'misconfig', '--format', 'json', '--quiet', '--skip-dirs', '.git', '--output', out_json, repo_path
        ]
        logging.info(f"Running Trivy config on {repo_name}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        with open(out_md, 'w') as f:
            f.write(f"# Trivy Config Report\n\n")
            f.write(f"**Repository:** {repo_name}\n\n")
            if result.returncode in (0, 1):
                try:
                    with open(out_json, 'r') as jf:
                        parsed = json.load(jf)
                    # Trivy config JSON structure varies; summarize counts
                    misconfigs = 0
                    if isinstance(parsed, dict) and 'Results' in parsed:
                        for r in parsed.get('Results') or []:
                            for mc in r.get('Misconfigurations') or []:
                                misconfigs += 1
                    f.write(f"- Misconfigurations: {misconfigs}\n")
                except Exception:
                    f.write("- Could not parse JSON output; see JSON file.\n")
            else:
                f.write(f"- Non-zero exit code: {result.returncode}\n")
                if result.stderr:
                    f.write(f"\n````\n{result.stderr}\n````\n")
        return {"success": True, "returncode": result.returncode, "output_file": out_json, "report_file": out_md}
    except Exception as e:
        msg = f"Error running Trivy config: {e}"
        logging.error(msg)
        return {"success": False, "error": msg, "report_file": out_md}


def run_trivy_fs(repo_path: str, repo_name: str, report_dir: str, kev_cache: Optional[str] = None, epss_cache: Optional[str] = None) -> Dict[str, Any]:
    os.makedirs(report_dir, exist_ok=True)
    out_json = os.path.join(report_dir, f"{repo_name}_trivy_fs.json")
    out_md = os.path.join(report_dir, f"{repo_name}_trivy_fs.md")
    if not shutil.which('trivy'):
        msg = "Trivy is not installed. Install: brew install trivy or see https://aquasecurity.github.io/trivy/"
        logging.error(msg)
        with open(out_md, 'w') as f:
            f.write(f"# Trivy FS Error\n\n{msg}\n")
        return {"success": False, "error": msg, "report_file": out_md}
    try:
        kev = load_kev(kev_cache or ".cache/kev.json")
        epss = load_epss(epss_cache or ".cache/epss.csv")
        cmd = [
            'trivy', 'fs', '--format', 'json', '--quiet', '--skip-dirs', '.git', '--output', out_json, repo_path
        ]
        logging.info(f"Running Trivy filesystem scan on {repo_name}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        with open(out_md, 'w') as f:
            f.write(f"# Trivy Filesystem Report\n\n")
            f.write(f"**Repository:** {repo_name}\n\n")
            if result.returncode in (0, 1):
                try:
                    with open(out_json, 'r') as jf:
                        parsed = json.load(jf)
                    vuln_count = 0
                    rows: List[Dict[str, Any]] = []
                    if isinstance(parsed, dict) and 'Results' in parsed:
                        for r in parsed.get('Results') or []:
                            target = r.get('Target') or ''
                            for v in r.get('Vulnerabilities') or []:
                                vuln_count += 1
                                cve = (v.get('VulnerabilityID') or '').upper()
                                pkg = v.get('PkgName') or ''
                                installed = v.get('InstalledVersion') or ''
                                severity = v.get('Severity') or ''
                                fixed = v.get('FixedVersion') or ''
                                e = epss.get(cve) if cve else None
                                k = kev.get(cve) if cve else None
                                rows.append({
                                    'target': target,
                                    'cve': cve,
                                    'package': pkg,
                                    'installed': installed,
                                    'severity': severity,
                                    'fixed': fixed,
                                    'epss': e.get('epss') if e else None,
                                    'percentile': e.get('percentile') if e else None,
                                    'kev': True if k else False,
                                })
                    f.write(f"- Vulnerabilities: {vuln_count}\n")
                    if rows:
                        f.write("\n## Vulnerabilities (with KEV/EPSS)\n\n")
                        f.write("| Severity | CVE | Package | Installed | Fixed In | EPSS | Percentile | KEV |\n")
                        f.write("|---------:|-----|---------|----------:|---------:|-----:|-----------:|----:|\n")
                        # Sort by KEV, EPSS desc, severity
                        def sort_key(r: Dict[str, Any]):
                            return (0 if r.get('kev') else 1, -(r.get('percentile') or 0.0), r.get('severity') or '')
                        for r in sorted(rows, key=sort_key):
                            epss_val = r.get('epss')
                            perc = r.get('percentile')
                            f.write(
                                f"| {r.get('severity','')} | {r.get('cve','')} | {r.get('package','')} | {r.get('installed','')} | {r.get('fixed','')} | "
                                f"{(epss_val if epss_val is not None else '')} | {(perc if perc is not None else '')} | {'Y' if r.get('kev') else ''} |\n"
                            )
                except Exception:
                    f.write("- Could not parse JSON output; see JSON file.\n")
            else:
                f.write(f"- Non-zero exit code: {result.returncode}\n")
                if result.stderr:
                    f.write(f"\n````\n{result.stderr}\n````\n")
        return {"success": True, "returncode": result.returncode, "output_file": out_json, "report_file": out_md}
    except Exception as e:
        msg = f"Error running Trivy fs: {e}"
        logging.error(msg)
        return {"success": False, "error": msg, "report_file": out_md}


def process_repo(repo: Dict[str, Any], report_dir: str, with_trivy_fs: bool = False,
                 allow_guidelines: bool = False, no_download_external_modules: bool = False,
                 guidelines_path: Optional[str] = None,
                 kev_cache: Optional[str] = None, epss_cache: Optional[str] = None):
    repo_name = repo['name']
    repo_full_name = repo['full_name']
    logging.info(f"Processing repository: {repo_full_name}")
    repo_report_dir = os.path.join(report_dir, repo_name)
    os.makedirs(repo_report_dir, exist_ok=True)
    repo_path = clone_repo(repo)
    if not repo_path:
        logging.error(f"Failed to clone repository: {repo_full_name}")
        return {"repo": repo_name, "skipped": True}
    try:
        if not repo_has_terraform(repo_path):
            logging.info(f"No Terraform detected in {repo_full_name}; skipping.")
            return {"repo": repo_name, "skipped": True}
        res_ckv = run_checkov(
            repo_path,
            repo_name,
            repo_report_dir,
            no_guidelines=(not allow_guidelines),
            download_external_modules=(not no_download_external_modules),
            guidelines_path=guidelines_path,
        )
        res_tvc = run_trivy_config(repo_path, repo_name, repo_report_dir)
        res_tvf = None
        if with_trivy_fs:
            res_tvf = run_trivy_fs(repo_path, repo_name, repo_report_dir, kev_cache=kev_cache, epss_cache=epss_cache)
        return {
            "repo": repo_name,
            "checkov": res_ckv,
            "trivy_config": res_tvc,
            "trivy_fs": res_tvf,
            "skipped": False,
        }
    except Exception as e:
        logging.error(f"Error processing repository {repo_full_name}: {e}")
        return {"repo": repo_name, "error": str(e), "skipped": False}
    finally:
        try:
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
        except Exception as e:
            logging.error(f"Error cleaning up repository {repo_full_name}: {e}")


def generate_summary_report(report_dir: str, all_results: List[Dict[str, Any]]):
    summary_file = os.path.join(report_dir, "terraform_scan_summary.md")
    scanned = [r for r in all_results if not r.get('skipped')]
    skipped = [r for r in all_results if r.get('skipped')]
    with open(summary_file, 'w') as f:
        f.write("# Terraform Security Scan Summary\n\n")
        f.write(f"**Scan Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("## Overview\n")
        f.write(f"- Total repositories processed: {len(all_results)}\n")
        f.write(f"- Repositories scanned (with Terraform): {len(scanned)}\n")
        f.write(f"- Repositories skipped (no Terraform): {len(skipped)}\n\n")
        # Per-repo table summary
        f.write("## Per-Repository Summary\n\n")
        f.write("| Repository | Checkov Failed | Trivy Misconfigs | Trivy FS Vulns |\n")
        f.write("|------------|---------------:|-----------------:|---------------:|\n")
        for r in scanned:
            repo = r.get('repo')
            # extract counts
            failed_ckv = ''
            misconf_tvc = ''
            vulns_tvf = ''
            try:
                # checkov
                ckv_json = r.get('checkov', {}).get('output_file')
                if ckv_json and os.path.exists(ckv_json):
                    with open(ckv_json, 'r') as jf:
                        ckv_parsed = json.load(jf)
                    failed_ckv = len(ckv_parsed.get('results', {}).get('failed_checks', []) or [])
            except Exception:
                pass
            try:
                tvc_json = r.get('trivy_config', {}).get('output_file')
                if tvc_json and os.path.exists(tvc_json):
                    with open(tvc_json, 'r') as jf:
                        tvc_parsed = json.load(jf)
                    count = 0
                    if isinstance(tvc_parsed, dict) and 'Results' in tvc_parsed:
                        for rr in tvc_parsed.get('Results') or []:
                            for mc in rr.get('Misconfigurations') or []:
                                count += 1
                    misconf_tvc = count
            except Exception:
                pass
            try:
                tvf_json = r.get('trivy_fs', {}).get('output_file') if r.get('trivy_fs') else None
                if tvf_json and os.path.exists(tvf_json):
                    with open(tvf_json, 'r') as jf:
                        tvf_parsed = json.load(jf)
                    count_v = 0
                    if isinstance(tvf_parsed, dict) and 'Results' in tvf_parsed:
                        for rr in tvf_parsed.get('Results') or []:
                            for vv in rr.get('Vulnerabilities') or []:
                                count_v += 1
                    vulns_tvf = count_v
            except Exception:
                pass
            f.write(f"| {repo} | {failed_ckv} | {misconf_tvc} | {vulns_tvf} |\n")
        if skipped:
            f.write("\n## Skipped Repositories (no Terraform detected)\n\n")
            for r in skipped:
                f.write(f"- {r.get('repo')}\n")
    logging.info(f"Summary report generated: {summary_file}")


def main():
    try:
        global config
        config = TFConfig()
    except ValueError as e:
        print(f"Error: {e}")
        print("Required variables: GITHUB_TOKEN, GITHUB_ORG")
        print("Optional: GITHUB_API, TERRAFORM_REPORT_DIR")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Scan GitHub repositories with Terraform using Checkov and Trivy')
    parser.add_argument('--org', type=str, default=config.ORG_NAME, help=f'GitHub organization name (default: {config.ORG_NAME})')
    parser.add_argument('--repo', type=str, help='Single repository to scan (format: owner/repo or repo_name)')
    parser.add_argument('--token', type=str, help='GitHub personal access token (overrides GITHUB_TOKEN from .env)')
    parser.add_argument('--output-dir', type=str, default=config.REPORT_DIR, help=f'Output directory (default: {config.REPORT_DIR})')
    parser.add_argument('--include-forks', action='store_true', help='Include forked repositories')
    parser.add_argument('--include-archived', action='store_true', help='Include archived repositories')
    parser.add_argument('--with-trivy-fs', action='store_true', help='Also run trivy fs (slower)')
    # Checkov network/module handling
    parser.add_argument('--allow-guidelines', action='store_true', help='Allow Checkov to fetch guidelines (may hit Bridgecrew API)')
    parser.add_argument('--no-download-external-modules', action='store_true', help='Do not download external Terraform modules in Checkov')
    parser.add_argument('--guidelines-path', type=str, default='guidelines', help='Path to local guidelines JSON (default: guidelines)')
    # Enrichment caches
    parser.add_argument('--kev-cache', type=str, default=None, help='Path to KEV cache JSON (default from env KEV_CACHE)')
    parser.add_argument('--epss-cache', type=str, default=None, help='Path to EPSS cache CSV (default from env EPSS_CACHE)')
    # Optional cache refresh
    parser.add_argument('--refresh-kev', action='store_true', help='Refresh KEV cache from CISA before scanning')
    parser.add_argument('--refresh-epss', action='store_true', help='Refresh EPSS cache from FIRST before scanning')
    # Gating flags
    parser.add_argument('--gate-severity', type=str, choices=['none','low','medium','high','critical'], default='none', help='Fail if Checkov contains findings at or above this severity')
    parser.add_argument('--gate-kev', action='store_true', help='Fail if any KEV CVE is found by Trivy FS')
    parser.add_argument('--gate-epss', type=float, default=None, help='Fail if any EPSS percentile is >= threshold (0.0-1.0)')
    parser.add_argument('-v', '--verbose', action='count', default=1, help='Increase verbosity (repeatable)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress output')

    args = parser.parse_args()

    if args.quiet:
        args.verbose = 0
    setup_logging(args.verbose)

    if args.token:
        config.GITHUB_TOKEN = args.token
        # session headers updated in make_session()

    if args.org and args.org != config.ORG_NAME:
        config.ORG_NAME = args.org
        logging.info(f"Using organization from command line: {config.ORG_NAME}")

    if args.output_dir != config.REPORT_DIR:
        config.REPORT_DIR = os.path.abspath(args.output_dir)
        logging.info(f"Using output directory: {config.REPORT_DIR}")
    kev_cache = args.kev_cache or config.KEV_CACHE
    epss_cache = args.epss_cache or config.EPSS_CACHE

    os.makedirs(config.REPORT_DIR, exist_ok=True)

    # Preflight tooling info
    check_tooling()

    session = make_session()

    if args.repo:
        repo = get_single_repo(session, args.repo)
        if not repo:
            logging.error(f"Repository not found: {args.repo}")
            sys.exit(1)
        repos = [repo]
    else:
        logging.info(f"Fetching repositories from organization: {config.ORG_NAME}")
        repos = get_all_repos(session, include_forks=args.include_forks, include_archived=args.include_archived)
        if not repos:
            logging.error("No repositories found or accessible with the provided token.")
            sys.exit(1)
        logging.info(f"Found {len(repos)} repositories to scan")

    # Optionally refresh caches
    kev_cache = args.kev_cache or config.KEV_CACHE
    epss_cache = args.epss_cache or config.EPSS_CACHE
    if args.refresh_kev:
        refresh_kev(kev_cache)
    if args.refresh_epss:
        refresh_epss(epss_cache)

    results: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_repo = {executor.submit(
            process_repo,
            repo,
            config.REPORT_DIR,
            args.with_trivy_fs,
            args.allow_guidelines,
            args.no_download_external_modules,
            args.guidelines_path,
            kev_cache,
            epss_cache
        ): repo for repo in repos}
        for future in concurrent.futures.as_completed(future_to_repo):
            repo = future_to_repo[future]
            try:
                outcome = future.result()
                results.append(outcome)
            except Exception as e:
                logging.error(f"Error processing repository {repo['name']}: {e}")

    generate_summary_report(config.REPORT_DIR, results)

    # Apply gating if requested
    def sev_rank(s: str) -> int:
        order = {"none":0, "low":1, "medium":2, "high":3, "critical":4}
        return order.get((s or '').lower(), 0)

    gate_fail = False
    gate_msgs: List[str] = []
    if args.gate_severity != 'none':
        thr = sev_rank(args.gate_severity)
        for r in results:
            ck_json = r.get('checkov', {}).get('output_file')
            parsed = {}
            try:
                # support dir layout
                if ck_json and os.path.isdir(ck_json):
                    candidate = os.path.join(ck_json, 'results_json.json')
                    if os.path.exists(candidate):
                        with open(candidate, 'r') as jf:
                            parsed = json.load(jf)
                elif ck_json and os.path.exists(ck_json):
                    with open(ck_json, 'r') as jf:
                        parsed = json.load(jf)
            except Exception:
                parsed = {}
            for fc in ((parsed.get('results', {}) or {}).get('failed_checks', []) or []):
                if sev_rank(fc.get('severity') or '') >= thr:
                    gate_fail = True
                    gate_msgs.append(f"{r.get('repo')}: {fc.get('check_id')} severity {fc.get('severity')}")
                    break
    if args.gate_kev:
        for r in results:
            tvf_json = r.get('trivy_fs', {}).get('output_file') if r.get('trivy_fs') else None
            try:
                if tvf_json and os.path.exists(tvf_json):
                    with open(tvf_json, 'r') as jf:
                        parsed = json.load(jf)
                    for res in (parsed.get('Results') or []):
                        for v in (res.get('Vulnerabilities') or []):
                            cve = (v.get('VulnerabilityID') or '').upper()
                            kev_map = load_kev(kev_cache)
                            if cve and kev_map.get(cve):
                                gate_fail = True
                                gate_msgs.append(f"{r.get('repo')}: KEV {cve}")
                                raise StopIteration
            except StopIteration:
                break
            except Exception:
                continue
    if args.gate_epss is not None:
        thr = float(args.gate_epss)
        epss_map = load_epss(epss_cache)
        for r in results:
            tvf_json = r.get('trivy_fs', {}).get('output_file') if r.get('trivy_fs') else None
            try:
                if tvf_json and os.path.exists(tvf_json):
                    with open(tvf_json, 'r') as jf:
                        parsed = json.load(jf)
                    for res in (parsed.get('Results') or []):
                        for v in (res.get('Vulnerabilities') or []):
                            cve = (v.get('VulnerabilityID') or '').upper()
                            row = epss_map.get(cve)
                            if row and (row.get('percentile') or 0.0) >= thr:
                                gate_fail = True
                                gate_msgs.append(f"{r.get('repo')}: EPSS≥{thr} {cve}")
                                raise StopIteration
            except StopIteration:
                break
            except Exception:
                continue

    if gate_fail:
        logging.error("Gating failed:\n" + "\n".join(gate_msgs[:20]))
        sys.exit(2)

    # Clean up temporary directory if it was created
    if hasattr(config, 'CLONE_DIR') and config.CLONE_DIR and os.path.exists(config.CLONE_DIR):
        try:
            shutil.rmtree(config.CLONE_DIR)
        except Exception as e:
            logging.error(f"Error cleaning up temporary directory: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)
