#!/usr/bin/env python3
"""
OSS vulnerability scanner for GitHub repositories.

This script scans repositories for vulnerable open-source packages using tools like pip-audit, safety, and osv-scanner. It identifies KEV, EPSS, and zero-day risks in dependencies to mitigate supply chain attacks. Modeled after scan_gitleaks.py.

Usage:
- Org-wide scan: python scan_oss.py -v
- Single repo: python scan_oss.py --repo owner/repo
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
from pathlib import Path
from typing import Any, Dict, List, Optional
import glob
import re

import requests
from src.github.rate_limit import make_rate_limited_session, request_with_rate_limit
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(override=True)

class OSSConfig:
    """Configuration for the OSS vulnerability scanner."""
    def __init__(self):
        self.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        self.ORG_NAME = os.getenv("GITHUB_ORG")
        if not self.GITHUB_TOKEN:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        if not self.ORG_NAME:
            raise ValueError("GITHUB_ORG environment variable is required")
        self.GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com")
        self.REPORT_DIR = os.path.abspath(os.getenv("OSS_REPORT_DIR", "oss_reports"))
        self.CLONE_DIR: Optional[str] = None
        self.HEADERS = {
            "Authorization": f"token {self.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "auditgh-scan-oss",
        }
        # Optional integrations (defaults)
        self.ENABLE_SYFT: bool = False
        self.ENABLE_GRYPE: bool = False
        self.GRYPE_SCAN_MODE: str = 'sbom'  # sbom|fs|both
        self.SYFT_FORMAT: str = os.getenv('SYFT_FORMAT', 'cyclonedx-json')
        # Optional: parse OSV CVSS vectors into numeric base scores
        self.PARSE_OSV_CVSS: bool = False

config: Optional[OSSConfig] = None

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
        handlers=[logging.StreamHandler(), logging.FileHandler('logs/oss_scan.log')]
    )

def make_session() -> requests.Session:
    token = config.GITHUB_TOKEN if config else None
    return make_rate_limited_session(token, user_agent="auditgh-oss")

def _filter_page_repos(page_repos: List[Dict[str, Any]], include_forks: bool, include_archived: bool) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for repo in page_repos or []:
        if (not include_forks and repo.get('fork')) or (not include_archived and repo.get('archived')):
            continue
        out.append(repo)
    return out

def deduplicate_vulnerabilities(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate by (package, version, vuln_id) and prefer rows with a fixed_version.

    Also merge useful fields from duplicates: description, mitigation, severity, epss_score.
    """
    dedup: Dict[tuple, Dict[str, Any]] = {}
    for v in vulns or []:
        key = (str(v.get('package', '')).lower(), str(v.get('version', '')), str(v.get('vuln_id', '')))
        cur = dedup.get(key)
        if not cur:
            dedup[key] = v.copy()
            continue
        # Prefer fixed_version when available
        fv_cur = cur.get('fixed_version', 'N/A')
        fv_new = v.get('fixed_version', 'N/A')
        if (fv_cur in (None, '', 'N/A')) and (fv_new not in (None, '', 'N/A')):
            cur['fixed_version'] = fv_new
            # If mitigation is generic and we now have a fixed version, upgrade mitigation
            cur['mitigation'] = cur.get('mitigation') or ''
            if not cur['mitigation'] or 'Upgrade to' not in cur['mitigation']:
                cur['mitigation'] = f"Upgrade to {fv_new}"
        # Merge description if missing
        if (not cur.get('description')) or cur.get('description') == 'N/A':
            if v.get('description') and v['description'] != 'N/A':
                cur['description'] = v['description']
        # Merge mitigation if missing
        if (not cur.get('mitigation')) or cur.get('mitigation') == 'Update package' or cur.get('mitigation') == 'Update package to a non-vulnerable version':
            if v.get('mitigation'):
                cur['mitigation'] = v['mitigation']
        # Prefer Grype severity explicitly when present; otherwise prefer non-unknown
        v_source = v.get('source')
        cur_source = cur.get('source')
        if v_source == 'grype':
            cur['severity'] = v.get('severity', cur.get('severity'))
            # Keep track of source preference
            cur['source'] = 'grype'
            # Carry over CVSS score if present
            if v.get('cvss_score') is not None:
                cur['cvss_score'] = v['cvss_score']
        elif (cur.get('severity') in (None, '', 'unknown')) and (v.get('severity') not in (None, '', 'unknown')):
            cur['severity'] = v['severity']
        # If current record lacks a cvss_score but the new record has one, carry it over (from any source)
        if (cur.get('cvss_score') is None) and (v.get('cvss_score') is not None):
            cur['cvss_score'] = v['cvss_score']
        # Prefer non-N/A EPSS if present
        if (cur.get('epss_score') in (None, '', 'N/A')) and (v.get('epss_score') not in (None, '', 'N/A')):
            cur['epss_score'] = v['epss_score']
        # Ensure source is set if missing
        if not cur.get('source') and v_source:
            cur['source'] = v_source
    return list(dedup.values())

def get_all_repos(session: requests.Session, include_forks: bool = True, include_archived: bool = True) -> List[Dict[str, Any]]:
    repos: List[Dict[str, Any]] = []
    page = 1
    per_page = 100
    is_user_fallback = False
    while True:
        base = "users" if is_user_fallback else "orgs"
        url = f"{config.GITHUB_API}/{base}/{config.ORG_NAME}/repos"
        params = {"type": "all", "per_page": per_page, "page": page}
        try:
            resp = request_with_rate_limit(session, 'GET', url, params=params, timeout=30, logger=logging.getLogger('oss.api'))
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
        resp = request_with_rate_limit(session, 'GET', url, timeout=30, logger=logging.getLogger('oss.api'))
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching repository {repo_identifier}: {e}")
        return None

def clone_repo(repo: Dict[str, Any]) -> Optional[str]:
    if not config.CLONE_DIR:
        config.CLONE_DIR = tempfile.mkdtemp(prefix="repo_scan_oss_")
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

# --------------
# Scanning Logic
# --------------

def _parse_cvss_vector(vector: str) -> Optional[float]:
    """Attempt to parse a CVSS v3.x vector string into a base score using optional libraries.

    Tries the 'cvss' package (CVSS3) first, then 'cvsslib' if available. Returns None if not parsable.
    """
    if not vector or not isinstance(vector, str):
        return None
    try:
        # Common normalizations
        v = vector.strip()
        # Ensure it starts with CVSS prefix for some parsers
        if not v.upper().startswith('CVSS:') and 'AV:' in v:
            v = 'CVSS:3.1/' + v
        try:
            from cvss import CVSS3  # type: ignore
            obj = CVSS3(v)
            if hasattr(obj, 'scores'):
                scores = obj.scores()
                if isinstance(scores, (list, tuple)) and scores:
                    return float(scores[0])
            if hasattr(obj, 'base_score'):
                return float(obj.base_score)
        except Exception:
            pass
        try:
            import cvsslib  # type: ignore
            # cvsslib does not have one canonical API; try common helpers
            if hasattr(cvsslib, 'CVSS3'):
                obj = cvsslib.CVSS3(v)  # type: ignore
                if hasattr(obj, 'base_score'):
                    return float(obj.base_score)
            elif hasattr(cvsslib, 'cvss3'):
                obj = cvsslib.cvss3.CVSS3(v)  # type: ignore
                if hasattr(obj, 'base_score'):
                    return float(obj.base_score)
        except Exception:
            pass
    except Exception:
        return None
    return None

def find_dependency_files(repo_path: str) -> Dict[str, List[str]]:
    """Locate dependency files for various package managers.

    Notes:
    - Python: only include requirements*.txt files for pip-audit; lockfiles (Pipfile.lock, poetry.lock) will be handled by OSV.
    - JavaScript: prefer lockfiles (package-lock.json, yarn.lock, pnpm-lock.yaml); also collect package.json as a manifest fallback.
    - Java: collect pom.xml and build.gradle to trigger Semgrep Struts2 checks.
    """
    paths: Dict[str, List[str]] = {
        'python': [],
        'javascript': [],  # lockfiles only
        'javascript_manifests': [],  # package.json
        'java': [],
        'java_sources': [],
    }
    logging.debug(f"Searching for dependency files in {repo_path}")
    # Python requirements files
    py_patterns = [
        '**/requirements.txt',
        '**/requirements-*.txt',
        '**/requirements/*.txt',
        '**/*requirements*.txt',
    ]
    for pat in py_patterns:
        for p in glob.glob(os.path.join(repo_path, pat), recursive=True):
            if os.path.isfile(p):
                paths['python'].append(p)
    # Python lockfiles (handled via OSV)
    for p in [
        *glob.glob(os.path.join(repo_path, '**/Pipfile.lock'), recursive=True),
        *glob.glob(os.path.join(repo_path, '**/poetry.lock'), recursive=True),
    ]:
        if os.path.isfile(p):
            paths['python'].append(p)
    logging.debug(f"Found Python deps: {paths['python']}")
    # JavaScript lockfiles
    for p in [
        *glob.glob(os.path.join(repo_path, '**/package-lock.json'), recursive=True),
        *glob.glob(os.path.join(repo_path, '**/yarn.lock'), recursive=True),
        *glob.glob(os.path.join(repo_path, '**/pnpm-lock.yaml'), recursive=True),
    ]:
        if os.path.isfile(p):
            paths['javascript'].append(p)
    # JS manifests
    for p in glob.glob(os.path.join(repo_path, '**/package.json'), recursive=True):
        if os.path.isfile(p):
            paths['javascript_manifests'].append(p)
    logging.debug(f"Found JS lockfiles: {paths['javascript']}")
    # Java manifests
    for p in [
        *glob.glob(os.path.join(repo_path, '**/pom.xml'), recursive=True),
        *glob.glob(os.path.join(repo_path, '**/build.gradle'), recursive=True),
        *glob.glob(os.path.join(repo_path, '**/build.gradle.kts'), recursive=True),
        *glob.glob(os.path.join(repo_path, '**/gradle.lockfile'), recursive=True),
    ]:
        if os.path.isfile(p):
            paths['java'].append(p)
    # Java source files (for Semgrep even without manifests)
    for p in glob.glob(os.path.join(repo_path, '**/*.java'), recursive=True):
        if os.path.isfile(p):
            paths['java_sources'].append(p)
    logging.debug(f"Found Java manifests: {paths['java']}")
    logging.debug(f"Found Java sources count: {len(paths['java_sources'])}")
    return paths

def run_vulnerability_scan(tool: str, repo_path: str, dep_files: List[str]) -> Dict[str, Any]:
    """Run the specified vulnerability scanner across a list of files and return combined JSON output.

    Supported tools:
    - pip-audit: runs per requirements*.txt file with JSON output
    - osv-scanner: runs per lockfile with JSON output
    - npm-audit: runs per package.json directory with JSON output
    - semgrep: runs repository-wide with provided Struts2 rules (handled by dedicated function)
    """
    if not dep_files:
        return {"success": False, "error": "No dependency files found"}

    # Verify tool availability when applicable (skip check for semgrep; custom handling for pip-audit)
    if tool not in ('semgrep', 'pip-audit'):
        if not shutil.which(tool):
            error_msg = f"{tool} is not installed or not in PATH."
            logging.error(error_msg)
            return {"success": False, "error": error_msg}

    outputs: List[str] = []
    try:
        if tool == 'pip-audit':
            # Only audit requirements*.txt files
            req_files = [f for f in dep_files if f.lower().endswith('.txt')]
            if not req_files:
                return {"success": False, "error": "No requirements*.txt files for pip-audit"}
            # Build command with fallback to module execution if CLI not found
            base_cmd: List[str]
            if shutil.which('pip-audit'):
                base_cmd = ['pip-audit']
            else:
                base_cmd = [sys.executable, '-m', 'pip_audit']
            for rf in req_files:
                logging.debug(f"Running pip-audit on {rf}")
                cmd = [*base_cmd, '-r', rf, '-f', 'json']
                # pip-audit returns non-zero when vulns are found; accept output regardless
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_path, check=False)
                outputs.append(result.stdout)
            return {"success": True, "output": "\n".join(outputs), "errors": ""}
        elif tool == 'safety':
            req_files = [f for f in dep_files if f.lower().endswith('.txt')]
            if not req_files:
                return {"success": False, "error": "No requirements*.txt files for safety"}
            combined_output = []
            for rf in req_files:
                logging.debug(f"Running safety on {rf}")
                # safety may return non-zero when issues are found; accept output
                result = subprocess.run(['safety', 'check', '-r', rf, '--json'], capture_output=True, text=True, cwd=repo_path, check=False)
                combined_output.append(result.stdout)
            return {"success": True, "output": "\n".join(combined_output), "errors": ""}
        elif tool == 'osv-scanner':
            # Prefer lockfiles across languages. For Java manifests, perform a recursive repo scan.
            java_manifests = [f for f in dep_files if f.endswith(('pom.xml', 'build.gradle', 'build.gradle.kts'))]
            if java_manifests:
                logging.debug(f"Running osv-scanner recursively on repo for Java manifests: {java_manifests}")
                result = subprocess.run(['osv-scanner', '-r', repo_path, '-f', 'json'], capture_output=True, text=True, cwd=repo_path, check=False)
                outputs.append(result.stdout)
                return {"success": True, "output": "\n".join(outputs), "errors": result.stderr}
            lockfiles = [
                f for f in dep_files if f.endswith(('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'Pipfile.lock', 'poetry.lock'))
            ]
            if not lockfiles:
                return {"success": False, "error": "No compatible lockfiles for osv-scanner"}
            for lf in lockfiles:
                logging.debug(f"Running osv-scanner on lockfile {lf}")
                # osv-scanner may return non-zero when vulns are found or when partial errors occur
                result = subprocess.run(['osv-scanner', '--lockfile', lf, '-f', 'json'], capture_output=True, text=True, cwd=repo_path, check=False)
                outputs.append(result.stdout)
            return {"success": True, "output": "\n".join(outputs), "errors": ""}
        elif tool == 'npm-audit':
            if not shutil.which('npm'):
                return {"success": False, "error": "npm not installed; cannot run npm audit"}
            manifests = [f for f in dep_files if os.path.basename(f) == 'package.json']
            if not manifests:
                return {"success": False, "error": "No package.json manifests for npm audit"}
            for mf in manifests:
                pkg_dir = os.path.dirname(mf)
                logging.debug(f"Running npm audit in {pkg_dir}")
                result = subprocess.run(['npm', 'audit', '--json'], capture_output=True, text=True, cwd=pkg_dir, check=False)
                # npm audit may exit non-zero when vulnerabilities are found; treat any output as usable
                outputs.append(result.stdout)
            return {"success": True, "output": "\n".join(outputs), "errors": ""}
        elif tool == 'semgrep':
            # Handled by dedicated function; shouldn't reach here
            return {"success": False, "error": "Use scan_java_struts_with_semgrep for semgrep"}
        return {"success": False, "error": f"Unsupported tool: {tool}"}
    except subprocess.CalledProcessError as e:
        error_detail = f"{tool} execution failed: {str(e)}. Stderr: {e.stderr}"
        logging.error(error_detail)
        return {"success": False, "error": error_detail}

# -----------------
# Helpers (JS lockfiles, Struts2 dependency detection)
# -----------------

def ensure_js_lockfiles(manifests: List[str]) -> List[str]:
    """Attempt to generate package-lock.json for each package.json when no lockfiles are present.

    Uses `npm install --ignore-scripts --package-lock-only` to avoid running build scripts.
    Returns a list of generated lockfile paths.
    """
    lockfiles: List[str] = []
    if not shutil.which('npm'):
        return lockfiles
    for mf in manifests:
        pkg_dir = os.path.dirname(mf)
        try:
            logging.debug(f"Generating package-lock.json in {pkg_dir}")
            subprocess.run(['npm', 'install', '--ignore-scripts', '--package-lock-only'], cwd=pkg_dir, capture_output=True, text=True, check=False)
            lock_path = os.path.join(pkg_dir, 'package-lock.json')
            if os.path.isfile(lock_path):
                lockfiles.append(lock_path)
        except Exception as e:
            logging.error(f"Failed to generate lockfile in {pkg_dir}: {e}")
    return lockfiles

# -----------------
# Syft/Grype helpers
# -----------------

def run_syft_sbom(repo_path: str, sbom_path: str, sbom_format: str = 'cyclonedx-json') -> Dict[str, Any]:
    """Generate an SBOM for the repository using Syft and save to sbom_path.

    Returns {success: bool, path: str, output: str, error: str}
    """
    if not shutil.which('syft'):
        return {"success": False, "error": "syft not installed"}
    try:
        # Syft prints SBOM to stdout; capture and write to file
        logging.debug(f"Running syft SBOM generation in {repo_path} -> {sbom_path} ({sbom_format})")
        result = subprocess.run(['syft', repo_path, '-o', sbom_format], capture_output=True, text=True, cwd=repo_path, check=False)
        if result.returncode != 0 and not result.stdout:
            return {"success": False, "error": result.stderr}
        os.makedirs(os.path.dirname(sbom_path), exist_ok=True)
        with open(sbom_path, 'w') as f:
            f.write(result.stdout)
        return {"success": True, "path": sbom_path, "output": result.stdout, "error": result.stderr}
    except Exception as e:
        return {"success": False, "error": str(e)}

def run_grype_scan_sbom(sbom_path: str) -> Dict[str, Any]:
    if not shutil.which('grype'):
        return {"success": False, "error": "grype not installed"}
    try:
        logging.debug(f"Running grype on SBOM {sbom_path}")
        target = f"sbom:{sbom_path}"
        result = subprocess.run(['grype', target, '-o', 'json'], capture_output=True, text=True, check=False)
        return {"success": True, "output": result.stdout, "error": result.stderr}
    except Exception as e:
        return {"success": False, "error": str(e)}

def run_grype_scan_fs(repo_path: str) -> Dict[str, Any]:
    if not shutil.which('grype'):
        return {"success": False, "error": "grype not installed"}
    try:
        logging.debug(f"Running grype filesystem scan on {repo_path}")
        result = subprocess.run(['grype', repo_path, '-o', 'json'], capture_output=True, text=True, check=False)
        return {"success": True, "output": result.stdout, "error": result.stderr}
    except Exception as e:
        return {"success": False, "error": str(e)}

def parse_grype_output(output: str) -> List[Dict[str, Any]]:
    """Parse Grype JSON into normalized vulnerability list."""
    out: List[Dict[str, Any]] = []
    if not output:
        return out
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logging.warning("Failed to parse grype JSON output")
        return out
    matches = data.get('matches') or []
    for m in matches:
        vuln = m.get('vulnerability', {})
        art = m.get('artifact', {})
        pkg = art.get('name', '')
        version = art.get('version', '')
        # Maven metadata normalization if available
        meta = art.get('metadata') or {}
        group_id = meta.get('pomGroupID') or meta.get('groupId')
        artifact_id = meta.get('pomArtifactID') or meta.get('artifactId')
        if group_id and artifact_id:
            pkg = f"{group_id}:{artifact_id}"
        sev = vuln.get('severity') or 'unknown'
        desc = vuln.get('description') or vuln.get('dataSource') or ''
        # Extract max CVSS base score when available
        cvss_list = vuln.get('cvss') or []
        cvss_base = None
        for c in cvss_list:
            try:
                metrics = c.get('metrics') or {}
                base = metrics.get('baseScore')
                if base is not None:
                    base_f = float(base)
                    if cvss_base is None or base_f > cvss_base:
                        cvss_base = base_f
            except Exception:
                continue
        fix = vuln.get('fix') or {}
        fixed_version = 'N/A'
        # Grype fix.versions is a list of strings
        versions = fix.get('versions') or []
        if versions:
            fixed_version = versions[0]
        out.append({
            'package': pkg,
            'version': version,
            'vuln_id': vuln.get('id') or '',
            'severity': sev,
            'epss_score': 'N/A',
            'description': desc or 'N/A',
            'fixed_version': fixed_version,
            'mitigation': ('Upgrade to ' + fixed_version) if fixed_version != 'N/A' else 'Upgrade to a patched version or apply vendor guidance',
            'source': 'grype',
            'cvss_score': cvss_base if cvss_base is not None else None
        })
    return out

def _version_tuple(v: str) -> List[int]:
    parts = re.split(r"[.-]", v)
    out: List[int] = []
    for p in parts:
        try:
            out.append(int(p))
        except ValueError:
            # Non-numeric suffix: ignore for simple compare
            break
    return out

def _version_in_range(v: str, low: str, high: str, include_high: bool = False) -> bool:
    vt = _version_tuple(v)
    lo = _version_tuple(low)
    hi = _version_tuple(high)
    if vt < lo:
        return False
    if include_high:
        return vt <= hi
    return vt < hi

def detect_struts2_known_cves_from_poms(pom_files: List[str]) -> List[Dict[str, Any]]:
    """Naively detect Struts2 vulnerable versions in pom.xml to flag CVEs like CVE-2017-5638.

    Looks for artifactId struts2-core and extracts the immediate <version> value.
    This is a best-effort detector and may miss property-managed or dependencyManagement cases.
    """
    findings: List[Dict[str, Any]] = []
    for pom in pom_files:
        try:
            with open(pom, 'r', encoding='utf-8', errors='ignore') as f:
                xml = f.read()
            # Simple regex to find struts2-core version near artifactId
            m = re.search(r"<artifactId>struts2-core</artifactId>.*?<version>([^<]+)</version>", xml, re.DOTALL | re.IGNORECASE)
            if not m:
                continue
            ver = m.group(1).strip()
            # Resolve property reference like ${struts2.version}
            prop_ref = re.match(r"\$\{([^}]+)\}", ver)
            if prop_ref:
                prop_name = prop_ref.group(1)
                # Look for <properties><prop_name>value</prop_name></properties>
                pm = re.search(rf"<properties>.*?<\s*{re.escape(prop_name)}\s*>([^<]+)</\s*{re.escape(prop_name)}\s*>.*?</properties>", xml, re.DOTALL | re.IGNORECASE)
                if pm:
                    ver = pm.group(1).strip()
            # CVE-2017-5638 affects 2.3.5 - 2.3.31 and 2.5.0 - 2.5.10 (fixed in 2.3.32 and 2.5.10.1)
            vuln_2017_5638 = _version_in_range(ver, '2.3.5', '2.3.32') or _version_in_range(ver, '2.5.0', '2.5.10.1')
            if vuln_2017_5638:
                findings.append({
                    'package': 'org.apache.struts:struts2-core',
                    'version': ver,
                    'vuln_id': 'CVE-2017-5638',
                    'severity': 'CRITICAL',
                    'epss_score': 'High',
                    'mitigation': 'Upgrade to 2.3.32 or 2.5.10.1 or later; review Content-Type handling.'
                })
        except Exception as e:
            logging.error(f"Error parsing {pom}: {e}")
    return findings

def scan_java_struts_with_semgrep(repo_path: str) -> Dict[str, Any]:
    """Run Semgrep with Struts2 rules to detect potential RCE patterns in Java code."""
    if not shutil.which('semgrep'):
        return {"success": False, "error": "semgrep not installed"}
    rules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'semgrep-rules'))
    rules = [
        os.path.join(rules_dir, 'java-struts2.yaml'),
        os.path.join(rules_dir, 'java-struts2-heuristics.yaml'),
    ]
    existing_rules = [r for r in rules if os.path.exists(r)]
    if not existing_rules:
        return {"success": False, "error": f"Struts2 semgrep rules not found in {rules_dir}"}
    try:
        cmd = ['semgrep', '--json', '--no-git-ignore', '--timeout', '120', '--max-target-bytes', '5000000', '--include', '**/*.java']
        for r in existing_rules:
            cmd.extend(['--config', r])
        cmd.append(repo_path)
        logging.debug(f"Running Semgrep for Struts2 in {repo_path} with rules: {existing_rules}")
        # Semgrep may return non-zero for errors or findings; still parse JSON if present
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_path, check=False)
        return {"success": True, "output": result.stdout, "errors": result.stderr}
    except subprocess.CalledProcessError as e:
        error_detail = f"semgrep execution failed: {str(e)}. Stderr: {e.stderr}"
        logging.error(error_detail)
        return {"success": False, "error": error_detail}

# --------------
# Reporting
# --------------

def _severity_score(sev: str) -> int:
    if not sev:
        return 0
    s = str(sev).lower()
    if 'critical' in s:
        return 4
    if 'high' in s:
        return 3
    if 'medium' in s or 'moderate' in s:
        return 2
    if 'low' in s:
        return 1
    # Attempt to infer from numeric score if present (0.0 - 10.0)
    nums = [float(n) for n in re.findall(r"\d+(?:\.\d+)?", s) if 0.0 <= float(n) <= 10.0]
    if nums:
        score = max(nums)
        if score >= 9.0:
            return 4
        if score >= 7.0:
            return 3
        if score >= 4.0:
            return 2
        if score > 0:
            return 1
    return 0

def _rank_tuple(v: Dict[str, Any]) -> tuple:
    """Ranking tuple for selecting representative findings.

    Order of preference:
    1. Source priority (grype preferred)
    2. CVSS base score if available, otherwise coarse severity mapping
    3. Presence of a fixed version
    """
    src = (v.get('source') or '').lower()
    src_weight = 1 if src == 'grype' else 0
    cvss = v.get('cvss_score')
    if cvss is not None:
        sev_val = float(cvss)
    else:
        sev_text = str(v.get('severity', '')).lower()
        if 'critical' in sev_text:
            sev_val = 10.0
        elif 'high' in sev_text:
            sev_val = 8.0
        elif 'medium' in sev_text or 'moderate' in sev_text:
            sev_val = 5.0
        elif 'low' in sev_text:
            sev_val = 2.0
        else:
            sev_val = 0.0
    has_fix = 1 if (v.get('fixed_version') not in (None, '', 'N/A')) else 0
    return (src_weight, sev_val, has_fix)

def write_repo_report(repo: Dict[str, Any], repo_path: str, report_dir: str, vulnerabilities: Dict[str, Any]) -> None:
    os.makedirs(report_dir, exist_ok=True)
    repo_name = repo['name']
    md_path = os.path.join(report_dir, f"{repo_name}_oss.md")
    with open(md_path, 'w') as f:
        f.write(f"# OSS Vulnerability Report\n\n")
        f.write(f"**Repository:** {repo.get('full_name', repo_name)}\n\n")
        f.write(f"- Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("## Scanned Dependency Files\n\n")
        for lang, files in vulnerabilities.get('dependency_files', {}).items():
            f.write(f"### {lang.capitalize()} Dependencies\n\n")
            for file in files:
                rel_path = os.path.relpath(file, repo_path)
                f.write(f"- `{rel_path}`\n")
            f.write("\n")
        f.write("## Vulnerabilities Found\n\n")
        vulns = vulnerabilities.get('vulnerabilities', [])
        if vulns:
            f.write("| Package | Version | Vulnerability ID | Severity | EPSS Score | Description | Fixed Version | Mitigation |\n")
            f.write("|---------|---------|-----------------|----------|------------|-------------|---------------|-----------|\n")
            for vuln in vulns:
                epss_score = vuln.get('epss_score', 'N/A')
                description = vuln.get('description', 'N/A')
                fixed_version = vuln.get('fixed_version', 'N/A')
                mitigation = vuln.get('mitigation', 'Update package or review dependencies')
                f.write(f"| {vuln['package']} | {vuln['version']} | {vuln['vuln_id']} | {vuln['severity']} | {epss_score} | {description} | {fixed_version} | {mitigation} |\n")
            # Aggregate summary: packages with multiple vulnerabilities
            pkg_groups: Dict[tuple, List[Dict[str, Any]]] = {}
            for v in vulns:
                key = (v.get('package', ''), v.get('version', ''))
                pkg_groups.setdefault(key, []).append(v)
            multi: List[Dict[str, Any]] = []
            for (pkg, ver), vs in pkg_groups.items():
                if len(vs) < 2:
                    continue
                # Choose representative with highest severity score; tie-breaker prefers having a fixed version
                rep = sorted(vs, key=_rank_tuple, reverse=True)[0]
                multi.append({
                    'package': pkg,
                    'version': ver,
                    'count': len(vs),
                    'severity': rep.get('severity', 'unknown'),
                    'description': rep.get('description', 'N/A'),
                    'fixed_version': rep.get('fixed_version', 'N/A'),
                    'mitigation': rep.get('mitigation', 'Update package or review dependencies'),
                    'source': rep.get('source', ''),
                    'cvss_score': rep.get('cvss_score')
                })
            f.write("\n## Packages with Multiple Vulnerabilities\n\n")
            if multi:
                f.write("| Package | Version | Count | Max Severity | Description | Fixed Version | Mitigation |\n")
                f.write("|---------|---------|-------|--------------|-------------|---------------|------------|\n")
                multi.sort(key=lambda r: (r['count'], 1 if (r.get('source') == 'grype') else 0, (r.get('cvss_score') if r.get('cvss_score') is not None else _severity_score(r.get('severity', '')))), reverse=True)
                for row in multi:
                    desc = str(row.get('description', 'N/A')).replace('\n', ' ').strip()
                    mit = str(row.get('mitigation', 'Update package')).replace('\n', ' ').strip()
                    fx = row.get('fixed_version', 'N/A')
                    f.write(f"| {row['package']} | {row['version']} | {row['count']} | {row['severity']} | {desc} | {fx} | {mit} |\n")
            else:
                f.write("No packages with multiple vulnerabilities.\n")

            # All packages summary (includes packages with only one vulnerability)
            f.write("\n## Package Summary (All Packages)\n\n")
            all_rows: List[Dict[str, Any]] = []
            for (pkg, ver), vs in pkg_groups.items():
                # Choose representative with highest severity score; tie-breaker prefers having a fixed version
                rep = sorted(vs, key=_rank_tuple, reverse=True)[0]
                all_rows.append({
                    'package': pkg,
                    'version': ver,
                    'count': len(vs),
                    'severity': rep.get('severity', 'unknown'),
                    'description': rep.get('description', 'N/A'),
                    'fixed_version': rep.get('fixed_version', 'N/A'),
                    'mitigation': rep.get('mitigation', 'Update package or review dependencies'),
                    'source': rep.get('source', ''),
                    'cvss_score': rep.get('cvss_score')
                })
            if all_rows:
                f.write("| Package | Version | Count | Max Severity | Description | Fixed Version | Mitigation |\n")
                f.write("|---------|---------|-------|--------------|-------------|---------------|------------|\n")
                all_rows.sort(key=lambda r: (r['count'], 1 if (r.get('source') == 'grype') else 0, (r.get('cvss_score') if r.get('cvss_score') is not None else _severity_score(r.get('severity', '')))), reverse=True)
                for row in all_rows:
                    desc = str(row.get('description', 'N/A')).replace('\n', ' ').strip()
                    mit = str(row.get('mitigation', 'Update package')).replace('\n', ' ').strip()
                    fx = row.get('fixed_version', 'N/A')
                    f.write(f"| {row['package']} | {row['version']} | {row['count']} | {row['severity']} | {desc} | {fx} | {mit} |\n")
            else:
                f.write("No packages found.\n")
        else:
            f.write("No vulnerabilities detected.\n")

# ---------
# Orchestration
# ---------

def process_repo(session: requests.Session, repo: Dict[str, Any], report_dir: str) -> Dict[str, Any]:
    repo_name = repo['name']
    repo_full = repo['full_name']
    logging.info(f"Processing repository: {repo_full}")
    repo_report_dir = os.path.join(report_dir, repo_name)
    os.makedirs(repo_report_dir, exist_ok=True)

    repo_path = clone_repo(repo)
    if not repo_path:
        logging.error(f"Failed to clone repository: {repo_full}")
        return {"name": repo_name, "skipped": True}

    try:
        dep_files = find_dependency_files(repo_path)
        vulnerabilities: Dict[str, Any] = {"dependency_files": dep_files}
        vulns_list: List[Dict[str, Any]] = []

        # Python: pip-audit for requirements*.txt
        py_req_files = [f for f in dep_files.get('python', []) if f.lower().endswith('.txt')]
        if py_req_files:
            pa = run_vulnerability_scan('pip-audit', repo_path, py_req_files)
            if pa['success']:
                vulns_list.extend(parse_vulnerability_output('pip-audit', pa['output']))
            else:
                logging.error(f"pip-audit failed: {pa.get('error')}")
        # Python lockfiles via OSV (Pipfile.lock, poetry.lock)
        py_lock_files = [f for f in dep_files.get('python', []) if f.endswith(('Pipfile.lock', 'poetry.lock'))]
        if py_lock_files and shutil.which('osv-scanner'):
            osv_py = run_vulnerability_scan('osv-scanner', repo_path, py_lock_files)
            if osv_py['success']:
                vulns_list.extend(parse_vulnerability_output('osv-scanner', osv_py['output']))
            else:
                logging.error(f"osv-scanner (python locks) failed: {osv_py.get('error')}")

        # JavaScript: OSV on lockfiles, else npm audit on package.json manifests
        js_lockfiles = dep_files.get('javascript', [])
        if js_lockfiles and shutil.which('osv-scanner'):
            osv_js = run_vulnerability_scan('osv-scanner', repo_path, js_lockfiles)
            if osv_js['success']:
                vulns_list.extend(parse_vulnerability_output('osv-scanner', osv_js['output']))
            else:
                logging.error(f"osv-scanner failed for JS: {osv_js.get('error')}")
        else:
            js_manifests = dep_files.get('javascript_manifests', [])
            if js_manifests:
                # Try to generate lockfiles for better OSV coverage; fallback to npm audit
                gen_locks = ensure_js_lockfiles(js_manifests)
                if gen_locks and shutil.which('osv-scanner'):
                    osv_js2 = run_vulnerability_scan('osv-scanner', repo_path, gen_locks)
                    if osv_js2['success']:
                        vulns_list.extend(parse_vulnerability_output('osv-scanner', osv_js2['output']))
                    else:
                        logging.error(f"osv-scanner (generated locks) failed: {osv_js2.get('error')}")
                else:
                    npm = run_vulnerability_scan('npm-audit', repo_path, js_manifests)
                    if npm['success']:
                        vulns_list.extend(parse_vulnerability_output('npm-audit', npm['output']))
                    else:
                        logging.error(f"npm audit failed: {npm.get('error')}")

        # Java: attempt OSV scanning on manifests (pom.xml / gradle) if available
        if dep_files.get('java') and shutil.which('osv-scanner'):
            osv_java = run_vulnerability_scan('osv-scanner', repo_path, dep_files['java'])
            if osv_java['success']:
                vulns_list.extend(parse_vulnerability_output('osv-scanner', osv_java['output']))
            else:
                logging.error(f"osv-scanner failed for Java: {osv_java.get('error')}")

        # Java: Semgrep Struts2 rules for potential RCE (run if manifests or sources exist)
        if dep_files.get('java') or dep_files.get('java_sources'):
            sg = scan_java_struts_with_semgrep(repo_path)
            if sg['success']:
                vulns_list.extend(parse_vulnerability_output('semgrep', sg['output']))
            else:
                logging.error(f"Semgrep Struts2 scan failed: {sg.get('error')}")

        # Java: naive dependency-based detection for known Struts2 CVEs from pom.xml
        pom_files = [p for p in dep_files.get('java', []) if p.endswith('pom.xml')]
        if pom_files:
            dep_findings = detect_struts2_known_cves_from_poms(pom_files)
            if dep_findings:
                vulns_list.extend(dep_findings)

        # SBOM + Grype integration
        sbom_path = os.path.join(repo_report_dir, f"{repo_name}_syft_repo.json")
        grype_json_path = os.path.join(repo_report_dir, f"{repo_name}_grype.json")
        if getattr(config, 'ENABLE_SYFT', False):
            syft_res = run_syft_sbom(repo_path, sbom_path, getattr(config, 'SYFT_FORMAT', 'cyclonedx-json'))
            if not syft_res.get('success'):
                logging.error(f"Syft SBOM generation failed: {syft_res.get('error')}")
        if getattr(config, 'ENABLE_GRYPE', False):
            combined_outputs: List[str] = []
            mode = getattr(config, 'GRYPE_SCAN_MODE', 'sbom')
            if mode in ('sbom', 'both') and os.path.isfile(sbom_path):
                gr_sbom = run_grype_scan_sbom(sbom_path)
                if gr_sbom.get('success'):
                    combined_outputs.append(gr_sbom['output'])
                else:
                    logging.error(f"Grype SBOM scan failed: {gr_sbom.get('error')}")
            if mode in ('fs', 'both'):
                gr_fs = run_grype_scan_fs(repo_path)
                if gr_fs.get('success'):
                    combined_outputs.append(gr_fs['output'])
                else:
                    logging.error(f"Grype FS scan failed: {gr_fs.get('error')}")
            # Save last output to file for reference
            try:
                if combined_outputs:
                    with open(grype_json_path, 'w') as gf:
                        gf.write(combined_outputs[-1])
                    for out_json in combined_outputs:
                        vulns_list.extend(parse_grype_output(out_json))
            except Exception as e:
                logging.error(f"Error writing Grype output: {e}")

        # Aggregate (deduplicate across tools)
        deduped_vulns = deduplicate_vulnerabilities(vulns_list)
        vulnerabilities['vulnerabilities'] = deduped_vulns
        # Write report
        write_repo_report(repo, repo_path, repo_report_dir, vulnerabilities)
        return {"name": repo_name, "vulnerabilities_found": len(deduped_vulns)}
    except Exception as e:
        logging.error(f"Error processing repo {repo_full}: {e}")
        return {"name": repo_name, "error": str(e)}
    finally:
        try:
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
        except Exception as e:
            logging.error(f"Error cleaning up {repo_full}: {e}")

def parse_vulnerability_output(tool: str, output: str) -> List[Dict[str, Any]]:
    """Parse scanner output into a standardized vulnerability list."""
    vulnerabilities: List[Dict[str, Any]] = []
    if not output:
        return vulnerabilities
    # The `output` may contain multiple JSON objects separated by newlines; parse each safely
    json_chunks = []
    for chunk in output.splitlines():
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            json_chunks.append(json.loads(chunk))
        except json.JSONDecodeError:
            # Try whole output if line-based parsing fails
            try:
                json_chunks = [json.loads(output)]
            except json.JSONDecodeError:
                logging.warning(f"Failed to parse {tool} output as JSON")
            break

    if tool == 'pip-audit':
        for data in json_chunks:
            # pip-audit JSON schema: {"dependencies": [{"name":"pkg","version":"v","vulns":[{"id":"CVE-...","fix_versions":[...]}]}]}
            for dep in data.get('dependencies', []):
                for v in dep.get('vulns', []):
                    fix_versions = v.get('fix_versions', []) or []
                    advisory = v.get('advisory') or {}
                    description = advisory.get('summary') or v.get('description') or 'N/A'
                    vulnerabilities.append({
                        'package': dep.get('name', ''),
                        'version': dep.get('version', ''),
                        'vuln_id': v.get('id') or v.get('cve', '') or v.get('advisory_id', ''),
                        'severity': (v.get('severity') or v.get('cvss_vector', '') or 'unknown'),
                        'epss_score': 'N/A',
                        'description': description,
                        'fixed_version': fix_versions[0] if fix_versions else 'N/A',
                        'mitigation': ('Upgrade to ' + fix_versions[0]) if fix_versions else 'Update package to a non-vulnerable version',
                        'source': 'pip-audit'
                    })
    elif tool == 'osv-scanner':
        for data in json_chunks:
            # osv-scanner JSON schema: {"results":[{"source":{"path":"..."},"packages":[{"package":{"name":"...","version":"..."},"vulnerabilities":[{"id":"CVE-...","summary":"...","severity":[...] }]}]}]}
            for res in data.get('results', []):
                for pkg in res.get('packages', []):
                    name = pkg.get('package', {}).get('name', '')
                    version = pkg.get('package', {}).get('version', '')
                    for v in pkg.get('vulnerabilities', []):
                        sev = 'unknown'
                        cvss_score: Optional[float] = None
                        fixed_version = 'N/A'
                        # Severity array entries can include CVSS vectors or numeric scores
                        for s in v.get('severity', []) or []:
                            t = (s.get('type') or '').upper()
                            sc = s.get('score')
                            if t.startswith('CVSS') and sc:
                                sev = sc
                                if getattr(config, 'PARSE_OSV_CVSS', False):
                                    # If numeric, just coerce; if vector, parse
                                    try:
                                        if isinstance(sc, (int, float)):
                                            cvss_score = float(sc)
                                        elif isinstance(sc, str):
                                            # Numeric string or vector string
                                            if re.fullmatch(r"\d+(?:\.\d+)?", sc.strip()):
                                                cvss_score = float(sc.strip())
                                            else:
                                                parsed = _parse_cvss_vector(sc)
                                                if parsed is not None:
                                                    cvss_score = parsed
                                    except Exception:
                                        pass
                        # Heuristic fixed version via affected ranges if present
                        affected = v.get('affected', []) or []
                        for aff in affected:
                            rng = aff.get('ranges', []) or []
                            for r in rng:
                                if r.get('type') == 'ECOSYSTEM':
                                    events = r.get('events', []) or []
                                    for e in events:
                                        if 'fixed' in e:
                                            fixed_version = e.get('fixed')
                                            break
                            if fixed_version != 'N/A':
                                break
                        description = v.get('summary') or v.get('details') or 'N/A'
                        vulnerabilities.append({
                            'package': name,
                            'version': version,
                            'vuln_id': v.get('id') or v.get('osvId') or v.get('aliases', [None])[0] or '',
                            'severity': sev,
                            'epss_score': 'N/A',
                            'description': description,
                            'fixed_version': fixed_version,
                            'mitigation': ('Upgrade to ' + fixed_version) if fixed_version != 'N/A' else 'Upgrade to a patched version or apply vendor guidance',
                            'source': 'osv-scanner',
                            'cvss_score': cvss_score
                        })
    elif tool == 'npm-audit':
        for data in json_chunks:
            # npm audit JSON varies; support legacy "advisories" and modern "vulnerabilities"
            if 'advisories' in data and isinstance(data['advisories'], dict):
                for adv in data['advisories'].values():
                    patched_versions = adv.get('patched_versions') or ''
                    fixed_version = patched_versions.replace('>=', '').split(' || ')[0] if patched_versions else 'N/A'
                    description = adv.get('title') or adv.get('overview') or adv.get('url') or 'N/A'
                    vulnerabilities.append({
                        'package': adv.get('module_name', ''),
                        'version': adv.get('findings', [{}])[0].get('version', ''),
                        'vuln_id': str(adv.get('id', '')),
                        'severity': adv.get('severity', 'unknown'),
                        'epss_score': 'N/A',
                        'description': description,
                        'fixed_version': fixed_version,
                        'mitigation': adv.get('recommendation', ('Upgrade to ' + fixed_version) if fixed_version != 'N/A' else 'Update package'),
                        'source': 'npm-audit'
                    })
            elif 'vulnerabilities' in data and isinstance(data['vulnerabilities'], dict):
                for pkg, v in data['vulnerabilities'].items():
                    fix_avail = v.get('fixAvailable')
                    fixed_version = 'N/A'
                    if isinstance(fix_avail, dict):
                        fixed_version = fix_avail.get('version') or 'N/A'
                    description = ''
                    via = v.get('via')
                    if isinstance(via, list) and via:
                        first = via[0]
                        if isinstance(first, str):
                            description = first
                        elif isinstance(first, dict):
                            description = first.get('title') or first.get('name') or first.get('url') or ''
                    if not description:
                        description = 'N/A'
                    vulnerabilities.append({
                        'package': pkg,
                        'version': '',
                        'vuln_id': ','.join(v.get('via', [])) if isinstance(v.get('via'), list) else str(v.get('via', '')),
                        'severity': v.get('severity', 'unknown'),
                        'epss_score': 'N/A',
                        'description': description,
                        'fixed_version': fixed_version,
                        'mitigation': ('Upgrade to ' + fixed_version) if fixed_version != 'N/A' else 'Update package',
                        'source': 'npm-audit'
                    })
    elif tool == 'semgrep':
        for data in json_chunks:
            for res in data.get('results', []):
                check_id = res.get('check_id', '')
                extra = res.get('extra', {})
                msg = extra.get('message', '')
                sev = extra.get('severity', 'WARNING')
                path = res.get('path', '')
                vulnerabilities.append({
                    'package': f"{os.path.basename(path)} (code)",
                    'version': '',
                    'vuln_id': check_id or 'STRUTS2_RCE_PATTERN',
                    'severity': sev,
                    'epss_score': 'N/A',
                    'description': msg or 'Potential insecure pattern in code',
                    'fixed_version': 'N/A',
                    'mitigation': 'Refactor code to remove unsafe pattern and upgrade affected libraries',
                    'source': 'semgrep'
                })
    return vulnerabilities

def write_org_summary(report_root: str, per_repo_stats: List[Dict[str, Any]]) -> None:
    md = os.path.join(report_root, "oss_summary.md")
    with open(md, 'w') as f:
        f.write("# OSS Vulnerability Summary\n\n")
        f.write(f"**Organization:** {config.ORG_NAME}\n\n")
        f.write(f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("## Repositories Scanned\n\n")
        f.write("| Repo | Vulnerabilities Found | High-Risk Vulnerabilities |\n")
        f.write("|------|-----------------------|---------------------------|\n")
        for st in per_repo_stats:
            high_risk = 'high' in str(st.get('vulnerabilities_found', ''))  # Simplify for now
            f.write(f"| {st['name']} | {st.get('vulnerabilities_found', 0)} | { 'Yes' if high_risk else 'No' } |\n")

# ---------
# Orchestration
# ---------

def main():
    global config
    try:
        config = OSSConfig()
    except ValueError as e:
        print(f"Error: {e}")
        print("Please set GITHUB_TOKEN and GITHUB_ORG in your environment or .env")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Scan repositories for OSS vulnerabilities')
    parser.add_argument('--org', type=str, default=config.ORG_NAME, help=f'GitHub organization (default: {config.ORG_NAME})')
    parser.add_argument('--repo', type=str, help='Single repository (owner/repo or repo name)')
    parser.add_argument('--token', type=str, help='Personal access token (overrides env)')
    parser.add_argument('--output-dir', type=str, default=config.REPORT_DIR, help=f'Output directory (default: {config.REPORT_DIR})')
    parser.add_argument('--include-forks', action='store_true', help='Include forked repositories (default: on)')
    parser.add_argument('--include-archived', action='store_true', help='Include archived repositories (default: on)')
    parser.add_argument('-v', '--verbose', action='count', default=1, help='Increase verbosity')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress output')
    parser.add_argument('--tools', nargs='+', default=['pip-audit', 'safety', 'osv-scanner'], help='Vulnerability tools to use (default: all)')
    # Syft/Grype
    parser.add_argument('--enable-syft', action='store_true', help='Generate SBOM with Syft and save JSON next to the report')
    parser.add_argument('--syft-format', type=str, default='cyclonedx-json', help='Syft SBOM format (default: cyclonedx-json)')
    parser.add_argument('--enable-grype', action='store_true', help='Run Grype vulnerability scan (SBOM and/or filesystem)')
    parser.add_argument('--grype-scan-mode', type=str, choices=['sbom', 'fs', 'both'], default='sbom', help='Grype scan mode (default: sbom)')
    # OSV CVSS parsing option
    parser.add_argument('--parse-osv-cvss', action='store_true', help='Parse OSV CVSS vectors into numeric base scores for severity ranking')

    args = parser.parse_args()

    if args.quiet:
        args.verbose = 0
    setup_logging(args.verbose)

    if args.token:
        config.GITHUB_TOKEN = args.token
        config.HEADERS["Authorization"] = f"token {config.GITHUB_TOKEN}"

    if args.org and args.org != config.ORG_NAME:
        config.ORG_NAME = args.org
        logging.info(f"Using organization from CLI: {config.ORG_NAME}")

    if args.output_dir != config.REPORT_DIR:
        config.REPORT_DIR = os.path.abspath(args.output_dir)
        logging.info(f"Using output directory: {config.REPORT_DIR}")

    os.makedirs(config.REPORT_DIR, exist_ok=True)

    session = make_session()

    # Apply syft/grype settings
    config.ENABLE_SYFT = bool(args.enable_syft)
    config.SYFT_FORMAT = args.syft_format
    config.ENABLE_GRYPE = bool(args.enable_grype)
    config.GRYPE_SCAN_MODE = args.grype_scan_mode
    # Apply OSV CVSS parsing preference
    config.PARSE_OSV_CVSS = bool(getattr(args, 'parse_osv_cvss', False))

    # Targets
    if args.repo:
        repo = get_single_repo(session, args.repo)
        if not repo:
            logging.error(f"Repository not found: {args.repo}")
            sys.exit(1)
        repos = [repo]
    else:
        logging.info(f"Fetching repositories for {config.ORG_NAME}")
        repos = get_all_repos(session, include_forks=args.include_forks, include_archived=args.include_archived)
        if not repos:
            logging.error("No repositories found or accessible with the provided token.")
            sys.exit(1)
        logging.info(f"Found {len(repos)} repositories to scan")

    # Process repos
    stats: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_repo = {executor.submit(process_repo, session, repo, config.REPORT_DIR): repo for repo in repos}
        for future in concurrent.futures.as_completed(future_to_repo):
            repo = future_to_repo[future]
            try:
                st = future.result()
                if st:
                    stats.append(st)
            except Exception as e:
                logging.error(f"Error processing repository {repo['name']}: {e}")

    write_org_summary(config.REPORT_DIR, stats)

    # Clean up temp clone dir
    if config.CLONE_DIR and os.path.exists(config.CLONE_DIR):
        try:
            shutil.rmtree(config.CLONE_DIR)
        except Exception as e:
            logging.error(f"Error cleaning up temporary directory: {e}")

    logging.info("OSS vulnerability scan completed!")

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
