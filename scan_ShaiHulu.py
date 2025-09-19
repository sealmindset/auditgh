#!/usr/bin/env python3
"""
Specialized detector for the "Shai-Hulud" campaign.

This scanner inspects GitHub repositories for:
- package-lock.json references containing packages from a provided IoC list (shaihulupkg.txt)
- suspicious security/audit logs committed to repos
- data.json files containing double-encoded base64 payloads
- suspicious workflow or script indicators (processor.sh, migrate-repos.sh, webhook.site)
- malicious JS file hash matches

It also executes GitHub search queries for public repositories named "Shai-Hulud" or with
"Shai-Hulud Migration" descriptions within the organization, and attempts to query
organization audit logs for anomalous activity (when permissions allow).
"""

import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple

import requests
from dotenv import load_dotenv
from src.github.rate_limit import make_rate_limited_session, request_with_rate_limit

# Load environment variables from .env file
load_dotenv(override=True)

IOC_MALICIOUS_JS_SHA256 = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
IOC_WEBHOOK_DOMAIN = "webhook.site"
IOC_SCRIPT_PATHS = ["/tmp/processor.sh", "/tmp/migrate-repos.sh"]

class ShaiHuluConfig:
    def __init__(self):
        self.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        self.ORG_NAME = os.getenv("GITHUB_ORG")
        if not self.GITHUB_TOKEN:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        if not self.ORG_NAME:
            raise ValueError("GITHUB_ORG environment variable is required")
        self.GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com")
        self.REPORT_DIR = os.path.abspath(os.getenv("REPORT_DIR", "shaihulud_reports"))
        self.CLONE_DIR = None
        self.HEADERS = {
            "Authorization": f"token {self.GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        }

config: Optional[ShaiHuluConfig] = None


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
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(), logging.FileHandler('logs/shaihulu_scan.log')]
    )


def make_session() -> requests.Session:
    token = config.GITHUB_TOKEN if config else None
    return make_rate_limited_session(token, user_agent="auditgh-shaihulu")


# -----------------
# GitHub helpers
# -----------------

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
            resp = request_with_rate_limit(session, 'GET', url, params=params, timeout=30, logger=logging.getLogger('shaihulu.api'))
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
        response = request_with_rate_limit(session, 'GET', url, timeout=30, logger=logging.getLogger('shaihulu.api'))
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching repository {repo_identifier}: {e}")
        return None


def org_audit_log_search(session: requests.Session, phrase: str, action: Optional[str] = None, limit: int = 200) -> Tuple[bool, List[Dict[str, Any]]]:
    """Attempt to query the org audit log. Returns (ok, events)."""
    url = f"{config.GITHUB_API}/orgs/{config.ORG_NAME}/audit-log"
    params: Dict[str, Any] = {"per_page": min(100, limit)}
    if phrase:
        params["phrase"] = phrase
    if action:
        params["action"] = action
    try:
        resp = request_with_rate_limit(session, 'GET', url, params=params, timeout=30, logger=logging.getLogger('shaihulu.audit'))
        if resp.status_code == 403:
            logging.warning("Audit log access forbidden. Token may not have org audit permissions.")
            return False, []
        resp.raise_for_status()
        events = resp.json() or []
        return True, events
    except requests.exceptions.RequestException as e:
        logging.error(f"Audit log query failed: {e}")
        return False, []


def search_repositories(session: requests.Session, query: str, max_items: int = 200) -> List[Dict[str, Any]]:
    url = f"{config.GITHUB_API}/search/repositories"
    items: List[Dict[str, Any]] = []
    page = 1
    per_page = 100
    while len(items) < max_items:
        try:
            resp = request_with_rate_limit(session, 'GET', url, params={"q": query, "per_page": per_page, "page": page}, timeout=30, logger=logging.getLogger('shaihulu.search'))
            resp.raise_for_status()
            data = resp.json() or {}
            items.extend(data.get('items', []))
            if len(data.get('items', [])) < per_page:
                break
            page += 1
        except requests.exceptions.RequestException as e:
            logging.error(f"Repo search failed: {e}")
            break
    return items[:max_items]


def search_code(session: requests.Session, query: str, max_items: int = 100) -> List[Dict[str, Any]]:
    url = f"{config.GITHUB_API}/search/code"
    items: List[Dict[str, Any]] = []
    page = 1
    per_page = 100
    while len(items) < max_items:
        try:
            resp = request_with_rate_limit(session, 'GET', url, params={"q": query, "per_page": per_page, "page": page}, timeout=30, logger=logging.getLogger('shaihulu.search'))
            resp.raise_for_status()
            data = resp.json() or {}
            items.extend(data.get('items', []))
            if len(data.get('items', [])) < per_page:
                break
            page += 1
        except requests.exceptions.RequestException as e:
            logging.error(f"Code search failed: {e}")
            break
    return items[:max_items]


def list_org_members(session: requests.Session, max_items: int = 500) -> List[Dict[str, Any]]:
    """List organization members (requires appropriate scope)."""
    url = f"{config.GITHUB_API}/orgs/{config.ORG_NAME}/members"
    members: List[Dict[str, Any]] = []
    page = 1
    per_page = 100
    while len(members) < max_items:
        try:
            resp = request_with_rate_limit(session, 'GET', url, params={"per_page": per_page, "page": page}, timeout=30, logger=logging.getLogger('shaihulu.members'))
            if resp.status_code == 403:
                logging.warning("Members listing forbidden; token may lack org:read scope.")
                break
            if resp.status_code == 404:
                logging.info("Org members endpoint not found; this may be a user account, not an org.")
                break
            resp.raise_for_status()
            batch = resp.json() or []
            members.extend(batch)
            if len(batch) < per_page:
                break
            page += 1
        except requests.exceptions.RequestException as e:
            logging.error(f"Members list failed: {e}")
            break
    return members[:max_items]


# -----------------
# Local repo scanning
# -----------------

def clone_repo(repo: Dict[str, Any]) -> Optional[str]:
    if not config.CLONE_DIR:
        config.CLONE_DIR = tempfile.mkdtemp(prefix="repo_scan_")
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


def load_ioc_packages(packages_file: str) -> Set[str]:
    pkgs: Set[str] = set()
    try:
        with open(packages_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Example: "teselagen-interval-tree (1.1.2)"
                name = line.split('(')[0].strip()
                if name:
                    pkgs.add(name.lower())
    except Exception as e:
        logging.warning(f"Could not read packages file '{packages_file}': {e}")
    return pkgs


def collect_npm_packages_from_lock(lock_path: Path) -> Set[str]:
    names: Set[str] = set()
    try:
        with open(lock_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        def walk_deps(obj: Any):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == 'dependencies' and isinstance(v, dict):
                        for dep_name in v.keys():
                            names.add(dep_name.lower())
                        walk_deps(v)
                    else:
                        walk_deps(v)
            elif isinstance(obj, list):
                for it in obj:
                    walk_deps(it)
        walk_deps(data)
    except Exception as e:
        logging.debug(f"Failed to parse {lock_path}: {e}")
    return names


def detect_double_base64(s: str) -> Tuple[bool, Optional[str]]:
    try:
        b1 = base64.b64decode(s, validate=True)
        b2 = base64.b64decode(b1, validate=True)
        try:
            decoded = b2.decode('utf-8', errors='ignore')
        except Exception:
            decoded = b2.decode('latin1', errors='ignore')
        return True, decoded
    except Exception:
        return False, None


SUSPICIOUS_STRINGS = [
    'AKIA', 'ASIA', '-----BEGIN', 'SECRET_KEY', 'PRIVATE KEY', 'xoxb-',
    'password=', 'token=', IOC_WEBHOOK_DOMAIN, 'child_process.exec', 'bash -c', 'curl ', 'wget '
]


def scan_repo_local(repo_path: str, repo: Dict[str, Any], ioc_packages: Set[str]) -> Dict[str, Any]:
    findings: Dict[str, Any] = {
        'repo': repo.get('full_name') or repo.get('name'),
        'package_lock_matches': [],
        'security_logs': [],
        'data_json_findings': [],
        'suspicious_strings': [],
        'workflow_findings': [],
        'ioc_scripts_refs': [],
        'malicious_js_hash_matches': [],
    }

    # package-lock.json search
    for lock_path in Path(repo_path).rglob('package-lock.json'):
        pkgs = collect_npm_packages_from_lock(lock_path)
        matches = sorted(list(pkgs.intersection(ioc_packages)))
        if matches:
            findings['package_lock_matches'].append({
                'path': str(lock_path.relative_to(repo_path)),
                'matches': matches
            })

    # security / audit logs committed
    for p in Path(repo_path).rglob('*'):
        if p.is_file():
            name = p.name.lower()
            if ('security' in name or 'audit' in name) and name.endswith('.log'):
                findings['security_logs'].append(str(p.relative_to(repo_path)))

    # data.json double base64
    for dp in Path(repo_path).rglob('data.json'):
        try:
            # Try to parse as JSON, fallback to raw
            with open(dp, 'r', encoding='utf-8', errors='ignore') as f:
                txt = f.read()
            decoded = None
            try:
                j = json.loads(txt)
                # common keys that could hold payloads
                candidates = []
                if isinstance(j, dict):
                    for k in ['data', 'payload', 'content', 'blob']:
                        v = j.get(k)
                        if isinstance(v, str):
                            candidates.append(v)
                if not candidates and isinstance(j, str):
                    candidates = [j]
                for c in candidates:
                    ok, out = detect_double_base64(c)
                    if ok:
                        decoded = out
                        break
            except Exception:
                ok, out = detect_double_base64(txt)
                if ok:
                    decoded = out
            if decoded:
                # heuristic secrets keywords
                suspicious = any(x in decoded for x in ['AKIA', 'BEGIN', 'SECRET', 'PASSWORD', 'TOKEN'])
                findings['data_json_findings'].append({
                    'path': str(dp.relative_to(repo_path)),
                    'decoded_preview': decoded[:200],
                    'suspicious': suspicious
                })
        except Exception as e:
            logging.debug(f"data.json parse error: {e}")

    # suspicious strings and IOC ref scans (.github/workflows + tree)
    for p in Path(repo_path).rglob('*'):
        if p.is_file():
            rel = str(p.relative_to(repo_path))
            try:
                if p.stat().st_size > 2 * 1024 * 1024:  # skip very large files
                    continue
                text = p.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                continue
            for s in SUSPICIOUS_STRINGS:
                if s in text:
                    findings['suspicious_strings'].append({'path': rel, 'indicator': s})
            for sp in IOC_SCRIPT_PATHS:
                if sp in text:
                    findings['ioc_scripts_refs'].append({'path': rel, 'script': sp})

    # malicious JS hash
    for js in Path(repo_path).rglob('*.js'):
        try:
            if js.stat().st_size > 1 * 1024 * 1024:  # cap to 1MB
                continue
            h = hashlib.sha256(js.read_bytes()).hexdigest()
            if h == IOC_MALICIOUS_JS_SHA256:
                findings['malicious_js_hash_matches'].append(str(js.relative_to(repo_path)))
        except Exception:
            continue

    # workflow-focused scan
    for wf in Path(repo_path).rglob('.github/workflows/*.yml'):
        try:
            text = wf.read_text(encoding='utf-8', errors='ignore')
            if IOC_WEBHOOK_DOMAIN in text:
                findings['workflow_findings'].append({'path': str(wf.relative_to(repo_path)), 'indicator': IOC_WEBHOOK_DOMAIN})
        except Exception:
            pass
    for wf in Path(repo_path).rglob('.github/workflows/*.yaml'):
        try:
            text = wf.read_text(encoding='utf-8', errors='ignore')
            if IOC_WEBHOOK_DOMAIN in text:
                findings['workflow_findings'].append({'path': str(wf.relative_to(repo_path)), 'indicator': IOC_WEBHOOK_DOMAIN})
        except Exception:
            pass

    return findings


# -----------------
# High-level queries
# -----------------

def run_high_level_queries(session: requests.Session) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        'first_wave': [],
        'second_wave': [],
        'audit_repo_create': [],
        'private_migration_repos': [],
        'dev_accounts_shai_hulud': []
    }
    org = config.ORG_NAME

    # First wave: public repos named Shai-Hulud within org
    q1 = f"org:{org} in:name \"Shai-Hulud\" is:public"
    results['first_wave'] = search_repositories(session, q1)

    # Second wave: public repos with description "Shai-Hulud Migration" and name containing 'mitigation'
    q2 = f"org:{org} in:description \"Shai-Hulud Migration\" in:name mitigation is:public"
    results['second_wave'] = search_repositories(session, q2)

    # Audit logs: look for repo create/publication actions mentioning Shai-Hulud
    ok, events = org_audit_log_search(session, phrase="Shai-Hulud", action=None, limit=200)
    if ok:
        results['audit_repo_create'] = events

    # Private repos with '-migration' suffix and description 'Shai-Hulud Migration'
    try:
        org_repos = get_all_repos(session, include_forks=True, include_archived=True)
        for r in org_repos:
            try:
                name = (r.get('name') or '').lower()
                desc = (r.get('description') or '')
                if r.get('private') and name.endswith('-migration') and ('Shai-Hulud Migration' in (desc or '')):
                    results['private_migration_repos'].append(r)
            except Exception:
                continue
    except Exception as e:
        logging.debug(f"private_migration_repos scan error: {e}")

    # Developer accounts: search for repos named Shai-Hulud in members' user accounts
    try:
        members = list_org_members(session)
        for m in members:
            login = m.get('login')
            if not login:
                continue
            qd = f"user:{login} in:name \"Shai-Hulud\""
            hits = search_repositories(session, qd, max_items=10)
            if hits:
                results['dev_accounts_shai_hulud'].extend(hits)
    except Exception as e:
        logging.debug(f"dev account search error: {e}")

    return results


# -----------------
# Reporting
# -----------------

def write_repo_report(report_dir: str, repo_name: str, findings: Dict[str, Any]):
    os.makedirs(report_dir, exist_ok=True)
    md = os.path.join(report_dir, f"{repo_name}_shaihulu.md")
    with open(md, 'w', encoding='utf-8') as f:
        f.write(f"# Shai-Hulud Scan Report\n\n")
        f.write(f"**Repository:** {repo_name}\n\n")
        for key in ['package_lock_matches','security_logs','data_json_findings','suspicious_strings','workflow_findings','ioc_scripts_refs','malicious_js_hash_matches']:
            items = findings.get(key) or []
            f.write(f"## {key}\n\n")
            if not items:
                f.write("- None\n\n")
            else:
                for it in items:
                    f.write(f"- {json.dumps(it, ensure_ascii=False)}\n")
                f.write("\n")


def write_summary(report_root: str, repos_scanned: int, summary: Dict[str, Any]):
    os.makedirs(report_root, exist_ok=True)
    md_path = os.path.join(report_root, "shaihulu_summary.md")
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write("# Shai-Hulud Summary\n\n")
        f.write(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Repos scanned:** {repos_scanned}\n\n")
        for sec in ['first_wave','second_wave','audit_repo_create','private_migration_repos','dev_accounts_shai_hulud']:
            f.write(f"## {sec}\n\n")
            items = summary.get(sec) or []
            if not items:
                f.write("- None\n\n")
            else:
                for it in items:
                    try:
                        f.write(f"- {json.dumps(it, ensure_ascii=False)}\n")
                    except Exception:
                        f.write(f"- {str(it)}\n")
                f.write("\n")


# -----------------
# Main
# -----------------

def main():
    try:
        global config
        config = ShaiHuluConfig()
    except ValueError as e:
        print(f"Error: {str(e)}")
        print("Please set GITHUB_TOKEN and GITHUB_ORG in your environment or .env file.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Scan for Shai-Hulud indicators across GitHub repositories')
    parser.add_argument('--org', type=str, default=config.ORG_NAME, help=f'Organization (default: {config.ORG_NAME})')
    parser.add_argument('--repo', type=str, help='Specific repository (owner/name or name)')
    parser.add_argument('--token', type=str, help='GitHub token override')
    parser.add_argument('--packages-file', type=str, default='shaihulupkg.txt', help='IoC packages list file')
    parser.add_argument('--output-dir', type=str, default=config.REPORT_DIR, help='Output directory')
    parser.add_argument('--include-forks', action='store_true')
    parser.add_argument('--include-archived', action='store_true')
    parser.add_argument('-v', '--verbose', action='count', default=1)
    parser.add_argument('-q', '--quiet', action='store_true')

    args = parser.parse_args()

    if args.quiet:
        args.verbose = 0
    setup_logging(args.verbose)

    if args.token:
        config.GITHUB_TOKEN = args.token
        config.HEADERS['Authorization'] = f"token {config.GITHUB_TOKEN}"
    if args.org and args.org != config.ORG_NAME:
        config.ORG_NAME = args.org
    if args.output_dir and args.output_dir != config.REPORT_DIR:
        config.REPORT_DIR = os.path.abspath(args.output_dir)

    os.makedirs(config.REPORT_DIR, exist_ok=True)

    session = make_session()

    # Load IoC packages list
    ioc_packages = load_ioc_packages(args.packages_file)
    if ioc_packages:
        logging.info(f"Loaded {len(ioc_packages)} IoC packages from {args.packages_file}")
    else:
        logging.warning("No IoC packages loaded; package-lock.json checks will still run but may not match.")

    # Collect repos
    if args.repo:
        repo = get_single_repo(session, args.repo)
        if not repo:
            logging.error(f"Repository not found: {args.repo}")
            sys.exit(1)
        repos = [repo]
    else:
        repos = get_all_repos(session, include_forks=args.include_forks, include_archived=args.include_archived)
        if not repos:
            logging.error("No repositories found or accessible")
            sys.exit(1)
        logging.info(f"Found {len(repos)} repos to scan")

    # Process repos in parallel
    repo_summaries: List[Dict[str, Any]] = []

    def _process(repo: Dict[str, Any]):
        repo_name = repo.get('name')
        repo_full = repo.get('full_name', repo_name)
        logging.info(f"Processing {repo_full}")
        repo_dir = os.path.join(config.REPORT_DIR, repo_name)
        os.makedirs(repo_dir, exist_ok=True)
        repo_path = clone_repo(repo)
        if not repo_path:
            logging.error(f"Clone failed for {repo_full}")
            return
        try:
            findings = scan_repo_local(repo_path, repo, ioc_packages)
            write_repo_report(repo_dir, repo_name, findings)
            repo_summaries.append({'repo': repo_full, 'findings': findings})
        finally:
            try:
                if os.path.exists(repo_path):
                    shutil.rmtree(repo_path)
            except Exception:
                pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        list(ex.map(_process, repos))

    # High-level queries
    hi = run_high_level_queries(session)

    # Summary report
    write_summary(config.REPORT_DIR, len(repos), hi)

    logging.info("Shai-Hulud scan completed")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)
