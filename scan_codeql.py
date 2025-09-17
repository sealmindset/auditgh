#!/usr/bin/env python3
"""
Polyglot SAST scanner using the CodeQL CLI.

- Detects repo languages
- Creates/uses a cached CodeQL database per repo+language
- Analyzes with per-language query packs (default: code-scanning)
- Exports SARIF and a normalized JSON
- Generates a Markdown report
- Normalizes to the shared schema with source=codeql and severity from CodeQL

Prereqs:
- CodeQL CLI installed and on PATH
- Build tools for compiled languages (CodeQL --autobuild will try)

Env (required): GITHUB_TOKEN, GITHUB_ORG
Optional env: GITHUB_API, REPORT_DIR, CODEQL_CACHE_DIR, CODEQL_QUERY_SUITE, CODEQL_MAX_WORKERS
"""

import argparse
import datetime
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import concurrent.futures
from typing import Dict, List, Optional, Any, Tuple, Set

import requests
from src.github.rate_limit import make_rate_limited_session, request_with_rate_limit
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from dotenv import load_dotenv

load_dotenv(override=True)

# -----------------
# Config
# -----------------
class CodeQLConfig:
    def __init__(self):
        self.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        self.ORG_NAME = os.getenv("GITHUB_ORG")
        if not self.GITHUB_TOKEN:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        if not self.ORG_NAME:
            raise ValueError("GITHUB_ORG environment variable is required")
        self.GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com")
        self.REPORT_DIR = os.path.abspath(os.getenv("REPORT_DIR", "codeql_reports"))
        self.CODEQL_CACHE_DIR = os.path.abspath(os.getenv("CODEQL_CACHE_DIR", ".cache/codeql"))
        self.HEADERS = {
            "Authorization": f"token {self.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
        }
        self.QUERY_SUITE = os.getenv("CODEQL_QUERY_SUITE", "code-scanning")
        try:
            self.MAX_WORKERS = int(os.getenv("CODEQL_MAX_WORKERS", "4"))
        except Exception:
            self.MAX_WORKERS = 4
        self.CLONE_DIR: Optional[str] = None

config: Optional[CodeQLConfig] = None
_AUTO_BUILD_SUPPORTED: Optional[bool] = None

# -----------------
# Logging/session
# -----------------

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
        handlers=[logging.StreamHandler(), logging.FileHandler('logs/codeql_scan.log')]
    )

def make_session() -> requests.Session:
    return make_rate_limited_session(config.GITHUB_TOKEN, user_agent="auditgh-codeql")

# -----------------
# GitHub helpers
# -----------------

def _filter_page_repos(page_repos: List[Dict[str, Any]], include_forks: bool, include_archived: bool) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in page_repos or []:
        if (not include_forks and r.get('fork')) or (not include_archived and r.get('archived')):
            continue
        out.append(r)
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
            resp = request_with_rate_limit(session, 'GET', url, params=params, timeout=30, logger=logging.getLogger('codeql.api'))
            if not is_user_fallback and page == 1 and resp.status_code == 404:
                logging.info("Org not found. Retrying as user...")
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
        r = request_with_rate_limit(session, 'GET', url, timeout=30, logger=logging.getLogger('codeql.api'))
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching repo {repo_identifier}: {e}")
        return None

def resolve_pack_queries(lang: str, suite: str, timeout: Optional[int] = None, suite_path: Optional[str] = None) -> Tuple[bool, List[str], str]:
    """Resolve concrete query file list for a lang:suite using CodeQL CLI.

    Prefer resolving the explicit suite file path when available.
    """
    target = suite_path if suite_path else f"codeql/{lang}-queries:{suite}"
    try:
        res = subprocess.run(
            ['codeql', 'resolve', 'queries', target, '--format', 'json'],
            capture_output=True, text=True, timeout=(timeout or 60)
        )
    except subprocess.TimeoutExpired:
        return False, [], f"codeql resolve queries timed out for {target}"
    if res.returncode != 0:
        return False, [], res.stderr or res.stdout
    try:
        data = json.loads(res.stdout)
        if isinstance(data, list) and data:
            return True, data, ''
    except Exception as e:
        return False, [], f"Failed parsing resolve queries output: {e}"
    return False, [], 'No queries resolved'

def _parse_query_metadata_id(ql_path: str) -> Optional[str]:
    """Parse a CodeQL query file to extract its @id (e.g., js/path-injection)."""
    try:
        with open(ql_path, 'r', encoding='utf-8', errors='ignore') as f:
            head = f.read(4000)
    except Exception:
        return None
    # Look for '@id <value>' in the query header block
    m = re.search(r"@id\s+([\w\-./]+)", head)
    if m:
        return m.group(1).strip()
    # Fallback: 'id: <value>' form
    m = re.search(r"\bid\s*:\s*([\w\-./]+)", head)
    if m:
        return m.group(1).strip()
    return None

def _build_ruleid_to_qhelp_map(lang: str, suite_guess: Optional[str], timeout: Optional[int]) -> Dict[str, str]:
    """Construct a mapping from rule id -> qhelp file path for a language/suite.

    Tries suite_guess first, then common suites to improve hit rate.
    """
    rule_to_qhelp: Dict[str, str] = {}
    suites = []
    if suite_guess:
        suites.append(suite_guess)
    for fb in ['code-scanning', 'security-extended']:
        if fb not in suites:
            suites.append(fb)
    seen_queries: Set[str] = set()
    for s in suites:
        ok, queries, _ = resolve_pack_queries(lang, s, timeout)
        if not ok:
            continue
        for q in queries:
            if q in seen_queries:
                continue
            seen_queries.add(q)
            rid = _parse_query_metadata_id(q) or ''
            if not rid:
                continue
            base, ext = os.path.splitext(q)
            qhelp = base + '.qhelp'
            if os.path.isfile(qhelp):
                rule_to_qhelp[rid] = qhelp
    return rule_to_qhelp

def _extract_qhelp_sections(qhelp_path: str) -> Dict[str, str]:
    """Parse a .qhelp file and return sections by heading name (lowercased)."""
    try:
        with open(qhelp_path, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
    except Exception:
        return {}
    lines = text.splitlines()
    sections: Dict[str, List[str]] = {}
    current = 'intro'
    sections[current] = []
    for ln in lines:
        if ln.startswith('#'):
            # Heading line: count #'s and get title
            title = ln.lstrip('#').strip().lower()
            if not title:
                title = 'intro'
            current = title
            if current not in sections:
                sections[current] = []
            continue
        sections.setdefault(current, []).append(ln)
    # Convert to text
    out: Dict[str, str] = {}
    for k, vals in sections.items():
        txt = '\n'.join(vals).strip()
        if txt:
            out[k] = txt
    return out

def clone_repo(repo: Dict[str, Any]) -> Optional[str]:
    if not config.CLONE_DIR:
        config.CLONE_DIR = tempfile.mkdtemp(prefix="repo_scan_codeql_")
    repo_name = repo['name']
    clone_url = repo.get('clone_url')
    if config.GITHUB_TOKEN and clone_url and clone_url.startswith('https://') and '@' not in clone_url:
        clone_url = clone_url.replace('https://', f'https://x-access-token:{config.GITHUB_TOKEN}@')
    repo_path = os.path.join(config.CLONE_DIR, repo_name)
    try:
        if os.path.exists(repo_path):
            subprocess.run(['git', '-C', repo_path, 'fetch', '--all'], check=True, capture_output=True, text=True)
            subprocess.run(['git', '-C', repo_path, 'reset', '--hard', 'origin/HEAD'], check=True, capture_output=True, text=True)
        else:
            subprocess.run(['git', 'clone', '--depth', '1', clone_url, repo_path], check=True, capture_output=True, text=True)
        return repo_path
    except subprocess.CalledProcessError as e:
        logging.error(f"Git error cloning {repo_name}: {e.stderr}")
        return None

# -----------------
# Language detection
# -----------------

def detect_languages(repo_path: str, explicit: Optional[List[str]] = None) -> List[str]:
    if explicit:
        return [l.lower() for l in explicit]
    langs: Set[str] = set()
    for root, _, files in os.walk(repo_path):
        for fname in files:
            low = fname.lower()
            # Java/Kotlin
            if low.endswith(('.java', '.kt', '.kts')) or low in ('pom.xml', 'build.gradle', 'build.gradle.kts'):
                langs.add('java')
            # JavaScript/TypeScript
            elif low.endswith(('.js', '.jsx', '.ts', '.tsx')) or low in ('package.json', 'tsconfig.json'):
                langs.add('javascript')
            # Python
            elif low.endswith('.py'):
                langs.add('python')
            # Go
            elif low.endswith('.go') or low == 'go.mod':
                langs.add('go')
            # C/C++
            elif low.endswith(('.c', '.cc', '.cpp', '.cxx', '.h', '.hpp')) or low in ('cmakelists.txt', 'cmakelists.txt'):
                langs.add('cpp')
            # C#
            elif low.endswith('.cs') or low.endswith('.csproj') or low.endswith('.sln'):
                langs.add('csharp')
            # Ruby
            elif low.endswith('.rb') or low == 'gemfile':
                langs.add('ruby')
            # Swift (optional; only if packs available)
            elif low.endswith('.swift'):
                langs.add('swift')
        if len(langs) >= 6:
            break
    return sorted(langs)

# -----------------
# CodeQL execution
# -----------------

def ensure_codeql() -> Optional[str]:
    path = shutil.which('codeql')
    if not path:
        logging.error("CodeQL CLI not found. Install CodeQL and ensure 'codeql' is on PATH.")
        return None
    return path

def _supports_autobuild() -> bool:
    global _AUTO_BUILD_SUPPORTED
    if _AUTO_BUILD_SUPPORTED is not None:
        return _AUTO_BUILD_SUPPORTED
    try:
        res = subprocess.run(['codeql', 'database', 'create', '--help'], capture_output=True, text=True, timeout=15)
        text = (res.stdout or '') + ("\n" + res.stderr if res.stderr else '')
        _AUTO_BUILD_SUPPORTED = ('--autobuild' in text)
        return _AUTO_BUILD_SUPPORTED
    except Exception:
        _AUTO_BUILD_SUPPORTED = False
        return False

def codeql_pack_for_lang(lang: str, suite: str) -> str:
    # Use named suite reference; CodeQL resolves within the pack.
    # Example: codeql/javascript-queries:code-scanning
    return f"codeql/{lang}-queries:{suite}"

def codeql_database_dir(repo_name: str, lang: str) -> str:
    return os.path.join(config.CODEQL_CACHE_DIR, repo_name, f"{lang}_db")

def ensure_codeql_pack(lang: str, timeout: Optional[int] = None) -> Tuple[bool, str]:
    """Download required query pack for the language to avoid missing suite errors."""
    pack = f"codeql/{lang}-queries"
    try:
        result = subprocess.run(['codeql', 'pack', 'download', pack], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"codeql pack download timed out after {timeout}s"
    if result.returncode != 0:
        return False, result.stderr
    return True, result.stdout

def codeql_database_finalize(db_dir: str, timeout: Optional[int] = None) -> Tuple[bool, str]:
    try:
        res = subprocess.run(['codeql', 'database', 'finalize', db_dir], capture_output=True, text=True, cwd=db_dir, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"CodeQL database finalize timed out after {timeout}s"
    # Some versions may return non-zero if already finalized; accept common messages
    out = (res.stdout or '') + ("\n" + res.stderr if res.stderr else '')
    if res.returncode == 0 or 'already' in out.lower():
        return True, out
    return False, out

def _version_key(v: str) -> Tuple[int, ...]:
    parts = re.split(r"[._-]", v)
    out: List[int] = []
    for p in parts:
        try:
            out.append(int(p))
        except Exception:
            break
    return tuple(out) if out else (0,)

def resolve_pack_suite_path(lang: str, suite: str) -> Optional[str]:
    """Best-effort resolution of a pack's suite .qls file on disk.

    Handles language-prefixed suite filenames (e.g., javascript-security-extended.qls)
    as well as generic names (e.g., security-extended.qls).

    Tries `codeql resolve qlpacks` JSON; falls back to ~/.codeql/packages lookup.
    """
    try:
        res = subprocess.run(
            ['codeql', 'resolve', 'qlpacks', f'codeql/{lang}-queries', '--format', 'json'],
            capture_output=True, text=True, timeout=15
        )
        if res.returncode == 0 and res.stdout:
            try:
                data = json.loads(res.stdout)
                # Common shapes: {"packs":[{"location":"/path"}, ...]} or {"codeql/<lang>-queries":"/path"}
                if isinstance(data, dict):
                    if 'packs' in data and isinstance(data['packs'], list) and data['packs']:
                        loc = data['packs'][0].get('location') or data['packs'][0].get('path')
                        if loc and os.path.isdir(loc):
                            suites_dir = os.path.join(loc, 'codeql-suites')
                            if os.path.isdir(suites_dir):
                                # Prefer exact match, then language-prefixed, then suffix match
                                candidates = [
                                    f"{suite}.qls",
                                    f"{lang}-{suite}.qls",
                                ]
                                for cand in candidates:
                                    qls = os.path.join(suites_dir, cand)
                                    if os.path.isfile(qls):
                                        return qls
                                # Suffix match (e.g., *-security-extended.qls)
                                try:
                                    for fname in os.listdir(suites_dir):
                                        if fname.endswith(f"-{suite}.qls") and os.path.isfile(os.path.join(suites_dir, fname)):
                                            return os.path.join(suites_dir, fname)
                                except Exception:
                                    pass
                    else:
                        # Keyed by pack name
                        for _, loc in data.items():
                            if isinstance(loc, str) and os.path.isdir(loc):
                                suites_dir = os.path.join(loc, 'codeql-suites')
                                if os.path.isdir(suites_dir):
                                    candidates = [
                                        f"{suite}.qls",
                                        f"{lang}-{suite}.qls",
                                    ]
                                    for cand in candidates:
                                        qls = os.path.join(suites_dir, cand)
                                        if os.path.isfile(qls):
                                            return qls
                                    try:
                                        for fname in os.listdir(suites_dir):
                                            if fname.endswith(f"-{suite}.qls") and os.path.isfile(os.path.join(suites_dir, fname)):
                                                return os.path.join(suites_dir, fname)
                                    except Exception:
                                        pass
            except Exception:
                pass
    except subprocess.TimeoutExpired:
        pass
    # Fallback: ~/.codeql/packages
    base = os.path.join(os.path.expanduser('~'), '.codeql', 'packages', 'codeql', f'{lang}-queries')
    try:
        if os.path.isdir(base):
            versions = [d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))]
            versions.sort(key=_version_key, reverse=True)
            for v in versions:
                loc = os.path.join(base, v)
                suites_dir = os.path.join(loc, 'codeql-suites')
                if not os.path.isdir(suites_dir):
                    continue
                # Try both generic and language-prefixed names
                for cand in [f"{suite}.qls", f"{lang}-{suite}.qls"]:
                    qls = os.path.join(suites_dir, cand)
                    if os.path.isfile(qls):
                        return qls
                # Suffix match fallback
                try:
                    for fname in os.listdir(suites_dir):
                        if fname.endswith(f"-{suite}.qls") and os.path.isfile(os.path.join(suites_dir, fname)):
                            return os.path.join(suites_dir, fname)
                except Exception:
                    pass
    except Exception:
        pass
    return None

def codeql_database_create(
    repo_path: str,
    db_dir: str,
    lang: str,
    recreate: bool = False,
    skip_autobuild: bool = False,
    build_command: Optional[str] = None,
    timeout: Optional[int] = None,
) -> Tuple[bool, str]:
    os.makedirs(os.path.dirname(db_dir), exist_ok=True)
    if os.path.exists(db_dir) and not recreate:
        logging.info(f"Reusing cached CodeQL DB: {db_dir}")
        return True, "cached"
    if os.path.exists(db_dir) and recreate:
        shutil.rmtree(db_dir, ignore_errors=True)
    # Optional pre-build
    if build_command:
        try:
            logging.info(f"Running custom build command for {lang}: {build_command}")
            pre = subprocess.run(build_command, shell=True, capture_output=True, text=True, cwd=repo_path, timeout=timeout)
            if pre.returncode != 0:
                logging.error(f"Build command failed: {pre.stderr}")
                return False, pre.stderr
        except subprocess.TimeoutExpired:
            return False, f"Build command timed out after {timeout}s"
        except Exception as e:
            return False, str(e)
    cmd = ['codeql', 'database', 'create', db_dir, '--language', lang, '--source-root', repo_path, '--overwrite']
    if (lang in {'java', 'cpp', 'csharp'}) and not skip_autobuild and not build_command and _supports_autobuild():
        cmd.append('--autobuild')
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_path, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"CodeQL database create timed out after {timeout}s"
    if result.returncode != 0:
        return False, result.stderr
    return True, result.stdout

def codeql_database_analyze(db_dir: str, lang: str, suite: str, sarif_out: str, timeout: Optional[int] = None) -> Tuple[bool, str]:
    # Try requested suite, then fall back to common suites if needed
    suites_to_try: List[str] = []
    if suite:
        suites_to_try.append(suite)
    for fallback in ['code-scanning', 'security-extended']:
        if fallback not in suites_to_try:
            suites_to_try.append(fallback)

    last_err = ''
    # Proactively finalize database before analyze to avoid stale cached DB errors
    _ = codeql_database_finalize(db_dir, timeout)
    for s in suites_to_try:
        # Prefer suite file path when available
        suite_path = resolve_pack_suite_path(lang, s)
        if suite_path:
            cmd = ['codeql', 'database', 'analyze', db_dir, suite_path, '--format', 'sarifv2.1.0', '--output', sarif_out, '--download']
        else:
            pack = codeql_pack_for_lang(lang, s)
            cmd = ['codeql', 'database', 'analyze', db_dir, pack, '--format', 'sarifv2.1.0', '--output', sarif_out, '--download']
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=db_dir, timeout=timeout)
        except subprocess.TimeoutExpired:
            last_err = f"CodeQL analyze timed out after {timeout}s"
            continue
        if result.returncode == 0:
            return True, result.stdout
        # If pack/suite missing, try next; otherwise keep the error
        err_text = (result.stderr or '') + ('\n' + result.stdout if result.stdout else '')
        last_err = err_text
        # Finalize-on-demand if required, then retry once for the same suite
        if 'needs to be finalized' in err_text.lower():
            f_ok, f_msg = codeql_database_finalize(db_dir, timeout)
            if f_ok:
                try:
                    rerun = subprocess.run(cmd, capture_output=True, text=True, cwd=db_dir, timeout=timeout)
                except subprocess.TimeoutExpired:
                    last_err = f"CodeQL analyze timed out after {timeout}s (after finalize)"
                else:
                    if rerun.returncode == 0:
                        return True, rerun.stdout
                    last_err = (rerun.stderr or '') + ('\n' + rerun.stdout if rerun.stdout else '')
        if ('NoSuchFileException' in err_text) or ('is not a directory' in err_text) or ('Could not read' in err_text) or ("referenced from a 'queries' instruction" in err_text):
            # Try resolving concrete queries and analyze with explicit list
            ok_q, queries, q_err = resolve_pack_queries(lang, s, timeout)
            if ok_q and queries:
                q_cmd = ['codeql', 'database', 'analyze', db_dir, '--format', 'sarifv2.1.0', '--output', sarif_out, '--download'] + queries
                try:
                    q_res = subprocess.run(q_cmd, capture_output=True, text=True, cwd=db_dir, timeout=timeout)
                except subprocess.TimeoutExpired:
                    last_err = f"CodeQL analyze (explicit queries) timed out after {timeout}s"
                    continue
                if q_res.returncode == 0:
                    return True, q_res.stdout
                last_err = (q_res.stderr or '') + ('\n' + q_res.stdout if q_res.stdout else '') or last_err
            continue
        # Non-suite-related failure; stop trying fallbacks
        break
    return False, last_err or 'Unknown analyze error'

# -----------------
# SARIF parsing and normalization
# -----------------

def _severity_from_codeql(level: Optional[str], sec_sev: Optional[float]) -> Tuple[str, Optional[float]]:
    if sec_sev is not None:
        if sec_sev >= 9.0:
            return 'Critical', sec_sev
        if sec_sev >= 7.0:
            return 'High', sec_sev
        if sec_sev >= 4.0:
            return 'Medium', sec_sev
        if sec_sev > 0:
            return 'Low', sec_sev
    lvl = (level or '').lower()
    if lvl == 'error':
        return 'High', None
    if lvl == 'warning':
        return 'Medium', None
    if lvl in ('note', 'none'):
        return 'Low', None
    return 'unknown', None

def parse_sarif_to_findings(sarif_path: str, lang: str, suite: Optional[str] = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not os.path.exists(sarif_path):
        return findings
    try:
        with open(sarif_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        logging.error(f"Failed to read SARIF {sarif_path}: {e}")
        return findings
    # Build qhelp mapping once per SARIF
    qhelp_map: Dict[str, str] = _build_ruleid_to_qhelp_map(lang, suite, timeout=30)
    for run in data.get('runs', []) or []:
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        drv = (run.get('tool') or {}).get('driver') or {}
        for rule in drv.get('rules', []) or []:
            rid = rule.get('id') or ''
            rules_by_id[rid] = rule
        for res in run.get('results', []) or []:
            rule_id = res.get('ruleId', '')
            level = res.get('level')
            rule = rules_by_id.get(rule_id, {})
            props = rule.get('properties', {}) if isinstance(rule, dict) else {}
            tags = props.get('tags', []) if isinstance(props, dict) else []
            precision = props.get('precision') if isinstance(props, dict) else None
            # Extract CWE IDs from tags when present (best-effort)
            cwe_ids: List[str] = []
            try:
                for t in tags or []:
                    m = re.search(r"cwe[-:]?(\d+)", str(t), re.IGNORECASE)
                    if m:
                        cwe_ids.append(m.group(1))
            except Exception:
                pass
            # Rule-specific mitigation and docs
            help_obj = rule.get('help') if isinstance(rule, dict) else None
            help_text = None
            if isinstance(help_obj, dict):
                help_text = help_obj.get('text') or help_obj.get('markdown')
            elif isinstance(help_obj, str):
                help_text = help_obj
            if not help_text:
                fd = rule.get('fullDescription', {}) if isinstance(rule, dict) else {}
                help_text = fd.get('text') if isinstance(fd, dict) else None
            # Use rule help/fullDescription as Description (concise: first sentence)
            description_text = None
            if help_text:
                text = str(help_text).strip().replace('\n', ' ')
                description_text = (text.split('. ')[0].strip())[:300]
            # If still missing, fallback to message text
            rule_doc_url = rule.get('helpUri') if isinstance(rule, dict) else None
            # Prefer qhelp remediation text if available
            mitigation = ''
            qh = qhelp_map.get(rule_id)
            if qh:
                secs = _extract_qhelp_sections(qh)
                # Prefer recommendation/remediation sections
                for key in ['recommendation', 'recommendations', 'remediation', 'mitigation', 'how to fix', 'fix', 'how to prevent', 'prevention']:
                    if key in secs and secs[key]:
                        mitigation = secs[key].replace('\n', ' ').strip()
                        break
                if not mitigation:
                    # Fallback to intro/summary if present
                    for key in ['summary', 'intro', 'introduction']:
                        if key in secs and secs[key]:
                            mitigation = secs[key].replace('\n', ' ').strip()
                            break
                mitigation = mitigation[:400] if mitigation else ''
            if not mitigation:
                mitigation = _rule_mitigation_suggestion(rule_id, lang, rule_doc_url)
            rule_doc_url = rule.get('helpUri') if isinstance(rule, dict) else None
            sec_sev: Optional[float] = None
            try:
                if 'security-severity' in props:
                    sec_sev = float(props.get('security-severity'))
            except Exception:
                sec_sev = None
            sev_label, cvss = _severity_from_codeql(level, sec_sev)
            msg = res.get('message', {}).get('text') or (rule.get('shortDescription', {}) or {}).get('text') or rule.get('name') or 'CodeQL finding'
            locs = res.get('locations', []) or []
            file_path = ''
            start_line = None
            if locs:
                pl = locs[0].get('physicalLocation', {})
                art = pl.get('artifactLocation', {})
                file_path = art.get('uri', '')
                region = pl.get('region', {})
                start_line = region.get('startLine')
            findings.append({
                'package': f'{lang} (code)',
                'version': '',
                'vuln_id': rule_id,
                'severity': sev_label,
                'cvss_score': cvss if cvss is not None else None,
                'epss_score': 'N/A',
                'description': description_text or msg,
                'fixed_version': 'N/A',
                'mitigation': mitigation,
                'source': 'codeql',
                'file': file_path,
                'line': start_line,
                'rule_name': rule.get('name'),
                'rule_tags': tags,
                'precision': precision,
                'cwe_ids': cwe_ids,
                'rule_doc_url': rule_doc_url,
            })
    return findings

# -----------------
# Normalization helpers
# -----------------

def _severity_rank(sev: str) -> int:
    s = (sev or '').lower()
    if 'critical' in s:
        return 4
    if 'high' in s:
        return 3
    if 'medium' in s:
        return 2
    if 'low' in s:
        return 1
    return 0

def _rule_mitigation_suggestion(rule_id: str, lang: str, rule_doc_url: Optional[str]) -> str:
    """Return concise, actionable mitigation text per rule where known; otherwise fallback to docs link."""
    rid = (rule_id or '').lower()
    l = (lang or '').lower()
    # JavaScript/TypeScript specific
    if l in {'javascript', 'typescript', 'js', 'ts'}:
        if 'path-injection' in rid:
            return (
                "Normalize and validate user-supplied paths; restrict to an allowlisted base directory; "
                "reject absolute paths and '..' segments; build paths with path.join/normalize and never concatenate raw input; "
                "perform final check that resolved path starts with the base directory."
            )
        if 'missing-rate-limiting' in rid or 'missingratelimiting' in rid:
            return (
                "Apply rate limiting to affected endpoints (for example, express-rate-limit); set per-route and global limits; "
                "log and monitor burst traffic; consider token bucket/leaky bucket algorithms to throttle expensive operations."
            )
    # Fallback
    if rule_doc_url:
        return f"See remediation guidance in the CodeQL rule docs: {rule_doc_url}"
    return "Review and apply the remediation guidance from the CodeQL rule documentation."

def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    dedup: Dict[Tuple[str, str, Optional[int]], Dict[str, Any]] = {}
    for v in findings or []:
        key = (str(v.get('vuln_id','')), str(v.get('file','')), v.get('line'))
        cur = dedup.get(key)
        if not cur:
            dedup[key] = v
            continue
        # Prefer higher CVSS, then severity rank
        cur_cvss = cur.get('cvss_score')
        v_cvss = v.get('cvss_score')
        if (v_cvss is not None and (cur_cvss is None or float(v_cvss) > float(cur_cvss))):
            dedup[key] = v
            continue
        if (cur_cvss is None and v_cvss is None) and (_severity_rank(v.get('severity','')) > _severity_rank(cur.get('severity',''))):
            dedup[key] = v
            continue
    return list(dedup.values())

# -----------------
# Orchestration per repo
# -----------------

def run_codeql_on_repo(
    repo: Dict[str, Any],
    report_dir: str,
    languages: Optional[List[str]] = None,
    recreate_db: bool = False,
    suite: Optional[str] = None,
    skip_autobuild: bool = False,
    build_command: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
    json_only: bool = False,
    sarif_only: bool = False,
    top_n: int = 300,
) -> Dict[str, Any]:
    os.makedirs(report_dir, exist_ok=True)
    repo_name = repo['name']
    repo_dir = os.path.join(report_dir, repo_name)
    os.makedirs(repo_dir, exist_ok=True)

    if not ensure_codeql():
        md_path = os.path.join(repo_dir, f"{repo_name}_codeql.md")
        with open(md_path, 'w') as f:
            f.write("# CodeQL Scan Report\n\nCodeQL CLI not found on PATH. Please install CodeQL and retry.\n")
        return {"success": False, "error": "CodeQL not installed", "report_file": md_path}

    repo_path = clone_repo(repo)
    if not repo_path:
        return {"success": False, "error": "Clone failed"}

    try:
        langs = detect_languages(repo_path, languages)
        if not langs:
            md_path = os.path.join(repo_dir, f"{repo_name}_codeql.md")
            with open(md_path, 'w') as f:
                f.write(f"# CodeQL Scan Report\n\n**Repository:** {repo_name}\n\nNo supported languages detected.\n")
            return {"success": True, "languages": []}

        all_findings: List[Dict[str, Any]] = []
        sarif_paths: List[str] = []
        diagnostics: List[str] = []
        for lang in langs:
            db_dir = codeql_database_dir(repo_name, lang)
            ok, db_msg = codeql_database_create(
                repo_path,
                db_dir,
                lang,
                recreate=recreate_db,
                skip_autobuild=skip_autobuild,
                build_command=build_command,
                timeout=timeout_seconds,
            )
            if not ok:
                logging.warning(f"Skipping analyze for {lang} due to DB create failure: {db_msg}")
                diagnostics.append(f"[{lang}] DB create failed: {db_msg}\n")
                continue
            # Finalize cached or newly created DB before analyze
            f_ok, f_msg = codeql_database_finalize(db_dir, timeout_seconds)
            if not f_ok:
                diagnostics.append(f"[{lang}] DB finalize warning: {f_msg}\n")
            # Ensure the language query pack is available locally
            p_ok, p_msg = ensure_codeql_pack(lang, timeout=timeout_seconds)
            if not p_ok:
                logging.warning(f"Failed to download CodeQL pack for {lang}: {p_msg}")
                diagnostics.append(f"[{lang}] Pack download failed: {p_msg}\n")
            sarif_out = os.path.join(repo_dir, f"{repo_name}_codeql_{lang}.sarif")
            ok, an_msg = codeql_database_analyze(db_dir, lang, suite or config.QUERY_SUITE, sarif_out, timeout=timeout_seconds)
            if not ok:
                logging.warning(f"Analyze failed for {lang}: {an_msg}")
                diagnostics.append(f"[{lang}] Analyze failed: {an_msg}\n")
                continue
            # Manage SARIF retention
            if not json_only:
                sarif_paths.append(sarif_out)
            # Parse SARIF for normalization and summaries
            parsed = parse_sarif_to_findings(sarif_out, lang, suite or config.QUERY_SUITE)
            all_findings.extend(parsed)
            # If JSON-only, remove SARIF to save space
            if json_only:
                try:
                    os.remove(sarif_out)
                except Exception:
                    pass

        # Deduplicate and rank
        deduped_findings = deduplicate_findings(all_findings)
        # Compute severity counts
        sev_counts: Dict[str, int] = {}
        for v in deduped_findings:
            sev = v.get('severity', 'unknown')
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Write normalized JSON unless SARIF-only
        norm_json = None
        if not sarif_only:
            norm_json = os.path.join(repo_dir, f"{repo_name}_codeql.json")
            with open(norm_json, 'w') as jf:
                json.dump(deduped_findings, jf, indent=2)

        # Markdown report unless SARIF-only
        md_path = None
        if not sarif_only:
            md_path = os.path.join(repo_dir, f"{repo_name}_codeql.md")
            with open(md_path, 'w') as f:
                f.write("# CodeQL Scan Report\n\n")
                f.write(f"**Repository:** {repo.get('full_name', repo_name)}\n\n")
                f.write(f"**Scanned on:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Languages:** {', '.join(langs)}\n\n")
                if diagnostics:
                    f.write("## Diagnostics\n\n")
                    for line in diagnostics:
                        f.write(f"- {line}")
                    f.write("\n")
                if sarif_paths:
                    f.write("## SARIF Artifacts\n\n")
                    for p in sarif_paths:
                        f.write(f"- `{os.path.relpath(p, repo_dir)}`\n")
                    f.write("\n")
                f.write("## Summary\n\n")
                f.write(f"- Total findings: {len(deduped_findings)}\n")
                for k in ['Critical','High','Medium','Low','unknown']:
                    if sev_counts.get(k):
                        f.write(f"- {k}: {sev_counts[k]}\n")
                f.write("\n")
                if deduped_findings:
                    f.write("## Top Findings\n\n")
                    f.write("| Severity | Rule | File | Line | Description | Mitigation |\n")
                    f.write("|----------|------|------|------|-------------|------------|\n")
                    # Sort by cvss desc, then severity rank
                    sorted_findings = sorted(deduped_findings, key=lambda v: (float(v.get('cvss_score') or -1), _severity_rank(v.get('severity',''))), reverse=True)
                    for v in sorted_findings[:max(1, top_n)]:
                        rule = v.get('vuln_id','')
                        filep = v.get('file','')
                        line = v.get('line','')
                        desc = (v.get('description','') or '').replace('\n',' ').strip()
                        mit = (v.get('mitigation','') or '').replace('\n',' ').strip()
                        f.write(f"| {v.get('severity','unknown')} | {rule} | {filep} | {line} | {desc} | {mit} |\n")
                else:
                    f.write("No findings.\n")

        return {
            "success": True,
            "languages": langs,
            "normalized": norm_json,
            "report_file": md_path,
            "sarif": sarif_paths,
            "count": len(deduped_findings),
            "severity_counts": sev_counts,
            "name": repo_name,
        }
    finally:
        try:
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
        except Exception as e:
            logging.error(f"Cleanup error for {repo_name}: {e}")

# -----------------
# CLI
# -----------------

def write_org_summary(report_root: str, per_repo_stats: List[Dict[str, Any]]) -> None:
    md = os.path.join(report_root, "codeql_summary.md")
    with open(md, 'w') as f:
        f.write("# CodeQL Summary\n\n")
        f.write(f"**Organization:** {config.ORG_NAME}\n\n")
        f.write(f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("## Repositories Scanned\n\n")
        f.write("| Repo | Languages | Total | Critical | High | Medium | Low |\n")
        f.write("|------|-----------|-------|----------|------|--------|-----|\n")
        for st in per_repo_stats:
            counts = st.get('severity_counts') or {}
            f.write(
                f"| {st['name']} | {', '.join(st.get('languages') or [])} | {st.get('count', 0)} | "
                f"{counts.get('Critical', 0)} | {counts.get('High', 0)} | {counts.get('Medium', 0)} | {counts.get('Low', 0)} |\n"
            )

def _meets_threshold(sev: str, threshold: str) -> bool:
    order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    return order.get(sev.lower(), 0) >= order.get(threshold.lower(), 0)

def main():
    try:
        global config
        config = CodeQLConfig()
    except ValueError as e:
        print(f"Error: {str(e)}")
        print("Ensure .env has GITHUB_TOKEN and GITHUB_ORG or pass --token/--org.")
        sys.exit(1)

    p = argparse.ArgumentParser(description='Scan GitHub repositories with CodeQL')
    p.add_argument('--org', type=str, default=config.ORG_NAME, help='GitHub organization')
    p.add_argument('--repo', type=str, help='Single repository (owner/repo or repo_name)')
    p.add_argument('--token', type=str, help='GitHub token (overrides env)')
    p.add_argument('--output-dir', type=str, default=config.REPORT_DIR, help='Output directory')
    p.add_argument('--include-forks', action='store_true', help='Include forked repos')
    p.add_argument('--include-archived', action='store_true', help='Include archived repos')
    p.add_argument('--languages', nargs='+', help='Explicit languages to scan (e.g., java javascript python)')
    p.add_argument('--recreate-db', action='store_true', help='Recreate CodeQL databases instead of reusing cache')
    p.add_argument('--query-suite', type=str, default=config.QUERY_SUITE, help='Query suite (code-scanning, security-extended, security-and-quality)')
    p.add_argument('--max-workers', type=int, default=config.MAX_WORKERS, help='Parallel workers for repo scanning')
    p.add_argument('--fail-fast', action='store_true', help='Exit with non-zero if threshold severity is found')
    p.add_argument('--fail-on-severity', type=str, choices=['critical','high','medium','low'], help='Severity threshold for failing the run')
    p.add_argument('--sarif-only', action='store_true', help='Only generate SARIF artifacts (skip JSON/Markdown)')
    p.add_argument('--json-only', action='store_true', help='Generate normalized JSON/Markdown and remove SARIF artifacts')
    p.add_argument('--top-n', type=int, default=300, help='Max findings rows in Markdown report')
    p.add_argument('--timeout-seconds', type=int, default=0, help='Timeout in seconds for CodeQL steps (0=disabled)')
    p.add_argument('--skip-autobuild', action='store_true', help='Disable CodeQL --autobuild for compiled languages')
    p.add_argument('--build-command', type=str, help='Custom build command to run before CodeQL DB create')
    p.add_argument('-v', '--verbose', action='count', default=1, help='Increase verbosity')
    p.add_argument('-q', '--quiet', action='store_true', help='Quiet mode')
    args = p.parse_args()

    if args.quiet:
        args.verbose = 0
    setup_logging(args.verbose)

    if args.token:
        config.GITHUB_TOKEN = args.token
        config.HEADERS["Authorization"] = f"token {config.GITHUB_TOKEN}"
    if args.org and args.org != config.ORG_NAME:
        config.ORG_NAME = args.org
    if args.output_dir != config.REPORT_DIR:
        config.REPORT_DIR = os.path.abspath(args.output_dir)
    os.makedirs(config.REPORT_DIR, exist_ok=True)

    session = make_session()

    # Resolve repos
    repos: List[Dict[str, Any]]
    if args.repo:
        r = get_single_repo(session, args.repo)
        if not r:
            logging.error(f"Repository not found: {args.repo}")
            sys.exit(1)
        repos = [r]
    else:
        repos = get_all_repos(session, include_forks=args.include_forks, include_archived=args.include_archived)
        if not repos:
            logging.error("No repositories found.")
            sys.exit(1)
        logging.info(f"Found {len(repos)} repositories")

    # Resolve timeouts
    timeout_seconds = args.timeout_seconds if args.timeout_seconds and args.timeout_seconds > 0 else None

    per_repo_stats: List[Dict[str, Any]] = []
    threshold_hit = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        fut_to_repo = {
            executor.submit(
                run_codeql_on_repo,
                repo,
                config.REPORT_DIR,
                languages=args.languages,
                recreate_db=args.recreate_db,
                suite=args.query_suite,
                skip_autobuild=args.skip_autobuild,
                build_command=args.build_command,
                timeout_seconds=timeout_seconds,
                json_only=args.json_only,
                sarif_only=args.sarif_only,
                top_n=args.top_n,
            ): repo for repo in repos
        }
        for fut in concurrent.futures.as_completed(fut_to_repo):
            repo = fut_to_repo[fut]
            repo_name = repo.get('full_name', repo.get('name'))
            try:
                res = fut.result()
            except Exception as e:
                logging.error(f"Unhandled error scanning {repo_name}: {e}")
                continue
            if res.get('success'):
                per_repo_stats.append({
                    'name': repo['name'],
                    'languages': res.get('languages') or [],
                    'count': res.get('count') or 0,
                    'severity_counts': res.get('severity_counts') or {}
                })
                # Evaluate threshold if requested
                if args.fail_on_severity:
                    counts = res.get('severity_counts') or {}
                    # If any finding meets or exceeds threshold
                    for sev in ['Critical','High','Medium','Low']:
                        if counts.get(sev, 0) and _meets_threshold(sev, args.fail_on_severity):
                            threshold_hit = True
                            break
            else:
                logging.error(f"Scan failed for {repo_name}: {res.get('error')}")

    # Write org summary
    write_org_summary(config.REPORT_DIR, per_repo_stats)

    if args.fail_fast and args.fail_on_severity and threshold_hit:
        logging.error(f"Fail-fast: findings at or above {args.fail_on_severity} detected")
        sys.exit(1)

    logging.info("CodeQL scanning complete.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)
