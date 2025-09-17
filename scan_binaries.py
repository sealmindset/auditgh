#!/usr/bin/env python3
"""
Repository scanner that identifies binaries and executables stored in repos.

Outputs per-repo into binaries_reports/<repo_name>/:
- <repo>_binaries.json
- <repo>_binaries.md

Heuristics used:
- Executable bit on POSIX (os.access X_OK)
- Magic headers (ELF, PE, Mach-O)
- Null-byte and non-text ratio to detect generic binary files
- Known executable extensions on Windows (.exe, .dll, .bat, .cmd, .msi, .ps1)
- Archives (zip, tar, gz) and other application/* types via simple header checks

Authentication and repo listing mirror scan_gitleaks.py behavior.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import logging
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import fnmatch

import requests
from dotenv import load_dotenv

from src.github.rate_limit import make_rate_limited_session, request_with_rate_limit

# Load environment variables from .env file
load_dotenv(override=True)


class BinariesConfig:
    """Configuration for the binaries scanner."""

    def __init__(self):
        self.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        self.ORG_NAME = os.getenv("GITHUB_ORG")
        if not self.GITHUB_TOKEN:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        if not self.ORG_NAME:
            raise ValueError("GITHUB_ORG environment variable is required")
        self.GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com")
        self.REPORT_DIR = os.path.abspath(os.getenv("BINARIES_REPORT_DIR", "binaries_reports"))
        self.CLONE_DIR: Optional[str] = None
        self.HEADERS = {
            "Authorization": f"token {self.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "auditgh-scan-binaries",
        }


config: Optional[BinariesConfig] = None


# --------------
# Logging / HTTP
# --------------

def setup_logging(verbosity: int = 1):
    level = logging.INFO
    if verbosity > 1:
        level = logging.DEBUG
    elif verbosity == 0:
        level = logging.WARNING
    # Ensure logs directory exists
    try:
        os.makedirs('logs', exist_ok=True)
    except Exception:
        pass
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(), logging.FileHandler('logs/binaries_scan.log')]
    )


def make_session() -> requests.Session:
    token = config.GITHUB_TOKEN if config else None
    return make_rate_limited_session(token, user_agent="auditgh-binaries")


# --------------
# GitHub helpers
# --------------

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
            resp = request_with_rate_limit(session, 'GET', url, params=params, timeout=30, logger=logging.getLogger('binaries.api'))
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
        response = request_with_rate_limit(session, 'GET', url, timeout=30, logger=logging.getLogger('binaries.api'))
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching repository {repo_identifier}: {e}")
        return None


# --------------
# Git helpers
# --------------

def clone_repo(repo: Dict[str, Any]) -> Optional[str]:
    if not config.CLONE_DIR:
        config.CLONE_DIR = tempfile.mkdtemp(prefix="repo_scan_bin_")
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
# Binary identification
# --------------

_WIN_EXEC_EXTS = {'.exe', '.dll', '.bat', '.cmd', '.msi', '.ps1'}
_ARCHIVE_EXTS = {'.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar'}


def _read_head(path: str, n: int = 8192) -> bytes:
    try:
        with open(path, 'rb') as f:
            return f.read(n)
    except Exception:
        return b''


def _sha256_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _is_executable(path: str, head: bytes) -> bool:
    try:
        st_mode = os.stat(path).st_mode
        if stat.S_ISREG(st_mode) and (st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
            return True
    except Exception:
        pass
    # Windows heuristics
    ext = os.path.splitext(path)[1].lower()
    if ext in _WIN_EXEC_EXTS:
        return True
    # Shebang (script)
    if head.startswith(b'#!'):
        return True
    return False


def _binary_type(head: bytes, path: str) -> str:
    # ELF
    if head.startswith(b"\x7fELF"):
        return 'ELF binary'
    # PE/COFF
    if head.startswith(b"MZ"):
        return 'PE/COFF (Windows)'
    # Mach-O (common magics)
    for m in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        if head.startswith(m):
            return 'Mach-O'
    # Archives
    ext = os.path.splitext(path)[1].lower()
    if ext in _ARCHIVE_EXTS:
        return f'Archive ({ext})'
    if head.startswith(b"PK\x03\x04"):
        return 'Zip archive'
    if head.startswith(b"\x1f\x8b\x08"):
        return 'Gzip archive'
    # Scripts (shebang)
    if head.startswith(b'#!'):
        return 'Script (shebang)'
    return 'Unknown'


def _is_probably_binary(head: bytes) -> bool:
    if not head:
        return False
    # Null-byte heuristic
    if b"\x00" in head:
        return True
    # Try to decode as UTF-8; if too many decode failures/ non-text chars, treat as binary
    # Simple heuristic: count of bytes outside common text range
    text_like = sum(1 for b in head if 9 <= b <= 13 or 32 <= b <= 126)
    ratio = text_like / max(1, len(head))
    return ratio < 0.7


def _is_ignored(rel_path: str, patterns: List[str]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(rel_path.lower(), pat.lower()):
            return True
    return False


def scan_repo_for_binaries(repo_path: str, *, min_size_bytes: int = 1024, ignore_globs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    ignore_globs = ignore_globs or []
    for root, dirs, files in os.walk(repo_path):
        # Skip .git and large vendor folders
        dirs[:] = [d for d in dirs if d not in {'.git', '.hg', '.svn', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__'}]
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                # Skip symlinks
                if os.path.islink(fpath):
                    continue
                head = _read_head(fpath)
                size = os.path.getsize(fpath)
                if size < max(0, int(min_size_bytes)):
                    continue
                ext = os.path.splitext(fname)[1].lower()
                is_exec = _is_executable(fpath, head)
                is_bin = _is_probably_binary(head) or is_exec
                if not is_bin:
                    continue
                btype = _binary_type(head, fpath)
                rel = os.path.relpath(fpath, repo_path)
                if ignore_globs and _is_ignored(rel, ignore_globs):
                    continue
                sha256 = _sha256_file(fpath)
                mode = ''
                try:
                    mode = oct(os.stat(fpath).st_mode & 0o777)
                except Exception:
                    pass
                findings.append({
                    'path': rel,
                    'filename': fname,
                    'extension': ext or '',
                    'size_bytes': int(size),
                    'is_executable': bool(is_exec),
                    'type': btype,
                    'sha256': sha256 or '',
                    'mode': mode,
                })
            except Exception as e:
                logging.debug(f"Error processing file {fpath}: {e}")
                continue
    return findings


# --------------
# Reporting
# --------------

def write_repo_report(repo: Dict[str, Any], repo_path: str, report_dir: str, findings: List[Dict[str, Any]]) -> None:
    os.makedirs(report_dir, exist_ok=True)
    repo_name = repo['name']
    md_path = os.path.join(report_dir, f"{repo_name}_binaries.md")
    json_path = os.path.join(report_dir, f"{repo_name}_binaries.json")

    # JSON
    try:
        with open(json_path, 'w') as jf:
            json.dump({'repository': repo.get('full_name', repo_name), 'findings': findings}, jf, indent=2)
    except Exception as e:
        logging.error(f"Failed to write JSON report for {repo_name}: {e}")

    # Markdown
    total = len(findings)
    total_exec = sum(1 for f in findings if f.get('is_executable'))
    total_archives = sum(1 for f in findings if 'archive' in (f.get('type','').lower()))

    with open(md_path, 'w') as f:
        f.write(f"# Binary/Executable Inventory\n\n")
        f.write(f"**Repository:** {repo.get('full_name', repo_name)}\n\n")
        f.write(f"- Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- Total binary-like files: {total}\n")
        f.write(f"- Executable files: {total_exec}\n")
        f.write(f"- Archives detected: {total_archives}\n\n")

        if findings:
            f.write("## Findings\n\n")
            f.write("| Path | Size | Executable | Type | SHA256 |\n")
            f.write("|------|-----:|-----------:|------|--------|\n")
            for it in sorted(findings, key=lambda x: (-int(x.get('is_executable') or 0), -int(x.get('size_bytes') or 0))):
                size_str = f"{it.get('size_bytes', 0):,}"
                exe_str = 'Y' if it.get('is_executable') else ''
                sha = (it.get('sha256') or '')[:12]
                f.write(f"| `{it.get('path','')}` | {size_str} | {exe_str} | {it.get('type','')} | `{sha}` |\n")
        else:
            f.write("## Findings\n\n")
            f.write("No binary files detected.\n")


# --------------
# Orchestration
# --------------

def process_repo(repo: Dict[str, Any], report_dir: str, *, min_size_bytes: int = 1024, ignore_globs: Optional[List[str]] = None) -> None:
    repo_name = repo['name']
    repo_full = repo['full_name']
    logging.info(f"Processing repository: {repo_full}")
    repo_report_dir = os.path.join(report_dir, repo_name)
    os.makedirs(repo_report_dir, exist_ok=True)

    repo_path = clone_repo(repo)
    if not repo_path:
        logging.error(f"Failed to clone repository: {repo_full}")
        return

    try:
        findings = scan_repo_for_binaries(repo_path, min_size_bytes=min_size_bytes, ignore_globs=ignore_globs)
        write_repo_report(repo, repo_path, repo_report_dir, findings)
    except Exception as e:
        logging.error(f"Error processing repository {repo_full}: {e}")
    finally:
        try:
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
        except Exception as e:
            logging.error(f"Error cleaning up repository {repo_full}: {e}")


def generate_summary_report(report_dir: str, repo_count: int, stats: List[Tuple[str, int, int]]):
    summary_file = os.path.join(report_dir, "binaries_scan_summary.md")
    with open(summary_file, 'w') as f:
        f.write("# Binaries Scan Summary\n\n")
        f.write(f"**Scan Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"## Scan Results\n")
        f.write(f"- **Total Repositories Scanned:** {repo_count}\n\n")
        if stats:
            f.write("| Repository | Binary-like Files | Executables |\n")
            f.write("|------------|------------------:|-----------:|\n")
            for name, total, execs in stats:
                f.write(f"| {name} | {total} | {execs} |\n")
        else:
            f.write("No repositories had binary files.\n")


def main():
    # Try to initialize config first to validate required environment variables
    try:
        global config
        config = BinariesConfig()
    except ValueError as e:
        print(f"Error: {str(e)}")
        print("Please ensure you have a .env file with the required variables or set them in your environment.")
        print("Required variables: GITHUB_TOKEN, GITHUB_ORG")
        print("Optional variables: GITHUB_API, BINARIES_REPORT_DIR")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Scan GitHub repositories for stored binaries/executables')
    parser.add_argument('--org', type=str, default=config.ORG_NAME,
                        help=f'GitHub organization name (default: {config.ORG_NAME})')
    parser.add_argument('--repo', type=str,
                        help='Single repository to scan (format: owner/repo or repo_name)')
    parser.add_argument('--token', type=str,
                        help='GitHub personal access token (overrides GITHUB_TOKEN from .env)')
    parser.add_argument('--output-dir', type=str, default=config.REPORT_DIR,
                        help=f'Output directory for reports (default: {config.REPORT_DIR})')
    parser.add_argument('--include-forks', action='store_true',
                        help='Include forked repositories')
    parser.add_argument('--include-archived', action='store_true',
                        help='Include archived repositories')
    parser.add_argument('-v', '--verbose', action='count', default=1,
                        help='Increase verbosity (can be specified multiple times)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Suppress output (overrides --verbose)')
    parser.add_argument('--min-size-bytes', type=int, default=1024,
                        help='Skip files smaller than this size in bytes (default: 1024)')
    parser.add_argument('--ignore-glob', action='append', default=[],
                        help='Glob pattern to ignore (repeatable), e.g., dist/**, build/**, *.map')

    args = parser.parse_args()

    # Configure logging
    if args.quiet:
        args.verbose = 0
    setup_logging(args.verbose)

    # Update config from command line arguments (overrides .env)
    if args.token:
        config.GITHUB_TOKEN = args.token
        config.HEADERS["Authorization"] = f"token {config.GITHUB_TOKEN}"

    if args.org and args.org != config.ORG_NAME:
        config.ORG_NAME = args.org
        logging.info(f"Using organization from command line: {config.ORG_NAME}")

    if args.output_dir != config.REPORT_DIR:
        config.REPORT_DIR = os.path.abspath(args.output_dir)
        logging.info(f"Using output directory: {config.REPORT_DIR}")

    # Create report directory
    os.makedirs(config.REPORT_DIR, exist_ok=True)

    # Set up requests session
    session = make_session()

    # Get repositories to scan
    if args.repo:
        # Single repository mode
        repo = get_single_repo(session, args.repo)
        if not repo:
            logging.error(f"Repository not found: {args.repo}")
            sys.exit(1)
        repos = [repo]
    else:
        # Organization-wide scan
        logging.info(f"Fetching repositories from organization: {config.ORG_NAME}")
        repos = get_all_repos(
            session,
            include_forks=args.include_forks,
            include_archived=args.include_archived
        )
        if not repos:
            logging.error("No repositories found or accessible with the provided token.")
            sys.exit(1)
        logging.info(f"Found {len(repos)} repositories to scan")

    # Process repositories in parallel
    stats: List[Tuple[str, int, int]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_repo = {executor.submit(process_repo, repo, config.REPORT_DIR, min_size_bytes=args.min_size_bytes, ignore_globs=args.ignore_glob or []): repo for repo in repos}
        for future in concurrent.futures.as_completed(future_to_repo):
            repo = future_to_repo[future]
            try:
                future.result()
                # Tally from per-repo JSON
                json_path = os.path.join(config.REPORT_DIR, repo['name'], f"{repo['name']}_binaries.json")
                totals = (0, 0)
                if os.path.exists(json_path):
                    try:
                        with open(json_path, 'r') as jf:
                            data = json.load(jf) or {}
                        fs = data.get('findings') or []
                        totals = (len(fs), sum(1 for x in fs if x.get('is_executable')))
                    except Exception:
                        totals = (0, 0)
                stats.append((repo['name'], totals[0], totals[1]))
            except Exception as e:
                logging.error(f"Error processing repository {repo['name']}: {e}")

    # Generate summary report
    generate_summary_report(config.REPORT_DIR, len(repos), stats)

    # Clean up temporary directory if it was created
    if hasattr(config, 'CLONE_DIR') and config.CLONE_DIR and os.path.exists(config.CLONE_DIR):
        try:
            shutil.rmtree(config.CLONE_DIR)
        except Exception as e:
            logging.error(f"Error cleaning up temporary directory: {e}")

    logging.info("Binaries scan completed!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)
