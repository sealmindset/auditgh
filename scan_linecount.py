#!/usr/bin/env python3
"""
Repository scanner that counts SAST-relevant lines of code (LOC) per repository.

Modeled after scan_gitleaks.py style (auth, repo discovery, cloning, logging, parallel processing),
with shared GitHub API rate-limiting helpers.

Outputs per-repo into linecount_reports/<repo_name>/:
- <repo>_linecount.json (totals, per-language breakdown)
- <repo>_linecount.md (human-readable summary)

Heuristics for SAST-relevant files:
- Include common source extensions (Python/JS/TS/Java/Go/Ruby/PHP/C/C++/C#/Kotlin/Swift/Scala/Rust/Shell/YAML)
- Exclude typical vendor/build/output directories (.git, node_modules, dist, build, vendor, .venv, venv, __pycache__, .idea, .vscode)
- Exclude minified JS/CSS by heuristic when --exclude-minified enabled (default on)
- Exclude lock and vendored metadata files by default (e.g., package-lock.json, yarn.lock, pnpm-lock.yaml, Pipfile.lock, poetry.lock)

CLI options let you customize includes/excludes.
"""
import argparse
import concurrent.futures
import datetime
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set

import requests
from dotenv import load_dotenv

from src.github.rate_limit import make_rate_limited_session, request_with_rate_limit

# Load environment variables from .env file
load_dotenv(override=True)


class LineCountConfig:
    """Configuration for the LineCount scanner."""

    def __init__(self):
        self.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        self.ORG_NAME = os.getenv("GITHUB_ORG")
        if not self.GITHUB_TOKEN:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        if not self.ORG_NAME:
            raise ValueError("GITHUB_ORG environment variable is required")
        self.GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com")
        self.REPORT_DIR = os.path.abspath(os.getenv("LINECOUNT_REPORT_DIR", "linecount_reports"))
        self.CLONE_DIR: Optional[str] = None
        self.HEADERS = {
            "Authorization": f"token {self.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "auditgh-scan-linecount",
        }


config: Optional[LineCountConfig] = None


# --------------
# Logging / HTTP
# --------------

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
        handlers=[logging.StreamHandler(), logging.FileHandler('logs/linecount_scan.log')]
    )


def make_session() -> requests.Session:
    token = config.GITHUB_TOKEN if config else None
    return make_rate_limited_session(token, user_agent="auditgh-linecount")


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
            resp = request_with_rate_limit(session, 'GET', url, params=params, timeout=30, logger=logging.getLogger('linecount.api'))
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
        response = request_with_rate_limit(session, 'GET', url, timeout=30, logger=logging.getLogger('linecount.api'))
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
        config.CLONE_DIR = tempfile.mkdtemp(prefix="repo_scan_loc_")
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
# LOC calculation
# --------------

# Default include file extensions considered by many SAST tools
_DEFAULT_EXTS: Dict[str, str] = {
    # Python
    ".py": "Python",
    # JavaScript/TypeScript
    ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    # Java/Kotlin/Scala
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala",
    # Go
    ".go": "Go",
    # Ruby
    ".rb": "Ruby",
    # PHP
    ".php": "PHP",
    # C/C++
    ".c": "C", ".h": "C/C++", ".hpp": "C++", ".hh": "C++", ".hxx": "C++", ".cpp": "C++", ".cc": "C++", ".cxx": "C++",
    # C#
    ".cs": "C#",
    # Swift/Objective-C
    ".swift": "Swift", ".m": "Objective-C", ".mm": "Objective-C++",
    # Rust
    ".rs": "Rust",
    # Shell/PowerShell
    ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell", ".ps1": "PowerShell",
    # YAML (CI/IaC often included in SAST context)
    ".yml": "YAML", ".yaml": "YAML",
    # JSON configs sometimes scanned (optional, can be excluded via flag)
    ".json": "JSON",
}

# Default excluded directories
_DEFAULT_EXCLUDE_DIRS = {".git", ".hg", ".svn", "node_modules", "dist", "build", "vendor", ".venv", "venv", "__pycache__", ".idea", ".vscode"}

# Default excluded file globs
_DEFAULT_EXCLUDE_GLOBS = [
    "*.min.js", "*.min.css",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock",
    "Cargo.lock", "go.sum",
]


def _looks_minified(text: str) -> bool:
    # Simple minified heuristic: very long lines or low newline density
    if not text:
        return False
    lines = text.splitlines() or [text]
    if len(lines) <= 2 and len(text) > 5000:
        return True
    avg_len = sum(len(l) for l in lines) / max(1, len(lines))
    return avg_len > 200


def _is_binary_by_sampling(path: str) -> bool:
    # Avoid reading entire large files; read small sample
    try:
        with open(path, 'rb') as f:
            sample = f.read(4096)
        if b"\x00" in sample:
            return True
    except Exception:
        return False
    return False


def _count_lines_text(path: str, exclude_minified: bool) -> int:
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        if exclude_minified and (path.endswith('.js') or path.endswith('.css')) and _looks_minified(content):
            return 0
        # Line count similar to SAST: number of newline-separated lines
        # If file doesn't end in newline, count last line
        lines = content.splitlines()
        return len(lines)
    except Exception:
        return 0


def scan_repo_for_loc(repo_path: str, *, include_exts: Optional[Dict[str, str]] = None,
                      exclude_dirs: Optional[Set[str]] = None,
                      exclude_globs: Optional[List[str]] = None,
                      exclude_minified: bool = True,
                      max_file_bytes: int = 5_000_000) -> Tuple[int, Dict[str, int], Dict[str, int]]:
    """Scan a repository and return:
    - total LOC
    - per-language LOC dict
    - per-language file count dict
    """
    include_exts = include_exts or dict(_DEFAULT_EXTS)
    exclude_dirs = exclude_dirs or set(_DEFAULT_EXCLUDE_DIRS)
    exclude_globs = exclude_globs or list(_DEFAULT_EXCLUDE_GLOBS)

    total_loc = 0
    lang_loc: Dict[str, int] = {}
    lang_files: Dict[str, int] = {}

    # Precompile glob regexes (simple fnmatch via regex)
    glob_regexes = [re.compile(fnmatch_to_regex(g)) for g in exclude_globs]

    for root, dirs, files in os.walk(repo_path):
        # Prune directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for fname in files:
            path = os.path.join(root, fname)
            rel = os.path.relpath(path, repo_path)

            # Exclude by glob
            if any(rgx.match(rel) for rgx in glob_regexes):
                continue

            ext = os.path.splitext(fname)[1]
            if ext not in include_exts:
                continue

            try:
                size = os.path.getsize(path)
                if size > max_file_bytes:
                    # Avoid gigantic files (likely generated or vendored)
                    continue
            except Exception:
                continue

            # Skip binary files
            if _is_binary_by_sampling(path):
                continue

            lines = _count_lines_text(path, exclude_minified)
            if lines <= 0:
                continue

            lang = include_exts.get(ext, 'Other')
            total_loc += lines
            lang_loc[lang] = lang_loc.get(lang, 0) + lines
            lang_files[lang] = lang_files.get(lang, 0) + 1

    return total_loc, lang_loc, lang_files


def fnmatch_to_regex(pat: str) -> str:
    # Convert a glob to a regex string anchored to full path
    # Use fnmatch.translate but without importing (keep simple)
    import fnmatch as _fn
    rx = _fn.translate(pat)
    # Ensure it matches whole string
    return rx


# --------------
# Reporting
# --------------

def write_repo_report(repo: Dict[str, Any], repo_path: str, report_dir: str,
                      total_loc: int, lang_loc: Dict[str, int], lang_files: Dict[str, int]) -> None:
    os.makedirs(report_dir, exist_ok=True)
    repo_name = repo['name']
    md_path = os.path.join(report_dir, f"{repo_name}_linecount.md")
    json_path = os.path.join(report_dir, f"{repo_name}_linecount.json")

    # JSON
    try:
        with open(json_path, 'w') as jf:
            json.dump({
                'repository': repo.get('full_name', repo_name),
                'total_loc': int(total_loc),
                'languages': lang_loc,
                'language_files': lang_files,
            }, jf, indent=2)
    except Exception as e:
        logging.error(f"Failed to write JSON report for {repo_name}: {e}")

    # Markdown
    with open(md_path, 'w') as f:
        f.write(f"# Line Count Summary\n\n")
        f.write(f"**Repository:** {repo.get('full_name', repo_name)}\n\n")
        f.write(f"- Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- Total SAST-relevant LOC: {total_loc:,}\n\n")

        if lang_loc:
            f.write("## By Language\n\n")
            f.write("| Language | LOC | Files | Percent |\n")
            f.write("|----------|----:|------:|--------:|\n")
            grand = max(1, sum(lang_loc.values()))
            for lang, loc in sorted(lang_loc.items(), key=lambda kv: kv[1], reverse=True):
                files = lang_files.get(lang, 0)
                pct = (loc / grand) * 100.0
                f.write(f"| {lang} | {loc:,} | {files:,} | {pct:5.1f}% |\n")
        else:
            f.write("No SAST-relevant code files detected.\n")


# --------------
# Orchestration
# --------------

def process_repo(repo: Dict[str, Any], report_dir: str, *, include_exts: Optional[Dict[str, str]] = None,
                 exclude_dirs: Optional[Set[str]] = None, exclude_globs: Optional[List[str]] = None,
                 exclude_minified: bool = True, max_file_bytes: int = 5_000_000) -> Tuple[str, int]:
    repo_name = repo['name']
    repo_full = repo['full_name']
    logging.info(f"Processing repository: {repo_full}")
    repo_report_dir = os.path.join(report_dir, repo_name)
    os.makedirs(repo_report_dir, exist_ok=True)

    repo_path = clone_repo(repo)
    if not repo_path:
        logging.error(f"Failed to clone repository: {repo_full}")
        return repo_name, 0

    try:
        total_loc, lang_loc, lang_files = scan_repo_for_loc(
            repo_path,
            include_exts=include_exts,
            exclude_dirs=exclude_dirs,
            exclude_globs=exclude_globs,
            exclude_minified=exclude_minified,
            max_file_bytes=max_file_bytes,
        )
        write_repo_report(repo, repo_path, repo_report_dir, total_loc, lang_loc, lang_files)
        return repo_name, total_loc
    except Exception as e:
        logging.error(f"Error processing repository {repo_full}: {e}")
        return repo_name, 0
    finally:
        try:
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
        except Exception as e:
            logging.error(f"Error cleaning up repository {repo_full}: {e}")


def generate_summary_report(report_dir: str, repo_counts: List[Tuple[str, int]]):
    summary_file = os.path.join(report_dir, "linecount_scan_summary.md")
    with open(summary_file, 'w') as f:
        f.write("# Line Count Scan Summary\n\n")
        f.write(f"**Scan Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("| Repository | SAST-Relevant LOC |\n")
        f.write("|------------|-------------------:|\n")
        total = 0
        for name, cnt in sorted(repo_counts, key=lambda x: x[1], reverse=True):
            total += cnt
            f.write(f"| {name} | {cnt:,} |\n")
        f.write(f"\n**Total LOC across repositories:** {total:,}\n")


def main():
    # Try to initialize config first to validate required environment variables
    try:
        global config
        config = LineCountConfig()
    except ValueError as e:
        print(f"Error: {str(e)}")
        print("Please ensure you have a .env file with the required variables or set them in your environment.")
        print("Required variables: GITHUB_TOKEN, GITHUB_ORG")
        print("Optional variables: GITHUB_API, LINECOUNT_REPORT_DIR")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Count SAST-relevant lines of code across GitHub repositories')
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

    # Filters
    parser.add_argument('--include-ext', action='append', default=[],
                        help='File extension to include (repeatable), e.g., .py .js .ts')
    parser.add_argument('--exclude-dir', action='append', default=[],
                        help='Directory name to exclude (repeatable), e.g., node_modules dist build')
    parser.add_argument('--exclude-glob', action='append', default=[],
                        help='File glob to exclude (repeatable), e.g., *.min.js package-lock.json')
    parser.add_argument('--no-exclude-minified', action='store_true',
                        help='Do not exclude minified JS/CSS by heuristic')
    parser.add_argument('--max-file-bytes', type=int, default=5_000_000,
                        help='Skip files larger than this (default: 5,000,000)')

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

    # Resolve filters
    include_exts = dict(_DEFAULT_EXTS)
    for e in args.include_ext:
        e = e.strip()
        if not e.startswith('.'):
            e = '.' + e
        include_exts[e] = include_exts.get(e, e.lstrip('.').upper())

    exclude_dirs = set(_DEFAULT_EXCLUDE_DIRS)
    exclude_dirs.update(args.exclude_dir or [])

    exclude_globs = list(_DEFAULT_EXCLUDE_GLOBS)
    exclude_globs.extend(args.exclude_glob or [])

    exclude_minified = not bool(args.no_exclude_minified)

    # Process repositories in parallel
    repo_counts: List[Tuple[str, int]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_repo = {executor.submit(
            process_repo,
            repo,
            config.REPORT_DIR,
            include_exts=include_exts,
            exclude_dirs=exclude_dirs,
            exclude_globs=exclude_globs,
            exclude_minified=exclude_minified,
            max_file_bytes=args.max_file_bytes,
        ): repo for repo in repos}
        for future in concurrent.futures.as_completed(future_to_repo):
            repo = future_to_repo[future]
            try:
                name, cnt = future.result()
                repo_counts.append((name, cnt))
            except Exception as e:
                logging.error(f"Error processing repository {repo['name']}: {e}")

    # Generate summary report
    generate_summary_report(config.REPORT_DIR, repo_counts)

    # Clean up temporary directory if it was created
    if hasattr(config, 'CLONE_DIR') and config.CLONE_DIR and os.path.exists(config.CLONE_DIR):
        try:
            shutil.rmtree(config.CLONE_DIR)
        except Exception as e:
            logging.error(f"Error cleaning up temporary directory: {e}")

    logging.info("Linecount scan completed!")


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
