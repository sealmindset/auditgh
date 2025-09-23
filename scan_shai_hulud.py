#!/usr/bin/env python3
"""
Scan repos for indicators related to the "Shai Hulud" supply-chain incident.

Checks implemented (per repo):
- Presence of @ctrl/tinycolor dependency (package.json, lockfiles, optional node_modules if present)
- Files whose SHA-256 equals the known malicious bundle.js hash
- Existence of a suspicious branch named "shai-hulud"
 - Best-effort CLI checks when tools are available:
   - `npm ls @ctrl/tinycolor` (if npm is installed)
   - `git ls-remote --heads origin` (if git is installed)

Exit codes:
- 0 = success, no findings
- 1 = success, findings present (non-hard error)
- 2 = usage or environment error
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from dotenv import load_dotenv

# Try to reuse the shared rate-limited session helper if available
try:
    from src.github.rate_limit import make_rate_limited_session  # type: ignore
except Exception:  # pragma: no cover - optional
    def make_rate_limited_session(token: Optional[str] = None, user_agent: str = "auditgh-shai-hulud") -> requests.Session:  # type: ignore
        s = requests.Session()
        headers = {"User-Agent": user_agent}
        if token:
            headers["Authorization"] = f"token {token}"
        s.headers.update(headers)
        return s

load_dotenv(override=True)

GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com")
WORKSPACE_ROOT = Path(os.getenv("AUDIT_WORKSPACE_DIR", "./runs")).resolve()
DEFAULT_MAX_WORKERS = int(os.getenv("SCAN_MAX_WORKERS") or 4)
SHA256_MALICIOUS_BUNDLE_JS = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"


@dataclass
class RepoFinding:
    repo: str
    has_tinycolor: bool = False
    tinycolor_sources: List[str] = None
    has_malicious_bundle_hash: bool = False
    malicious_files: List[str] = None
    has_shai_hulud_branch: bool = False

    def __post_init__(self):
        if self.tinycolor_sources is None:
            self.tinycolor_sources = []
        if self.malicious_files is None:
            self.malicious_files = []

    @property
    def has_any(self) -> bool:
        return self.has_tinycolor or self.has_malicious_bundle_hash or self.has_shai_hulud_branch


def setup_logging(verbosity: int = 1) -> None:
    level = logging.INFO
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity <= 0:
        level = logging.WARNING
    for h in logging.root.handlers[:]:
        logging.root.removeHandler(h)
    try:
        os.makedirs('logs', exist_ok=True)
    except Exception:
        pass
    logging.basicConfig(
        level=level,
        format='%(asctime)s | %(levelname)-8s | %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('logs/shai_hulud_scan.log')
        ],
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Scan repos for Shai Hulud indicators")
    p.add_argument("--org", type=str, help="GitHub organization or user (fallback to user if org not found)")
    p.add_argument("--repo", type=str, help="Single repository (owner/name or name)")
    p.add_argument("--token", type=str, default=os.getenv("GITHUB_TOKEN"), help="GitHub token (or set GITHUB_TOKEN)")
    p.add_argument("--api-base", type=str, default=GITHUB_API, help=f"GitHub API base (default: {GITHUB_API})")
    p.add_argument("--include-forks", action="store_true", help="Include forked repositories")
    p.add_argument("--include-archived", action="store_true", help="Include archived repositories")
    p.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help=f"Thread pool size (default {DEFAULT_MAX_WORKERS})")
    p.add_argument("--shallow", action="store_true", default=True, help="Use shallow clone (depth=1) when cloning for file hash checks (default)")
    p.add_argument("--no-clone", action="store_true", help="Do not clone repos (disables file hash and static package checks)")
    # Logging verbosity controls
    p.add_argument("-v", "--verbose", action="count", default=1, help="Increase verbosity (repeatable)")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress info logs")
    return p.parse_args()


def make_session(token: Optional[str]) -> requests.Session:
    return make_rate_limited_session(token, user_agent="auditgh-shai-hulud")


def request(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    return session.request(method, url, timeout=kwargs.pop("timeout", 30), **kwargs)


def get_all_repos(session: requests.Session, api_base: str, name: str, include_forks: bool, include_archived: bool) -> List[Dict[str, Any]]:
    repos: List[Dict[str, Any]] = []
    page = 1
    per_page = 100
    is_user_fallback = False
    while True:
        base = "users" if is_user_fallback else "orgs"
        url = f"{api_base}/{base}/{name}/repos"
        params = {"type": "all", "per_page": per_page, "page": page}
        resp = request(session, 'GET', url, params=params)
        if not is_user_fallback and page == 1 and resp.status_code == 404:
            logging.info(f"Org '{name}' not found; retrying as user…")
            is_user_fallback = True
            page = 1
            repos.clear()
            continue
        resp.raise_for_status()
        chunk = resp.json() or []
        if not chunk:
            break
        for r in chunk:
            if (not include_forks and r.get('fork')) or (not include_archived and r.get('archived')):
                continue
            repos.append(r)
        if len(chunk) < per_page:
            break
        page += 1
    return repos


def get_single_repo(session: requests.Session, api_base: str, spec: str, default_owner: Optional[str]) -> Optional[Dict[str, Any]]:
    if "/" in spec:
        owner, name = spec.split("/", 1)
    else:
        if not default_owner:
            logging.error("--repo without owner requires --org for owner inference")
            return None
        owner, name = default_owner, spec
    url = f"{api_base}/repos/{owner}/{name}"
    resp = request(session, 'GET', url)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def list_branches(session: requests.Session, api_base: str, owner: str, repo: str) -> Iterable[str]:
    page = 1
    per_page = 100
    while True:
        url = f"{api_base}/repos/{owner}/{repo}/branches"
        resp = request(session, 'GET', url, params={"per_page": per_page, "page": page})
        if resp.status_code == 404:
            return
        resp.raise_for_status()
        items = resp.json() or []
        if not items:
            break
        for br in items:
            name = (br or {}).get("name")
            if isinstance(name, str):
                yield name
        if len(items) < per_page:
            break
        page += 1


def git_clone(owner: str, name: str, token: Optional[str], dest_dir: Path, shallow: bool = True) -> bool:
    """Clone repo to dest_dir using Authorization header to avoid token in URL."""
    repo_url = f"https://github.com/{owner}/{name}.git"
    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)
    dest_dir.parent.mkdir(parents=True, exist_ok=True)
    depth_args = ["--depth", "1"] if shallow else []
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    # Add header via -c to avoid logging token in URL; use Bearer where supported
    header_val = f"Authorization: Bearer {token}" if token else None
    cmd = [
        "git",
        "-c",
        f"http.extraheader={header_val}" if header_val else "",
        "clone",
        *depth_args,
        repo_url,
        str(dest_dir),
    ]
    # Filter empty args
    cmd = [c for c in cmd if c]
    try:
        proc = subprocess.run(cmd, env=env, text=True, capture_output=True, check=False)
        if proc.returncode != 0:
            logging.debug("git clone stderr: %s", proc.stderr)
            logging.warning("Clone failed for %s/%s (rc=%s)", owner, name, proc.returncode)
            return False
        return True
    except Exception as e:
        logging.warning("Clone exception for %s/%s: %s", owner, name, e)
        return False


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_js_hashes(root: Path, target_hash: str) -> Tuple[bool, List[str]]:
    hits: List[str] = []
    for p in root.rglob("*.js"):
        try:
            digest = compute_sha256(p)
            if digest == target_hash:
                hits.append(str(p.relative_to(root)))
        except Exception:
            continue
    return (len(hits) > 0), hits


def detect_tinycolor(root: Path) -> Tuple[bool, List[str]]:
    sources: List[str] = []
    # package.json
    pkg = root / "package.json"
    try:
        if pkg.exists():
            data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore") or "{}")
            for sec in ("dependencies", "devDependencies", "peerDependencies"):
                d = data.get(sec) or {}
                if isinstance(d, dict) and "@ctrl/tinycolor" in d:
                    sources.append("package.json:" + sec)
    except Exception:
        pass
    # package-lock.json, pnpm-lock.yaml, yarn.lock (string search)
    lockfiles = [
        root / "package-lock.json",
        root / "pnpm-lock.yaml",
        root / "pnpm-lock.yml",
        root / "yarn.lock",
        *list(root.rglob("**/package-lock.json")),
        *list(root.rglob("**/pnpm-lock.yaml")),
        *list(root.rglob("**/pnpm-lock.yml")),
        *list(root.rglob("**/yarn.lock")),
    ]
    seen: set[Path] = set()
    for lf in lockfiles:
        if not lf.exists() or lf in seen:
            continue
        seen.add(lf)
        try:
            txt = lf.read_text(encoding="utf-8", errors="ignore")
            if "@ctrl/tinycolor" in txt:
                sources.append(str(lf.relative_to(root)))
        except Exception:
            continue
    # node_modules presence (if installed)
    nm = root / "node_modules" / "@ctrl" / "tinycolor" / "package.json"
    if nm.exists():
        sources.append("node_modules/@ctrl/tinycolor/package.json")
    return (len(sources) > 0), sources

def npm_ls_tinycolor(root: Path) -> bool:
    """Run `npm ls @ctrl/tinycolor` in repo. Returns True if dependency is reported.
    Uses --json when available; falls back to text parsing. Non-fatal on errors.
    """
    if shutil.which("npm") is None:
        return False
    try:
        # Prefer JSON for reliable parsing
        proc = subprocess.run(
            ["npm", "ls", "@ctrl/tinycolor", "--json"],
            cwd=str(root),
            text=True,
            capture_output=True,
            check=False,
        )
        out = proc.stdout or ""
        if out.strip():
            try:
                data = json.loads(out)
                # If the package appears in dependencies tree, it's present
                # npm may return non-zero when unmet peer deps exist; ignore rc
                deps = data.get("dependencies") or {}
                if isinstance(deps, dict) and "@ctrl/tinycolor" in deps:
                    return True
            except Exception:
                pass
        # Fallback: text contains package at version
        txt = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return "@ctrl/tinycolor@" in txt
    except Exception:
        return False

def git_ls_remote_has_branch(root: Path, branch: str = "shai-hulud") -> bool:
    """Run `git ls-remote --heads origin` to detect a branch by name. Non-fatal on errors."""
    if shutil.which("git") is None:
        return False
    try:
        proc = subprocess.run(
            ["git", "ls-remote", "--heads", "origin"],
            cwd=str(root),
            text=True,
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            return False
        return any(line.strip().endswith(f"refs/heads/{branch}") for line in (proc.stdout or "").splitlines())
    except Exception:
        return False


def process_repo(session: requests.Session, api_base: str, repo: Dict[str, Any], *, token: Optional[str], shallow: bool, no_clone: bool) -> RepoFinding:
    full = repo.get("full_name") or f"{(repo.get('owner') or {}).get('login')}/{repo.get('name')}"
    owner, name = full.split("/", 1)
    logging.info("Scanning %s", full)
    finding = RepoFinding(repo=full)

    # Branch check via API (no clone needed)
    try:
        for br in list_branches(session, api_base, owner, name):
            if br == "shai-hulud":
                finding.has_shai_hulud_branch = True
                break
    except Exception as e:
        logging.debug("Branch listing error for %s: %s", full, e)

    # Clone and run static checks (hash + dependency)
    if not no_clone:
        repo_dir = WORKSPACE_ROOT / "shai_hulud" / owner / name
        cloned_ok = git_clone(owner, name, token, repo_dir, shallow=shallow)
        if cloned_ok:
            try:
                # Malicious bundle.js hash search
                has_hash, files = scan_js_hashes(repo_dir, SHA256_MALICIOUS_BUNDLE_JS)
                finding.has_malicious_bundle_hash = has_hash
                finding.malicious_files = files
            except Exception as e:
                logging.debug("Hash scan error for %s: %s", full, e)
            try:
                # Tinycolor dependency detection
                has_tiny, sources = detect_tinycolor(repo_dir)
                finding.has_tinycolor = has_tiny
                finding.tinycolor_sources = sources
            except Exception as e:
                logging.debug("Dependency detection error for %s: %s", full, e)
            # Optional CLI-based checks
            try:
                if npm_ls_tinycolor(repo_dir):
                    finding.has_tinycolor = True
                    if "npm ls" not in (finding.tinycolor_sources or []):
                        finding.tinycolor_sources.append("npm ls")
            except Exception:
                pass
            try:
                if not finding.has_shai_hulud_branch and git_ls_remote_has_branch(repo_dir, "shai-hulud"):
                    finding.has_shai_hulud_branch = True
            except Exception:
                pass
        else:
            logging.warning("Skipping file-based checks for %s due to clone failure", full)

    # Summarize
    if finding.has_any:
        logging.warning(
            "FINDINGS %s | tinycolor=%s (%s) | malicious_hash=%s (%d files) | shai-hulud-branch=%s",
            full,
            finding.has_tinycolor,
            ",".join(finding.tinycolor_sources) if finding.tinycolor_sources else "",
            finding.has_malicious_bundle_hash,
            len(finding.malicious_files or []),
            finding.has_shai_hulud_branch,
        )
    else:
        logging.info("No indicators found in %s", full)

    return finding


def main() -> int:
    args = parse_args()
    if getattr(args, "quiet", False):
        args.verbose = 0
    setup_logging(args.verbose)

    token = args.token or os.getenv("GITHUB_TOKEN")
    if not token:
        logging.error("GITHUB_TOKEN is required (set env or pass --token)")
        return 2

    session = make_session(token)

    # Resolve repos
    if args.repo:
        repo = get_single_repo(session, args.api_base, args.repo, args.org)
        if not repo:
            logging.error("Repository not found: %s", args.repo)
            return 2
        repos = [repo]
    else:
        org = args.org or os.getenv("GITHUB_ORG")
        if not org:
            logging.error("--org or GITHUB_ORG is required when --repo is not provided")
            return 2
        repos = get_all_repos(session, args.api_base, org, args.include_forks, args.include_archived)
        if not repos:
            logging.error("No repositories found or accessible with the provided token.")
            return 1
        logging.info("Found %d repositories", len(repos))

    findings: List[RepoFinding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(args.max_workers))) as pool:
        futs: Dict[Any, Dict[str, Any]] = {}
        for r in repos:
            fut = pool.submit(
                process_repo,
                session,
                args.api_base,
                r,
                token=token,
                shallow=not (not args.shallow),
                no_clone=bool(args.no_clone),
            )
            futs[fut] = r
        for fut in concurrent.futures.as_completed(futs):
            try:
                findings.append(fut.result())
            except Exception as e:
                full = futs[fut].get("full_name") or futs[fut].get("name")
                logging.warning("Repo failed %s: %s", full, e)

    any_findings = any(f.has_any for f in findings)

    # Print short summary to stdout for convenience
    print("\n# Shai Hulud Scan Summary")
    print(f"Total repos scanned: {len(findings)}")
    print(f"Repos with @ctrl/tinycolor: {sum(1 for f in findings if f.has_tinycolor)}")
    print(f"Repos with malicious bundle.js hash: {sum(1 for f in findings if f.has_malicious_bundle_hash)}")
    print(f"Repos with 'shai-hulud' branch: {sum(1 for f in findings if f.has_shai_hulud_branch)}")

    return 1 if any_findings else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.info("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)
