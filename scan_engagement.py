#!/usr/bin/env python3
"""
Collect repository engagement snapshots (stars, forks, watchers, open issues, optional contributors estimate)
for a GitHub org/user and persist into PostgREST via api.upsert_project_engagement.

This is a thin scanner: one REST call per repo (plus optional count helpers) and a single RPC upsert per repo.
"""
import argparse
import concurrent.futures
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv

# Local rate-limited session helper
try:
    from src.github.rate_limit import make_rate_limited_session
except Exception:
    def make_rate_limited_session(token: Optional[str] = None, user_agent: str = "auditgh-engagement") -> requests.Session:  # type: ignore
        s = requests.Session()
        headers = {"User-Agent": user_agent}
        if token:
            headers["Authorization"] = f"token {token}"
        s.headers.update(headers)
        return s

# Load env
load_dotenv(override=True)

GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com")
DEFAULT_MAX_WORKERS = int(os.getenv("ENGAGEMENT_MAX_WORKERS") or os.getenv("SCAN_MAX_WORKERS") or 4)


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
            logging.FileHandler('logs/engagement_scan.log')
        ],
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Collect per-repo engagement snapshot (stars,forks,watchers,issues)")
    p.add_argument("--org", type=str, help="GitHub organization or user (fallback to user if org not found)")
    p.add_argument("--repo", type=str, help="Single repository (owner/name or name)")
    p.add_argument("--token", type=str, default=os.getenv("GITHUB_TOKEN"), help="GitHub token (or set GITHUB_TOKEN)")
    p.add_argument("--api-base", type=str, default=GITHUB_API, help=f"GitHub API base (default: {GITHUB_API})")
    p.add_argument("--include-forks", action="store_true", help="Include forked repositories")
    p.add_argument("--include-archived", action="store_true", help="Include archived repositories")
    p.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help=f"Thread pool size (default {DEFAULT_MAX_WORKERS})")
    # Persistence
    p.add_argument("--postgrest-url", type=str, help="Base URL for PostgREST (e.g., http://localhost:3001)")
    p.add_argument("--persist", action="store_true", help="Persist snapshots via PostgREST RPC upsert_project_engagement")
    # Logging
    p.add_argument("-v", "--verbose", action="count", default=1, help="Increase verbosity (repeatable)")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress info logs")
    return p.parse_args()


def make_session(token: Optional[str]) -> requests.Session:
    return make_rate_limited_session(token, user_agent="auditgh-engagement")


def request(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    resp = session.request(method, url, timeout=kwargs.pop("timeout", 30), **kwargs)
    return resp


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


def _repo_counts(session: requests.Session, api_base: str, full_name: str) -> Tuple[Optional[int], Optional[int]]:
    """Return (commits_estimate, contributors_estimate) quickly using pagination headers when possible.
    These are best-effort and may be None if unavailable.
    """
    owner, repo = full_name.split("/", 1)
    # contributors count via per_page=1 trick
    try:
        r = request(session, 'GET', f"{api_base}/repos/{owner}/{repo}/contributors", params={"per_page": 1})
        if r.status_code < 400:
            link = r.headers.get('Link') or r.headers.get('link')
            if link and 'rel="last"' in link:
                # …page=NN> rel="last"
                import re
                m = re.search(r"[?&]page=(\d+)>; rel=\"last\"", link)
                if m:
                    contributors = int(m.group(1))
                else:
                    contributors = 1
            else:
                contributors = len(r.json() or [])
        else:
            contributors = None
    except Exception:
        contributors = None

    # commits estimate is trickier; skip heavy counting and leave None
    commits = None
    return commits, contributors


def _persist_snapshot(postgrest_url: str, repo: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
    base = postgrest_url.rstrip('/')
    name = repo.get('name')
    repo_url = repo.get('html_url') or repo.get('clone_url') or ''
    description = repo.get('description')
    ensure_payload = {"p_name": name, "p_repo_url": repo_url, "p_description": description}
    try:
        r = requests.post(f"{base}/rpc/ensure_project", json=ensure_payload, timeout=30)
        r.raise_for_status()
        row = (r.json() or [{}])[0]
        api_id = row.get('id')
        if not api_id:
            logging.warning(f"ensure_project returned no id for {name}")
            return
        up = requests.post(f"{base}/rpc/upsert_project_engagement", json={"p_project_id": api_id, "p_payload": [snapshot]}, timeout=30)
        if up.status_code >= 400:
            logging.warning(f"upsert_project_engagement failed for {name}: {up.status_code} {up.text}")
    except Exception as e:
        logging.warning(f"Persistence failed for {name}: {e}")


def process_repo(session: requests.Session, api_base: str, repo: Dict[str, Any], *, persist: bool = False, postgrest_url: Optional[str] = None) -> Optional[Dict[str, Any]]:
    repo_full = repo.get('full_name') or f"{(repo.get('owner') or {}).get('login')}/{repo.get('name')}"
    logging.info(f"Processing {repo_full}")
    owner, name = repo_full.split("/", 1)
    resp = request(session, 'GET', f"{api_base}/repos/{owner}/{name}")
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    data = resp.json() or {}
    stars = int(data.get('stargazers_count') or 0)
    forks = int(data.get('forks_count') or 0)
    watchers = int(data.get('subscribers_count') or data.get('watchers_count') or 0)
    open_issues = int(data.get('open_issues_count') or 0)
    commits, contributors = _repo_counts(session, api_base, repo_full)
    snapshot = {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "stars": stars,
        "forks": forks,
        "watchers": watchers,
        "open_issues": open_issues,
    }
    if commits is not None:
        snapshot["commits"] = int(commits)
    if contributors is not None:
        snapshot["collaborators"] = int(contributors)
    if persist and postgrest_url:
        _persist_snapshot(postgrest_url, repo, snapshot)
    return snapshot


def main() -> int:
    args = parse_args()
    if args.quiet:
        args.verbose = 0
    setup_logging(args.verbose)

    token = args.token or os.getenv("GITHUB_TOKEN")
    if not token:
        logging.error("GITHUB_TOKEN is required (set env or pass --token)")
        return 2

    session = make_session(token)

    if args.repo:
        repo = get_single_repo(session, args.api_base, args.repo, args.org)
        if not repo:
            logging.error(f"Repository not found: {args.repo}")
            return 1
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
        logging.info(f"Found {len(repos)} repositories")

    # Process in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(args.max_workers))) as pool:
        fut_to_repo: Dict[Any, Dict[str, Any]] = {}
        for r in repos:
            fut = pool.submit(process_repo, session, args.api_base, r, persist=bool(args.persist), postgrest_url=getattr(args, 'postgrest_url', None))
            fut_to_repo[fut] = r
        # Drain
        for fut in concurrent.futures.as_completed(fut_to_repo):
            try:
                fut.result()
            except Exception as e:
                rn = fut_to_repo[fut].get('full_name') or fut_to_repo[fut].get('name')
                logging.warning(f"Repo failed {rn}: {e}")

    logging.info("Engagement scan completed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.info("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)
