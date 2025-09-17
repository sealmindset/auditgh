#!/usr/bin/env python3
"""
Scan GitHub repositories and report contributors with commit counts and enriched profile info.

Template inspired by scan_gitleaks_fixed.py.
"""
import argparse
import concurrent.futures
import datetime
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from src.github.rate_limit import make_rate_limited_session, request_with_rate_limit
from dotenv import load_dotenv
import fnmatch
import glob
import subprocess
try:
    import yaml  # optional for --critical-globs
except Exception:
    yaml = None

# Load environment variables from .env
load_dotenv(override=True)


# -----------------------------
# Logging
# -----------------------------

def setup_logging(verbosity: int = 1, quiet: bool = False, level_name: Optional[str] = None):
    if quiet:
        verbosity = 0
    level = logging.INFO
    if level_name:
        level = getattr(logging, str(level_name).upper(), logging.INFO)
    else:
        if verbosity > 1:
            level = logging.DEBUG
        elif verbosity == 0:
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
            logging.FileHandler('logs/contributors_scan.log')
        ],
    )


# -----------------------------
# HTTP session
# -----------------------------

def make_session(token: str) -> requests.Session:
    return make_rate_limited_session(token, user_agent="auditgh-contributors")

def api_get(session: requests.Session, url: str, **kwargs) -> requests.Response:
    return request_with_rate_limit(session, 'GET', url, logger=logging.getLogger('contributors.api'), **kwargs)


# -----------------------------
# Repo discovery (org→user fallback)
# -----------------------------

def get_all_repos(session: requests.Session, api_base: str, name: str,
                  include_forks: bool, include_archived: bool) -> List[Dict[str, Any]]:
    repos: List[Dict[str, Any]] = []
    page = 1
    per_page = 100
    is_user_fallback = False

    while True:
        base = "users" if is_user_fallback else "orgs"
        url = f"{api_base}/{base}/{name}/repos"
        params = {"type": "all", "per_page": per_page, "page": page}
        resp = api_get(session, url, params=params, timeout=30)
        if not is_user_fallback and page == 1 and resp.status_code == 404:
            logging.info(f"Organization '{name}' not found or inaccessible. Retrying as a user account...")
            is_user_fallback = True
            page = 1
            repos.clear()
            continue
        resp.raise_for_status()
        page_repos = resp.json() or []
        if not page_repos:
            break
        for r in page_repos:
            if (not include_forks and r.get('fork')) or (not include_archived and r.get('archived')):
                continue
            repos.append(r)
        if len(page_repos) < per_page:
            break
        page += 1
    return repos


def get_single_repo(session: requests.Session, api_base: str, owner: str, repo: str) -> Optional[Dict[str, Any]]:
    url = f"{api_base}/repos/{owner}/{repo}"
    resp = api_get(session, url, timeout=30)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


# -----------------------------
# Contributors + enrichment
# -----------------------------

def fetch_contributors(session: requests.Session, api_base: str, full_name: str, include_anon: bool = False) -> List[Dict[str, Any]]:
    """Get contributors for a repo with their contributions count.
    API: GET /repos/{owner}/{repo}/contributors
    """
    owner, repo = full_name.split("/", 1)
    url = f"{api_base}/repos/{owner}/{repo}/contributors"
    contributors: List[Dict[str, Any]] = []
    page = 1
    per_page = 100
    while True:
        resp = api_get(
            url,
            params={
                "per_page": per_page,
                "page": page,
                # GitHub API expects string 'true' to include anonymous contributors
                "anon": "true" if include_anon else False,
            },
            timeout=30,
        )
        resp.raise_for_status()
        page_items = resp.json() or []
        if not page_items:
            break
        for c in page_items:
            # c has: login, id, html_url, contributions
            contributors.append(c)
        if len(page_items) < per_page:
            break
        page += 1
    return contributors


def enrich_user(session: requests.Session, api_base: str, login: str) -> Dict[str, Any]:
    """Fetch user profile fields. Email may be None if private."""
    url = f"{api_base}/users/{login}"
    resp = session.get(url, timeout=30)
    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    data = resp.json() or {}
    keep = {
        "login": data.get("login"),
        "name": data.get("name"),
        "company": data.get("company"),
        "blog": data.get("blog"),
        "location": data.get("location"),
        "email": data.get("email"),  # often null
        "hireable": data.get("hireable"),
        "bio": data.get("bio"),
        "twitter_username": data.get("twitter_username"),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
        "type": data.get("type"),
        "site_admin": data.get("site_admin"),
        "html_url": data.get("html_url"),
        "id": data.get("id"),
    }
    return keep


def get_author_recent_info(session: requests.Session, api_base: str, full_name: str, login: str, limit: int = 50) -> Dict[str, Optional[str]]:
    """Fetch recent commits for an author and extract first email and most recent commit date.

    Returns dict with keys: email, last_commit_date (ISO 8601) or None if unavailable.
    """
    owner, repo = full_name.split("/", 1)
    url = f"{api_base}/repos/{owner}/{repo}/commits"
    resp = api_get(session, url, params={"author": login, "per_page": limit}, timeout=30)
    if resp.status_code == 404:
        return {"email": None, "last_commit_date": None}
    if resp.status_code == 409:  # empty repo
        return {"email": None, "last_commit_date": None}
    resp.raise_for_status()
    commits = resp.json() or []
    email_found: Optional[str] = None
    last_date: Optional[str] = None
    # API returns newest first by default
    if commits:
        last_date = (commits[0].get("commit") or {}).get("author", {}).get("date")
    for commit in commits:
        # Prefer git author email from commit metadata
        email = (
            (commit.get("commit") or {}).get("author", {}).get("email")
            or (commit.get("author") or {}).get("email")
        )
        if email:
            email_found = email
            break
    return {"email": email_found, "last_commit_date": last_date}


def load_critical_globs(globs_path: Optional[str]) -> Dict[str, List[str]]:
    """Load critical path glob patterns from YAML file or return defaults."""
    default_globs: Dict[str, List[str]] = {
        "ci_cd": [".github/workflows/**", ".gitlab-ci.yml", "Jenkinsfile*"],
        "secrets": ["**/.env*", "config/**secrets*", "**/creds/**"],
        "deps": ["requirements*.txt", "pyproject.toml", "package*.json", "yarn.lock", "pnpm-lock.yaml", "go.mod"],
        "build": ["Dockerfile*", "Makefile*", "build.gradle*", "pom.xml"],
        "infra": ["terraform/**", "k8s/**", "helm/**", "ansible/**"],
    }
    if not globs_path:
        return default_globs
    try:
        if yaml is None:
            logging.warning("PyYAML not available; using default critical globs")
            return default_globs
        with open(globs_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        merged = default_globs.copy()
        for k, v in (data or {}).items():
            if isinstance(v, list):
                merged[k] = v
        return merged
    except Exception as e:
        logging.warning(f"Failed to load critical globs from {globs_path}: {e}. Using defaults.")
        return default_globs


def _match_any(path: str, patterns: List[str]) -> bool:
    path_norm = path.lstrip("./")
    for pat in patterns:
        if fnmatch.fnmatch(path_norm, pat) or fnmatch.fnmatch(path_norm.lower(), pat.lower()):
            return True
    return False


def analyze_commits_for_author(
    session: requests.Session,
    api_base: str,
    full_name: str,
    login: str,
    max_commits: int,
    critical_globs: Dict[str, List[str]],
    include_verified: bool,
) -> Dict[str, Any]:
    """Return churn, critical touches, and verified stats for an author in a repo."""
    owner, repo = full_name.split("/", 1)
    base_url = f"{api_base}/repos/{owner}/{repo}"
    # page through commits by author
    page = 1
    per_page = 100
    shas: List[str] = []
    while len(shas) < max_commits:
        resp = session.get(f"{base_url}/commits", params={"author": login, "per_page": per_page, "page": page}, timeout=30)
        if resp.status_code in (404, 409):
            break
        resp.raise_for_status()
        items = resp.json() or []
        if not items:
            break
        for it in items:
            sha = it.get("sha")
            if sha:
                shas.append(sha)
                if len(shas) >= max_commits:
                    break
        if len(items) < per_page:
            break
        page += 1

    additions = deletions = 0
    critical_counts = {k: 0 for k in critical_globs.keys()}
    verified_count = total_count = 0

    for sha in shas:
        try:
            c = api_get(session, f"{base_url}/commits/{sha}", timeout=30)
            if c.status_code in (404, 409):
                continue
            c.raise_for_status()
            detail = c.json() or {}
            stats = detail.get("stats") or {}
            additions += int(stats.get("additions") or 0)
            deletions += int(stats.get("deletions") or 0)
            files = detail.get("files") or []
            for f in files:
                filename = f.get("filename") or ""
                for cat, pats in critical_globs.items():
                    if _match_any(filename, pats):
                        critical_counts[cat] += 1
            if include_verified:
                total_count += 1
                if (detail.get("verification") or {}).get("verified"):
                    verified_count += 1
        except Exception as e:
            logging.debug(f"Commit analysis failed for {full_name}@{sha}: {e}")
            continue

    verified_ratio = (verified_count / total_count * 100.0) if include_verified and total_count > 0 else None
    return {
        "churn": {"additions": additions, "deletions": deletions, "net": additions - deletions},
        "critical": critical_counts,
        "verified": {"commits": total_count, "verified": verified_count, "ratio": verified_ratio},
    }

def get_user_permission(session: requests.Session, api_base: str, full_name: str, login: str) -> Optional[str]:
    """Get user's permission on a repo: admin|maintain|write|triage|read. Returns None if unavailable."""
    try:
        owner, repo = full_name.split("/", 1)
        url = f"{api_base}/repos/{owner}/{repo}/collaborators/{login}/permission"
        resp = api_get(session, url, timeout=30)
        if resp.status_code in (404, 403):
            return None
        resp.raise_for_status()
        data = resp.json() or {}
        perm = (data.get("permission") or "").strip() or None
        return perm
    except Exception:
        return None

def crosslink_findings_for_repo(repo_name: str, findings_dir: str, with_blame: bool = False, repos_root: Optional[str] = None) -> Dict[str, int]:
    """Read findings JSON (secrets, Semgrep, Bandit) and count by author email/name.

    We attempt to extract author or email from shallow or nested fields (e.g., extra/metadata).
    This is a lightweight mapper and does not run git blame.
    """
    def _deep_first_key(obj: Any, keys: List[str]) -> Optional[str]:
        try:
            if isinstance(obj, dict):
                # direct
                for k in keys:
                    if k in obj and obj[k]:
                        return str(obj[k])
                # nested
                for v in obj.values():
                    res = _deep_first_key(v, keys)
                    if res:
                        return res
            elif isinstance(obj, list):
                for v in obj:
                    res = _deep_first_key(v, keys)
                    if res:
                        return res
        except Exception:
            return None
        return None

    def _extract_path_line(it: Any) -> (Optional[str], Optional[int]):
        # Try common fields across tools
        path = _deep_first_key(it, [
            "path", "file", "filename", "location.path", "check_location.path"
        ])
        if isinstance(path, str):
            path_str = path
        else:
            path_str = None
        # Line number
        line_val = _deep_first_key(it, [
            "line", "line_number", "start.line", "location.start.line", "startLine"
        ])
        try:
            line_num = int(str(line_val)) if line_val is not None else None
        except Exception:
            line_num = None
        return path_str, line_num

    def _blame_email_name(repo_dir: Path, file_path: str, line_num: Optional[int]) -> (Optional[str], Optional[str]):
        try:
            if not line_num or line_num <= 0:
                return None, None
            abs_path = repo_dir / file_path
            if not abs_path.exists():
                return None, None
            cmd = [
                "git", "blame", "-L", f"{line_num},{line_num}", "--line-porcelain", str(abs_path)
            ]
            result = subprocess.run(cmd, cwd=str(repo_dir), capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                return None, None
            author = None
            email = None
            for ln in result.stdout.splitlines():
                if ln.startswith("author ") and not author:
                    author = ln[len("author "):].strip()
                elif ln.startswith("author-mail ") and not email:
                    email = ln[len("author-mail "):].strip().strip("<>")
                if author and email:
                    break
            return email, author
        except Exception:
            return None, None

    out: Dict[str, int] = {}
    base = Path(findings_dir)
    if not base.exists():
        return out
    candidates = []
    candidates += glob.glob(str(base / f"{repo_name}*.json"))
    if (base / repo_name).exists():
        candidates += glob.glob(str(base / repo_name / "*.json"))
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "results" in data:
                items = data.get("results") or []
            elif isinstance(data, list):
                items = data
            else:
                items = []
            for it in items:
                # Common keys across tools
                email = _deep_first_key(it, [
                    "AuthorEmail", "authorEmail", "email", "author_email", "committer_email"
                ]) or ""
                name = _deep_first_key(it, [
                    "Author", "author", "commit_author", "committer_name", "name"
                ]) or ""
                # Optional blame (prefer blame-derived ids)
                if with_blame and repos_root:
                    repo_dir = Path(repos_root) / repo_name
                    file_path, line_num = _extract_path_line(it)
                    if file_path and repo_dir.exists():
                        b_email, b_name = _blame_email_name(repo_dir, file_path, line_num)
                        email = b_email or email
                        name = b_name or name
                key = (email.strip().lower() if isinstance(email, str) else "") or (name.strip().lower() if isinstance(name, str) else "")
                if not key:
                    continue
                out[key] = out.get(key, 0) + 1
        except Exception:
            continue
    return out


def analyze_prs_for_author(
    session: requests.Session,
    api_base: str,
    full_name: str,
    login: str,
    max_prs: int = 200,
) -> Dict[str, Any]:
    """Return PR hygiene metrics for an author in a repo."""
    owner, repo = full_name.split("/", 1)
    base_url = f"{api_base}/repos/{owner}/{repo}"
    page = 1
    per_page = 100
    pr_numbers: List[int] = []
    while len(pr_numbers) < max_prs:
        resp = api_get(session, f"{base_url}/pulls", params={"state": "all", "per_page": per_page, "page": page}, timeout=30)
        if resp.status_code in (404, 409):
            break
        resp.raise_for_status()
        pulls = resp.json() or []
        if not pulls:
            break
        for pr in pulls:
            if pr.get("user", {}).get("login") == login:
                number = pr.get("number")
                if number:
                    pr_numbers.append(int(number))
                    if len(pr_numbers) >= max_prs:
                        break
        if len(pulls) < per_page:
            break
        page += 1

    merged = 0
    reviewed = 0
    considered = 0
    self_merged = 0
    ttm_days_total = 0.0

    for num in pr_numbers:
        try:
            pr_resp = api_get(session, f"{base_url}/pulls/{num}", timeout=30)
            if pr_resp.status_code in (404, 409):
                continue
            pr_resp.raise_for_status()
            pr = pr_resp.json() or {}
            considered += 1

            # merged?
            merged_at = pr.get("merged_at")
            if merged_at:
                merged += 1
                # self merged?
                merged_by = (pr.get("merged_by") or {}).get("login")
                if merged_by == login:
                    self_merged += 1
                # time-to-merge
                try:
                    from datetime import datetime as _dt, timezone as _tz
                    c_at = pr.get("created_at")
                    if c_at:
                        ttm = (_dt.fromisoformat(merged_at.replace("Z", "+00:00")) - _dt.fromisoformat(c_at.replace("Z", "+00:00"))).total_seconds() / 86400.0
                        ttm_days_total += max(0.0, ttm)
                except Exception:
                    pass

            # reviews
            rev_resp = api_get(session, f"{base_url}/pulls/{num}/reviews", timeout=30)
            if rev_resp.status_code not in (404, 409):
                try:
                    rev_resp.raise_for_status()
                    reviews = rev_resp.json() or []
                    # Count as reviewed if any review exists and at least one reviewer is different from author
                    if any((rv.get("user") or {}).get("login") and (rv.get("user") or {}).get("login") != login for rv in reviews):
                        reviewed += 1
                except Exception:
                    pass
        except Exception as e:
            logging.debug(f"PR analysis failed for {full_name} PR #{num}: {e}")
            continue

    reviewed_pct = (reviewed / considered * 100.0) if considered > 0 else None
    ttm_days_avg = (ttm_days_total / merged) if merged > 0 else None
    return {
        "merged": merged,
        "reviewed_pct": reviewed_pct,
        "self_merged": self_merged,
        "ttm_days": ttm_days_avg,
        "considered": considered,
    }


def process_repo(session: requests.Session, api_base: str, repo: Dict[str, Any], output_dir: Path, include_anon: bool = False,
                 compute_churn: bool = False, critical_globs: Optional[Dict[str, List[str]]] = None,
                 with_verified: bool = False, max_commits: int = 200,
                 with_pr_metrics: bool = False, max_prs: int = 200, exclude_bots: bool = False,
                 with_permissions: bool = False, crosslink_findings: bool = False, findings_dir: str = "secrets_reports",
                 with_blame: bool = False, repos_root: Optional[str] = None) -> None:
    full_name = repo.get("full_name") or f"{repo.get('owner', {}).get('login')}/{repo.get('name')}"
    repo_name = repo.get("name")
    logging.info(f"Processing repository: {full_name}")

    out_dir = output_dir / repo_name
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{repo_name}_contributors.json"
    md_path = out_dir / f"{repo_name}_contributors.md"

    contributors = fetch_contributors(session, api_base, full_name, include_anon)
    # Preload findings for this repo
    sec_map: Dict[str, int] = {}
    if crosslink_findings:
        sec_map = crosslink_findings_for_repo(repo_name, findings_dir, with_blame=with_blame, repos_root=repos_root)

    enriched_rows: List[Dict[str, Any]] = []
    for c in contributors:
        login = c.get("login")
        contributions = c.get("contributions", 0)
        if exclude_bots and login and login.endswith("[bot]"):
            continue
        # Anonymous entries may lack login and include minimal fields
        if not login and (c.get("type") == "Anonymous" or include_anon):
            row = {
                "login": "(anonymous)",
                "contributions": contributions,
                "name": c.get("name") or "",
                "email": c.get("email") or "",
                "last_commit_date": "",
                "company": "",
                "location": "",
                "blog": "",
                "created_at": "",
                "updated_at": "",
                "type": c.get("type") or "Anonymous",
                "site_admin": False,
                "html_url": c.get("html_url") or "",
                "id": c.get("id"),
                "churn": None,
                "critical": None,
                "verified": None,
                "perms": None,
                "sec_attrib": None,
                "pr": None,
            }
            enriched_rows.append(row)
            continue

        profile = enrich_user(session, api_base, login) if login else {}
        email = profile.get("email")
        last_commit_date = None
        if login:
            # Reuse a single call to get both inferred email (if needed) and recent date
            recent = get_author_recent_info(session, api_base, full_name, login, limit=50)
            if not email and recent.get("email"):
                email = recent["email"]
            last_commit_date = recent.get("last_commit_date")
        analysis = None
        if compute_churn and login:
            analysis = analyze_commits_for_author(
                session, api_base, full_name, login, max_commits,
                critical_globs or load_critical_globs(None), with_verified,
            )
        pr_metrics = None
        if with_pr_metrics and login:
            pr_metrics = analyze_prs_for_author(session, api_base, full_name, login, max_prs=max_prs)
        perm_role = None
        if with_permissions and login:
            perm_role = get_user_permission(session, api_base, full_name, login)
        sec_attr = None
        if crosslink_findings:
            key_email = (email or "").strip().lower()
            key_name = (profile.get("name") or "").strip().lower()
            count = 0
            if key_email and key_email in sec_map:
                count += sec_map.get(key_email, 0)
            if key_name and key_name in sec_map:
                count += sec_map.get(key_name, 0)
            sec_attr = {"secrets": count} if count else None
        row = {
            "login": login or "",
            "contributions": contributions,
            "name": profile.get("name"),
            "email": email,
            "last_commit_date": last_commit_date,
            "company": profile.get("company"),
            "location": profile.get("location"),
            "blog": profile.get("blog"),
            "created_at": profile.get("created_at"),
            "updated_at": profile.get("updated_at"),
            "type": profile.get("type"),
            "site_admin": profile.get("site_admin"),
            "html_url": profile.get("html_url"),
            "id": profile.get("id"),
            "churn": (analysis or {}).get("churn") if analysis else None,
            "critical": (analysis or {}).get("critical") if analysis else None,
            "verified": (analysis or {}).get("verified") if analysis else None,
            "perms": perm_role,
            "sec_attrib": sec_attr,
            "pr": pr_metrics,
        }
        enriched_rows.append(row)

    # Save JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "repository": full_name,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "contributors": enriched_rows,
        }, f, indent=2)

    # Save Markdown
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Contributors Report: {full_name}\n\n")
        f.write(f"Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        if not enriched_rows:
            f.write("No contributors found.\n")
        else:
            f.write("| Login | Name | Email | Last Commit | Commits | Additions | Deletions | Net | Verified% | Critical Touches | PR (rev%/self/ttm/merged) | Perm | Sec | Company | Location |\n")
            f.write("|-------|------|-------|-------------|---------|----------:|----------:|-----:|----------:|------------------|-----------------------------|------|-----|---------|----------|\n")
            for r in enriched_rows:
                churn = r.get('churn') or {}
                crit = r.get('critical') or {}
                ver = r.get('verified') or {}
                pr = r.get('pr') or {}
                perm = r.get('perms') or ''
                secx = r.get('sec_attrib') or {}
                crit_str = ", ".join([f"{k}:{v}" for k, v in crit.items() if v]) if crit else ""
                ver_pct = f"{(ver.get('ratio') or 0):.1f}%" if ver and ver.get('ratio') is not None else ""
                pr_str = ""
                if pr:
                    rp = pr.get('reviewed_pct'); sm = pr.get('self_merged'); ttm = pr.get('ttm_days'); mg = pr.get('merged')
                    rp_s = f"{rp:.0f}%" if rp is not None else ""
                    ttm_s = f"{ttm:.1f}" if ttm is not None else ""
                    pr_str = f"{rp_s}/{sm or 0}/{ttm_s}/{mg or 0}"
                f.write(
                    f"| {r.get('login','')} | {r.get('name','') or ''} | {r.get('email','') or ''} | "
                    f"{r.get('last_commit_date','') or ''} | {r.get('contributions',0)} | "
                    f"{(churn.get('additions') or 0)} | {(churn.get('deletions') or 0)} | {(churn.get('net') or 0)} | {ver_pct} | {crit_str} | {pr_str} | {perm or ''} | {(secx.get('secrets') or '')} | {r.get('company','') or ''} | {r.get('location','') or ''} |\n"
                )


# -----------------------------
# CLI
# -----------------------------

def parse_args() -> argparse.Namespace:
    default_token = os.getenv("GITHUB_TOKEN")
    default_org = os.getenv("GITHUB_ORG")
    default_api = os.getenv("GITHUB_API", "https://api.github.com")
    default_out = os.path.abspath(os.getenv("REPORT_DIR", "contributors_reports"))

    p = argparse.ArgumentParser(description="Scan contributors per repository and enrich profile info")
    p.add_argument("--org", type=str, default=default_org, help=f"GitHub organization or user (default: {default_org})")
    p.add_argument("--repo", type=str, help="Single repository to scan (name or owner/name)")
    p.add_argument("--api-base", type=str, default=default_api, help=f"GitHub API base (default: {default_api})")
    p.add_argument("--token", type=str, default=default_token, help="GitHub token (or set GITHUB_TOKEN)")
    p.add_argument("--output-dir", type=str, default=default_out, help=f"Output directory (default: {default_out})")
    p.add_argument("--include-forks", action="store_true", help="Include forked repositories")
    p.add_argument("--include-archived", action="store_true", help="Include archived repositories")
    p.add_argument("--include-anon", action="store_true", help="Include anonymous contributors in results")
    # analysis flags
    p.add_argument("--compute-churn", action="store_true", help="Compute additions/deletions/net and critical touches")
    p.add_argument("--critical-globs", type=str, help="YAML file defining critical path glob patterns")
    p.add_argument("--with-verified", action="store_true", help="Compute verified commit ratio")
    p.add_argument("--risk-score", action="store_true", help="Compute a basic risk score per contributor")
    p.add_argument("--max-commits", type=int, default=200, help="Max commits per contributor per repo to analyze (default 200)")
    p.add_argument("--with-pr-metrics", action="store_true", help="Compute PR hygiene metrics (reviews, self-merge, TTM)")
    p.add_argument("--max-prs", type=int, default=200, help="Max PRs per contributor per repo to analyze (default 200)")
    p.add_argument("--exclude-bots", action="store_true", help="Exclude accounts ending with [bot]")
    p.add_argument("--with-permissions", action="store_true", help="Fetch collaborator permissions per repo (requires org scope)")
    p.add_argument("--crosslink-findings", action="store_true", help="Attribute secrets findings to contributors from findings directory")
    p.add_argument("--findings-dir", type=str, default="secrets_reports", help="Directory containing findings JSON (default secrets_reports)")
    p.add_argument("--with-blame", action="store_true", help="Use local git blame to attribute findings to last line author (requires local clone)")
    p.add_argument("--repos-root", type=str, default="repos", help="Root directory containing local clones in subfolders named by repo (default repos)")
    # logging
    p.add_argument("-v", "--verbose", action="count", default=1, help="Increase verbosity (repeatable)")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress output")
    p.add_argument("--loglevel", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Explicit log level")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    setup_logging(verbosity=args.verbose, quiet=args.quiet, level_name=args.loglevel)
    # Hydrate from environment if missing
    env_token = os.getenv("GITHUB_TOKEN")
    env_org = os.getenv("GITHUB_ORG")
    # If org missing but repo=owner/name is provided, infer org=owner
    inferred_owner = None
    if args.repo and "/" in args.repo:
        inferred_owner = args.repo.split("/", 1)[0]
    if not args.token:
        args.token = env_token
    if not args.org:
        args.org = env_org or inferred_owner

    if not args.token:
        logging.error("GitHub token is required. Set GITHUB_TOKEN in .env or pass --token")
        return 1
    if not args.org and not args.repo:
        logging.error("Provide --org (or set GITHUB_ORG in .env) or --repo owner/name")
        return 1

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    session = make_session(args.token)

    repos: List[Dict[str, Any]] = []
    if args.repo:
        # accept name or owner/name
        owner = args.org
        repo_name = args.repo
        if "/" in args.repo:
            owner, repo_name = args.repo.split("/", 1)
        repo = get_single_repo(session, args.api_base, owner, repo_name)
        if not repo:
            logging.error(f"Repository not found: {owner}/{repo_name}")
            return 1
        repos = [repo]
    else:
        logging.info(f"Fetching repositories for: {args.org}")
        repos = get_all_repos(
            session,
            api_base=args.api_base,
            name=args.org,
            include_forks=args.include_forks,
            include_archived=args.include_archived,
        )
        logging.info(f"Found {len(repos)} repositories")
        if not repos:
            logging.error("No repositories found or accessible with the provided token.")
            return 1

    critical_globs_cfg = load_critical_globs(args.critical_globs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [
            executor.submit(
                process_repo, session, args.api_base, r, output_dir,
                args.include_anon, args.compute_churn, critical_globs_cfg,
                args.with_verified, args.max_commits,
                args.with_pr_metrics, args.max_prs, args.exclude_bots,
                args.with_permissions, args.crosslink_findings, args.findings_dir,
                args.with_blame, args.repos_root
            ) for r in repos
        ]
        for fut in concurrent.futures.as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                logging.error(f"Error processing repo: {e}")

    # Write an overall summary
    summary_md = output_dir / "contributors_summary.md"
    try:
        rows: List[Dict[str, Any]] = []
        unique_by_repo: Dict[str, set] = {}
        display_by_repo: Dict[str, Dict[str, str]] = {}
        aggregate_unique: Dict[str, Dict[str, Any]] = {}
        for r in repos:
            repo_name = r.get("name")
            repo_dir = output_dir / repo_name
            json_path = repo_dir / f"{repo_name}_contributors.json"
            if not json_path.exists():
                continue
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            repo_full = data.get("repository")
            unique_by_repo.setdefault(repo_full, set())
            display_by_repo.setdefault(repo_full, {})
            for c in data.get("contributors", []):
                rows.append({
                    "repository": repo_full,
                    "login": c.get("login"),
                    "name": c.get("name"),
                    "email": c.get("email"),
                    "last_commit_date": c.get("last_commit_date"),
                    "contributions": c.get("contributions", 0),
                    "churn": (c.get("churn") or {}),
                    "critical": (c.get("critical") or {}),
                    "verified": (c.get("verified") or {}),
                    "pr": (c.get("pr") or {}),
                    "perms": c.get("perms"),
                    "sec_attrib": (c.get("sec_attrib") or {}),
                })
                # Build uniqueness key: prefer login, else email, else name
                key = c.get("login") or c.get("email") or c.get("name") or "(anonymous)"
                unique_by_repo[repo_full].add(key)
                # Build a short display label
                label = c.get("login") or (c.get("name") or "(anonymous)")
                if c.get("email") and c.get("email") != "":
                    label = f"{label}"
                display_by_repo[repo_full][key] = label
                # Aggregate across all repos
                agg = aggregate_unique.setdefault(key, {
                    "login": c.get("login") or "",
                    "name": c.get("name") or "",
                    "email": c.get("email") or "",
                    "total_contributions": 0,
                    "repositories": set(),
                    "latest_commit_date": None,
                    "churn": {"additions": 0, "deletions": 0, "net": 0},
                    "critical": {"ci_cd": 0, "secrets": 0, "deps": 0, "build": 0, "infra": 0},
                    "verified": {"commits": 0, "verified": 0},
                    "pr": {"merged": 0, "reviewed": 0, "considered": 0, "self_merged": 0, "ttm_days_total": 0.0},
                    "perms": {"admin": 0, "maintain": 0, "write": 0, "triage": 0, "read": 0, "none": 0},
                    "sec_attrib": {"secrets": 0},
                })
                agg["total_contributions"] += int(c.get("contributions") or 0)
                agg["repositories"].add(repo_full)
                # Track most recent commit date across repos for this contributor
                lcd = c.get("last_commit_date")
                if lcd:
                    prev = agg.get("latest_commit_date")
                    # ISO 8601 strings compare lexicographically for max
                    if not prev or lcd > prev:
                        agg["latest_commit_date"] = lcd
        rows.sort(key=lambda x: (x.get("repository"), -int(x.get("contributions") or 0), x.get("login") or ""))
        with open(summary_md, "w", encoding="utf-8") as f:
            f.write("# Contributors Summary\n\n")
            f.write(f"Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
            # Detailed rows
            f.write("| Repository | Login | Name | Email | Last Commit | Commits |\n")
            f.write("|------------|-------|------|-------|-------------|---------|\n")
            for row in rows:
                f.write(
                    f"| {row.get('repository','')} | {row.get('login','')} | {row.get('name','') or ''} | {row.get('email','') or ''} | {row.get('last_commit_date','') or ''} | {row.get('contributions',0)} |\n"
                )
            # Unique contributors per repo
            f.write("\n## Unique Contributors Per Repository\n\n")
            f.write("| Repository | Unique Contributors Count | Contributors |\n")
            f.write("|------------|---------------------------|--------------|\n")
            for repo_full, uniq_set in sorted(unique_by_repo.items(), key=lambda x: x[0]):
                labels = [display_by_repo[repo_full][k] for k in sorted(uniq_set)]
                contributors_list = ", ".join(labels)
                f.write(
                    f"| {repo_full} | {len(uniq_set)} | {contributors_list} |\n"
                )

            # Organization-wide unique contributors with total commits
            f.write("\n## Unique Contributors Across All Repositories\n\n")
            f.write("| Contributor | Name | Email | Total Commits | Most Recent Commit | Repositories |\n")
            f.write("|-------------|------|-------|---------------|--------------------|--------------|\n")
            # Sort by total contributions desc, then by contributor key
            for key, info in sorted(aggregate_unique.items(), key=lambda x: (-x[1]["total_contributions"], x[0])):
                repos_list = sorted(list(info["repositories"]))
                repos_str = ", ".join(repos_list)
                contributor = info.get("login") or info.get("name") or key
                f.write(
                    f"| {contributor} | {info.get('name','')} | {info.get('email','')} | {info.get('total_contributions',0)} | {info.get('latest_commit_date','') or ''} | {repos_str} |\n"
                )

            # Organization-wide unique contributors with repository count
            f.write("\n## Unique Contributors Across All Repositories (by Repo Count)\n\n")
            f.write("| Contributor | Name | Email | Total Commits | Most Recent Commit | Repositories Count |\n")
            f.write("|-------------|------|-------|---------------|--------------------|--------------------|\n")
            for key, info in sorted(
                aggregate_unique.items(),
                key=lambda x: (-len(x[1]["repositories"]), -x[1]["total_contributions"], x[0])
            ):
                contributor = info.get("login") or info.get("name") or key
                repo_count = len(info["repositories"]) if isinstance(info.get("repositories"), set) else 0
                f.write(
                    f"| {contributor} | {info.get('name','')} | {info.get('email','')} | {info.get('total_contributions',0)} | {info.get('latest_commit_date','') or ''} | {repo_count} |\n"
                )

            # Top Risk Contributors (basic score)
            if args.risk_score:
                def score(info: Dict[str, Any]) -> float:
                    # weights
                    crit = info.get("critical") or {}
                    crit_score = (
                        crit.get("secrets", 0) * 5 +
                        crit.get("ci_cd", 0) * 4 +
                        crit.get("infra", 0) * 3 +
                        crit.get("deps", 0) * 3 +
                        crit.get("build", 0) * 2
                    )

            # PR Hygiene (org-wide)
            if aggregate_unique:
                f.write("\n## PR Hygiene (Across All Repositories)\n\n")
                f.write("| Contributor | Reviewed% | Self-Merged | Avg TTM (days) | Merged PRs | Considered PRs |\n")
                f.write("|-------------|-----------:|------------:|---------------:|-----------:|----------------:|\n")
                for key, info in sorted(aggregate_unique.items(), key=lambda x: (-(x[1]["pr"]["considered"] or 0), x[0])):
                    pr = info.get("pr") or {}
                    considered = pr.get("considered", 0)
                    reviewed_pct = ((pr.get("reviewed", 0) / considered) * 100.0) if considered else None
                    avg_ttm = ((pr.get("ttm_days_total", 0.0) / pr.get("merged", 1)) if pr.get("merged", 0) else None)
                    contributor = info.get("login") or info.get("name") or key
                    f.write(
                        f"| {contributor} | {reviewed_pct:.1f}% | {pr.get('self_merged',0)} | {avg_ttm:.1f} | {pr.get('merged',0)} | {considered} |\n"
                        if reviewed_pct is not None and avg_ttm is not None else
                        f"| {contributor} | {reviewed_pct:.1f}% | {pr.get('self_merged',0)} |  | {pr.get('merged',0)} | {considered} |\n"
                        if reviewed_pct is not None else
                        f"| {contributor} |  | {pr.get('self_merged',0)} |  | {pr.get('merged',0)} | {considered} |\n"
                    )

            # Repo Permissions overview
            if aggregate_unique:
                f.write("\n## Repo Permissions Overview (Counts of repos where contributor has role)\n\n")
                f.write("| Contributor | Admin | Maintain | Write | Triage | Read |\n")
                f.write("|-------------|------:|---------:|------:|-------:|-----:|\n")
                for key, info in sorted(aggregate_unique.items(), key=lambda x: (-sum(x[1]["perms"].values()), x[0])):
                    contributor = info.get("login") or info.get("name") or key
                    p = info.get("perms") or {}
                    f.write(
                        f"| {contributor} | {p.get('admin',0)} | {p.get('maintain',0)} | {p.get('write',0)} | {p.get('triage',0)} | {p.get('read',0)} |\n"
                    )

            # Security Findings Attributed to Authors (Secrets)
            if aggregate_unique:
                f.write("\n## Security Findings Attributed to Authors (Secrets)\n\n")
                f.write("| Contributor | Secrets Findings |\n")
                f.write("|-------------|------------------:|\n")
                for key, info in sorted(aggregate_unique.items(), key=lambda x: (-x[1]["sec_attrib"].get("secrets", 0), x[0])):
                    contributor = info.get("login") or info.get("name") or key
                    s = info.get("sec_attrib") or {}
                    f.write(
                        f"| {contributor} | {s.get('secrets',0)} |\n"
                    )

                # end security findings table
        logging.info(f"Summary written: {summary_md}")
    except Exception as e:
        logging.error(f"Failed to write summary: {e}")

    logging.info("Scan completed!")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)
