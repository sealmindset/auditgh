"""
GitHub GraphQL client with TTL caching and cost-aware pacing.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

import requests

from .rate_limit import make_rate_limited_session, request_with_rate_limit

GRAPHQL_ENDPOINT = "https://api.github.com/graphql"


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")


def _stable_dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


@dataclass
class CacheConfig:
    dir: Path
    ttl_seconds: int


class TTLCache:
    def __init__(self, directory: str, ttl_seconds: int):
        self.cfg = CacheConfig(dir=Path(directory), ttl_seconds=ttl_seconds)
        self.cfg.dir.mkdir(parents=True, exist_ok=True)

    def _key_path(self, query: str, variables: Dict[str, Any], token: str) -> Path:
        # Never store the raw token; only a fingerprint to segregate caches by identity
        token_fp = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
        raw = _stable_dumps({"q": query, "v": variables, "t": token_fp})
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return self.cfg.dir / f"{h}.json"

    def get(self, query: str, variables: Dict[str, Any], token: str) -> Optional[Dict[str, Any]]:
        if self.cfg.ttl_seconds <= 0:
            return None
        p = self._key_path(query, variables, token)
        if not p.exists():
            return None
        try:
            with p.open("r", encoding="utf-8") as f:
                payload = json.load(f)
            expires_at = float(payload.get("_expires", 0))
            if time.time() > expires_at:
                return None
            return payload.get("data")
        except Exception:
            return None

    def set(self, query: str, variables: Dict[str, Any], token: str, data: Dict[str, Any]) -> None:
        if self.cfg.ttl_seconds <= 0:
            return
        p = self._key_path(query, variables, token)
        tmp = {
            "_created": time.time(),
            "_expires": time.time() + self.cfg.ttl_seconds,
            "data": data,
        }
        try:
            with p.open("w", encoding="utf-8") as f:
                json.dump(tmp, f)
        except Exception:
            pass


class GitHubGraphQLClient:
    def __init__(self, token: str, user_agent: str = "auditgh-graphql"):
        self.token = token
        self.session = make_rate_limited_session(token, user_agent=user_agent)
        self.logger = logging.getLogger("auditgh.github.graphql")
        cache_dir = os.getenv("GITHUB_GRAPHQL_CACHE_DIR", ".cache/github/graphql")
        ttl = int(os.getenv("GITHUB_GRAPHQL_CACHE_TTL", "3600"))
        self.cache = TTLCache(cache_dir, ttl)

    def _post(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        url = GRAPHQL_ENDPOINT
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            # Override session Authorization to ensure GraphQL bearer scheme
            "Authorization": f"bearer {self.token}",
        }

        # Cache check
        cached = self.cache.get(query, variables, self.token)
        if cached is not None:
            self.logger.debug("GraphQL cache hit")
            return cached

        body = {"query": query, "variables": variables}
        # Use central rate-limited requester for consistent pacing
        resp = request_with_rate_limit(
            self.session, "POST", url, json=body, headers=headers, timeout=60, logger=self.logger
        )
        if resp.status_code >= 400:
            resp.raise_for_status()
        data = resp.json()

        # Handle GraphQL errors
        if data.get("errors"):
            # Still may have partial data; log errors and proceed
            self.logger.warning("GraphQL returned errors: %s", data.get("errors"))
        core = data.get("data") or {}

        # Cache set
        self.cache.set(query, variables, self.token, core)

        # Cost-aware pacing if available
        rate = (core.get("rateLimit") if isinstance(core, dict) else None) or data.get("rateLimit")
        # Some queries embed rateLimit at top-level data; be defensive
        if isinstance(rate, dict):
            remaining = rate.get("remaining")
            reset_at = rate.get("resetAt")
            cost = rate.get("cost")
            self.logger.info("GraphQL cost=%s remaining=%s resetAt=%s", cost, remaining, reset_at)
        return core

    def paginate(self, query: str, variables: Dict[str, Any], connection_path: List[str]) -> Iterator[Dict[str, Any]]:
        """Yield nodes from a GraphQL connection given a path like
        ["organization", "repositories"] or ["user", "repositories"].
        """
        after: Optional[str] = None
        while True:
            vars2 = dict(variables)
            vars2["after"] = after
            data = self._post(query, vars2)
            # Walk the connection path
            obj: Any = data
            for k in connection_path:
                obj = (obj or {}).get(k)
            if not obj:
                return
            nodes = (obj.get("nodes") or [])
            for n in nodes:
                yield n
            page_info = obj.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                break
            after = page_info.get("endCursor")

    # ---- High-level helpers ----
    def list_org_repositories(self, org: str, page_size: int = 100) -> Iterator[Dict[str, Any]]:
        q = (
            "query($org:String!,$perPage:Int!,$after:String){"
            " rateLimit { cost remaining resetAt }"
            " organization(login:$org){"
            "  repositories(first:$perPage, after:$after, orderBy:{field:NAME,direction:ASC}){"
            "    pageInfo{ hasNextPage endCursor }"
            "    nodes{"
            "      name nameWithOwner url sshUrl isFork isArchived isDisabled"
            "      defaultBranchRef{ name }"
            "      primaryLanguage{ name }"
            "      languages(first:10, orderBy:{field:SIZE, direction:DESC}){ edges{ size } nodes{ name } }"
            "      diskUsage stargazerCount"
            "      watchers{ totalCount }"
            "      forkCount"
            "      issues(states:OPEN){ totalCount }"
            "      pushedAt updatedAt createdAt"
            "    }"
            "  }"
            " }"
            " user(login:$org){"
            "  repositories(first:$perPage, after:$after, orderBy:{field:NAME,direction:ASC}){"
            "    pageInfo{ hasNextPage endCursor }"
            "    nodes{"
            "      name nameWithOwner url sshUrl isFork isArchived isDisabled"
            "      defaultBranchRef{ name }"
            "      primaryLanguage{ name }"
            "      languages(first:10, orderBy:{field:SIZE, direction:DESC}){ edges{ size } nodes{ name } }"
            "      diskUsage stargazerCount"
            "      watchers{ totalCount }"
            "      forkCount"
            "      issues(states:OPEN){ totalCount }"
            "      pushedAt updatedAt createdAt"
            "    }"
            "  }"
            " }"
            "}"
        )
        vars = {"org": org, "perPage": page_size}
        # Prefer organization if present, but we request both and pick available path per page
        for page_nodes in self._iter_dual_repos(q, vars):
            for n in page_nodes:
                yield n

    def _iter_dual_repos(self, query: str, variables: Dict[str, Any]) -> Iterator[List[Dict[str, Any]]]:
        after: Optional[str] = None
        while True:
            vars2 = dict(variables)
            vars2["after"] = after
            data = self._post(query, vars2)
            org_conn = (((data or {}).get("organization") or {}).get("repositories"))
            user_conn = (((data or {}).get("user") or {}).get("repositories"))
            conn = org_conn or user_conn
            if not conn:
                return
            nodes = conn.get("nodes") or []
            yield nodes
            page_info = conn.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                break
            after = page_info.get("endCursor")


def map_repo_node_to_rest_like(n: Dict[str, Any]) -> Dict[str, Any]:
    name = n.get("name") or ""
    full = n.get("nameWithOwner") or name
    html_url = n.get("url")
    ssh_url = n.get("sshUrl")
    clone_url = f"https://github.com/{full}.git"
    default_branch = ((n.get("defaultBranchRef") or {}).get("name")) or "main"
    primary_lang = ((n.get("primaryLanguage") or {}).get("name"))
    # Build language bytes map
    lang_edges = ((n.get("languages") or {}).get("edges") or [])
    lang_nodes = ((n.get("languages") or {}).get("nodes") or [])
    lang_map: Dict[str, int] = {}
    for i in range(min(len(lang_edges), len(lang_nodes))):
        try:
            nm = lang_nodes[i].get("name")
            sz = int(lang_edges[i].get("size") or 0)
            if nm:
                lang_map[nm] = sz
        except Exception:
            continue
    repo = {
        "name": name,
        "full_name": full,
        "html_url": html_url,
        "description": None,
        "language": primary_lang,
        "created_at": n.get("createdAt"),
        "updated_at": n.get("updatedAt"),
        "pushed_at": n.get("pushedAt"),
        # diskUsage is in KB. The REST field `size` is also KB. Keep KB.
        "size": int(n.get("diskUsage") or 0),
        "stargazers_count": int(n.get("stargazerCount") or 0),
        "watchers_count": int(((n.get("watchers") or {}).get("totalCount")) or 0),
        "forks_count": int(n.get("forkCount") or 0),
        "open_issues_count": int(((n.get("issues") or {}).get("totalCount")) or 0),
        "is_fork": bool(n.get("isFork") or False),
        "is_archived": bool(n.get("isArchived") or False),
        "is_disabled": bool(n.get("isDisabled") or False),
        "default_branch": default_branch,
        # Additional fields expected by clone_repo()
        "clone_url": clone_url,
        "ssh_url": ssh_url,
        # Languages detail for persistence
        "languages_map": lang_map,
    }
    return repo
