#!/usr/bin/env python3
"""
Launch a deep CodeQL wave with bounded concurrency via the portal server API.

- Selects active projects with a non-empty repo_url from PostgREST
- Converts repo_url -> owner/repo slug
- Submits POST /api/scans/ with profile=deep, scanners=["codeql"], scope=repo
- Enforces a hard cap on concurrently running scans by polling PostgREST

Environment variables (overridden by CLI):
- BASE_URL          default http://localhost:3001 (PostgREST)
- SERVER_URL        default http://localhost:8080 (Portal server)
- WAVE_SIZE         default 10
- MAX_CONCURRENT    default 2

Usage examples:
  python3 scripts/launch_codeql_wave.py --wave-size 10 --max-concurrent 2
  BASE_URL=http://postgrest:3001 SERVER_URL=http://server:8080 python3 scripts/launch_codeql_wave.py
"""
from __future__ import annotations
import argparse
import json
import os
import time
import urllib.request
from typing import Any, Dict, List


def env_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if v is not None and v != "" else default


def env_int(name: str, default: int) -> int:
    try:
        raw = os.getenv(name)
        return int(raw) if raw is not None and raw != "" else default
    except Exception:
        return default


def to_slug(url: str) -> str:
    s = (url or "").strip()
    if s.startswith("http://") or s.startswith("https://"):
        try:
            s = s.split("://", 1)[1].split("/", 1)[1]
        except Exception:
            return ""
    if s.startswith("git@"):
        try:
            s = s.split(":", 1)[1]
        except Exception:
            return ""
    if s.endswith(".git"):
        s = s[:-4]
    return s if "/" in s else ""


def fetch_projects(base_url: str) -> List[Dict[str, Any]]:
    url = f"{base_url}/projects?select=uuid,name,repo_url,is_active&is_active=eq.true&order=name.asc"
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read().decode("utf-8"))


def count_running(base_url: str) -> int:
    url = f"{base_url}/scans?select=id&status=eq.running"
    with urllib.request.urlopen(url) as resp:
        return len(json.loads(resp.read().decode("utf-8")))


def post_scan(server_url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{server_url}/api/scans/",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Launch a deep CodeQL wave with bounded concurrency")
    parser.add_argument("--base-url", default=env_str("BASE_URL", "http://localhost:3001"), help="PostgREST base URL")
    parser.add_argument("--server-url", default=env_str("SERVER_URL", "http://localhost:8080"), help="Portal server base URL")
    parser.add_argument("--wave-size", type=int, default=env_int("WAVE_SIZE", 10), help="Number of repos to submit in this wave")
    parser.add_argument("--max-concurrent", type=int, default=env_int("MAX_CONCURRENT", 2), help="Max running scans allowed at once")
    args = parser.parse_args(argv)

    base = args.base_url.rstrip("/")
    server = args.server_url.rstrip("/")

    projects = fetch_projects(base)
    queue = [p for p in projects if p.get("repo_url")]
    wave = queue[: max(0, args.wave_size)]

    print(f"Launching deep CodeQL scans for {len(wave)} repos, max concurrency {args.max_concurrent}...")
    launched = 0
    idx = 0
    while idx < len(wave):
        while count_running(base) >= args.max_concurrent:
            time.sleep(5)
        p = wave[idx]
        slug = to_slug(p.get("repo_url", ""))
        if not slug:
            print(f"Skip {p.get('name')} invalid repo_url: {p.get('repo_url')}")
            idx += 1
            continue
        payload = {
            "project_id": p["uuid"],
            "profile": "deep",
            "scanners": ["codeql"],
            "scope": "repo",
            "repo": slug,
        }
        try:
            resp = post_scan(server, payload)
            d = resp.get("data", {})
            print(f"Started scan id={d.get('id','')} repo={slug} status={d.get('status','')}")
            launched += 1
        except Exception as e:
            print(f"Failed to start scan for {p.get('name')} ({slug}): {e}")
        idx += 1
        time.sleep(2)

    print(f"Launched {launched} scans in this wave. Monitor running via {base}/scans?status=eq.running")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
