#!/usr/bin/env python3
"""
Detect GenAI provider API tokens in repositories and optionally persist to PostgREST.

Providers (initial): openai, anthropic, cohere

Persistence: api.upsert_ai_tokens(p_project_id int, p_payload jsonb)
- Externally use api_id (numeric) for project; we resolve or create via ensure_project RPC if needed.
"""
import argparse
import concurrent.futures
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv

load_dotenv(override=True)

LOG = logging.getLogger('genai.tokens')

# Simple provider regex registry (initial set)
PROVIDER_PATTERNS: Dict[str, List[re.Pattern]] = {
    'openai': [re.compile(r"sk-[A-Za-z0-9]{32,64}")],
    'anthropic': [re.compile(r"sk-ant-[A-Za-z0-9]{20,64}")],
    # Cohere keys are typically 32+ alnum; keep conservative to reduce FPs
    'cohere': [re.compile(r"(?:cohere_|COHERE_)?[A-Za-z0-9]{32,64}")],
}

TEXT_EXTS = {
    '.py','.js','.jsx','.ts','.tsx','.json','.yml','.yaml','.md','.env','.sh','.bash','.zsh','.tf','.tfvars',
    '.rb','.go','.java','.kt','.scala','.php','.rs','.c','.cpp','.h','.cs','.ini','.cfg','.conf','.toml','.dockerfile','.gradle'
}

DEFAULT_EXCLUDE_DIRS = {'.git','node_modules','dist','build','vendor','__pycache__','.venv','venv','.idea','.vscode'}


def setup_logging(verbosity: int = 1):
    level = logging.INFO if verbosity == 1 else (logging.DEBUG if verbosity > 1 else logging.WARNING)
    os.makedirs('logs', exist_ok=True)
    logging.basicConfig(level=level,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        handlers=[logging.StreamHandler(), logging.FileHandler('logs/genai_tokens.log')])


def is_binary(path: str) -> bool:
    try:
        with open(path, 'rb') as f:
            chunk = f.read(4096)
        return b"\x00" in chunk
    except Exception:
        return False


def list_repos(org: str, token: Optional[str], include_forks: bool, include_archived: bool) -> List[Dict[str, Any]]:
    headers = {'User-Agent': 'auditgh-genai-tokens'}
    if token:
        headers['Authorization'] = f'token {token}'
    repos: List[Dict[str, Any]] = []
    page = 1
    session = requests.Session()
    while True:
        url = f"https://api.github.com/orgs/{org}/repos"
        params = {'type':'all','per_page':100,'page':page}
        try:
            resp = session.get(url, headers=headers, params=params, timeout=30)
            if resp.status_code == 404:
                url = f"https://api.github.com/users/{org}/repos"
                resp = session.get(url, headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            page_repos = resp.json() or []
            if not page_repos:
                break
            for r in page_repos:
                if (not include_forks and r.get('fork')) or (not include_archived and r.get('archived')):
                    continue
                repos.append(r)
            if len(page_repos) < 100:
                break
            page += 1
        except requests.RequestException as e:
            LOG.error(f"Repo listing failed: {e}")
            break
    return repos


def clone_repo(repo: Dict[str, Any], token: Optional[str], base_dir: str) -> Optional[str]:
    name = repo['name']
    path = os.path.join(base_dir, name)
    url = repo.get('clone_url')
    if token and url and url.startswith('https://') and '@' not in url:
        url = url.replace('https://', f'https://x-access-token:{token}@')
    try:
        if os.path.exists(path):
            subprocess.run(['git','-C',path,'fetch','--all'], check=True, capture_output=True, text=True)
            subprocess.run(['git','-C',path,'reset','--hard','origin/HEAD'], check=True, capture_output=True, text=True)
        else:
            subprocess.run(['git','clone','--depth','1', url, path], check=True, capture_output=True, text=True)
        return path
    except subprocess.CalledProcessError as e:
        LOG.warning(f"Clone failed for {name}: {e.stderr}")
        return None


def detect_tokens(repo_path: str, max_file_bytes: int = 2_000_000) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDE_DIRS]
        for f in files:
            p = os.path.join(root, f)
            ext = ''.join(Path(p).suffixes[-1:])
            if ext and ext.lower() not in TEXT_EXTS:
                continue
            try:
                if os.path.getsize(p) > max_file_bytes:
                    continue
            except Exception:
                continue
            if is_binary(p):
                continue
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as fh:
                    for i, line in enumerate(fh, start=1):
                        for provider, patterns in PROVIDER_PATTERNS.items():
                            for rx in patterns:
                                for m in rx.finditer(line):
                                    token = m.group(0)
                                    hits.append({
                                        'provider': provider,
                                        'token': token,
                                        'file_path': os.path.relpath(p, repo_path),
                                        'line_start': i,
                                        'line_end': i,
                                        'confidence': 'high',
                                    })
            except Exception:
                continue
    return hits


def ensure_project(postgrest_url: str, repo: Dict[str, Any]) -> Optional[int]:
    base = postgrest_url.rstrip('/')
    name = repo.get('name')
    repo_url = repo.get('html_url') or repo.get('clone_url') or ''
    description = repo.get('description')
    try:
        # Use existing ensure_project RPC if present; fall back to selecting projects by name
        # Attempt RPC by convention
        resp = requests.post(f"{base}/rpc/ensure_project", json={
            'p_name': name,
            'p_repo_url': repo_url,
            'p_description': description,
        }, timeout=30)
        if resp.status_code < 400:
            data = resp.json()
            if isinstance(data, list) and data:
                row = data[0]
                api_id = row.get('id') or row.get('api_id')
                if isinstance(api_id, int):
                    return api_id
        # Fallback: lookup
        r2 = requests.get(f"{base}/projects?select=id,name&name=eq.{name}", timeout=15)
        if r2.status_code < 400:
            arr = r2.json() or []
            if arr and isinstance(arr[0].get('id'), int):
                return int(arr[0]['id'])
    except Exception as e:
        LOG.warning(f"ensure_project failed for {name}: {e}")
    return None


def persist_tokens(postgrest_url: str, project_api_id: int, repo_short: str, hits: List[Dict[str, Any]]) -> int:
    base = postgrest_url.rstrip('/')
    payload = []
    for h in hits:
        obj = {
            'provider': h['provider'],
            'token': h['token'],
            'file_path': h.get('file_path'),
            'line_start': h.get('line_start'),
            'line_end': h.get('line_end'),
            'confidence': h.get('confidence','medium'),
            'repo_short': repo_short,
            'metadata': {},
        }
        payload.append(obj)
    try:
        resp = requests.post(f"{base}/rpc/upsert_ai_tokens", json={
            'p_project_id': project_api_id,
            'p_payload': payload
        }, timeout=60)
        if resp.status_code >= 400:
            LOG.warning(f"upsert_ai_tokens failed: {resp.status_code} {resp.text}")
            return 0
        return len(payload)
    except Exception as e:
        LOG.warning(f"persist failed: {e}")
        return 0


def main():
    parser = argparse.ArgumentParser(description='Detect GenAI provider API tokens in repositories')
    parser.add_argument('--org', type=str, help='GitHub org/user (overrides GITHUB_ORG)')
    parser.add_argument('--repo', type=str, help='Single repo (owner/name or name); default: all in org')
    parser.add_argument('--token', type=str, help='GitHub token (overrides GITHUB_TOKEN)')
    parser.add_argument('--include-forks', action='store_true')
    parser.add_argument('--include-archived', action='store_true')
    parser.add_argument('--max-workers', type=int, default=4)
    parser.add_argument('--persist', action='store_true', help='Persist to PostgREST api.ai_tokens via RPC')
    parser.add_argument('--postgrest-url', type=str, default=os.getenv('POSTGREST_URL') or 'http://localhost:3001')
    parser.add_argument('-v','--verbose', action='count', default=1)

    args = parser.parse_args()
    setup_logging(args.verbose or 1)

    org = args.org or os.getenv('GITHUB_ORG')
    gh_token = args.token or os.getenv('GITHUB_TOKEN')
    if not org:
        print('GITHUB_ORG is required', file=sys.stderr)
        sys.exit(2)

    repos: List[Dict[str, Any]] = []
    if args.repo:
        # Fetch single
        owner, name = (args.repo.split('/',1) if '/' in args.repo else (org, args.repo))
        try:
            h = {'User-Agent':'auditgh-genai-tokens'}
            if gh_token: h['Authorization'] = f'token {gh_token}'
            r = requests.get(f"https://api.github.com/repos/{owner}/{name}", headers=h, timeout=30)
            r.raise_for_status()
            repos = [r.json()]
        except Exception as e:
            LOG.error(f"Failed to fetch repo {args.repo}: {e}")
            sys.exit(1)
    else:
        repos = list_repos(org, gh_token, args.include_forks, args.include_archived)

    base_clone = tempfile.mkdtemp(prefix='genai_tokens_')
    report_dir = Path('genai_tokens_reports'); report_dir.mkdir(parents=True, exist_ok=True)

    total_hits = 0
    try:
        def _proc(repo: Dict[str, Any]) -> Tuple[str, int]:
            name = repo['name']
            path = clone_repo(repo, gh_token, base_clone)
            if not path:
                return name, 0
            hits = detect_tokens(path)
            # Write artifact
            out_dir = report_dir / name
            out_dir.mkdir(parents=True, exist_ok=True)
            with (out_dir / f"{name}_genai_tokens.json").open('w') as f:
                json.dump(hits, f)
            # Persist if requested
            if args.persist and hits:
                project_api_id = ensure_project(args.postgrest_url, repo)
                if project_api_id is not None:
                    inserted = persist_tokens(args.postgrest_url, project_api_id, name, hits)
                    return name, inserted
            return name, len(hits)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,args.max_workers)) as tp:
            futs = [tp.submit(_proc, r) for r in repos]
            for fut in concurrent.futures.as_completed(futs):
                repo_name, cnt = fut.result()
                LOG.info(f"{repo_name}: {cnt} tokens")
                total_hits += cnt
    finally:
        try:
            shutil.rmtree(base_clone)
        except Exception:
            pass

    LOG.info(f"Done. Total tokens seen: {total_hits}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        LOG = logging.getLogger('genai.tokens')
        LOG.error(f"Unexpected error: {e}")
        if LOG.getEffectiveLevel() <= logging.DEBUG:
            import traceback; traceback.print_exc()
        sys.exit(1)
