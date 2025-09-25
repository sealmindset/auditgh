#!/usr/bin/env python3
"""Specialized repository scanner for detecting secrets using TruffleHog."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

from secret_scanner_github import (
    SecretScannerConfig,
    setup_logging,
    create_session,
    get_all_repos,
    get_single_repo,
    clone_repo,
    cleanup_clone_dir,
    ensure_report_dir,
)
from secret_scanner_utils import (
    normalize_trufflehog_record,
    ensure_project,
    persist_secret_leaks,
)

load_dotenv(override=True)

LOGGER = logging.getLogger('trufflehog')


def run_trufflehog_scan(repo_path: str, repo_name: str, report_dir: Path) -> Dict[str, Any]:
    json_path = report_dir / f"{repo_name}_trufflehog.json"
    md_path = report_dir / f"{repo_name}_trufflehog.md"

    if shutil.which('trufflehog') is None:
        error_msg = "TruffleHog is not installed. Please install it (e.g., pip install trufflehog)."
        LOGGER.error(error_msg)
        md_path.write_text(f"# Error\n\n{error_msg}\n")
        json_path.write_text("[]")
        return {
            'success': False,
            'returncode': 127,
            'output_file': str(json_path),
            'report_file': str(md_path),
            'normalized': [],
            'raw': [],
        }

    cmd = [
        'trufflehog',
        'filesystem',
        '--path', repo_path,
        '--json',
        '--no-update',
    ]

    LOGGER.info("Running TruffleHog on %s", repo_name)
    result = subprocess.run(cmd, capture_output=True, text=True)

    raw_records: List[Dict[str, Any]] = []
    normalized: List[Dict[str, Any]] = []

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            if isinstance(record, dict):
                raw_records.append(record)
                normalized_record = normalize_trufflehog_record(record)
                if normalized_record:
                    normalized.append(normalized_record)
        except json.JSONDecodeError:
            LOGGER.debug("Skipping non-JSON output line from TruffleHog: %s", line[:200])

    # Persist artifacts to disk for manual review
    report_dir.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(raw_records, indent=2))

    with md_path.open('w', encoding='utf-8') as md:
        md.write("# TruffleHog Secret Scan Report\n\n")
        md.write(f"**Repository:** {repo_name}\n\n")
        md.write(f"**Command:** `{ ' '.join(cmd) }`\n\n")
        if result.returncode == 0 and normalized:
            md.write(f"## Found {len(normalized)} potential secrets\n\n")
            for idx, finding in enumerate(normalized, 1):
                md.write(f"### Secret {idx}\n")
                md.write(f"- **Detector:** {finding.get('detector', 'trufflehog')}\n")
                md.write(f"- **Rule ID:** {finding.get('rule_id', 'N/A')}\n")
                md.write(f"- **File:** `{finding.get('file_path', 'N/A')}`\n")
                md.write(f"- **Line:** {finding.get('line_start', 'N/A')}\n")
                md.write(f"- **Description:** {finding.get('description', 'N/A')}\n")
                md.write(f"- **Confidence:** {finding.get('confidence', 'medium')}\n")
                redacted = finding.get('metadata', {}).get('redacted')
                if redacted:
                    md.write(f"- **Redacted:** `{redacted}`\n")
                md.write("\n---\n\n")
        elif result.returncode == 0:
            md.write("## No secrets found\n")
        else:
            md.write("## Error\n\n")
            md.write(f"TruffleHog exited with code {result.returncode}.\n\n")
            if result.stderr:
                md.write("### stderr\n\n````\n")
                md.write(result.stderr)
                md.write("\n````\n")

    success = result.returncode == 0
    return {
        'success': success,
        'returncode': result.returncode,
        'output_file': str(json_path),
        'report_file': str(md_path),
        'normalized': normalized,
        'raw': raw_records,
    }


def process_repo(
    config: SecretScannerConfig,
    repo: Dict[str, Any],
    *,
    persist: bool,
    postgrest_url: Optional[str],
) -> int:
    repo_name = repo['name']
    repo_full_name = repo['full_name']

    LOGGER.info("Processing repository: %s", repo_full_name)

    repo_report_dir = ensure_report_dir(config) / repo_name
    repo_report_dir.mkdir(parents=True, exist_ok=True)

    repo_path = clone_repo(config, repo, LOGGER)
    if not repo_path:
        LOGGER.error("Failed to clone repository: %s", repo_full_name)
        return 0

    pg_url = (postgrest_url or os.getenv('POSTGREST_URL') or 'http://localhost:3001').rstrip('/')

    try:
        result = run_trufflehog_scan(repo_path, repo_name, repo_report_dir)
        if not result.get('success', False):
            LOGGER.error(
                "TruffleHog scan finished with errors for %s (code %s)",
                repo_full_name,
                result.get('returncode'),
            )

        normalized = result.get('normalized', []) or []
        if persist and normalized:
            project_api_id = ensure_project(pg_url, repo, LOGGER)
            if project_api_id is None:
                LOGGER.warning('Skipping persistence for %s; project api_id unavailable', repo_full_name)
            else:
                inserted = persist_secret_leaks(pg_url, project_api_id, repo_name, normalized, LOGGER)
                LOGGER.info('Persisted %s secret leak findings from %s', inserted, repo_full_name)
    finally:
        try:
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
        except Exception as exc:
            LOGGER.warning("Failed to clean up repo %s: %s", repo_full_name, exc)

    return len(result.get('normalized', []) or [])


def generate_summary(report_dir: Path, repo_count: int, secret_repos: List[str], total_hits: int) -> None:
    summary_path = report_dir / "trufflehog_summary.md"
    with summary_path.open('w', encoding='utf-8') as fh:
        fh.write("# TruffleHog Secret Scan Summary\n\n")
        fh.write(f"**Scan Date:** {Path.cwd()}\n\n")
        fh.write("## Scan Results\n")
        fh.write(f"- **Total Repositories Scanned:** {repo_count}\n")
        fh.write(f"- **Repositories with Secrets Found:** {len(secret_repos)}\n")
        fh.write(f"- **Total Findings:** {total_hits}\n\n")
        if secret_repos:
            fh.write("## Repositories with Findings\n")
            for repo in secret_repos:
                fh.write(f"- {repo}\n")
        else:
            fh.write("## No Secrets Found\n")


def parse_args(config: SecretScannerConfig) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Scan repositories for secrets using TruffleHog')
    parser.add_argument('--org', type=str, default=config.ORG_NAME,
                        help=f'GitHub organization name (default: {config.ORG_NAME})')
    parser.add_argument('--repo', type=str,
                        help='Single repository to scan (format: owner/repo or repo_name)')
    parser.add_argument('--token', type=str,
                        help='GitHub personal access token (overrides GITHUB_TOKEN from .env)')
    parser.add_argument('--output-dir', type=str, default=config.REPORT_DIR,
                        help=f'Output directory for reports (default: {config.REPORT_DIR})')
    parser.add_argument('--include-forks', action='store_true', help='Include forked repositories')
    parser.add_argument('--include-archived', action='store_true', help='Include archived repositories')
    parser.add_argument('-v', '--verbose', action='count', default=1,
                        help='Increase verbosity (can be specified multiple times)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress output (overrides --verbose)')
    try:
        default_max_workers = int(os.getenv("TRUFFLEHOG_MAX_WORKERS") or os.getenv("SCAN_MAX_WORKERS") or 5)
    except Exception:
        default_max_workers = 5
    parser.add_argument('--max-workers', type=int, default=default_max_workers,
                        help=f'Max worker threads (default: {default_max_workers})')
    parser.add_argument('--persist', action='store_true',
                        help='Persist detected secrets to PostgREST secret_leaks via RPC')
    parser.add_argument('--postgrest-url', type=str, default=os.getenv('POSTGREST_URL') or 'http://localhost:3001',
                        help='PostgREST base URL (default: %(default)s)')
    return parser.parse_args()


def main() -> None:
    try:
        config = SecretScannerConfig.from_env(default_report_dir='secrets_reports')
    except ValueError as exc:
        print(f"Error: {exc}")
        print("Required variables: GITHUB_TOKEN, GITHUB_ORG")
        sys.exit(1)

    args = parse_args(config)

    if args.quiet:
        args.verbose = 0
    logger = setup_logging('trufflehog', 'logs/trufflehog_scan.log', args.verbose)
    global LOGGER
    LOGGER = logger

    if args.token:
        config.GITHUB_TOKEN = args.token
        config.HEADERS["Authorization"] = f"token {config.GITHUB_TOKEN}"

    if args.org and args.org != config.ORG_NAME:
        config.ORG_NAME = args.org
        LOGGER.info("Using organization from CLI: %s", config.ORG_NAME)

    if args.output_dir and os.path.abspath(args.output_dir) != config.REPORT_DIR:
        config.REPORT_DIR = os.path.abspath(args.output_dir)
        LOGGER.info("Using output directory: %s", config.REPORT_DIR)

    ensure_report_dir(config)

    session = create_session(config, user_agent='auditgh-trufflehog')

    if args.repo:
        repo = get_single_repo(config, session, args.repo, LOGGER)
        if not repo:
            LOGGER.error("Repository not found: %s", args.repo)
            sys.exit(1)
        repos = [repo]
    else:
        LOGGER.info("Fetching repositories from %s", config.ORG_NAME)
        repos = get_all_repos(
            config,
            session,
            include_forks=args.include_forks,
            include_archived=args.include_archived,
            logger=LOGGER,
        )
        if not repos:
            LOGGER.error("No repositories found or accessible with the provided token")
            sys.exit(1)

    total_hits = 0
    secret_repos: List[str] = []

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:
            future_to_repo = {
                executor.submit(
                    process_repo,
                    config,
                    repo,
                    persist=args.persist,
                    postgrest_url=args.postgrest_url,
                ): repo for repo in repos
            }

            for future in concurrent.futures.as_completed(future_to_repo):
                repo = future_to_repo[future]
                try:
                    hits = future.result()
                    if hits:
                        secret_repos.append(repo['name'])
                        total_hits += hits
                except Exception as exc:
                    LOGGER.error("Error processing repository %s: %s", repo['name'], exc)
    finally:
        cleanup_clone_dir(config, LOGGER)

    report_dir = Path(config.REPORT_DIR)
    generate_summary(report_dir, len(repos), secret_repos, total_hits)
    LOGGER.info("TruffleHog scan complete: %s repos scanned, %s findings", len(repos), total_hits)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        LOGGER.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as exc:  # pragma: no cover - top-level safety
        LOGGER.error("Unexpected error: %s", exc)
        if LOGGER.getEffectiveLevel() <= logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)
