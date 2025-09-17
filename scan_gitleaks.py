#!/usr/bin/env python3
"""
Specialized repository scanner for detecting secrets using Gitleaks.

This script scans one or more GitHub repositories for exposed secrets and sensitive information
using Gitleaks. It generates detailed reports showing the actual secret values found.
"""

import argparse
import concurrent.futures
import datetime
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any

import requests
from src.github.rate_limit import make_rate_limited_session, request_with_rate_limit
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(override=True)

class GitleaksConfig:
    """Configuration for the Gitleaks scanner."""
    
    def __init__(self):
        # Load required environment variables
        self.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        self.ORG_NAME = os.getenv("GITHUB_ORG")
        
        # Validate required environment variables
        if not self.GITHUB_TOKEN:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        if not self.ORG_NAME:
            raise ValueError("GITHUB_ORG environment variable is required")
            
        # Set other configuration with defaults
        self.GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com")
        self.REPORT_DIR = os.path.abspath(os.getenv("REPORT_DIR", "secrets_reports"))
        self.CLONE_DIR = None
        self.HEADERS = {
            "Authorization": f"token {self.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }

# Global config instance
config = None

def setup_logging(verbosity: int = 1):
    """Configure logging based on verbosity level."""
    log_level = logging.INFO
    if verbosity > 1:
        log_level = logging.DEBUG
    elif verbosity == 0:
        log_level = logging.WARNING
    
    try:
        os.makedirs('logs', exist_ok=True)
    except Exception:
        pass
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('logs/gitleaks_scan.log')
        ]
    )

def make_session() -> requests.Session:
    """Create a session with rate-limit aware retries and auth headers."""
    token = config.GITHUB_TOKEN if config else None
    return make_rate_limited_session(token, user_agent="auditgh-gitleaks")

def _filter_page_repos(page_repos: List[Dict[str, Any]], include_forks: bool, include_archived: bool) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for repo in page_repos or []:
        if (not include_forks and repo.get('fork')) or (not include_archived and repo.get('archived')):
            continue
        out.append(repo)
    return out

def get_all_repos(session: requests.Session, include_forks: bool = False,
                  include_archived: bool = False) -> List[Dict[str, Any]]:
    """Fetch all repositories from an org, with fallback to user if org not found.

    Tries /orgs/{name}/repos first. If the first page returns 404, retries with /users/{name}/repos.
    """
    repos: List[Dict[str, Any]] = []
    page = 1
    per_page = 100

    is_user_fallback = False

    while True:
        base = "users" if is_user_fallback else "orgs"
        url = f"{config.GITHUB_API}/{base}/{config.ORG_NAME}/repos"
        params = {"type": "all", "per_page": per_page, "page": page}
        try:
            resp = request_with_rate_limit(session, 'GET', url, params=params, timeout=30, logger=logging.getLogger('gitleaks.api'))
            if not is_user_fallback and page == 1 and resp.status_code == 404:
                logging.info(f"Organization '{config.ORG_NAME}' not found or inaccessible. Retrying as a user account...")
                # switch to user mode and restart pagination
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
    """Fetch a single repository by name or owner/name."""
    if '/' in repo_identifier:
        owner, repo_name = repo_identifier.split('/', 1)
    else:
        owner = config.ORG_NAME
        repo_name = repo_identifier
    
    url = f"{config.GITHUB_API}/repos/{owner}/{repo_name}"
    
    try:
        response = request_with_rate_limit(session, 'GET', url, timeout=30, logger=logging.getLogger('gitleaks.api'))
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching repository {repo_identifier}: {e}")
        return None

def clone_repo(repo: Dict[str, Any]) -> Optional[str]:
    """Clone a repository from GitHub."""
    if not config.CLONE_DIR:
        config.CLONE_DIR = tempfile.mkdtemp(prefix="repo_scan_")
    
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
            subprocess.run(
                ['git', '-C', repo_path, 'fetch', '--all'],
                check=True,
                capture_output=True,
                text=True
            )
            subprocess.run(
                ['git', '-C', repo_path, 'reset', '--hard', 'origin/HEAD'],
                check=True,
                capture_output=True,
                text=True
            )
        else:
            logging.info(f"Cloning repository: {repo_name}")
            subprocess.run(
                ['git', 'clone', '--depth', '1', clone_url, repo_path],
                check=True,
                capture_output=True,
                text=True
            )
        return repo_path
    except subprocess.CalledProcessError as e:
        logging.error(f"Error cloning/updating repository {repo_name}: {e.stderr}")
        return None

def run_gitleaks_scan(repo_path: str, repo_name: str, report_dir: str) -> Dict[str, Any]:
    """Run gitleaks scan on the repository."""
    os.makedirs(report_dir, exist_ok=True)
    output_json = os.path.join(report_dir, f"{repo_name}_gitleaks.json")
    output_md = os.path.join(report_dir, f"{repo_name}_gitleaks.md")
    
    if not shutil.which('gitleaks'):
        error_msg = "Gitleaks is not installed. Please install it first: brew install gitleaks"
        logging.error(error_msg)
        with open(output_md, 'w') as f:
            f.write(f"# Error\n\n{error_msg}")
        return {
            "error": error_msg,
            "success": False,
            "report_file": output_md
        }
    
    try:
        cmd = [
            'gitleaks',
            'detect',
            '--source', repo_path,
            '--report-format', 'json',
            '--report-path', output_json,
            '--verbose',
            '--no-git'
        ]
        
        logging.info(f"Running gitleaks on {repo_name}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=repo_path
        )
        
        with open(output_md, 'w') as f:
            f.write(f"# Gitleaks Secret Scan Report\n\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Scanned on:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Command:** `{' '.join(cmd)}`\n\n")
            
            if result.returncode == 1:
                try:
                    with open(output_json, 'r') as json_file:
                        findings = json.load(json_file)
                    
                    if not isinstance(findings, list):
                        findings = [findings] if findings else []
                    
                    f.write(f"## Found {len(findings)} potential secrets\n\n")
                    
                    for idx, finding in enumerate(findings, 1):
                        f.write(f"### Secret {idx}\n")
                        f.write(f"- **File:** `{finding.get('File', 'N/A')}`\n")
                        f.write(f"- **Line:** {finding.get('StartLine', 'N/A')}\n")
                        f.write(f"- **Rule ID:** {finding.get('RuleID', 'N/A')}\n")
                        f.write(f"- **Description:** {finding.get('Rule', {}).get('Description', 'N/A')}\n")
                        f.write(f"- **Secret:** `{finding.get('Secret', 'N/A')}`\n")
                        f.write(f"- **Match:** `{finding.get('Match', 'N/A')}`\n")
                        
                        if 'Commit' in finding:
                            f.write(f"- **Commit:** {finding['Commit']}\n")
                        if 'Author' in finding:
                            f.write(f"- **Author:** {finding['Author']} ({finding.get('Email', 'N/A')})\n")
                        if 'Date' in finding:
                            f.write(f"- **Date:** {finding['Date']}\n")
                        
                        f.write("\n---\n\n")
                    
                    logging.info(f"Found {len(findings)} potential secrets in {repo_name}")
                    
                except Exception as e:
                    error_msg = f"Error processing findings: {str(e)}"
                    f.write(f"## Error\n\n{error_msg}\n\n{result.stderr}")
                    logging.error(error_msg)
            
            elif result.returncode == 0:
                f.write("## No secrets found\n")
                logging.info(f"No secrets found in {repo_name}")
            
            else:
                error_msg = f"Gitleaks failed with return code {result.returncode}:\n{result.stderr}"
                f.write(f"## Error\n\n{error_msg}")
                logging.error(f"Gitleaks scan failed for {repo_name}: {error_msg}")
        
        return {
            "success": result.returncode in [0, 1],
            "returncode": result.returncode,
            "output_file": output_json,
            "report_file": output_md,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    
    except Exception as e:
        error_msg = f"Error running gitleaks: {str(e)}"
        logging.error(f"Error running gitleaks on {repo_name}: {error_msg}")
        return {
            "error": error_msg,
            "success": False,
            "report_file": output_md
        }

def process_repo(repo: Dict[str, Any], report_dir: str):
    """Process a single repository: clone and scan for secrets."""
    repo_name = repo['name']
    repo_full_name = repo['full_name']
    
    logging.info(f"Processing repository: {repo_full_name}")
    
    repo_report_dir = os.path.join(report_dir, repo_name)
    os.makedirs(repo_report_dir, exist_ok=True)
    
    repo_path = clone_repo(repo)
    if not repo_path:
        logging.error(f"Failed to clone repository: {repo_full_name}")
        return
    
    try:
        gitleaks_result = run_gitleaks_scan(repo_path, repo_name, repo_report_dir)
        
        if gitleaks_result.get('success', False):
            if gitleaks_result['returncode'] == 1:
                logging.warning(f"Found secrets in {repo_full_name}")
            else:
                logging.info(f"No secrets found in {repo_full_name}")
        else:
            logging.error(f"Failed to scan {repo_full_name}: {gitleaks_result.get('error', 'Unknown error')}")
    
    except Exception as e:
        logging.error(f"Error processing repository {repo_full_name}: {str(e)}")
    
    finally:
        try:
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
        except Exception as e:
            logging.error(f"Error cleaning up repository {repo_full_name}: {str(e)}")

def generate_summary_report(report_dir: str, repo_count: int, secret_repos: List[str]):
    """Generate a summary report of all gitleaks scans."""
    summary_file = os.path.join(report_dir, "secrets_scan_summary.md")
    
    with open(summary_file, 'w') as f:
        f.write("# Gitleaks Secret Scan Summary\n\n")
        f.write(f"**Scan Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"## Scan Results\n")
        f.write(f"- **Total Repositories Scanned:** {repo_count}\n")
        f.write(f"- **Repositories with Secrets Found:** {len(secret_repos)}\n\n")
        
        if secret_repos:
            f.write("## Repositories with Secrets Found\n\n")
            for repo in secret_repos:
                f.write(f"- [{repo}]({repo}/README.md)  ")
                f.write(f"[View Report]({repo}/{repo}_gitleaks.md)  ")
                f.write(f"[JSON Results]({repo}/{repo}_gitleaks.json)\n")
        else:
            f.write("## No Secrets Found\n\n")
            f.write("No secrets were found in any of the scanned repositories.\n")
    
    logging.info(f"Summary report generated: {summary_file}")

def main():
    """Main function to orchestrate the repository scanning process."""
    # Try to initialize config first to validate required environment variables
    try:
        global config
        config = GitleaksConfig()
    except ValueError as e:
        print(f"Error: {str(e)}")
        print("Please ensure you have a .env file with the required variables or set them in your environment.")
        print("Required variables: GITHUB_TOKEN, GITHUB_ORG")
        print("Optional variables: GITHUB_API, REPORT_DIR")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description='Scan GitHub repositories for secrets using Gitleaks')
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
    secret_repos = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_repo = {
            executor.submit(process_repo, repo, config.REPORT_DIR): repo 
            for repo in repos
        }
        
        for future in concurrent.futures.as_completed(future_to_repo):
            repo = future_to_repo[future]
            try:
                future.result()
                # Check if the repository had secrets
                report_file = os.path.join(config.REPORT_DIR, repo['name'], f"{repo['name']}_gitleaks.md")
                if os.path.exists(report_file):
                    with open(report_file, 'r') as f:
                        content = f.read()
                        if "No secrets found" not in content:
                            secret_repos.append(repo['name'])
            except Exception as e:
                logging.error(f"Error processing repository {repo['name']}: {str(e)}")
    
    # Generate summary report
    generate_summary_report(config.REPORT_DIR, len(repos), secret_repos)
    
    # Clean up temporary directory if it was created
    if hasattr(config, 'CLONE_DIR') and config.CLONE_DIR and os.path.exists(config.CLONE_DIR):
        try:
            shutil.rmtree(config.CLONE_DIR)
        except Exception as e:
            logging.error(f"Error cleaning up temporary directory: {str(e)}")
    
    logging.info("Scan completed!")

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
