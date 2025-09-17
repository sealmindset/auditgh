#!/usr/bin/env python3
import argparse
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import datetime
import fnmatch
import json
import logging
import logging.handlers
import os
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler('auditgh_scan.log', maxBytes=5*1024*1024, backupCount=3)
    ]
)

# Enable debug logging for requests/urllib3
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('requests').setLevel(logging.WARNING)
import shutil
import threading
import select
import tty
import termios
import subprocess
import sys
import tempfile
import time
import traceback
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, DefaultDict
from collections import defaultdict
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv
import toml
from functools import lru_cache

# Load environment variables from .env file
load_dotenv()

class Config:
    """Global configuration for the script."""
    def __init__(self):
        self.GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com")
        self.ORG_NAME = os.getenv("GITHUB_ORG", "sleepnumberinc")
        self.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        self.REPORT_DIR = os.getenv("REPORT_DIR", "vulnerability_reports")
        self.CLONE_DIR = None
        self.HEADERS = {}
        # Optional Docker image target for SBOMs (Syft)
        self.DOCKER_IMAGE = None
        # Syft optional integration
        self.SYFT_FORMAT = os.getenv("SYFT_FORMAT", "cyclonedx-json")
        # Grype VEX support (list of files)
        self.VEX_FILES: List[str] = []
        # Control directory for pause/stop flags and state
        self.CONTROL_DIR = os.getenv("AUDITGH_CONTROL_DIR", ".auditgh_control")
        # Optional Semgrep taint-mode config path (ruleset)
        self.SEMGREP_TAINT_CONFIG: Optional[str] = None
        # Optional policy file for gating
        self.POLICY_PATH: Optional[str] = None
        
        # Set up headers if token is available
        if self.GITHUB_TOKEN:
            self.HEADERS = {
                "Authorization": f"Bearer {self.GITHUB_TOKEN}",
                "Accept": "application/vnd.github.v3+json"
            }

# Create a global config instance
config = Config()

def setup_temp_dir() -> str:
    """
    Create and return a temporary directory for repository cloning.
    
    Returns:
        str: Path to the created temporary directory
    """
    try:
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp(prefix="repo_scan_")
        
        # Ensure the directory exists
        os.makedirs(temp_dir, exist_ok=True)
        
        # Set permissions to ensure the directory is accessible
        os.chmod(temp_dir, 0o755)
        
        # Update the global config with the new temp directory
        config.CLONE_DIR = temp_dir
        
        return temp_dir
        
    except Exception as e:
        error_msg = f"Failed to create temporary directory: {e}"
        logging.error(error_msg)
        # Set CLONE_DIR to None to prevent further operations on invalid directory
        config.CLONE_DIR = None
        raise RuntimeError(error_msg)
        raise

def configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )

def make_session():
    """Create and configure a requests session with retry logic and GitHub authentication."""
    session = requests.Session()
    
    # Configure retry strategy
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    
    # Add headers from config
    if hasattr(config, 'HEADERS') and config.HEADERS:
        session.headers.update(config.HEADERS)
    
    return session

# -------------------- Control: Pause / Resume / Stop --------------------

def ensure_control_dir():
    try:
        os.makedirs(config.CONTROL_DIR, exist_ok=True)
    except Exception:
        pass

def _control_path(name: str) -> str:
    return os.path.join(config.CONTROL_DIR, name)

def write_scan_state(status: str, last_repo: str = ""):
    try:
        ensure_control_dir()
        state = {"status": status, "last_repo": last_repo}
        with open(_control_path("scan_state.json"), 'w') as f:
            json.dump(state, f, indent=2)
    except Exception:
        logging.debug("Failed to write scan_state.json")

def check_control(current_repo: str):
    """Blocking wait loop for pause. Stop exits current repo gracefully.

    If stop.flag exists: write state and raise SystemExit to abort processing.
    If pause.flag exists: write state=paused and sleep until it is removed.
    """
    ensure_control_dir()
    stop_flag = _control_path("stop.flag")
    pause_flag = _control_path("pause.flag")
    # Stop immediately if requested
    if os.path.exists(stop_flag):
        write_scan_state("stopped", current_repo)
        logging.warning("Stop requested via stop.flag. Halting after current checkpoint.")
        raise SystemExit("Stopped by control flag")
    # Pause loop
    while os.path.exists(pause_flag):
        write_scan_state("paused", current_repo)
        logging.info("Paused by pause.flag. Remove the flag file to resume...")
        # Print convenience commands to help the user resume/stop
        try:
            print_control_instructions()
        except Exception:
            pass
        time.sleep(10)
        # Check stop while paused
        if os.path.exists(stop_flag):
            write_scan_state("stopped", current_repo)
            logging.warning("Stop requested during pause. Halting.")
            raise SystemExit("Stopped by control flag")
    # Clear to running
    write_scan_state("running", current_repo)

def print_control_instructions():
    """Print convenience commands for pause/resume/stop using the configured control dir."""
    try:
        ensure_control_dir()
        cdir = config.CONTROL_DIR
        pause = os.path.join(cdir, "pause.flag")
        stop = os.path.join(cdir, "stop.flag")
        state = os.path.join(cdir, "scan_state.json")
        print("[auditgh] Control commands:")
        print(f"  Pause:   touch {pause}")
        print(f"  Resume:  rm {pause}")
        print(f"  Stop:    touch {stop}")
        print(f"  State:   cat {state}")
        # Hotkeys note (only effective when running in a TTY)
        try:
            if sys.stdin.isatty():
                print("  Hotkeys (active in this terminal): [p]=pause/resume, [s]=stop, [q]=stop")
        except Exception:
            pass
    except Exception:
        pass

# -------------------- Hotkey Listener --------------------

class HotkeyListener(threading.Thread):
    """Listen for single-key hotkeys on a TTY to control pause/stop.

    Hotkeys:
      p -> toggle pause.flag (pause/resume)
      s -> create stop.flag (stop at next checkpoint)
      q -> create stop.flag (stop)
    """
    def __init__(self):
        super().__init__(daemon=True)
        self._running = True

    def stop(self):
        self._running = False

    def _toggle_pause(self):
        ensure_control_dir()
        pf = _control_path("pause.flag")
        if os.path.exists(pf):
            try:
                os.remove(pf)
                print("[auditgh] Hotkey: resume (removed pause.flag)")
            except Exception:
                pass
        else:
            try:
                with open(pf, 'w'):
                    pass
                print("[auditgh] Hotkey: pause (created pause.flag)")
            except Exception:
                pass

    def _stop(self):
        ensure_control_dir()
        sf = _control_path("stop.flag")
        try:
            with open(sf, 'w'):
                pass
            print("[auditgh] Hotkey: stop (created stop.flag)")
        except Exception:
            pass

    def run(self):
        # Only attach if stdin is a TTY (interactive terminal)
        try:
            if not sys.stdin.isatty():
                return
        except Exception:
            return
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while self._running:
                rlist, _, _ = select.select([sys.stdin], [], [], 0.5)
                if not rlist:
                    continue
                ch = sys.stdin.read(1)
                if not ch:
                    continue
                ch = ch.lower()
                if ch == 'p':
                    self._toggle_pause()
                elif ch == 's' or ch == 'q':
                    self._stop()
                # ignore others
        except Exception:
            pass
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                pass

def get_rate_limit_headers(response: requests.Response) -> dict:
    """Extract rate limit headers from response."""
    return {
        'limit': int(response.headers.get('X-RateLimit-Limit', 0)),
        'remaining': int(response.headers.get('X-RateLimit-Remaining', 0)),
        'reset': int(response.headers.get('X-RateLimit-Reset', 0)),
    }

def get_all_repos(session: requests.Session, include_forks: bool = False, include_archived: bool = False, timeout: int = 30) -> list:
    """
    Fetch all repositories from the organization with pagination and rate limit handling.
    
    Args:
        session: The requests session to use for API calls
        include_forks: Whether to include forked repositories
        include_archived: Whether to include archived repositories
        timeout: Request timeout in seconds
        
    Returns:
        List of repository objects
    """
    if not all([config.GITHUB_API, config.ORG_NAME, config.HEADERS]):
        logging.error("Missing required configuration for get_all_repos")
        return []
    
    logging.info(f"Fetching repositories for organization: {config.ORG_NAME}")
    
    repos = []
    page = 1
    per_page = 100  # Maximum allowed by GitHub API
    max_retries = 3
    retry_delay = 5  # seconds
    # Default to organization endpoint, but fall back to user endpoint on 404
    api_path = f"/orgs/{config.ORG_NAME}/repos"
    tried_user_fallback = False
    
    while True:
        retry_count = 0
        while retry_count < max_retries:
            try:
                # Build the API URL with parameters
                url = f"{config.GITHUB_API}{api_path}"
                params = {
                    'per_page': per_page,
                    'page': page,
                    'type': 'all',  # Get all repository types
                    'sort': 'full_name',
                    'direction': 'asc'
                }
                
                logging.debug(f"Fetching repos page {page}...")
                response = session.get(
                    url,
                    headers=config.HEADERS,
                    params=params,
                    timeout=timeout
                )
                
                # Check rate limits
                check_rate_limits(response)
                
                # Handle rate limiting (HTTP 403)
                if response.status_code == 403:
                    handle_rate_limit(response)
                    continue  # Retry the same request after rate limit resets
                
                # Handle 404 for orgs by falling back to user endpoint once
                if response.status_code == 404 and not tried_user_fallback and api_path.startswith("/orgs/"):
                    logging.info(f"Organization '{config.ORG_NAME}' not found or inaccessible. Retrying as a user account...")
                    api_path = f"/users/{config.ORG_NAME}/repos"
                    tried_user_fallback = True
                    # Reset retries and keep page at 1 for user listing
                    retry_count = 0
                    page = 1
                    time.sleep(1)
                    continue
                
                # Handle other HTTP errors
                response.raise_for_status()
                
                # Process the successful response
                page_repos = response.json()
                if not page_repos:
                    logging.debug("No more repositories found")
                    return repos
                
                # Process repositories from this page
                process_repositories(page_repos, repos, include_forks, include_archived)
                
                # Check if we've reached the last page
                if len(page_repos) < per_page:
                    logging.debug("Reached the last page of repositories")
                    return repos
                
                # Move to the next page
                page += 1
                break  # Success, exit retry loop
                
            except requests.exceptions.HTTPError as http_err:
                # If we already tried user fallback and still got 404, stop early
                if http_err.response is not None and http_err.response.status_code == 404 and tried_user_fallback:
                    logging.error(f"Account '{config.ORG_NAME}' not found as organization or user at {url}")
                    return repos
                retry_count += 1
                if retry_count >= max_retries:
                    logging.error(f"Failed to fetch repositories after {max_retries} attempts: {str(http_err)}")
                    if hasattr(http_err, 'response') and http_err.response is not None:
                        logging.error(f"Response: {http_err.response.status_code} - {http_err.response.text}")
                    return repos
                wait_time = retry_delay * (2 ** (retry_count - 1))
                logging.warning(f"Request failed (attempt {retry_count}/{max_retries}). Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            except requests.exceptions.RequestException as e:
                retry_count += 1
                if retry_count >= max_retries:
                    logging.error(f"Failed to fetch repositories after {max_retries} attempts: {str(e)}")
                    if hasattr(e, 'response') and e.response is not None:
                        logging.error(f"Response: {e.response.status_code} - {e.response.text}")
                    return repos
                
                wait_time = retry_delay * (2 ** (retry_count - 1))  # Exponential backoff
                logging.warning(f"Request failed (attempt {retry_count}/{max_retries}). Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
    
    return repos

def get_single_repo(session: requests.Session, repo_identifier: str, timeout: int = 30) -> Optional[dict]:
    """Fetch a single repository by name or owner/name.
    
    repo_identifier can be one of:
    - "repo" (resolved against config.ORG_NAME as owner)
    - "owner/repo" (explicit owner)
    """
    try:
        if "/" in repo_identifier:
            owner, name = repo_identifier.split("/", 1)
        else:
            owner, name = config.ORG_NAME, repo_identifier
        url = f"{config.GITHUB_API}/repos/{owner}/{name}"
        logging.info(f"Fetching repository: {owner}/{name}")
        resp = session.get(url, headers=config.HEADERS, timeout=timeout)
        if resp.status_code == 404:
            logging.error(f"Repository not found or inaccessible: {owner}/{name}")
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch repository {repo_identifier}: {e}")
        return None

def check_rate_limits(response: requests.Response) -> None:
    """Check and log rate limit information from response headers."""
    if 'X-RateLimit-Remaining' in response.headers:
        remaining = int(response.headers['X-RateLimit-Remaining'])
        limit = int(response.headers.get('X-RateLimit-Limit', 0))
        
        if remaining < 10:  # Warn when running low on API requests
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
            reset_dt = datetime.datetime.fromtimestamp(reset_time)
            logging.warning(
                f"API rate limit: {remaining}/{limit} requests remaining. "
                f"Resets at {reset_dt.strftime('%Y-%m-%d %H:%M:%S')}"
            )

def handle_rate_limit(response: requests.Response) -> None:
    """Handle GitHub API rate limiting by waiting until the rate limit resets."""
    if 'X-RateLimit-Reset' in response.headers:
        reset_time = int(response.headers['X-RateLimit-Reset'])
        wait_time = max(0, reset_time - int(time.time())) + 5  # Add buffer
        logging.warning(f"Rate limit reached. Waiting {wait_time} seconds until reset...")
        time.sleep(wait_time)
    else:
        # If we don't have reset info, use a default wait time
        logging.warning("Rate limited but no reset time provided. Waiting 60 seconds...")
        time.sleep(60)

def process_repositories(page_repos: list, repos: list, include_forks: bool, include_archived: bool) -> None:
    """Process a page of repositories and add them to the results if they match the criteria."""
    for repo in page_repos:
        repo_name = repo.get('name', 'unnamed')
        is_fork = repo.get('fork', False)
        is_archived = repo.get('archived', False)
        
        # Skip based on filters
        if (not include_forks and is_fork) or (not include_archived and is_archived):
            logging.debug(
                f"Skipping repository: {repo_name} "
                f"(fork={is_fork}, archived={is_archived})"
            )
            continue
        
        # Add repository to results
        repos.append(repo)
        logging.debug(f"Added repository: {repo_name} (fork={is_fork}, archived={is_archived})")
    
    logging.info(f"Processed {len(page_repos)} repositories. Total so far: {len(repos)}")

def clone_repo(repo: dict) -> bool:
    """
    Clone a repository from GitHub.
    
    Args:
        repo: Repository information dictionary from GitHub API
        
    Returns:
        bool: True if clone was successful, False otherwise
    """
    if not config.CLONE_DIR:
        logging.error("CLONE_DIR is not configured")
        return False
        
    repo_name = repo.get("name") or (repo.get("full_name", "").split("/")[-1] if repo.get("full_name") else "repo")
    if not repo_name:
        logging.error("Could not determine repository name")
        return False
        
    dest_path = os.path.join(config.CLONE_DIR, repo_name)
    
    # Get the clone URL
    clone_url = repo.get("clone_url")
    if not clone_url and repo.get("full_name"):
        clone_url = f"https://github.com/{repo['full_name']}.git"
    
    if not clone_url:
        logging.error(f"No clone URL found for repository: {repo_name}")
        return False
    
    # Insert token into the URL for authentication (no global git config side-effects)
    if config.GITHUB_TOKEN and "@github.com" not in clone_url and clone_url.startswith("https://"):
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(clone_url)
        if parsed.scheme == 'https':
            netloc = f"x-access-token:{config.GITHUB_TOKEN}@{parsed.netloc}"
            clone_url = urlunparse((
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
    
    try:
        # Create parent directory if it doesn't exist
        os.makedirs(config.CLONE_DIR, exist_ok=True)
        
        # Remove existing directory if it exists
        if os.path.exists(dest_path):
            logging.debug(f"Removing existing directory: {dest_path}")
            shutil.rmtree(dest_path, ignore_errors=True)
        
        # Clone the repository with a timeout
        logging.info(f"Cloning {repo_name} from {clone_url} to {dest_path}...")
        
        # Use subprocess.Popen for better control over the process
        process = subprocess.Popen(
            ["git", "clone", "--depth", "1", clone_url, dest_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        try:
            # Wait for the process to complete with a timeout
            stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
            
            if process.returncode != 0:
                error_msg = stderr or "Unknown error"
                logging.error(f"Failed to clone {repo_name}: {error_msg}")
                # Clean up partial clone if it exists
                if os.path.exists(dest_path):
                    shutil.rmtree(dest_path, ignore_errors=True)
                return False
                
        except subprocess.TimeoutExpired:
            # Terminate the process if it times out
            process.kill()
            stdout, stderr = process.communicate()
            logging.error(f"Clone operation timed out for {repo_name}")
            if os.path.exists(dest_path):
                shutil.rmtree(dest_path, ignore_errors=True)
            return False
        
        # Verify the repository was cloned successfully
        if not os.path.isdir(dest_path):
            logging.error(f"Repository directory not found after clone: {dest_path}")
            return False
            
        logging.info(f"Successfully cloned {repo_name} to {dest_path}")
        return True
        
    except Exception as e:
        logging.error(f"Error cloning {repo_name}: {str(e)}", exc_info=True)
        # Clean up on error
        if os.path.exists(dest_path):
            shutil.rmtree(dest_path, ignore_errors=True)
        return False

def extract_requirements(repo_path):
    """
    Extract Python dependencies from various dependency files.
    Returns a tuple of (requirements_path, is_temporary, source_file).
    """
    # Check for requirements.txt first
    req_file = os.path.join(repo_path, "requirements.txt")
    if os.path.exists(req_file):
        return req_file, False, "requirements.txt"
        
    # Check for pyproject.toml
    pyproject = os.path.join(repo_path, "pyproject.toml")
    if os.path.exists(pyproject):
        try:
            data = toml.load(pyproject)
            deps = []
            
            # Check for modern PEP 621 format
            if "project" in data and "dependencies" in data["project"]:
                deps.extend(data["project"]["dependencies"])
                
            # Check for optional dependencies
            if "project" in data and "optional-dependencies" in data["project"]:
                for optional_deps in data["project"]["optional-dependencies"].values():
                    deps.extend(optional_deps)
            
            if deps:
                temp_req = os.path.join(CLONE_DIR, "temp_requirements.txt")
                with open(temp_req, "w") as f:
                    for dep in deps:
                        # Skip environment markers for now
                        if ";" in dep:
                            dep = dep.split(";")[0].strip()
                        f.write(f"{dep}\n")
                return temp_req, True, "pyproject.toml"
                
        except Exception as e:
            logging.warning(f"Error parsing pyproject.toml: {e}")
    
    # Check for setup.py as a last resort
    setup_py = os.path.join(repo_path, "setup.py")
    if os.path.exists(setup_py):
        try:
            # Use pipreqs to generate requirements.txt from imports
            temp_req = os.path.join(CLONE_DIR, "temp_requirements.txt")
            result = subprocess.run(
                ["pipreqs", "--print", repo_path],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                with open(temp_req, "w") as f:
                    f.write(result.stdout)
                return temp_req, True, "setup.py (generated)"
        except Exception as e:
            logging.warning(f"Error generating requirements from setup.py: {e}")
    
    return None, False, None

def process_repo(repo: Dict[str, Any], report_dir: str) -> None:
    """
    Process a single repository: clone, scan for vulnerabilities, and generate a report.
    
    Args:
        repo: Repository information from GitHub API
        report_dir: Directory to save the report
    """
    # Validate configuration
    if not config.CLONE_DIR:
        config.CLONE_DIR = setup_temp_dir()
        if not config.CLONE_DIR:
            logging.error("Failed to set up temporary directory for cloning")
            return
    
    # Get repository information
    repo_name = repo.get('name', '').strip()
    repo_url = repo.get('html_url', '')
    repo_full_name = repo.get('full_name', repo_name)
    repo_path = None
    
    if not repo_name:
        logging.error("Repository name is missing")
        return
    
    # Sanitize the repository name for use in file paths
    safe_repo_name = "".join(c if c.isalnum() or c in '._-' else '_' for c in repo_name)
    
    logging.info(f"Processing repository: {repo_name}")
    
    # Create a directory for this repository's report
    repo_report_dir = os.path.join(report_dir, safe_repo_name)
    os.makedirs(repo_report_dir, exist_ok=True)
    logging.debug(f"Created report directory: {repo_report_dir}")
    
    # Initialize error log file
    error_log_path = os.path.join(repo_report_dir, f"{safe_repo_name}_error.log")
    
    def log_error(message: str) -> None:
        """Helper function to log errors to both console and error log"""
        logging.error(message)
        with open(error_log_path, 'a') as f:
            f.write(f"{datetime.datetime.now().isoformat()} - {message}\n")
    
    # Clone the repository
    logging.info(f"Cloning repository: {repo_name}")
    if not clone_repo(repo):
        error_msg = f"Failed to clone repository: {repo_name}"
        log_error(error_msg)
        return
    
    # Verify the repository was cloned successfully
    repo_path = os.path.join(config.CLONE_DIR, repo_name)
    if not os.path.isdir(repo_path):
        error_msg = f"Repository directory not found after clone: {repo_path}"
        log_error(error_msg)
        return
        
    logging.info(f"Successfully cloned repository to: {repo_path}")
    
    try:
        # Run various security scans
        logging.info(f"Running security scans for {repo_name}...")
        
        # Extract requirements for Python projects
        requirements_path, is_temp, source_file = extract_requirements(repo_path)
        if requirements_path:
            logging.info(f"Found requirements file: {source_file} at {requirements_path}")
            
            # Run safety scan
            safety_result = run_safety_scan(requirements_path, repo_name, repo_report_dir)
            
            # Run pip-audit scan
            pip_audit_result = run_pip_audit_scan(requirements_path, repo_name, repo_report_dir)
            
            # Clean up temporary requirements file if created
            if is_temp and os.path.exists(requirements_path):
                os.remove(requirements_path)
        else:
            logging.info("No Python requirements file found")
            safety_result = None
            pip_audit_result = None
        semgrep_result = None
        syft_repo_result = None
        syft_image_result = None
        grype_repo_result = None
        grype_image_result = None
        checkov_result = None
        gitleaks_result = None
        semgrep_taint_result = None
        bandit_result = None
        trivy_fs_result = None
        
        # Control checkpoint
        check_control(repo_full_name or repo_name)
        # Run npm audit for Node.js projects
        npm_audit_result = run_npm_audit(repo_path, repo_name, repo_report_dir)
        
        # Control checkpoint
        check_control(repo_full_name or repo_name)
        # Run govulncheck for Go projects
        govulncheck_result = run_govulncheck(repo_path, repo_name, repo_report_dir)
        
        # Control checkpoint
        check_control(repo_full_name or repo_name)
        # Run bundle audit for Ruby projects
        bundle_audit_result = run_bundle_audit(repo_path, repo_name, repo_report_dir)
        
        # Control checkpoint
        check_control(repo_full_name or repo_name)
        # Run OWASP Dependency-Check for Java projects
        dependency_check_result = run_dependency_check(repo_path, repo_name, repo_report_dir)
        
        # Control checkpoint
        check_control(repo_full_name or repo_name)
        # Run Semgrep scan for the repository
        semgrep_result = run_semgrep_scan(repo_path, repo_name, repo_report_dir)
        # Optional Semgrep taint-mode scan
        if config.SEMGREP_TAINT_CONFIG:
            check_control(repo_full_name or repo_name)
            semgrep_taint_result = run_semgrep_taint(repo_path, repo_name, repo_report_dir, config.SEMGREP_TAINT_CONFIG)
        
        # Control checkpoint
        check_control(repo_full_name or repo_name)
        # Run Syft to generate SBOM for the repo directory
        syft_repo_result = run_syft(repo_path, repo_name, repo_report_dir, target_type="repo", sbom_format=config.SYFT_FORMAT)
        
        # If Docker image provided, also run Syft on the image
        if config.DOCKER_IMAGE:
            syft_image_result = run_syft(config.DOCKER_IMAGE, repo_name, repo_report_dir, target_type="image", sbom_format=config.SYFT_FORMAT)
        
        # Control checkpoint
        check_control(repo_full_name or repo_name)
        # Run Grype vulnerability scan on the repo directory
        grype_repo_result = run_grype(repo_path, repo_name, repo_report_dir, target_type="repo", vex_files=config.VEX_FILES)
        # If Docker image provided, run Grype on the image
        if config.DOCKER_IMAGE:
            grype_image_result = run_grype(config.DOCKER_IMAGE, repo_name, repo_report_dir, target_type="image", vex_files=config.VEX_FILES)

        # Control checkpoint
        check_control(repo_full_name or repo_name)
        # Run Checkov for Terraform if applicable
        check_control(repo_full_name or repo_name)
        checkov_result = run_checkov(repo_path, repo_name, repo_report_dir)

        # Secrets scanning with Gitleaks
        check_control(repo_full_name or repo_name)
        gitleaks_result = run_gitleaks(repo_path, repo_name, repo_report_dir)

        # Bandit for Python projects (if any .py files)
        check_control(repo_full_name or repo_name)
        bandit_result = run_bandit(repo_path, repo_name, repo_report_dir)

        # Trivy filesystem scan (optional if installed)
        check_control(repo_full_name or repo_name)
        trivy_fs_result = run_trivy_fs(repo_path, repo_name, repo_report_dir)

        # Control checkpoint
        check_control(repo_full_name or repo_name)
        # Generate summary report
        generate_summary_report(
            repo_name=repo_name,
            repo_url=repo_url,
            requirements_path=requirements_path if requirements_path else "",
            safety_result=safety_result,
            pip_audit_result=pip_audit_result,
            npm_audit_result=npm_audit_result,
            govulncheck_result=govulncheck_result,
            bundle_audit_result=bundle_audit_result,
            dependency_check_result=dependency_check_result,
            semgrep_result=semgrep_result,
            semgrep_taint_result=semgrep_taint_result,
            checkov_result=checkov_result,
            gitleaks_result=gitleaks_result,
            bandit_result=bandit_result,
            trivy_fs_result=trivy_fs_result,
            repo_local_path=repo_path,
            report_dir=repo_report_dir,
            repo_full_name=repo_full_name
        )
        
        logging.info(f"Completed processing repository: {repo_name}")
        write_scan_state("done", repo_full_name or repo_name)
        # Also print to console so users see an immediate pointer to the report location
        try:
            summary_path = os.path.join(repo_report_dir, f"{repo_name}_summary.md")
            if os.path.exists(summary_path):
                print(f"[auditgh] {repo_name}: summary -> {summary_path}")
            else:
                print(f"[auditgh] {repo_name}: reports -> {repo_report_dir}")
        except Exception:
            pass
        
    except Exception as e:
        error_msg = f"Error processing repository {repo_name}: {str(e)}"
        log_error(error_msg)
        logging.exception("Unexpected error:")
        
    finally:
        # Clean up temporary files
        if 'requirements_path' in locals() and is_temp and requirements_path and os.path.exists(requirements_path):
            try:
                os.remove(requirements_path)
                logging.debug(f"Cleaned up temporary file: {requirements_path}")
            except Exception as e:
                logging.warning(f"Failed to remove temporary file {requirements_path}: {e}")
        
        # Clean up the cloned repository if it exists
        if repo_path and os.path.exists(repo_path):
            try:
                shutil.rmtree(repo_path, ignore_errors=True)
                logging.debug(f"Cleaned up repository directory: {repo_path}")
            except Exception as e:
                logging.warning(f"Failed to clean up repository directory {repo_path}: {e}")

def run_safety_scan(requirements_path, repo_name, report_dir):
    """Run safety scan on requirements file and return the output."""
    output_path = os.path.join(report_dir, f"{repo_name}_safety.txt")
    logging.info(f"Running Safety scan for {repo_name}...")
    
    # Use the new 'safety scan' command with appropriate arguments
    cmd = [
        "safety", "scan", "--file", requirements_path,
        "--output", "json",
        "--ignore-unpinned-requirements",
        "--continue-on-error",
        "--disable-optional-output"
    ]
    
    try:
        logging.debug(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # If we get no output but the command succeeded, it might mean no vulnerabilities
        if not result.stdout.strip() and result.returncode == 0:
            logging.debug("No vulnerabilities found in safety scan")
            # Return a valid result with empty findings
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout='{"scanned": [], "affected_packages": {}, "vulnerabilities": []}',
                stderr=result.stderr
            )
        
        # Write results to file
        with open(output_path, "w") as f:
            f.write(result.stdout or "")
            if result.stderr:
                f.write("\n[ERROR] stderr output:\n")
                f.write(result.stderr)
            
            # Add warning if there were issues
            if result.returncode != 0:
                f.write("\n[WARNING] Safety scan completed with non-zero exit code")
        
        if result.returncode != 0:
            logging.warning(f"Safety scan exited with code {result.returncode} for {repo_name}")
            
        return result
    except Exception as e:
        error_msg = f"Error running safety scan: {e}"
        logging.error(error_msg)
        with open(output_path, "w") as f:
            f.write(f"Error running safety scan: {e}")
        return subprocess.CompletedProcess(
            args=cmd, returncode=1,
            stdout="", stderr=error_msg
        )

def run_semgrep_taint(repo_path: str, repo_name: str, report_dir: str, config_path: str) -> subprocess.CompletedProcess:
    """Run Semgrep taint-mode scan using a provided ruleset/config.

    Writes JSON and Markdown summaries to <repo>_semgrep_taint.*
    """
    output_json = os.path.join(report_dir, f"{repo_name}_semgrep_taint.json")
    output_md = os.path.join(report_dir, f"{repo_name}_semgrep_taint.md")
    os.makedirs(report_dir, exist_ok=True)
    cmd = ["semgrep", "--config", config_path, "--json", "--quiet", repo_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    with open(output_json, 'w') as f:
        f.write(result.stdout or "")
    try:
        data = json.loads(result.stdout or '{}')
    except Exception:
        data = {}
    # Minimal exploitable flows summary
    with open(output_md, 'w') as f:
        f.write("# Semgrep Taint-Mode (Exploitable Flows)\n\n")
        flows = data.get('results', []) if isinstance(data, dict) else []
        if not flows:
            f.write("No exploitable flows found or ruleset produced no results.\n")
        else:
            # show up to 10 flows with source->sink
            count = 0
            for r in flows:
                if count >= 10: break
                path = r.get('path','')
                m = r.get('extra',{}).get('message','')
                start = r.get('start',{}).get('line')
                end = r.get('end',{}).get('line')
                f.write(f"- {path}:{start}-{end} — {m}\n")
                count += 1
    return result

def run_pip_audit_scan(requirements_path, repo_name, report_dir):
    """Run pip-audit scan on requirements file and return the output."""
    output_path = os.path.join(report_dir, f"{repo_name}_pip_audit.md")
    logging.info(f"Running pip-audit scan for {repo_name}...")
    
    base_cmd = ["pip-audit", "-r", requirements_path]
    
    try:
        # First try with markdown output
        cmd = base_cmd + ["--output", "markdown"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # If markdown output fails, try with JSON and convert
        if result.returncode != 0 or not result.stdout.strip():
            logging.debug("Markdown output failed, trying JSON output")
            cmd = base_cmd + ["--format", "json"]
            json_result = subprocess.run(cmd, capture_output=True, text=True)
            
            if json_result.returncode == 0 and json_result.stdout.strip():
                try:
                    # Convert JSON to markdown
                    data = json.loads(json_result.stdout)
                    markdown = "# pip-audit Report\n\n"
                    
                    if "vulnerabilities" in data and data["vulnerabilities"]:
                        markdown += "## Vulnerabilities\n\n"
                        for vuln in data["vulnerabilities"]:
                            pkg = vuln.get("package", {})
                            markdown += f"### {pkg.get('name', 'Unknown')} {pkg.get('version', '')}\n"
                            markdown += f"- **ID:** {vuln.get('id', 'Unknown')}\n"
                            if "fix_versions" in vuln and vuln["fix_versions"]:
                                markdown += f"- **Fixed in:** {', '.join(vuln['fix_versions'])}\n"
                            if "details" in vuln:
                                markdown += f"\n{vuln['details']}\n"
                            markdown += "\n---\n\n"
                    else:
                        markdown += "No vulnerabilities found.\n"
                    
                    result = subprocess.CompletedProcess(
                        args=cmd,
                        returncode=0,
                        stdout=markdown,
                        stderr=json_result.stderr
                    )
                except json.JSONDecodeError:
                    result = json_result
        
        # Write the output to file
        with open(output_path, "w") as f:
            f.write(result.stdout or "")
            if result.stderr:
                f.write("\n[ERROR] stderr output:\n")
                f.write(result.stderr)
            
            if result.returncode != 0:
                f.write("\n[WARNING] pip-audit completed with non-zero exit code")
        
        if result.returncode != 0:
            logging.warning(f"pip-audit exited with code {result.returncode} for {repo_name}")
        
        return result

    except Exception as e:
        error_msg = f"Error running pip-audit: {e}"
        logging.error(error_msg)
        with open(output_path, "w") as f:
            f.write(error_msg)
        return subprocess.CompletedProcess(
            args=cmd, returncode=1,
            stdout="", stderr=error_msg
        )


def run_npm_audit(repo_path, repo_name, report_dir):
    """Run npm audit for Node.js projects."""
    output_path = os.path.join(report_dir, f"{repo_name}_npm_audit.json")
    logging.info(f"Running npm audit for {repo_name}...")
    
    if not os.path.exists(os.path.join(repo_path, "package.json")):
        return None
        
    try:
        cmd = ["npm", "audit", "--json"]
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        
        with open(output_path, "w") as f:
            f.write(result.stdout)
            
        # Convert to markdown (handle both legacy 'advisories' and modern 'vulnerabilities' schemas)
        md_output = os.path.join(report_dir, f"{repo_name}_npm_audit.md")
        try:
            data = json.loads(result.stdout)
            with open(md_output, "w") as f:
                f.write(f"# npm Audit Report\n\n")
                f.write(f"**Repository:** {repo_name}\n\n")

                # Summary from metadata if available
                metadata = data.get('metadata') or {}
                vulns_summary = metadata.get('vulnerabilities') or {}
                if vulns_summary:
                    f.write("## Summary\n\n")
                    for sev, count in vulns_summary.items():
                        f.write(f"- {sev.title()}: {count}\n")
                    total = sum(vulns_summary.values())
                    f.write(f"- Total: {total}\n\n")

                # Legacy schema: 'advisories'
                if isinstance(data.get('advisories'), dict) and data['advisories']:
                    f.write("## Vulnerabilities\n\n")
                    for adv in data['advisories'].values():
                        f.write(f"### {adv.get('module_name','unknown')} ({adv.get('vulnerable_versions','unknown')})\n")
                        f.write(f"**Severity:** {adv.get('severity','unknown').title()}\n")
                        f.write(f"**Vulnerable Versions:** {adv.get('vulnerable_versions','unknown')}\n")
                        f.write(f"**Fixed In:** {adv.get('patched_versions','None')}\n")
                        f.write(f"**Title:** {adv.get('title','No title')}\n")
                        overview = adv.get('overview') or adv.get('recommendation') or 'No overview'
                        f.write(f"**Overview:** {overview}\n")
                        if adv.get('url'):
                            f.write(f"**More Info:** {adv['url']}\n")
                        f.write("\n---\n\n")

                # Modern schema: 'vulnerabilities' is a dict keyed by package
                elif isinstance(data.get('vulnerabilities'), dict) and data['vulnerabilities']:
                    f.write("## Vulnerabilities\n\n")
                    for pkg, vuln in data['vulnerabilities'].items():
                        severity = (vuln.get('severity') or 'unknown').title()
                        rng = vuln.get('range') or vuln.get('vulnerable_versions') or 'unknown'
                        fix = vuln.get('fixAvailable')
                        if isinstance(fix, dict):
                            fixed_in = f"{fix.get('name', pkg)}@{fix.get('version','unknown')}"
                        elif fix is True:
                            fixed_in = 'Update to latest'
                        else:
                            fixed_in = 'No fix available'

                        title = ' | '.join(sorted({(i.get('title') if isinstance(i, dict) else str(i)) for i in (vuln.get('via') or []) if i})) or 'No title'
                        nodes = vuln.get('nodes') or []
                        sample_paths = '\n'.join(f"  - `{n}`" for n in nodes[:5]) if nodes else '  - (paths not provided)'

                        f.write(f"### {pkg}\n")
                        f.write(f"**Severity:** {severity}\n")
                        f.write(f"**Vulnerable Range:** {rng}\n")
                        f.write(f"**Fixed In:** {fixed_in}\n")
                        f.write(f"**Title(s):** {title}\n")
                        f.write(f"**Sample Paths:**\n{sample_paths}\n")
                        f.write("\n---\n\n")
                else:
                    f.write("## No vulnerabilities found\n")

        except json.JSONDecodeError:
            with open(md_output, "w") as f:
                f.write("Error parsing npm audit output\n")
                f.write(result.stderr or "No error details available")
                
        return result
        
    except Exception as e:
        logging.error(f"Error running npm audit: {e}")
        with open(output_path, "w") as f:
            f.write(f"Error running npm audit: {e}")
        return None

def run_govulncheck(repo_path, repo_name, report_dir):
    """Run govulncheck for Go projects."""
    output_path = os.path.join(report_dir, f"{repo_name}_govulncheck.json")
    logging.info(f"Running govulncheck for {repo_name}...")
    
    if not os.path.exists(os.path.join(repo_path, "go.mod")):
        return None
        
    try:
        cmd = ["govulncheck", "-json", "./..."]
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        
        with open(output_path, "w") as f:
            f.write(result.stdout)
            
        # Convert to markdown
        md_output = os.path.join(report_dir, f"{repo_name}_govulncheck.md")
        with open(md_output, "w") as f:
            f.write(f"# Go Vulnerability Check Report\n\n")
            f.write(f"**Repository:** {repo_name}\n\n")
            
            if result.stdout.strip():
                try:
                    for line in result.stdout.splitlines():
                        if line.strip():
                            vuln = json.loads(line)
                            if vuln.get("Type") == "vuln":
                                f.write(f"## {vuln.get('OSV', 'Unknown')}\n")
                                f.write(f"**Module:** {vuln.get('PkgPath', 'Unknown')}\n")
                                f.write(f"**Version:** {vuln.get('FoundIn', 'Unknown')}\n")
                                f.write(f"**Fixed In:** {vuln.get('FixedIn', 'Not fixed')}\n")
                                f.write(f"**Details:** {vuln.get('Details', 'No details')}\n")
                                f.write("\n---\n\n")
                except json.JSONDecodeError:
                    f.write("Error parsing govulncheck output\n")
                    f.write(result.stderr or "No error details available")
            else:
                f.write("## No vulnerabilities found\n")
                
        return result
        
    except Exception as e:
        logging.error(f"Error running govulncheck: {e}")
        with open(output_path, "w") as f:
            f.write(f"Error running govulncheck: {e}")
        return None
    finally:
        # Clean up the temporary directory if the clone failed
        if temp_dir and os.path.exists(temp_dir) and not os.path.isdir(os.path.join(temp_dir, repo_name)):
            logging.debug(f"Cleaning up temporary directory: {temp_dir}")
            shutil.rmtree(temp_dir, ignore_errors=True)

def run_bundle_audit(repo_path, repo_name, report_dir):
    """Run bundle audit for Ruby projects."""
    output_path = os.path.join(report_dir, f"{repo_name}_bundle_audit.txt")
    logging.info(f"Running bundle audit for {repo_name}...")
    
    if not os.path.exists(os.path.join(repo_path, "Gemfile.lock")):
        return None
        
    try:
        cmd = ["bundle", "audit", "--update"]
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        
        with open(output_path, "w") as f:
            f.write(result.stdout)
            if result.stderr:
                f.write("\n=== STDERR ===\n")
                f.write(result.stderr)
                
        return result
        
    except Exception as e:
        logging.error(f"Error running bundle audit: {e}")
        with open(output_path, "w") as f:
            f.write(f"Error running bundle audit: {e}")
        return None

def run_dependency_check(repo_path, repo_name, report_dir):
    """
    Run OWASP Dependency-Check for Java projects.
    
    Args:
        repo_path: Path to the repository
        repo_name: Name of the repository
        report_dir: Directory to save the report
        
    Returns:
        str: Path to the generated report or None if not applicable
    """
    output_dir = os.path.join(report_dir, f"{repo_name}_dependency_check")
    output_path = os.path.join(output_dir, "dependency-check-report.json")
    logging.info(f"Running OWASP Dependency-Check for {repo_name}...")
    
    # Check for common Java build files
    java_project = any(
        os.path.exists(os.path.join(repo_path, f)) 
        for f in ["pom.xml", "build.gradle", "build.gradle.kts"]
    )
    if not java_project:
        return None
        
    try:
        # Skip if dependency-check is not installed
        # Prefer Python wrapper 'dependency-check' (dependency-check-py), fallback to shell script if present
        dc_bin = shutil.which("dependency-check") or shutil.which("dependency-check.sh")
        if not dc_bin:
            logging.info("OWASP Dependency-Check not found on PATH; skipping for this repository")
            return None
        os.makedirs(output_dir, exist_ok=True)
        # Common excludes to reduce noise and speed up
        excludes = [
            ".git/**", ".venv/**", "**/__pycache__/**", ".tox/**", "node_modules/**", "build/**", "dist/**"
        ]
        cmd = [dc_bin,
               "--project", repo_name,
               "--scan", repo_path,
               "--out", output_dir,
               "--format", "JSON",
               "--disableYarnAudit",
               "--disableNodeAudit",
               ]
        # Add excludes
        for pattern in excludes:
            cmd += ["--exclude", pattern]
        # Prefer not to fail the whole scan due to minor issues
        cmd += ["--disableAssembly"]
        
        # Ensure a cache/data directory for NVD to avoid repeated downloads
        env = os.environ.copy()
        data_dir = env.get("DC_DATA_DIR") or os.path.join(os.path.expanduser("~"), ".cache", "dependency-check")
        os.makedirs(data_dir, exist_ok=True)
        env["DC_DATA_DIR"] = data_dir
        
        logging.debug(f"Running Dependency-Check: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=60*20)
        
        # Convert to markdown if the report was generated
        if os.path.exists(output_path):
            md_output = os.path.join(report_dir, f"{repo_name}_dependency_check.md")
            try:
                with open(output_path, 'r') as f:
                    data = json.load(f)
                    
                with open(md_output, 'w') as f:
                    f.write(f"# OWASP Dependency-Check Report\n\n")
                    f.write(f"**Repository:** {repo_name}\n")
                    f.write(f"**Generated:** {data.get('projectInfo', {}).get('reportDate', 'Unknown')}\n\n")
                    
                    if 'dependencies' in data:
                        vuln_count = sum(1 for dep in data['dependencies'] 
                                      if 'vulnerabilities' in dep and dep['vulnerabilities'])
                        f.write(f"## Summary\n")
                        f.write(f"- **Total Dependencies:** {len(data['dependencies'])}\n")
                        f.write(f"- **Vulnerable Dependencies:** {vuln_count}\n\n")
                        
                        if vuln_count > 0:
                            f.write("## Vulnerable Dependencies\n\n")
                            for dep in data['dependencies']:
                                if 'vulnerabilities' in dep and dep['vulnerabilities']:
                                    f.write(f"### {dep.get('fileName', 'Unknown')}\n")
                                    f.write(f"**Version:** {dep.get('version', 'Unknown')}\n")
                                    f.write(f"**Vulnerabilities:** {len(dep['vulnerabilities'])}\n\n")
                                    
                                    for vuln in dep['vulnerabilities']:
                                        f.write(f"#### {vuln.get('name', 'Unknown')}\n")
                                        f.write(f"**Severity:** {vuln.get('severity', 'Unknown').title()}\n")
                                        f.write(f"**CVSS Score:** {vuln.get('cvssv3', {}).get('baseScore', 'N/A')}\n")
                                        f.write(f"**Description:** {vuln.get('description', 'No description')}\n")
                                        f.write(f"**Solution:** {vuln.get('solution', 'No solution provided')}\n")
                                        f.write("\n---\n\n")
                    else:
                        f.write("## No vulnerabilities found\n")
                        
            except Exception as e:
                logging.error(f"Error processing dependency-check report: {e}")
                with open(md_output, 'w') as f:
                    f.write(f"Error processing dependency-check report: {e}")
        
        return result
        
    except Exception as e:
        logging.error(f"Error running OWASP Dependency-Check: {e}")
        with open(os.path.join(report_dir, f"{repo_name}_dependency_check_error.txt"), 'w') as f:
            f.write(f"Error running OWASP Dependency-Check: {e}")
        return None

def write_code_snippet(f, finding):
    """Helper function to write code snippet with line numbers."""
    extra = finding.get('extra', {})
    if not ('lines' in extra and extra['lines']):
        return
    
    lang = extra['lines'][0].get('language', '')
    content = extra['lines'][0].get('content', '')
    start = int(finding.get('start', {}).get('line', 1)) - 1
    code_lines = [f"{i + start + 1}: {line}" for i, line in enumerate(content.split('\n'))]
    f.write(f"```{lang}\n")
    f.write("\n".join(code_lines))
    f.write("\n```\n\n")

def run_semgrep_scan(repo_path, repo_name, report_dir):
    """Run semgrep scan on the repository and save results."""
    output_path = os.path.join(report_dir, f"{repo_name}_semgrep.json")
    md_output = os.path.join(report_dir, f"{repo_name}_semgrep.md")
    logging.info(f"Running Semgrep scan for {repo_name}...")
    
    # Initialize cmd variable at function scope
    cmd = None
    
    # Ensure the report directory exists
    os.makedirs(report_dir, exist_ok=True)
    
    # Initialize result with failure state in case of early return
    result = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr=f"Repository directory not found or not accessible: {repo_path}"
    )
    
    # Check if repository directory exists and is accessible
    if not os.path.isdir(repo_path):
        error_msg = f"Repository directory not found or not accessible: {repo_path}"
        logging.error(error_msg)
        with open(md_output, 'w') as f:
            f.write(f"# Semgrep Scan Failed\n\n{error_msg}\n")
        return result
    
    try:
        # First, check if semgrep is installed
        if not shutil.which("semgrep"):
            raise RuntimeError("semgrep is not installed. Please install it with 'pip install semgrep'")
        
        # Run semgrep with JSON output
        cmd = [
            "semgrep", "scan",
            "--config", "p/security-audit",
            "--config", "p/ci",
            "--config", "p/owasp-top-ten",
            "--config", "p/secrets",
        ]
        # Auto-include local custom rules in semgrep-rules/
        try:
            project_root = os.path.dirname(os.path.abspath(__file__))
            rules_dir = os.path.join(project_root, "semgrep-rules")
            if os.path.isdir(rules_dir):
                for fname in os.listdir(rules_dir):
                    if fname.endswith((".yml", ".yaml")):
                        cmd += ["--config", os.path.join(rules_dir, fname)]
        except Exception as _semgrep_rules_err:
            logging.debug(f"Skipping custom semgrep rules due to error: {_semgrep_rules_err}")
        # Output and execution options
        cmd += [
            "--json",
            "--output", output_path,
            "--error",
            "--metrics", "off",
            "--quiet",
            "--timeout", "600"
        ]
        
        # Log semgrep version for diagnostics
        try:
            ver = subprocess.run(["semgrep", "--version"], capture_output=True, text=True)
            logging.debug(f"Semgrep version: {ver.stdout.strip() or ver.stderr.strip()}")
        except Exception:
            pass
        logging.debug(f"Running command: {' '.join(cmd)} in directory: {repo_path}")
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        
        # Check if output file was created, create empty results if not
        if not os.path.exists(output_path) and result.returncode == 0:
            with open(output_path, 'w') as f:
                json.dump({"results": []}, f)
        
        # Generate markdown report
        with open(md_output, 'w') as f:
            f.write(f"# Semgrep Scan Results\n\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if result.returncode in (0, 1):
                if os.path.exists(output_path):
                    try:
                        with open(output_path, 'r') as json_file:
                            semgrep_results = json.load(json_file)
                        
                        if 'results' in semgrep_results and semgrep_results['results']:
                            f.write("## Findings Summary\n\n")
                            f.write(f"Found {len(semgrep_results['results'])} potential issues.\n\n")
                            
                            # Group by severity
                            by_severity = {}
                            for finding in semgrep_results['results']:
                                severity = finding.get('extra', {}).get('severity', 'WARNING')
                                by_severity[severity] = by_severity.get(severity, 0) + 1
                            
                            if by_severity:
                                f.write("### Issues by Severity\n\n")
                                for severity, count in sorted(by_severity.items()):
                                    f.write(f"- **{severity.capitalize()}**: {count} issues\n")
                                f.write("\n")
                            
                            # Show top 5 findings
                            f.write("## Top 5 Findings\n\n")
                            for i, finding in enumerate(semgrep_results['results'][:5], 1):
                                path = finding.get('path', 'unknown')
                                line = finding.get('start', {}).get('line', '?')
                                message = finding.get('extra', {}).get('message', 'No message')
                                severity = finding.get('extra', {}).get('severity', 'WARNING')
                                
                                f.write(f"### {i}. {severity.upper()}: {message.splitlines()[0]}\n")
                                f.write(f"**File:** `{path}:{line}`  \n")
                                f.write(f"**Rule ID:** `{finding.get('check_id', 'unknown')}`  \n")
                                f.write(f"**Severity:** {severity.capitalize()}  \n\n")
                                
                                # Show code snippet if available
                                write_code_snippet(f, finding)
                                f.write("---\n\n")
                            
                            if len(semgrep_results['results']) > 5:
                                f.write(f"*And {len(semgrep_results['results']) - 5} more findings...*\n\n")
                        else:
                            f.write("## No issues found! ✅\n")
                    
                    except json.JSONDecodeError as e:
                        f.write("Error: Could not parse semgrep JSON output\n")
                        f.write("```\n")
                        f.write(str(e))
                        f.write("\n```\n")
                        return result
                else:
                    f.write("## No issues found! ✅\n")
            else:
                f.write("## Scan Failed\n\n")
                f.write("Semgrep encountered an error during the scan.\n\n")
                f.write("### Error Details\n")
                f.write("```\n")
                # Include both stderr and stdout for better diagnostics
                if result.stderr:
                    f.write(result.stderr)
                    f.write("\n")
                if result.stdout:
                    f.write(result.stdout)
                if not (result.stderr or result.stdout):
                    f.write("No error details available")
                f.write("\n```\n")
        
        return result
            
    except Exception as e:
        error_msg = f"Error running semgrep: {str(e)}"
        logging.error(error_msg)
        with open(md_output, 'w') as f:
            f.write(f"# Semgrep Scan Failed\n\n{error_msg}\n\n**Error Details:**\n```\n{traceback.format_exc()}\n```")
        return subprocess.CompletedProcess(
            args=cmd if cmd is not None else [],
            returncode=1,
            stdout="",
            stderr=error_msg
        )
def get_repo_contributors(session: requests.Session, repo_full_name: str) -> List[Dict[str, Any]]:
    """
    Get top 5 contributors for a repository with detailed information.
    
    Args:
        session: The requests session to use for the API call
        repo_full_name: Full name of the repository (e.g., 'owner/repo')
        
    Returns:
        List of contributor dictionaries with detailed information
    """
    try:
        logging.info(f"Fetching contributors for {repo_full_name}")
        
        # Get basic contributor information
        url = f"{config.GITHUB_API}/repos/{repo_full_name}/contributors?per_page=5&anon=false"
        response = session.get(url, headers=config.HEADERS)
        
        # Log response status and headers for debugging
        logging.debug(f"Response status: {response.status_code}")
        logging.debug(f"Response headers: {dict(response.headers)}")
        
        # Handle rate limiting before raising HTTP errors
        rate_limit = get_rate_limit_headers(response)
        remaining = int(rate_limit.get('remaining', 0))
        
        if remaining < 10:
            reset_time = int(rate_limit.get('reset', 0))
            wait_time = max(0, reset_time - int(time.time())) + 5  # Add 5 second buffer
            if wait_time > 0:
                logging.warning(f"Approaching rate limit. Remaining: {remaining}. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                # Retry the request after waiting
                response = session.get(url, headers=HEADERS)
                response.raise_for_status()
        else:
            response.raise_for_status()
        
        # Log response content for debugging
        response_text = response.text
        logging.debug(f"Response content (first 500 chars): {response_text[:500]}")
        
        try:
            contributors = response.json()
        except json.JSONDecodeError as json_err:
            logging.error(f"Failed to parse JSON response: {json_err}")
            logging.error(f"Response content: {response_text}")
            return []
            
        if not isinstance(contributors, list):
            logging.error(f"Unexpected response format for contributors. Expected list, got: {type(contributors)}")
            logging.error(f"Response content: {contributors}")
            return []
            
        # Get additional user details for each contributor
        detailed_contributors = []
        for contributor in contributors[:5]:  # Limit to top 5
            try:
                if 'login' in contributor:  # Skip anonymous contributors
                    user_url = f"{config.GITHUB_API}/users/{contributor['login']}"
                    user_response = session.get(user_url, headers=config.HEADERS)
                    user_response.raise_for_status()
                    user_data = user_response.json()
                    
                    # Combine basic contributor info with detailed user data
                    detailed_contributor = {
                        'login': contributor.get('login'),
                        'id': contributor.get('id'),
                        'contributions': contributor.get('contributions', 0),
                        'avatar_url': contributor.get('avatar_url', ''),
                        'html_url': contributor.get('html_url', ''),
                        'name': user_data.get('name', ''),
                        'company': user_data.get('company', ''),
                        'location': user_data.get('location', ''),
                        'public_repos': user_data.get('public_repos', 0),
                        'followers': user_data.get('followers', 0),
                        'created_at': user_data.get('created_at', ''),
                        'updated_at': user_data.get('updated_at', '')
                    }
                    detailed_contributors.append(detailed_contributor)
                    
                    # Be nice to the API
                    time.sleep(0.5)
                    
            except Exception as user_error:
                logging.warning(f"Error getting details for user {contributor.get('login')}: {user_error}")
                # Fall back to basic info if detailed fetch fails
                detailed_contributors.append(contributor)
        
        return detailed_contributors
        
    except requests.exceptions.HTTPError as http_err:
        if http_err.response.status_code == 403:  # Rate limited
            reset_time = int(http_err.response.headers.get('X-RateLimit-Reset', time.time() + 60))
            wait_time = max(0, reset_time - int(time.time())) + 5
            logging.warning(f"Rate limited. Waiting {wait_time} seconds...")
            time.sleep(wait_time)
            return get_repo_contributors(session, repo_full_name)  # Retry after waiting
        logging.error(f"HTTP error getting contributors for {repo_full_name}: {http_err}")
    except Exception as e:
        logging.error(f"Error getting contributors for {repo_full_name}: {e}", exc_info=True)
    
    return []

def get_repo_languages(session: requests.Session, repo_full_name: str) -> List[Tuple[str, int]]:
    """Get programming languages used in the repository, sorted by bytes of code."""
    try:
        url = f"{config.GITHUB_API}/repos/{repo_full_name}/languages"
        response = session.get(url, headers=config.HEADERS)
        response.raise_for_status()
        languages = response.json()
        return sorted(languages.items(), key=lambda x: x[1], reverse=True)[:5]
    except Exception as e:
        logging.error(f"Error getting languages for {repo_full_name}: {e}")
        return []

def analyze_commit_messages(session: requests.Session, repo_full_name: str) -> Dict[str, Any]:
    """Analyze commit messages to get last update date and top 5 commit reasons."""
    try:
        # Get the latest commit
        commits_url = f"{config.GITHUB_API}/repos/{repo_full_name}/commits?per_page=1"
        commits_response = session.get(commits_url, headers=config.HEADERS)
        commits_response.raise_for_status()
        
        last_commit = commits_response.json()[0] if commits_response.json() else None
        last_update = last_commit['commit']['committer']['date'] if last_commit else "Unknown"
        
        # Get recent commits for analysis (last 100)
        all_commits_url = f"{config.GITHUB_API}/repos/{repo_full_name}/commits?per_page=100"
        all_commits_response = session.get(all_commits_url, headers=config.HEADERS)
        all_commits_response.raise_for_status()
        
        # Simple commit message analysis
        commit_messages = [commit['commit']['message'] for commit in all_commits_response.json()]
        common_prefixes = defaultdict(int)
        
        for msg in commit_messages:
            # Extract first few words as a prefix
            words = msg.strip().split()
            if words:
                prefix = ' '.join(words[:3]).lower()
                common_prefixes[prefix] += 1
        
        top_commit_reasons = sorted(common_prefixes.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'last_update': last_update,
            'top_commit_reasons': top_commit_reasons
        }
    except Exception as e:
        logging.error(f"Error analyzing commits for {repo_full_name}: {e}")
        return {
            'last_update': 'Unknown',
            'top_commit_reasons': []
        }

def get_top_vulnerabilities(scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract top 5 vulnerabilities from scan results (Safety, npm audit, and Grype)."""
    vulnerabilities: List[Dict[str, Any]] = []

    # Process Safety results
    try:
        res = scan_results.get('safety')
        if res and res.stdout:
            safety_data = json.loads(res.stdout)
            for vuln in safety_data.get('vulnerabilities', [])[:10]:
                vulnerabilities.append({
                    'type': 'Python',
                    'name': vuln.get('package_name', 'Unknown'),
                    'severity': (vuln.get('severity') or 'unknown'),
                    'affected_versions': vuln.get('affected_versions', 'Unknown'),
                    'fixed_in': vuln.get('patched_versions', 'None'),
                    'remediation': f"Update to version {vuln.get('patched_versions', 'latest')}"
                })
    except Exception as e:
        logging.error(f"Error processing safety results: {e}")

    # Process npm audit results (legacy format; modern npm uses audit levels differently)
    try:
        res = scan_results.get('npm_audit')
        if res and res.stdout:
            npm_data = json.loads(res.stdout)
            advisories = (npm_data.get('advisories') or {}) if isinstance(npm_data, dict) else {}
            for adv in list(advisories.values())[:10]:
                vulnerabilities.append({
                    'type': 'Node',
                    'name': adv.get('module_name', 'Unknown'),
                    'severity': (adv.get('severity') or 'unknown'),
                    'affected_versions': adv.get('vulnerable_versions', 'Unknown'),
                    'fixed_in': ', '.join(adv.get('patched_versions', [])) if isinstance(adv.get('patched_versions'), list) else adv.get('patched_versions', 'None'),
                    'remediation': f"Update {adv.get('module_name','package')} to a fixed version"
                })
    except Exception as e:
        logging.error(f"Error processing npm audit results: {e}")

    # Process Trivy filesystem results (augment Top 5 with FS scan vulns)
    try:
        trivy = scan_results.get('trivy_fs') or {}
        results = trivy.get('Results', []) if isinstance(trivy, dict) else []
        kev_map = load_kev()
        epss_map = load_epss()
        for res in results:
            for v in res.get('Vulnerabilities', []) or []:
                vid = v.get('VulnerabilityID') or ''
                name = v.get('PkgName') or 'unknown'
                sev = (v.get('Severity') or 'unknown').lower()
                affected = v.get('InstalledVersion') or ''
                fixed_in = v.get('FixedVersion') or ''
                vulnerabilities.append({
                    'type': 'Trivy',
                    'name': name,
                    'severity': sev,
                    'affected_versions': affected,
                    'fixed_in': fixed_in,
                    'kev': bool(kev_map.get(vid)) if vid.startswith('CVE-') else False,
                    'epss': float(epss_map.get(vid, 0.0)) if vid.startswith('CVE-') else 0.0,
                    'remediation': f"Update {name} to a fixed version"
                })
    except Exception as e:
        logging.error(f"Error processing trivy fs results: {e}")

    # Process Grype repo results (JSON already loaded/enriched by caller if present)
    try:
        grype_data = scan_results.get('grype') or {}
        matches = grype_data.get('matches', []) if isinstance(grype_data, dict) else []
        for m in matches:
            v = m.get('vulnerability', {})
            vuln = m.get('vulnerability', {})
            art = m.get('artifact', {})
            sev = (vuln.get('severity') or 'Unknown').lower()
            pkg = art.get('name') or 'Unknown'
            ver = art.get('version') or 'Unknown'
            fix = vuln.get('fix', {}) or {}
            fix_versions = fix.get('versions') or []
            fixed_in = ', '.join(fix_versions) if isinstance(fix_versions, list) and fix_versions else fix.get('state', 'None')
            # Threat intel
            cve = vuln.get('id') or ''
            kev = False
            epss = None
            try:
                ti = m.get('_threat', {})
                kev = bool(ti.get('kev'))
                epss = ti.get('epss')
            except Exception:
                pass
            vulnerabilities.append({
                'type': 'Dependency',
                'name': pkg,
                'severity': sev,
                'affected_versions': ver,
                'fixed_in': fixed_in,
                'remediation': f"Update {pkg} to a fixed version" if fixed_in and fixed_in != 'None' else "Monitor vendor guidance",
                'cve': cve,
                'kev': kev,
                'epss': epss
            })
    except Exception as e:
        logging.error(f"Error processing grype results: {e}")

    # Deduplicate entries across sources
    seen = set()
    unique_vulns: List[Dict[str, Any]] = []
    for v in vulnerabilities:
        key = (
            (v.get('type') or '').lower(),
            (v.get('name') or '').lower(),
            (v.get('affected_versions') or '').lower(),
            (v.get('severity') or '').lower(),
            (v.get('fixed_in') or '').lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        unique_vulns.append(v)

    # Sort by KEV, EPSS, then severity (critical, high, moderate/medium, low, unknown)
    severity_order = {'critical': 0, 'high': 1, 'moderate': 2, 'medium': 2, 'low': 3, 'unknown': 4}
    def _rank(v: Dict[str, Any]):
        kev = 0 if not v.get('kev') else -1  # kev=True gets higher priority
        epss_rank = -float(v.get('epss') or 0.0)
        sev_rank = severity_order.get((v.get('severity') or 'unknown').lower(), 5)
        return (kev, epss_rank, sev_rank)
    unique_vulns.sort(key=_rank)

    return unique_vulns[:5]

# -------------------- Threat Intel (KEV / EPSS) --------------------

def _cache_dir() -> str:
    d = os.path.join('.cache')
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return d

@lru_cache(maxsize=1)
def load_kev() -> Dict[str, bool]:
    kev_map: Dict[str, bool] = {}
    url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    try:
        r = requests.get(url, timeout=10)
        if r.ok:
            data = r.json()
            for item in data.get('vulnerabilities', []):
                cve = item.get('cveID')
                if cve:
                    kev_map[cve] = True
            # cache file
            with open(os.path.join(_cache_dir(), 'kev.json'), 'w') as f:
                json.dump(list(kev_map.keys()), f)
    except Exception:
        # try cache
        try:
            with open(os.path.join(_cache_dir(), 'kev.json'), 'r') as f:
                ids = json.load(f)
                kev_map = {cve: True for cve in ids}
        except Exception:
            pass
    return kev_map

@lru_cache(maxsize=1)
def load_epss() -> Dict[str, float]:
    epss_map: Dict[str, float] = {}
    url = 'https://epss.cyentia.com/epss_scores-current.csv.gz'
    try:
        r = requests.get(url, timeout=10)
        if r.ok:
            import gzip
            import io
            buf = io.BytesIO(r.content)
            with gzip.open(buf, 'rt') as gz:
                for line in gz:
                    if line.startswith('cve,epss,percentile'):
                        continue
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        cve, epss = parts[0], float(parts[1] or 0.0)
                        epss_map[cve] = epss
            with open(os.path.join(_cache_dir(), 'epss.json'), 'w') as f:
                json.dump(epss_map, f)
    except Exception:
        # try cache
        try:
            with open(os.path.join(_cache_dir(), 'epss.json'), 'r') as f:
                epss_map = json.load(f)
        except Exception:
            pass
    return epss_map

def enrich_grype_with_threat_intel(grype_data: Dict[str, Any]) -> Dict[str, Any]:
    kev = load_kev()
    epss = load_epss()
    try:
        for m in grype_data.get('matches', []) or []:
            v = m.get('vulnerability', {})
            cve = v.get('id') or ''
            if not cve:
                continue
            m['_threat'] = {
                'kev': bool(kev.get(cve)),
                'epss': float(epss.get(cve, 0.0))
            }
    except Exception:
        pass
    return grype_data

# -------------------- Policy Loading and Evaluation --------------------

def _read_json(path: str) -> Any:
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return None

def load_policy() -> Dict[str, Any]:
    path = config.POLICY_PATH or 'policy.yaml'
    if not os.path.exists(path):
        return {}
    try:
        import yaml  # type: ignore
        with open(path, 'r') as f:
            return yaml.safe_load(f) or {}
    except Exception:
        # Very small fallback: attempt to parse limited subset is not safe; return empty
        return {}

def evaluate_policy(report_dir: str, repo_name: str) -> Tuple[bool, List[str]]:
    policy = load_policy()
    if not policy:
        # default: evaluate current Checkov gate only (High+ = fail)
        violations: List[str] = []
        chk_json = os.path.join(report_dir, f"{repo_name}_checkov.json")
        data = _read_json(chk_json) or {}
        failed = (data.get('results', {}) or {}).get('failed_checks', [])
        if any((i.get('severity') or '').upper() in ('CRITICAL','HIGH') for i in (failed or [])):
            violations.append("checkov: contains High or Critical failed checks")
        return (len(violations) == 0, violations)

    gates = (policy.get('gates') or {})
    violations: List[str] = []

    # Grype gates
    gcfg = gates.get('grype') or {}
    if gcfg:
        grype_json = os.path.join(report_dir, f"{repo_name}_grype_repo.json")
        gd = _read_json(grype_json) or {}
        # If enriched not present, enrich on the fly
        try:
            if gd:
                gd = enrich_grype_with_threat_intel(gd)
        except Exception:
            pass
        matches = gd.get('matches') or []
        if gcfg.get('require_no_kev', False):
            if any(bool(m.get('_threat',{}).get('kev')) for m in matches):
                violations.append("grype: KEV vulnerability present")
        max_epss = gcfg.get('max_epss')
        if isinstance(max_epss, (int,float)):
            if any(float(m.get('_threat',{}).get('epss') or 0.0) >= float(max_epss) for m in matches):
                violations.append(f"grype: EPSS >= {max_epss}")
        max_sev = (gcfg.get('max_severity') or '').lower()
        sev_rank = {'critical':4,'high':3,'medium':2,'low':1,'negligible':0}
        if max_sev in sev_rank:
            for m in matches:
                s = (m.get('vulnerability',{}).get('severity') or 'unknown').lower()
                if sev_rank.get(s, -1) >= sev_rank[max_sev]:
                    violations.append(f"grype: severity {s} >= {max_sev}")
                    break

    # Checkov gates
    ccfg = gates.get('checkov') or {}
    if ccfg:
        chk_json = os.path.join(report_dir, f"{repo_name}_checkov.json")
        data = _read_json(chk_json) or {}
        failed = (data.get('results', {}) or {}).get('failed_checks', [])
        counts = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0,'UNKNOWN':0}
        for i in failed or []:
            sev = (i.get('severity') or 'UNKNOWN').upper()
            if sev not in counts: sev = 'UNKNOWN'
            counts[sev]+=1
        max_sev = (ccfg.get('max_severity') or '').upper()
        order = {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1,'UNKNOWN':0}
        if max_sev in order:
            for sev, n in counts.items():
                if order[sev] >= order[max_sev] and n>0 and (sev in ('CRITICAL','HIGH','MEDIUM','LOW')):
                    violations.append(f"checkov: contains {sev} findings >= {max_sev}")
                    break
        mcounts = ccfg.get('max_counts') or {}
        for sev, limit in mcounts.items():
            s = sev.upper()
            try:
                lim = int(limit)
                if counts.get(s,0) > lim:
                    violations.append(f"checkov: {s} count {counts.get(s,0)} exceeds {lim}")
            except Exception:
                continue

    # Secrets gates
    scfg = gates.get('secrets') or {}
    if scfg:
        gl_json = os.path.join(report_dir, f"{repo_name}_gitleaks.json")
        secrets = _read_json(gl_json)
        total = len(secrets) if isinstance(secrets, list) else 0
        max_findings = scfg.get('max_findings')
        if isinstance(max_findings, int) and total > max_findings:
            violations.append(f"secrets: {total} findings > {max_findings}")

    # Semgrep gates
    sgcfg = gates.get('semgrep') or {}
    if sgcfg:
        sg_json = os.path.join(report_dir, f"{repo_name}_semgrep.json")
        data = _read_json(sg_json) or {}
        results = data.get('results', []) if isinstance(data, dict) else []
        # Map severities
        map_sev = {'ERROR':'high','WARNING':'medium','INFO':'low'}
        counts = {'high':0,'medium':0,'low':0}
        for r in results:
            sev = map_sev.get((r.get('extra',{}).get('severity') or '').upper())
            if sev: counts[sev]+=1
        max_sev = (sgcfg.get('max_severity') or '').lower()
        rank = {'critical':3,'high':2,'medium':1,'low':0}
        if max_sev in rank and counts:
            for sev, n in counts.items():
                if rank.get(sev, -1) >= rank[max_sev] and n>0:
                    violations.append(f"semgrep: contains {sev} findings >= {max_sev}")
                    break
        mcounts = sgcfg.get('max_counts') or {}
        for sev, limit in mcounts.items():
            try:
                if counts.get(sev.lower(),0) > int(limit):
                    violations.append(f"semgrep: {sev} count {counts.get(sev.lower(),0)} exceeds {limit}")
            except Exception:
                continue

    # Semgrep taint gates
    tcfg = gates.get('semgrep_taint') or {}
    if tcfg:
        st_json = os.path.join(report_dir, f"{repo_name}_semgrep_taint.json")
        data = _read_json(st_json) or {}
        flows = data.get('results', []) if isinstance(data, dict) else []
        max_flows = tcfg.get('max_flows')
        if isinstance(max_flows, int) and len(flows) > max_flows:
            violations.append(f"semgrep_taint: flows {len(flows)} exceeds {max_flows}")

    # Bandit gates (if present)
    bcfg = gates.get('bandit') or {}
    if bcfg:
        bj = os.path.join(report_dir, f"{repo_name}_bandit.json")
        bd = _read_json(bj) or {}
        results = bd.get('results', []) if isinstance(bd, dict) else []
        counts = {'HIGH':0,'MEDIUM':0,'LOW':0}
        for r in results:
            sev = (r.get('issue_severity') or '').upper()
            if sev in counts: counts[sev]+=1
        max_sev = (bcfg.get('max_severity') or '').upper()
        order = {'CRITICAL':3,'HIGH':2,'MEDIUM':1,'LOW':0}
        if max_sev in order:
            for sev, n in counts.items():
                if order.get(sev, -1) >= order[max_sev] and n>0:
                    violations.append(f"bandit: contains {sev} findings >= {max_sev}")
                    break
        mcounts = bcfg.get('max_counts') or {}
        for sev, limit in mcounts.items():
            try:
                if counts.get(sev.upper(),0) > int(limit):
                    violations.append(f"bandit: {sev} count {counts.get(sev.upper(),0)} exceeds {limit}")
            except Exception:
                continue

    # Trivy FS gates (if present)
    tvcfg = gates.get('trivy_fs') or {}
    if tvcfg:
        tj = os.path.join(report_dir, f"{repo_name}_trivy_fs.json")
        td = _read_json(tj) or {}
        results = td.get('Results', []) if isinstance(td, dict) else []
        counts = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0,'UNKNOWN':0}
        for res in results:
            for v in res.get('Vulnerabilities', []) or []:
                sev = (v.get('Severity') or 'UNKNOWN').upper()
                if sev not in counts: sev='UNKNOWN'
                counts[sev]+=1
        max_sev = (tvcfg.get('max_severity') or '').upper()
        order = {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1,'UNKNOWN':0}
        if max_sev in order:
            for sev, n in counts.items():
                if order[sev] >= order[max_sev] and n>0 and sev in order:
                    violations.append(f"trivy_fs: contains {sev} findings >= {max_sev}")
                    break
        mcounts = tvcfg.get('max_counts') or {}
        for sev, limit in mcounts.items():
            try:
                if counts.get(sev.upper(),0) > int(limit):
                    violations.append(f"trivy_fs: {sev} count {counts.get(sev.upper(),0)} exceeds {limit}")
            except Exception:
                continue

    return (len(violations) == 0, violations)

# -------------------- Contributor Attribution Helpers --------------------

def load_semgrep_results(path: str) -> List[dict]:
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        return data.get('results', []) if isinstance(data, dict) else []
    except Exception:
        return []

def load_grype_results(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return {}

@lru_cache(maxsize=2048)
def _blame_cache_key(repo_path: str, rel_path: str, line: int) -> str:
    return f"{rel_path}:{line}"

def blame_line(repo_local_path: str, rel_path: str, line: int) -> Dict[str, str]:
    try:
        cmd = ["git", "blame", "-L", f"{line},{line}", "--line-porcelain", rel_path]
        result = subprocess.run(cmd, cwd=repo_local_path, capture_output=True, text=True)
        if result.returncode != 0:
            return {"name": "unknown", "email": "", "raw": result.stderr.strip()}
        name, email = "unknown", ""
        for ln in result.stdout.splitlines():
            if ln.startswith("author "):
                name = ln[len("author ") :].strip()
            elif ln.startswith("author-mail "):
                email = ln[len("author-mail ") :].strip(" <>")
        return {"name": name or "unknown", "email": email, "raw": ""}
    except Exception as e:
        return {"name": "unknown", "email": "", "raw": str(e)}

def map_author_to_contributor(author_name: str, author_email: str, contributors: List[Dict[str, Any]]) -> str:
    name_l = (author_name or "").strip().lower()
    email_l = (author_email or "").strip().lower()
    for c in (contributors or [])[:10]:
        login = (c.get('login') or '').strip()
        if login and login.lower() in (name_l, email_l):
            return login
        if c.get('name') and c['name'].strip().lower() == name_l:
            return login or c['name']
    return author_name or "unknown"

MANIFEST_GLOBS = [
    "requirements.txt", "requirements.in", "Pipfile", "pyproject.toml",
    "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
    "go.mod", "Gemfile", "Gemfile.lock"
]

def _iter_manifest_files(repo_local_path: str) -> List[str]:
    found = []
    for root, _dirs, files in os.walk(repo_local_path):
        for fn in files:
            if fn in MANIFEST_GLOBS or fn.endswith((".lock",)):
                found.append(os.path.relpath(os.path.join(root, fn), repo_local_path))
    return found

def find_manifest_references(repo_local_path: str, package: str, version: Optional[str]) -> List[Tuple[str, int, str]]:
    refs: List[Tuple[str, int, str]] = []
    pk_re = re.compile(re.escape(package), re.IGNORECASE)
    ver_re = re.compile(re.escape(version)) if version else None
    for rel in _iter_manifest_files(repo_local_path):
        try:
            with open(os.path.join(repo_local_path, rel), 'r', errors='ignore') as f:
                for idx, line in enumerate(f, start=1):
                    if pk_re.search(line) and (ver_re.search(line) if ver_re else True):
                        disp = f"[dep] {rel}:{idx} {package}{('@'+version) if version else ''}"
                        refs.append((rel, idx, disp))
                        if len(refs) >= 3:
                            return refs
        except Exception:
            continue
    return refs

def get_last_commit_per_contributor(session: requests.Session, repo_full_name: str, contributors: List[Dict[str, Any]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for c in (contributors or [])[:5]:
        login = c.get('login')
        if not login:
            continue
        try:
            url = f"{config.GITHUB_API}/repos/{repo_full_name}/commits?author={login}&per_page=1"
            r = session.get(url, headers=config.HEADERS)
            if r.status_code == 200 and r.json():
                out[login] = r.json()[0]['commit']['author']['date']
        except Exception:
            continue
    return out

def aggregate_vulns_by_contributor(repo_local_path: str,
                                   semgrep_results: List[dict],
                                   grype_data: Dict[str, Any],
                                   contributors: List[Dict[str, Any]],
                                   blame_cap_semgrep: int = 200,
                                   blame_cap_grype: int = 100) -> Dict[str, Dict[str, Any]]:
    contrib_map: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "locations": [], "details": []})

    # Semgrep mapping
    seen = set()
    blamed = 0
    for res in semgrep_results:
        path = res.get('path')
        start = res.get('start', {}).get('line') or res.get('start', {}).get('lineNumber') or 0
        rule_id = (res.get('check_id') or res.get('extra', {}).get('id') or 'rule')
        if not (path and start):
            continue
        key = (path, int(start), str(rule_id))
        if key in seen:
            continue
        seen.add(key)
        if blamed >= blame_cap_semgrep:
            break
        blamed += 1
        author = blame_line(repo_local_path, path, int(start))
        who = map_author_to_contributor(author.get('name', ''), author.get('email', ''), contributors)
        contrib_map[who]["count"] += 1
        loc = f"{path}:{start}"
        if len(contrib_map[who]["locations"]) < 3 and loc not in contrib_map[who]["locations"]:
            contrib_map[who]["locations"].append(loc)
        # Details
        rule_name = res.get('extra', {}).get('message', '') or str(rule_id)
        contrib_map[who]["details"].append(f"- Semgrep: {loc} ({rule_name})")

    # Grype mapping
    matches = (grype_data.get('matches') or []) if isinstance(grype_data, dict) else []
    blamed_g = 0
    for m in matches:
        if blamed_g >= blame_cap_grype:
            break
        vuln = m.get('vulnerability', {})
        art = m.get('artifact', {})
        pkg = art.get('name') or art.get('pkg', {}).get('name') or ''
        ver = art.get('version') or ''
        if not pkg:
            continue
        refs = find_manifest_references(repo_local_path, pkg, ver)
        for (rel, line_no, disp) in refs:
            if blamed_g >= blame_cap_grype:
                break
            blamed_g += 1
            author = blame_line(repo_local_path, rel, int(line_no))
            who = map_author_to_contributor(author.get('name', ''), author.get('email', ''), contributors)
            contrib_map[who]["count"] += 1
            if len(contrib_map[who]["locations"]) < 3 and disp not in contrib_map[who]["locations"]:
                contrib_map[who]["locations"].append(disp)
            vid = vuln.get('id') or vuln.get('cve') or ''
            sev = vuln.get('severity') or ''
            contrib_map[who]["details"].append(f"- Grype: {disp} {pkg}{('@'+ver) if ver else ''} {vid} {('Severity: '+sev) if sev else ''}")

    return contrib_map

def build_contributor_vuln_table(session: requests.Session,
                                 repo_full_name: str,
                                 repo_local_path: str,
                                 report_dir: str,
                                 repo_name: str) -> Tuple[List[List[str]], Dict[str, str]]:
    # Load contributors
    contributors = get_repo_contributors(session, repo_full_name)
    # Load Semgrep/Grype outputs
    semgrep_json = os.path.join(report_dir, f"{repo_name}_semgrep.json")
    grype_json = os.path.join(report_dir, f"{repo_name}_grype_repo.json")
    semgrep_results = load_semgrep_results(semgrep_json)
    grype_results = load_grype_results(grype_json)
    # Aggregate
    contrib_map = aggregate_vulns_by_contributor(repo_local_path, semgrep_results, grype_results, contributors)
    # Last commit per contributor
    last_commits = get_last_commit_per_contributor(session, repo_full_name, contributors)
    # Build rows for the top 5 contributors by contributions
    rows: List[List[str]] = []
    details_md: Dict[str, str] = {}
    top5 = (contributors or [])[:5]
    for c in top5:
        login = c.get('login') or (c.get('name') or 'unknown')
        total_commits = str(c.get('contributions', '0'))
        last_commit = last_commits.get(login, 'Unknown')
        stats = contrib_map.get(login) or contrib_map.get(c.get('name') or '') or {"count": 0, "locations": [], "details": []}
        count = str(stats["count"]) if isinstance(stats.get("count"), int) else str(stats.get("count", 0))
        locs = "; ".join(stats["locations"]) if stats.get("locations") else "—"
        rows.append([login, total_commits, last_commit, count, locs])
        # Details md
        if stats.get("details"):
            details_md[login] = "\n".join(stats["details"][:50])
        else:
            details_md[login] = "(No mapped findings)"
    return rows, details_md

# -------------------- Terraform Pre-Deploy Section --------------------

def build_tf_predeploy_section(report_dir: str, repo_name: str) -> str:
    """Build a Terraform Pre-Deploy section using Checkov JSON results.

    Returns a markdown string or empty string if no Checkov JSON is available.
    """
    checkov_json = os.path.join(report_dir, f"{repo_name}_checkov.json")
    if not os.path.exists(checkov_json):
        return ""
    try:
        with open(checkov_json, 'r') as f:
            data = json.load(f)
    except Exception:
        return ""

    results = (data or {}).get('results', {})
    failed = results.get('failed_checks', []) or []
    # Severity counts
    sev_counts = {"CRITICAL":0, "HIGH":0, "MEDIUM":0, "LOW":0, "UNKNOWN":0}
    for item in failed:
        sev = (item.get('severity') or 'UNKNOWN').upper()
        if sev not in sev_counts:
            sev = 'UNKNOWN'
        sev_counts[sev] += 1
    gate_fail = (sev_counts['CRITICAL'] > 0) or (sev_counts['HIGH'] > 0)
    gate = "FAIL" if gate_fail else "PASS"

    # Deduplicate and sort top items
    def _sev_rank(s: str) -> int:
        s = (s or 'UNKNOWN').upper()
        order = {"CRITICAL":0, "HIGH":1, "MEDIUM":2, "LOW":3, "UNKNOWN":4}
        return order.get(s, 5)
    seen = set()
    unique_failed = []
    for it in failed:
        key = (
            (it.get('check_id') or '').lower(),
            (it.get('resource') or '').lower(),
            (it.get('file_path') or '').lower(),
            str(it.get('file_line_range') or '')
        )
        if key in seen:
            continue
        seen.add(key)
        unique_failed.append(it)
    unique_failed.sort(key=lambda x: (_sev_rank(x.get('severity')), (x.get('file_path') or '')))

    # Build Top table (up to 10)
    md = []
    md.append("## Terraform Pre-Deploy\n")
    md.append(f"**Gate:** {gate} (Critical: {sev_counts['CRITICAL']}, High: {sev_counts['HIGH']}, Medium: {sev_counts['MEDIUM']}, Low: {sev_counts['LOW']})\n\n")
    md.append("### Summary of Failed Checks (Top 10)\n\n")
    md.append("| Severity | Check ID | Resource | File:Line |\n")
    md.append("|---|---|---|---|\n")
    for it in unique_failed[:10]:
        sev = (it.get('severity') or 'UNKNOWN').upper()
        chk = it.get('check_id', 'UNKNOWN')
        res = it.get('resource', 'resource')
        file_path = it.get('file_path', 'unknown')
        lines = it.get('file_line_range') or []
        line_disp = f"{file_path}{(':' + '-'.join(map(str, lines))) if lines else ''}"
        guide = it.get('guideline') or ''
        chk_disp = f"[{chk}]({guide})" if guide else chk
        md.append(f"| {sev} | {chk_disp} | {res} | {line_disp} |\n")
    md.append("\n")

    # Grouped remediation tasks
    md.append("### Required Remediation Tasks (Grouped)\n\n")
    groups = {
        'Security': [],
        'Network': [],
        'IAM': [],
        'Logging/Monitoring': [],
        'Data Protection': [],
        'Compliance/Tagging': [],
    }
    def _assign_group(name: str) -> str:
        s = (name or '').lower()
        if any(k in s for k in ['encrypt', 'kms', 'public access block', 'versioning']):
            return 'Security'
        if any(k in s for k in ['security group', 'ingress', 'egress', 'cidr', 'public']):
            return 'Network'
        if any(k in s for k in ['policy', 'role', 'wildcard', 'iam', 'principal']):
            return 'IAM'
        if any(k in s for k in ['cloudtrail', 'log', 'retention', 'config']):
            return 'Logging/Monitoring'
        if any(k in s for k in ['s3 bucket policy', 'storage_encrypted', 'rds', 'db']):
            return 'Data Protection'
        if any(k in s for k in ['tag', 'owner', 'environment', 'cost']):
            return 'Compliance/Tagging'
        return 'Security'
    for it in unique_failed:
        name = it.get('check_name') or it.get('check_id') or ''
        grp = _assign_group(name)
        res = it.get('resource', 'resource')
        file_path = it.get('file_path', 'unknown')
        lines = it.get('file_line_range') or []
        md_line = f"- {name} on {res} ({file_path}{':' + '-'.join(map(str, lines)) if lines else ''})"
        groups[grp].append(md_line)
    for gname, items in groups.items():
        if not items:
            continue
        md.append(f"#### {gname}\n\n")
        md.extend([i + "\n" for i in items[:20]])
        md.append("\n")

    # Collapsible details
    md.append("### Detailed Remediation Guidance\n\n")
    for it in unique_failed[:50]:
        chk = it.get('check_id', 'UNKNOWN')
        name = it.get('check_name', '')
        res = it.get('resource', 'resource')
        file_path = it.get('file_path', 'unknown')
        lines = it.get('file_line_range') or []
        guide = it.get('guideline') or ''
        md.append(f"<details><summary>{chk}: {name}</summary>\n\n")
        md.append(f"- Resource: {res}\n")
        md.append(f"- File: {file_path}{(':' + '-'.join(map(str, lines))) if lines else ''}\n")
        if guide:
            md.append(f"- Guideline: {guide}\n")
        # Heuristic fix hint
        lower = (name or '').lower()
        if 'encrypt' in lower or 'kms' in lower:
            md.append("- How to fix: enable encryption at rest (e.g., KMS or SSE where applicable).\n")
        elif 'public' in lower or 'ingress' in lower or 'egress' in lower or 'cidr' in lower:
            md.append("- How to fix: restrict network exposure (tighten CIDRs, remove public access).\n")
        elif 'policy' in lower or 'iam' in lower or 'wildcard' in lower:
            md.append("- How to fix: restrict IAM policies (avoid wildcards, least privilege).\n")
        elif 'log' in lower or 'trail' in lower or 'retention' in lower:
            md.append("- How to fix: ensure logging/monitoring is enabled with appropriate retention.\n")
        elif 'tag' in lower:
            md.append("- How to fix: add required tags (owner, environment, cost-center).\n")
        else:
            md.append("- How to fix: update resource configuration per guideline.\n")
        md.append("\n</details>\n\n")

    # Hygiene & Readiness
    md.append("### Configuration Hygiene Checklist\n\n")
    md.append("- terraform fmt and terraform validate pass\n")
    md.append("- Provider and module versions pinned\n")
    md.append("- .terraform.lock.hcl committed\n")
    md.append("- Remote backend state encryption enabled\n")
    md.append("- Sensitive variables sourced from secrets manager (not plaintext)\n")
    md.append("- Tagging standards (owner, env, cost-center) applied\n\n")

    md.append("### Deployment Readiness Criteria\n\n")
    md.append("- 0 Critical/High failed checks from Checkov\n")
    md.append("- No public exposure of critical resources\n")
    md.append("- Encryption-at-rest enabled for storage resources\n")
    md.append("- Logging/monitoring enabled where applicable\n")

    return "".join(md)


def generate_summary_report(repo_name: str, repo_url: str, requirements_path: str, 
                          safety_result: subprocess.CompletedProcess,
                          pip_audit_result: subprocess.CompletedProcess,
                          npm_audit_result: subprocess.CompletedProcess,
                          govulncheck_result: subprocess.CompletedProcess,
                          bundle_audit_result: subprocess.CompletedProcess,
                          dependency_check_result: subprocess.CompletedProcess,
                          semgrep_result: subprocess.CompletedProcess,
                          semgrep_taint_result: Optional[subprocess.CompletedProcess],
                          checkov_result: Optional[subprocess.CompletedProcess],
                          gitleaks_result: Optional[subprocess.CompletedProcess],
                          bandit_result: Optional[subprocess.CompletedProcess],
                          trivy_fs_result: Optional[subprocess.CompletedProcess],
                          repo_local_path: str,
                          report_dir: str,
                          repo_full_name: str = "") -> None:
    """Generate a summary report of all scan results."""
    summary_path = os.path.join(report_dir, f"{repo_name}_summary.md")
    
    def get_scan_status(result):
        if not result:
            return "Not run"
        if result.returncode == 0:
            return "✅ Success (No issues found)"
        elif result.returncode == 1:
            return "⚠️  Issues found"
        return f"❌ Error (Code: {result.returncode})"
    
    try:
        with open(summary_path, 'w') as f:
            f.write(f"# Security Scan Summary\n\n")
            f.write(f"**Repository:** [{repo_name}]({repo_url})\n")
            f.write(f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Scan Summary Table
            f.write("## Scan Summary\n\n")
            # Derive Bandit and Trivy statuses from JSON outputs (return codes may be 0 even with findings)
            bandit_status = "Not run"
            try:
                bandit_json = os.path.join(report_dir, f"{repo_name}_bandit.json")
                if os.path.exists(bandit_json):
                    bd = json.load(open(bandit_json))
                    results = bd.get('results', []) if isinstance(bd, dict) else []
                    bandit_status = "✅ Success (No issues found)" if not results else "⚠️  Issues found"
            except Exception:
                bandit_status = get_scan_status(bandit_result)

            trivy_status = "Not run"
            try:
                trivy_json = os.path.join(report_dir, f"{repo_name}_trivy_fs.json")
                if os.path.exists(trivy_json):
                    td = json.load(open(trivy_json))
                    results = td.get('Results', []) if isinstance(td, dict) else []
                    total = 0
                    for res in results:
                        vulns = res.get('Vulnerabilities', []) or []
                        total += len(vulns)
                    trivy_status = "✅ Success (No issues found)" if total == 0 else "⚠️  Issues found"
            except Exception:
                trivy_status = get_scan_status(trivy_fs_result)
            f.write("| Tool | Status |\n")
            f.write("|------|--------|\n")
            f.write(f"| Safety | {get_scan_status(safety_result)} |\n")
            f.write(f"| pip-audit | {get_scan_status(pip_audit_result)} |\n")
            f.write(f"| npm audit | {get_scan_status(npm_audit_result)} |\n")
            f.write(f"| govulncheck | {get_scan_status(govulncheck_result)} |\n")
            f.write(f"| bundle audit | {get_scan_status(bundle_audit_result)} |\n")
            f.write(f"| OWASP Dependency-Check | {get_scan_status(dependency_check_result)} |\n")
            f.write(f"| Semgrep | {get_scan_status(semgrep_result)} |\n")
            f.write(f"| Semgrep (taint) | {get_scan_status(semgrep_taint_result)} |\n")
            f.write(f"| Checkov (Terraform) | {get_scan_status(checkov_result)} |\n")
            f.write(f"| Gitleaks (Secrets) | {get_scan_status(gitleaks_result)} |\n")
            f.write(f"| Bandit (Python) | {bandit_status} |\n")
            f.write(f"| Trivy (fs) | {trivy_status} |\n")

            # Policy Gate evaluation (if policy file present)
            passed, violations = evaluate_policy(report_dir, repo_name)
            gate_status = "PASS" if passed else "FAIL"
            f.write(f"| Policy Gate | {gate_status} |\n\n")
            # Compact Threat Intel counts just under the summary table
            try:
                grype_repo_json = os.path.join(report_dir, f"{repo_name}_grype_repo.json")
                if os.path.exists(grype_repo_json):
                    with open(grype_repo_json, 'r') as gf:
                        grype_data = json.load(gf)
                    grype_data = enrich_grype_with_threat_intel(grype_data)
                    matches = grype_data.get('matches', []) if isinstance(grype_data, dict) else []
                    kev_mapped = sum(1 for m in matches if (m.get('_threat') or {}).get('kev'))
                    epss_mapped = sum(1 for m in matches if isinstance((m.get('_threat') or {}).get('epss'), (int, float)) and (m.get('_threat') or {}).get('epss') > 0)
                    f.write(f"- Threat Intel: KEV mapped {kev_mapped}, EPSS mapped {epss_mapped}\n\n")
            except Exception:
                pass
            
            # Syft status based on presence of SBOMs
            syft_repo_path = os.path.join(report_dir, f"{repo_name}_syft_repo.json")
            syft_image_path = os.path.join(report_dir, f"{repo_name}_syft_image.json")
            syft_status = "Not run"
            if os.path.exists(syft_repo_path) or os.path.exists(syft_image_path):
                syft_status = "✅ Generated"
            f.write(f"| Syft SBOM | {syft_status} |\n\n")
            # Small Policy link for reviewers
            try:
                f.write(f"Policy: [policy.yaml](../../policy.yaml)\n\n")
            except Exception:
                pass

            # Grype status based on presence of JSON reports
            grype_repo_path = os.path.join(report_dir, f"{repo_name}_grype_repo.json")
            grype_image_path = os.path.join(report_dir, f"{repo_name}_grype_image.json")
            grype_status = "Not run"
            if os.path.exists(grype_repo_path) or os.path.exists(grype_image_path):
                grype_status = "✅ Generated"
                if getattr(config, 'VEX_FILES', []):
                    grype_status += " (VEX applied)"
            f.write(f"| Grype Vulnerabilities | {grype_status} |\n\n")
            
            # Detailed Reports Section
            f.write("## Detailed Reports\n\n")
            f.write("| Report | Link |\n")
            f.write("|--------|------|\n")
            report_map = {
                "Safety": f"{repo_name}_safety.txt",
                "pip-audit": f"{repo_name}_pip_audit.md",
                "npm audit": f"{repo_name}_npm_audit.md",
                "govulncheck": f"{repo_name}_govulncheck.md",
                "bundle audit": f"{repo_name}_bundle_audit.txt",
                "OWASP DC": f"{repo_name}_dependency_check.md",
                "Semgrep": f"{repo_name}_semgrep.md",
                "Semgrep (taint)": f"{repo_name}_semgrep_taint.md",
            }
            # Dagda links removed
            # Include Syft SBOMs
            report_map["Syft SBOM (repo)"] = f"{repo_name}_syft_repo.json"
            report_map["Syft SBOM (image)"] = f"{repo_name}_syft_image.json"
            # Include Grype reports
            report_map["Grype (repo)"] = f"{repo_name}_grype_repo.json"
            report_map["Grype (image)"] = f"{repo_name}_grype_image.json"
            # Include Checkov report
            report_map["Checkov (Terraform)"] = f"{repo_name}_checkov.md"
            # Include Gitleaks
            report_map["Gitleaks (secrets)"] = f"{repo_name}_gitleaks.md"
            # Bandit & Trivy FS reports
            report_map["Bandit (Python)"] = f"{repo_name}_bandit.md"
            report_map["Trivy (fs)"] = f"{repo_name}_trivy_fs.md"
            for label, filename in report_map.items():
                path = os.path.join(report_dir, filename)
                if os.path.exists(path):
                    f.write(f"| {label} | [{filename}](./{filename}) |\n")
                else:
                    f.write(f"| {label} | Not generated |\n")
            f.write("\n")
            # VEX files used (if any)
            if getattr(config, 'VEX_FILES', []):
                f.write("### VEX files used\n\n")
                for vf in config.VEX_FILES:
                    f.write(f"- {vf}\n")
                f.write("\n")

            # Threat Intel summary (KEV/EPSS mapping coverage)
            try:
                grype_repo_json = os.path.join(report_dir, f"{repo_name}_grype_repo.json")
                if os.path.exists(grype_repo_json):
                    with open(grype_repo_json, 'r') as gf:
                        grype_data = json.load(gf)
                    # Ensure enrichment so _threat is present
                    grype_data = enrich_grype_with_threat_intel(grype_data)
                    matches = grype_data.get('matches', []) if isinstance(grype_data, dict) else []
                    kev_mapped = 0
                    epss_mapped = 0
                    unmapped = 0
                    for m in matches:
                        thr = m.get('_threat') or {}
                        if thr.get('kev'):
                            kev_mapped += 1
                        if isinstance(thr.get('epss'), (int, float)) and thr.get('epss') > 0:
                            epss_mapped += 1
                        # Consider unmapped where no CVE id or missing _threat entirely
                        vul_id = (m.get('vulnerability', {}) or {}).get('id') or ''
                        if not thr or not vul_id.startswith('CVE-'):
                            unmapped += 1
                    f.write("## Threat Intel\n\n")
                    f.write(f"- KEV mapped: {kev_mapped}\n")
                    f.write(f"- EPSS mapped: {epss_mapped}\n")
                    f.write(f"- Unmapped (check identifiers/aliases): {unmapped}\n\n")
            except Exception as e:
                logging.debug(f"Threat Intel summary unavailable: {e}")

            # Terraform Pre-Deploy (from Checkov)
            try:
                tf_predeploy_md = build_tf_predeploy_section(report_dir, repo_name)
                if tf_predeploy_md:
                    f.write(tf_predeploy_md)
                    f.write("\n")
            except Exception as e:
                logging.error(f"Failed to build Terraform Pre-Deploy section: {e}")

            # Policy Gate details
            try:
                passed, violations = evaluate_policy(report_dir, repo_name)
                f.write("## Policy Gate\n\n")
                f.write(f"Status: {'PASS' if passed else 'FAIL'}\n\n")
                if violations:
                    f.write("### Violations\n\n")
                    for v in violations[:20]:
                        f.write(f"- {v}\n")
                    f.write("\n")
                else:
                    f.write("No violations detected under current policy.\n\n")
            except Exception as e:
                logging.error(f"Failed to evaluate policy: {e}")

            # Secrets Findings (from Gitleaks)
            try:
                gitleaks_json = os.path.join(report_dir, f"{repo_name}_gitleaks.json")
                if os.path.exists(gitleaks_json):
                    with open(gitleaks_json, 'r') as gf:
                        leaks_data = json.load(gf)
                    findings = leaks_data if isinstance(leaks_data, list) else []
                    f.write("## Secrets Findings (Gitleaks)\n\n")
                    f.write(f"Total findings: {len(findings)}\n\n")
                    if findings:
                        f.write("| Rule | File:Line | Description |\n")
                        f.write("|------|-----------|-------------|\n")
                        for item in findings[:10]:
                            rule = item.get('rule','')
                            file = item.get('file','')
                            line = item.get('line','')
                            desc = item.get('description','')
                            f.write(f"| {rule} | {file}:{line} | {desc} |\n")
                        f.write("\n")
                        f.write("Remediation: rotate and revoke exposed credentials, invalidate tokens, re-issue keys, and purge secrets from history where possible.\n\n")
            except Exception as e:
                logging.error(f"Failed to build Secrets Findings section: {e}")
            
            # Exploitable Flows (from Semgrep taint)
            try:
                semgrep_taint_json = os.path.join(report_dir, f"{repo_name}_semgrep_taint.json")
                if os.path.exists(semgrep_taint_json):
                    with open(semgrep_taint_json, 'r') as sf:
                        taint = json.load(sf)
                    flows = taint.get('results', []) if isinstance(taint, dict) else []
                    f.write("## Exploitable Flows (Semgrep Taint)\n\n")
                    if not flows:
                        f.write("No exploitable flows found.\n\n")
                    else:
                        for r in flows[:5]:
                            path = r.get('path','unknown')
                            msg = r.get('extra',{}).get('message','')
                            start = r.get('start',{}).get('line')
                            end = r.get('end',{}).get('line')
                            f.write(f"- {path}:{start}-{end} — {msg}\n")
                        f.write("\n")
            except Exception as e:
                logging.error(f"Failed to build Exploitable Flows section: {e}")
            
            # Repository Metadata
            if repo_full_name and config.GITHUB_TOKEN:
                try:
                    session = make_session()
                    
                    # 1. Get top contributors
                    contributors = get_repo_contributors(session, repo_full_name)
                    
                    # 2. Get top languages
                    languages = get_repo_languages(session, repo_full_name)
                    
                    # 3. Get commit analysis
                    commit_analysis = analyze_commit_messages(session, repo_full_name)
                    
                    # 4. Get top vulnerabilities
                    scan_results = {
                        'safety': safety_result,
                        'npm_audit': npm_audit_result,
                        'pip_audit': pip_audit_result
                    }
                    # Optionally include Grype (repo) results if present
                    try:
                        grype_repo_json = os.path.join(report_dir, f"{repo_name}_grype_repo.json")
                        if os.path.exists(grype_repo_json):
                            with open(grype_repo_json, 'r') as gf:
                                grype_data = json.load(gf)
                                # Enrich with KEV/EPSS and store
                                grype_data = enrich_grype_with_threat_intel(grype_data)
                                scan_results['grype'] = grype_data
                    except Exception as _e:
                        logging.debug(f"Could not load/enrich Grype results for top vulnerabilities: {_e}")
                    # Include Trivy FS results if present
                    try:
                        trivy_fs_json = os.path.join(report_dir, f"{repo_name}_trivy_fs.json")
                        if os.path.exists(trivy_fs_json):
                            with open(trivy_fs_json, 'r') as tf:
                                trivy_data = json.load(tf)
                                scan_results['trivy_fs'] = trivy_data
                    except Exception as _e:
                        logging.debug(f"Could not load Trivy fs results for top vulnerabilities: {_e}")
                    top_vulnerabilities = get_top_vulnerabilities(scan_results)
                    
                    # Write repository metadata section
                    f.write("## Repository Information\n\n")
                    
                    # Top Contributors
                    f.write("### Top 5 Contributors\n\n")
                    try:
                        # Build contributor stats table with vulnerability attribution
                        contributor_rows, contributor_details = build_contributor_vuln_table(
                            session=session,
                            repo_full_name=repo_full_name,
                            repo_local_path=repo_local_path,
                            report_dir=report_dir,
                            repo_name=repo_name
                        )
                        f.write("| Contributor | Total Number of Commits | Timestamp of Last Commit | Number of Exploitable Vulnerabilities Introduced by Contributor | Exploitable Code Location |\n")
                        f.write("|---|---:|---|---:|---|\n")
                        for row in contributor_rows:
                            f.write("| " + " | ".join(row) + " |\n")
                        f.write("\n")
                        # Collapsible details by contributor
                        for login, details_md in contributor_details.items():
                            f.write(f"<details><summary>Details for {login}</summary>\n\n")
                            f.write(details_md)
                            f.write("\n</details>\n\n")
                    except Exception as e:
                        logging.error(f"Failed to build contributor table: {e}")
                        f.write("(Failed to compute contributor attribution)\n\n")
                        
                    f.write("\n")
                    
                    # Top Languages
                    f.write("### Top 5 Languages\n\n")
                    if languages:
                        for lang, bytes_count in languages:
                            f.write(f"- {lang}: {bytes_count:,} bytes\n")
                    else:
                        f.write("No language data available\n")
                    f.write("\n")
                    
                    # Last Update and Commit Analysis
                    f.write("### Recent Activity\n\n")
                    f.write(f"**Last Updated:** {commit_analysis['last_update']}\n\n")
                    
                    f.write("**Top 5 Commit Patterns:**\n")
                    if commit_analysis['top_commit_reasons']:
                        for pattern, count in commit_analysis['top_commit_reasons']:
                            f.write(f"- `{pattern}` ({count} commits)\n")
                    else:
                        f.write("No commit data available\n")
                    f.write("\n")
                    
                    # Top Vulnerabilities
                    f.write("### Top 5 Vulnerabilities\n\n")
                    if top_vulnerabilities:
                        f.write("| Type | Package | Severity | Exploitability | Affected | Fixed In | Remediation |\n")
                        f.write("|------|---------|----------|----------------|-----------|-----------|-------------|\n")
                        for vuln in top_vulnerabilities:
                            # Visible badges in package name (kept) and a dedicated column
                            name_badged = vuln['name']
                            kev = vuln.get('kev')
                            epss = vuln.get('epss')
                            badges = []
                            if kev:
                                badges.append("[KEV]")
                            if isinstance(epss, (int, float)) and epss > 0:
                                badges.append(f"(EPSS: {epss:.2f})")
                            if badges:
                                name_badged = f"{name_badged} {' '.join(badges)}"

                            # Exploitability column value
                            expl_parts = []
                            if kev:
                                expl_parts.append("[KEV]")
                            if isinstance(epss, (int, float)) and epss > 0:
                                expl_parts.append(f"EPSS: {epss:.2f}")
                            expl_col = " ".join(expl_parts) if expl_parts else "—"

                            f.write(
                                f"| {vuln['type']} | {name_badged} | {vuln['severity']} | {expl_col} | "
                                f"{vuln['affected_versions']} | {vuln['fixed_in']} | {vuln['remediation']} |\n"
                            )
                        # Legend for badges
                        f.write("\n> Legend: [KEV] = Known Exploited Vulnerability; EPSS = Exploit Prediction Scoring System probability.\n\n")

                        # Threat Intel Diagnostics for Top 5
                        try:
                            f.write("#### Threat Intel Diagnostics\n\n")
                            f.write("| Package | KEV | EPSS | Notes |\n")
                            f.write("|---------|-----|------|-------|\n")
                            for vuln in top_vulnerabilities:
                                kev = vuln.get('kev')
                                epss = vuln.get('epss')
                                kev_cell = "✅" if kev else "—"
                                if isinstance(epss, (int, float)):
                                    epss_cell = f"{epss:.2f}" if epss > 0 else "0.00"
                                else:
                                    epss_cell = "—"
                                notes = ""  # Reserved for future mapping notes
                                f.write(f"| {vuln['name']} | {kev_cell} | {epss_cell} | {notes} |\n")
                            f.write("\n")
                        except Exception as _e:
                            logging.debug(f"Threat Intel Diagnostics skipped: {_e}")
                    else:
                        f.write("No critical vulnerabilities found.\n")
                    f.write("\n")
                    
                except Exception as e:
                    logging.error(f"Error fetching repository metadata: {e}")
                    f.write("*Error: Could not fetch repository metadata*\n\n")
            
            # Next Steps
            f.write("## Next Steps\n\n")
            f.write("1. Review the detailed reports for any vulnerabilities found\n")
            f.write("2. Update dependencies to their latest secure versions\n")
            f.write("3. Rerun the scan after making changes to verify fixes\n")
            
            # Repository reference
            f.write("## Repository\n\n")
            f.write(f"**URL:** {repo_url}\n")
            
            # Only attempt cleanup if we have a valid file path
            if requirements_path and isinstance(requirements_path, str):
                try:
                    if os.path.isfile(requirements_path):
                        os.remove(requirements_path)
                except Exception as e:
                    logging.debug(f"Cleanup skipped for requirements file '{requirements_path}': {e}")
    except Exception as e:
        logging.error(f"Error processing {repo_name or repo.get('name', 'unknown')}: {e}", exc_info=True)
    finally:
        # Clean up temporary directory if it exists
        if config.CLONE_DIR and os.path.exists(config.CLONE_DIR):
            try:
                shutil.rmtree(config.CLONE_DIR, ignore_errors=True)
                logging.info(f"Cleaned up temporary directory: {config.CLONE_DIR}")
            except Exception as e:
                logging.warning(f"Failed to clean up temporary directory {config.CLONE_DIR}: {e}")

def main():
    """Main function to orchestrate the repository scanning process."""
    # Early console signal that the script started
    try:
        print("[auditgh] Starting scan_repos.py ...")
    except Exception:
        pass
    parser = argparse.ArgumentParser(description="Scan GitHub org repos for security vulnerabilities.")
    parser.add_argument("--org", type=str, default=config.ORG_NAME,
                      help="GitHub organization name")
    parser.add_argument("--api-base", type=str, default=config.GITHUB_API,
                      help="GitHub API base URL (e.g., https://api.github.com or GHE /api/v3)")
    parser.add_argument("--report-dir", type=str, default=config.REPORT_DIR,
                      help="Directory to write reports")
    parser.add_argument("--repo", type=str, default=None,
                      help="Scan a single repository (name or owner/name). If omitted, scans all repos in --org.")
    parser.add_argument("--dry-run", action="store_true",
                      help="Do not run scanners. Print which repo(s) would be scanned and exit.")
    parser.add_argument("--docker-image", type=str, default=None,
                      help="Docker image name to generate an SBOM for using Syft (e.g., repo/image:tag).")
    parser.add_argument("--syft-format", type=str, default=config.SYFT_FORMAT,
                      help="Syft SBOM output format (e.g., cyclonedx-json, spdx-json). Default: cyclonedx-json")
    parser.add_argument("--control-dir", type=str, default=config.CONTROL_DIR,
                      help="Directory for control flags (pause.flag, stop.flag) and scan_state.json. Default: .auditgh_control")
    parser.add_argument("--vex", action="append", default=None,
                      help="Path to a VEX document (repeatable). Passed to Grype to refine vulnerability results.")
    parser.add_argument("--semgrep-taint", type=str, default=None,
                      help="Path to a Semgrep taint-mode ruleset (e.g., p/ci or a local .yaml). If provided, runs a second Semgrep pass.")
    parser.add_argument("--policy", type=str, default=None,
                      help="Path to policy.yaml if not in repo root.")
    parser.add_argument("--token", type=str, default=config.GITHUB_TOKEN,
                      help="GitHub token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--include-forks", action="store_true",
                      help="Include forked repositories")
    parser.add_argument("--include-archived", action="store_true",
                      help="Include archived repositories")
    parser.add_argument("--max-workers", type=int, default=4,
                      help="Max concurrent workers (default: 4)")
    parser.add_argument("--loglevel", type=str, default="INFO",
                      choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                      help="Set the logging level (default: INFO)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                      help="Increase verbosity (can be used multiple times)")
    
    args = parser.parse_args()
    
    # Set log level from command line or use default
    if args.verbose > 0:
        configure_logging(args.verbose)
    else:
        numeric_level = getattr(logging, args.loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(f"Invalid log level: {args.loglevel}")
        logging.basicConfig(level=numeric_level)
    
    # Update config with command line args
    config.ORG_NAME = args.org
    config.GITHUB_API = args.api_base.rstrip('/')
    config.REPORT_DIR = args.report_dir
    config.GITHUB_TOKEN = args.token or os.getenv("GITHUB_TOKEN")
    config.DOCKER_IMAGE = args.docker_image
    config.SYFT_FORMAT = args.syft_format
    config.CONTROL_DIR = args.control_dir
    ensure_control_dir()
    config.VEX_FILES = [p for p in (args.vex or []) if p]
    config.SEMGREP_TAINT_CONFIG = args.semgrep_taint
    config.POLICY_PATH = args.policy or 'policy.yaml'
    # Print control convenience commands once at startup
    print_control_instructions()
    # Start hotkey listener if interactive
    try:
        hk = HotkeyListener()
        hk.start()
    except Exception:
        pass
    
    # Update headers if token is available
    if config.GITHUB_TOKEN:
        config.HEADERS = {
            "Authorization": f"Bearer {config.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
    
    if not config.GITHUB_TOKEN:
        logging.error("GitHub token is required. Set GITHUB_TOKEN environment variable or use --token")
        print("[auditgh] ERROR: Missing GitHub token. Set GITHUB_TOKEN or pass --token.")
        sys.exit(1)

    # Ensure report directory exists
    os.makedirs(config.REPORT_DIR, exist_ok=True)
    
    # Set up the temporary directory for cloning
    try:
        temp_dir = setup_temp_dir()
        config.CLONE_DIR = temp_dir
        logging.info(f"Temporary directory for cloning: {temp_dir}")
    except Exception as e:
        logging.error(f"Failed to set up temporary directory: {e}")
        sys.exit(1)
    
    logging.info(f"Reports will be saved to: {os.path.abspath(config.REPORT_DIR)}")
    if args.repo:
        logging.info(f"Single repository mode: {args.repo}")
    else:
        logging.info(f"Fetching repositories for organization: {config.ORG_NAME}")
    
    try:
        session = make_session()
        
        if args.repo:
            # Single repository mode
            repo = get_single_repo(session, args.repo)
            if not repo:
                logging.error("Aborting: could not resolve the requested repository.")
                print(f"[auditgh] Repository not found or inaccessible: {args.repo}")
                return
            if args.dry_run:
                full_name = repo.get("full_name") or f"{repo.get('owner',{}).get('login','?')}/{repo.get('name','?')}"
                logging.info(f"[DRY-RUN] Would scan repository: {full_name}")
                return
            process_repo(repo, config.REPORT_DIR)
        else:
            # Get all repositories
            repos = get_all_repos(
                session=session,
                include_forks=args.include_forks,
                include_archived=args.include_archived
            )
            
            if not repos:
                logging.warning("No repositories found matching the criteria.")
                return
                
            logging.info(f"Found {len(repos)} repositories to scan")
            if args.dry_run:
                for r in repos:
                    logging.info(f"[DRY-RUN] Would scan: {r.get('full_name', r.get('name','unknown'))}")
                logging.info("[DRY-RUN] Exiting without running any scanners.")
                return
            
            # Process repositories in parallel
            max_workers = max(1, int(args.max_workers))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for repo in repos:
                    futures.append(executor.submit(process_repo, repo, config.REPORT_DIR))
                
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logging.error(f"Error processing a repository: {e}")
        
        logging.info("Scan completed successfully!")
        # Ensure a final console line for users
        print(f"[auditgh] Scan completed. Reports saved to: {os.path.abspath(config.REPORT_DIR)}")
        
    except KeyboardInterrupt:
        logging.info("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)
    finally:
        # Clean up temporary directory if it exists
        if config.CLONE_DIR and os.path.exists(config.CLONE_DIR):
            try:
                shutil.rmtree(config.CLONE_DIR, ignore_errors=True)
                logging.info(f"Cleaned up temporary directory: {config.CLONE_DIR}")
            except Exception as e:
                logging.warning(f"Failed to clean up temporary directory {config.CLONE_DIR}: {e}")

def run_syft(target: str, repo_name: str, report_dir: str, target_type: str = "repo", sbom_format: str = "cyclonedx-json") -> subprocess.CompletedProcess:
    """Run Anchore Syft to generate SBOMs for a directory (repo) or a docker image.

    target: filesystem path (repo) or image reference (image)
    target_type: 'repo' or 'image'
    sbom_format: syft output format (e.g., cyclonedx-json, spdx-json)
    """
    os.makedirs(report_dir, exist_ok=True)
    syft_bin = shutil.which("syft")
    output_json = os.path.join(report_dir, f"{repo_name}_syft_{'repo' if target_type=='repo' else 'image'}.json")
    output_md = os.path.join(report_dir, f"{repo_name}_syft_{'repo' if target_type=='repo' else 'image'}.md")
    if not syft_bin:
        with open(output_md, 'w') as f:
            f.write("Syft is not installed. Install via: brew install syft or follow https://github.com/anchore/syft\n")
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="syft not installed")
    try:
        # Build syft command
        cmd = [syft_bin, target, f"-o", sbom_format]
        logging.debug(f"Running Syft: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=report_dir)
        # Write JSON output
        with open(output_json, 'w') as f:
            f.write(result.stdout or "")
        # Minimal MD summary
        with open(output_md, 'w') as f:
            f.write(f"# Syft SBOM ({target_type})\n\n")
            f.write(f"**Target:** {target}\n\n")
            try:
                data = json.loads(result.stdout)
                # Heuristic summaries for common formats
                if isinstance(data, dict):
                    pkgs = []
                    for key in ("packages", "components", "artifacts"):
                        if key in data and isinstance(data[key], list):
                            pkgs = data[key]
                            break
                    f.write("## Summary\n\n")
                    f.write(f"- Packages/Components: {len(pkgs)}\n")
                else:
                    f.write("SBOM generated. See JSON for details.\n")
            except Exception:
                f.write("SBOM generated. See JSON for details.\n")
        return result
    except Exception as e:
        with open(output_md, 'w') as f:
            f.write(f"Error running Syft: {e}\n")
        return subprocess.CompletedProcess(args=["syft", target], returncode=1, stdout="", stderr=str(e))

def run_grype(target: str, repo_name: str, report_dir: str, target_type: str = "repo", vex_files: Optional[List[str]] = None) -> subprocess.CompletedProcess:
    """Run Anchore Grype to find vulnerabilities in a directory (repo) or docker image.

    target: filesystem path (repo) or image reference (image)
    """
    os.makedirs(report_dir, exist_ok=True)
    grype_bin = shutil.which("grype")
    output_json = os.path.join(report_dir, f"{repo_name}_grype_{'repo' if target_type=='repo' else 'image'}.json")
    output_md = os.path.join(report_dir, f"{repo_name}_grype_{'repo' if target_type=='repo' else 'image'}.md")
    if not grype_bin:
        with open(output_md, 'w') as f:
            f.write("Grype is not installed. Install via: brew install grype or see https://github.com/anchore/grype\n")
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="grype not installed")
    try:
        cmd = [grype_bin, target, "-o", "json"]
        # Append VEX documents if provided
        for vf in (vex_files or []):
            cmd += ["--vex", vf]
        logging.debug(f"Running Grype: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=report_dir)
        # Write JSON output
        with open(output_json, 'w') as f:
            f.write(result.stdout or "")
        # Minimal MD summary
        with open(output_md, 'w') as f:
            f.write(f"# Grype Vulnerability Scan ({target_type})\n\n")
            f.write(f"**Target:** {target}\n\n")
            try:
                data = json.loads(result.stdout)
                matches = data.get("matches", []) if isinstance(data, dict) else []
                sev_counts = {"Critical":0, "High":0, "Medium":0, "Low":0, "Negligible":0, "Unknown":0}
                for m in matches:
                    sev = (m.get('vulnerability', {}).get('severity') or 'Unknown').title()
                    if sev not in sev_counts:
                        sev = 'Unknown'
                    sev_counts[sev] += 1
                f.write("## Summary\n\n")
                for k in ["Critical","High","Medium","Low","Negligible","Unknown"]:
                    f.write(f"- {k}: {sev_counts[k]}\n")
            except Exception:
                f.write("Scan completed. See JSON for details.\n")
        return result
    except Exception as e:
        with open(output_md, 'w') as f:
            f.write(f"Error running Grype: {e}\n")
        return subprocess.CompletedProcess(args=["grype", target], returncode=1, stdout="", stderr=str(e))

def run_checkov(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """Run Checkov to scan Terraform if .tf files are present in repo_path.

    Writes JSON and Markdown summaries. Returns the CompletedProcess on run, or None if not applicable.
    """
    # Detect Terraform files
    has_tf = False
    for root, _dirs, files in os.walk(repo_path):
        if any(fn.endswith('.tf') for fn in files):
            has_tf = True
            break
    if not has_tf:
        return None

    os.makedirs(report_dir, exist_ok=True)
    output_json = os.path.join(report_dir, f"{repo_name}_checkov.json")
    output_md = os.path.join(report_dir, f"{repo_name}_checkov.md")
    checkov_bin = shutil.which('checkov')
    if not checkov_bin:
        with open(output_md, 'w') as f:
            f.write("Checkov is not installed. Install via: pip install checkov or see https://github.com/bridgecrewio/checkov\n")
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="checkov not installed")

    try:
        cmd = [checkov_bin, '-d', repo_path, '-o', 'json']
        logging.debug(f"Running Checkov: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        # Write JSON
        with open(output_json, 'w') as f:
            f.write(result.stdout or "")
        # Write MD summary
        with open(output_md, 'w') as f:
            f.write("# Checkov Terraform Scan\n\n")
            f.write(f"**Target:** {repo_path}\n\n")
            try:
                data = json.loads(result.stdout or '{}')
                failed = data.get('results', {}).get('failed_checks', [])
                # Summarize by severity if present
                sev_counts = {"CRITICAL":0, "HIGH":0, "MEDIUM":0, "LOW":0, "UNKNOWN":0}
                for item in failed:
                    sev = (item.get('severity') or 'UNKNOWN').upper()
                    if sev not in sev_counts:
                        sev = 'UNKNOWN'
                    sev_counts[sev] += 1
                f.write("## Summary\n\n")
                for k in ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]:
                    f.write(f"- {k.title()}: {sev_counts[k]}\n")
                # List a few failed checks
                f.write("\n## Sample Findings (up to 10)\n\n")
                for chk in failed[:10]:
                    rid = chk.get('check_id', 'UNKNOWN')
                    res = chk.get('resource', 'resource')
                    file_path = chk.get('file_path', 'unknown')
                    lines = chk.get('file_line_range') or []
                    f.write(f"- {rid} in {res} ({file_path}{':' + str(lines) if lines else ''})\n")
            except Exception:
                f.write("Scan completed. See JSON for details.\n")
        return result
    except Exception as e:
        with open(output_md, 'w') as f:
            f.write(f"Error running Checkov: {e}\n")
        return subprocess.CompletedProcess(args=['checkov', '-d', repo_path], returncode=1, stdout="", stderr=str(e))

def run_gitleaks(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """Run Gitleaks secret scan against the working tree and history.

    Writes JSON and Markdown summaries. Returns CompletedProcess or None if tool missing.
    """
    os.makedirs(report_dir, exist_ok=True)
    gl_bin = shutil.which('gitleaks')
    output_json = os.path.join(report_dir, f"{repo_name}_gitleaks.json")
    output_md = os.path.join(report_dir, f"{repo_name}_gitleaks.md")
    if not gl_bin:
        with open(output_md, 'w') as f:
            f.write("Gitleaks is not installed. Install via: brew install gitleaks or see https://github.com/gitleaks/gitleaks\n")
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="gitleaks not installed")
    try:
        # Detect in working tree and history
        cmd = [gl_bin, 'detect', '-s', repo_path, '-f', 'json']
        result = subprocess.run(cmd, capture_output=True, text=True)
        with open(output_json, 'w') as f:
            f.write(result.stdout or "")
        # MD summary
        with open(output_md, 'w') as f:
            f.write("# Gitleaks Secrets Scan\n\n")
            try:
                data = json.loads(result.stdout or '[]')
                findings = data if isinstance(data, list) else []
                f.write(f"Total findings: {len(findings)}\n\n")
                if findings:
                    f.write("## Sample Findings (up to 10)\n\n")
                    for item in findings[:10]:
                        rule = item.get('rule','')
                        file = item.get('file','')
                        line = item.get('line','')
                        desc = item.get('description','')
                        f.write(f"- {rule} in {file}:{line} — {desc}\n")
            except Exception:
                f.write("Scan completed. See JSON for details.\n")
        return result
    except Exception as e:
        with open(output_md, 'w') as f:
            f.write(f"Error running Gitleaks: {e}\n")
        return subprocess.CompletedProcess(args=['gitleaks','detect','-s',repo_path], returncode=1, stdout="", stderr=str(e))

def run_bandit(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """Run Bandit SAST for Python projects if any .py files exist."""
    # Detect Python files
    has_py = False
    for root, _dirs, files in os.walk(repo_path):
        if any(fn.endswith('.py') for fn in files):
            has_py = True
            break
    if not has_py:
        return None

    os.makedirs(report_dir, exist_ok=True)
    bandit_bin = shutil.which('bandit')
    output_json = os.path.join(report_dir, f"{repo_name}_bandit.json")
    output_md = os.path.join(report_dir, f"{repo_name}_bandit.md")
    if not bandit_bin:
        with open(output_md, 'w') as f:
            f.write("Bandit is not installed. Install via: pip install bandit or brew install bandit\n")
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="bandit not installed")
    try:
        cmd = [bandit_bin, "-r", repo_path, "-f", "json", "-q"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        with open(output_json, 'w') as f:
            f.write(result.stdout or "")
        # MD summary
        with open(output_md, 'w') as f:
            f.write("# Bandit Python Security Scan\n\n")
            try:
                data = json.loads(result.stdout or '{}')
                results = data.get('results', []) if isinstance(data, dict) else []
                counts = {"HIGH":0, "MEDIUM":0, "LOW":0}
                for r in results:
                    sev = (r.get('issue_severity') or '').upper()
                    if sev in counts:
                        counts[sev] += 1
                f.write("## Summary\n\n")
                for k in ["HIGH","MEDIUM","LOW"]:
                    f.write(f"- {k.title()}: {counts[k]}\n")
                if results:
                    f.write("\n## Sample Findings (up to 10)\n\n")
                    for r in results[:10]:
                        test_id = r.get('test_id','')
                        issue = r.get('issue_text','')
                        path = r.get('filename','')
                        line = r.get('line_number','')
                        sev = r.get('issue_severity','')
                        f.write(f"- [{test_id}] {sev} in {path}:{line} — {issue}\n")
            except Exception:
                f.write("Scan completed. See JSON for details.\n")
        return result
    except Exception as e:
        with open(output_md, 'w') as f:
            f.write(f"Error running Bandit: {e}\n")
        return subprocess.CompletedProcess(args=['bandit','-r',repo_path], returncode=1, stdout="", stderr=str(e))

def run_trivy_fs(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """Run Trivy filesystem scan for vulnerabilities/misconfigs."""
    os.makedirs(report_dir, exist_ok=True)
    trivy_bin = shutil.which('trivy')
    output_json = os.path.join(report_dir, f"{repo_name}_trivy_fs.json")
    output_md = os.path.join(report_dir, f"{repo_name}_trivy_fs.md")
    if not trivy_bin:
        with open(output_md, 'w') as f:
            f.write("Trivy is not installed. Install via: brew install trivy or see https://aquasecurity.github.io/trivy/\n")
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="trivy not installed")
    try:
        # Run with vulnerability and config checks; quiet + JSON
        cmd = [trivy_bin, "fs", "-q", "-f", "json", repo_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        with open(output_json, 'w') as f:
            f.write(result.stdout or "")
        # MD summary
        with open(output_md, 'w') as f:
            f.write("# Trivy Filesystem Scan\n\n")
            try:
                data = json.loads(result.stdout or '{}')
                results = data.get('Results', []) if isinstance(data, dict) else []
                counts = {"CRITICAL":0, "HIGH":0, "MEDIUM":0, "LOW":0, "UNKNOWN":0}
                for res in results:
                    for v in res.get('Vulnerabilities', []) or []:
                        sev = (v.get('Severity') or 'UNKNOWN').upper()
                        if sev not in counts: sev = 'UNKNOWN'
                        counts[sev] += 1
                f.write("## Summary\n\n")
                for k in ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]:
                    f.write(f"- {k.title()}: {counts[k]}\n")
            except Exception:
                f.write("Scan completed. See JSON for details.\n")
        return result
    except Exception as e:
        with open(output_md, 'w') as f:
            f.write(f"Error running Trivy fs: {e}\n")
        return subprocess.CompletedProcess(args=['trivy','fs',repo_path], returncode=1, stdout="", stderr=str(e))

if __name__ == "__main__":
    main()
