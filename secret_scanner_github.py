"""Shared GitHub repository helpers for secret scanning scripts."""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

from src.github.rate_limit import make_rate_limited_session, request_with_rate_limit

load_dotenv(override=True)


@dataclass
class SecretScannerConfig:
  """Common configuration for GitHub-backed scanners."""

  GITHUB_TOKEN: str
  ORG_NAME: str
  GITHUB_API: str
  REPORT_DIR: str
  CLONE_DIR: Optional[str]
  HEADERS: Dict[str, str]

  @classmethod
  def from_env(cls, *, default_report_dir: str) -> "SecretScannerConfig":
    token = os.getenv("GITHUB_TOKEN")
    org = os.getenv("GITHUB_ORG")
    if not token:
      raise ValueError("GITHUB_TOKEN environment variable is required")
    if not org:
      raise ValueError("GITHUB_ORG environment variable is required")

    api = os.getenv("GITHUB_API", "https://api.github.com")
    report_dir = os.path.abspath(os.getenv("REPORT_DIR", default_report_dir))
    headers = {
      "Authorization": f"token {token}",
      "Accept": "application/vnd.github.v3+json",
    }
    return cls(
      GITHUB_TOKEN=token,
      ORG_NAME=org,
      GITHUB_API=api,
      REPORT_DIR=report_dir,
      CLONE_DIR=None,
      HEADERS=headers,
    )


def setup_logging(name: str, logfile: str, verbosity: int) -> logging.Logger:
  """Configure logging for a scanner script and return its logger."""
  level = logging.INFO
  if verbosity > 1:
    level = logging.DEBUG
  elif verbosity == 0:
    level = logging.WARNING

  os.makedirs('logs', exist_ok=True)
  logging.basicConfig(
    level=level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
      logging.StreamHandler(),
      logging.FileHandler(logfile),
    ],
    force=True,
  )
  return logging.getLogger(name)


def create_session(config: SecretScannerConfig, user_agent: str) -> requests.Session:
  """Return an authenticated, rate-limit-aware requests session."""
  session = make_rate_limited_session(config.GITHUB_TOKEN, user_agent=user_agent)
  return session


def _filter_repos(page_repos: List[Dict[str, Any]], include_forks: bool, include_archived: bool) -> List[Dict[str, Any]]:
  filtered: List[Dict[str, Any]] = []
  for repo in page_repos or []:
    if (not include_forks and repo.get('fork')) or (not include_archived and repo.get('archived')):
      continue
    filtered.append(repo)
  return filtered


def get_all_repos(
  config: SecretScannerConfig,
  session: requests.Session,
  *,
  include_forks: bool,
  include_archived: bool,
  logger: logging.Logger,
) -> List[Dict[str, Any]]:
  repos: List[Dict[str, Any]] = []
  page = 1
  per_page = 100

  is_user_fallback = False

  while True:
    base = "users" if is_user_fallback else "orgs"
    url = f"{config.GITHUB_API}/{base}/{config.ORG_NAME}/repos"
    params = {"type": "all", "per_page": per_page, "page": page}
    try:
      resp = request_with_rate_limit(session, 'GET', url, params=params, timeout=30, logger=logger)
      if not is_user_fallback and page == 1 and resp.status_code == 404:
        logger.info("Organization '%s' not found. Retrying as user...", config.ORG_NAME)
        is_user_fallback = True
        page = 1
        repos.clear()
        continue
      resp.raise_for_status()
      page_repos = resp.json() or []
      if not page_repos:
        break
      repos.extend(_filter_repos(page_repos, include_forks, include_archived))
      if len(page_repos) < per_page:
        break
      page += 1
    except requests.exceptions.RequestException as exc:
      logger.error("Error fetching repositories: %s", exc)
      break

  return repos


def get_single_repo(
  config: SecretScannerConfig,
  session: requests.Session,
  repo_identifier: str,
  logger: logging.Logger,
) -> Optional[Dict[str, Any]]:
  if '/' in repo_identifier:
    owner, repo_name = repo_identifier.split('/', 1)
  else:
    owner = config.ORG_NAME
    repo_name = repo_identifier

  url = f"{config.GITHUB_API}/repos/{owner}/{repo_name}"

  try:
    response = request_with_rate_limit(session, 'GET', url, timeout=30, logger=logger)
    response.raise_for_status()
    return response.json()
  except requests.exceptions.RequestException as exc:
    logger.error("Error fetching repository %s: %s", repo_identifier, exc)
    return None


def clone_repo(config: SecretScannerConfig, repo: Dict[str, Any], logger: logging.Logger) -> Optional[str]:
  if not config.CLONE_DIR:
    config.CLONE_DIR = tempfile.mkdtemp(prefix="repo_scan_")

  repo_name = repo['name']
  clone_url = repo['clone_url']

  if not config.GITHUB_TOKEN and 'ssh_url' in repo:
    clone_url = repo['ssh_url']
  elif config.GITHUB_TOKEN and clone_url.startswith('https://'):
    if '@' not in clone_url:
      clone_url = clone_url.replace('https://', f"https://x-access-token:{config.GITHUB_TOKEN}@")

  repo_path = os.path.join(config.CLONE_DIR, repo_name)

  try:
    if os.path.exists(repo_path):
      logger.info("Updating existing repository: %s", repo_name)
      subprocess.run(
        ['git', '-C', repo_path, 'fetch', '--all'],
        check=True,
        capture_output=True,
        text=True,
      )
      subprocess.run(
        ['git', '-C', repo_path, 'reset', '--hard', 'origin/HEAD'],
        check=True,
        capture_output=True,
        text=True,
      )
    else:
      logger.info("Cloning repository: %s", repo_name)
      subprocess.run(
        ['git', 'clone', '--depth', '1', clone_url, repo_path],
        check=True,
        capture_output=True,
        text=True,
      )
    return repo_path
  except subprocess.CalledProcessError as exc:
    logger.error("Error cloning/updating repository %s: %s", repo_name, exc.stderr)
    return None


def cleanup_clone_dir(config: SecretScannerConfig, logger: logging.Logger) -> None:
  if config.CLONE_DIR and os.path.exists(config.CLONE_DIR):
    try:
      shutil.rmtree(config.CLONE_DIR)
    except Exception as exc:  # pragma: no cover - cleanup best effort
      logger.warning("Error cleaning up temporary directory: %s", exc)


def ensure_report_dir(config: SecretScannerConfig) -> Path:
  path = Path(config.REPORT_DIR)
  path.mkdir(parents=True, exist_ok=True)
  return path
