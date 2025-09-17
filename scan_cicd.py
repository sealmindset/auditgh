#!/usr/bin/env python3
"""
CI/CD pipeline inventory for GitHub repositories.

This script enumerates GitHub Actions workflows and common external CI systems (Jenkins, Azure Pipelines,
CircleCI, GitLab CI) across repositories in an organization (or a single repo), then generates per-repo
and org-level Markdown reports summarizing pipeline definitions, triggers, permissions, concurrency,
third-party actions usage, and recent run status via the GitHub Actions API.

Defaults:
- Org-wide targets are read from .env (GITHUB_ORG) and include forks and archived repos as requested.
- Output directory defaults to ci_reports

Usage examples:
- Org-wide (include forks and archived):
  ./scan_cicd.py -v
- Single repo:
  ./scan_cicd.py --repo sealmindset/terragoat -v
"""

import argparse
import concurrent.futures
import datetime
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from glob import glob
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from src.github.rate_limit import make_rate_limited_session, request_with_rate_limit
import yaml
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(override=True)


class CICDConfig:
    """Configuration for the CI/CD scanner."""

    def __init__(self):
        self.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        self.ORG_NAME = os.getenv("GITHUB_ORG")
        if not self.GITHUB_TOKEN:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        if not self.ORG_NAME:
            raise ValueError("GITHUB_ORG environment variable is required")
        self.GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com")
        self.REPORT_DIR = os.path.abspath(os.getenv("CI_REPORT_DIR", "ci_reports"))
        self.CLONE_DIR: Optional[str] = None
        self.HEADERS = {
            "Authorization": f"token {self.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "auditgh-scan-cicd",
        }


config: Optional[CICDConfig] = None


def setup_logging(verbosity: int = 1):
    level = logging.INFO
    if verbosity > 1:
        level = logging.DEBUG
    elif verbosity == 0:
        level = logging.WARNING
    try:
        os.makedirs('logs', exist_ok=True)
    except Exception:
        pass
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(), logging.FileHandler('logs/cicd_scan.log')]
    )


def make_session() -> requests.Session:
    token = config.GITHUB_TOKEN if config else None
    return make_rate_limited_session(token, user_agent="auditgh-cicd")


def _filter_page_repos(page_repos: List[Dict[str, Any]], include_forks: bool, include_archived: bool) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for repo in page_repos or []:
        if (not include_forks and repo.get('fork')) or (not include_archived and repo.get('archived')):
            continue
        out.append(repo)
    return out


def get_all_repos(session: requests.Session, include_forks: bool = True,
                  include_archived: bool = True) -> List[Dict[str, Any]]:
    """Fetch all repositories from an org (or user fallback), including forks and archived by default."""
    repos: List[Dict[str, Any]] = []
    page = 1
    per_page = 100
    is_user_fallback = False
    while True:
        base = "users" if is_user_fallback else "orgs"
        url = f"{config.GITHUB_API}/{base}/{config.ORG_NAME}/repos"
        params = {"type": "all", "per_page": per_page, "page": page}
        try:
            resp = request_with_rate_limit(session, 'GET', url, params=params, timeout=30, logger=logging.getLogger('cicd.api'))
            if not is_user_fallback and page == 1 and resp.status_code == 404:
                logging.info(f"Organization '{config.ORG_NAME}' not found or inaccessible. Retrying as a user account...")
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
    if '/' in repo_identifier:
        owner, repo_name = repo_identifier.split('/', 1)
    else:
        owner = config.ORG_NAME
        repo_name = repo_identifier
    url = f"{config.GITHUB_API}/repos/{owner}/{repo_name}"
    try:
        resp = request_with_rate_limit(session, 'GET', url, timeout=30, logger=logging.getLogger('cicd.api'))
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching repository {repo_identifier}: {e}")
        return None


def clone_repo(repo: Dict[str, Any]) -> Optional[str]:
    if not config.CLONE_DIR:
        config.CLONE_DIR = tempfile.mkdtemp(prefix="repo_scan_cicd_")
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
            subprocess.run(['git', '-C', repo_path, 'fetch', '--all'], check=True, capture_output=True, text=True)
            subprocess.run(['git', '-C', repo_path, 'reset', '--hard', 'origin/HEAD'], check=True, capture_output=True, text=True)
        else:
            logging.info(f"Cloning repository: {repo_name}")
            subprocess.run(['git', 'clone', '--depth', '1', clone_url, repo_path], check=True, capture_output=True, text=True)
        return repo_path
    except subprocess.CalledProcessError as e:
        logging.error(f"Error cloning/updating repository {repo_name}: {e.stderr}")
        return None


# ----------
# CI parsing
# ----------

def find_ci_files(repo_path: str) -> Dict[str, List[str]]:
    """Locate CI/CD configuration files in the repository."""
    paths: Dict[str, List[str]] = {
        'github_workflows': [],
        'jenkins': [],
        'azure_pipelines': [],
        'circleci': [],
        'gitlabci': [],
        'other': [],
    }
    workflows_dir = os.path.join(repo_path, '.github', 'workflows')
    if os.path.isdir(workflows_dir):
        paths['github_workflows'] = sorted(glob(os.path.join(workflows_dir, '*.yml')) + glob(os.path.join(workflows_dir, '*.yaml')))
    # External CIs
    jenkinsfile = os.path.join(repo_path, 'Jenkinsfile')
    if os.path.exists(jenkinsfile):
        paths['jenkins'].append(jenkinsfile)
    az_pipes = [p for p in [os.path.join(repo_path, 'azure-pipelines.yml'), os.path.join(repo_path, 'azure-pipelines.yaml')] if os.path.exists(p)]
    paths['azure_pipelines'].extend(az_pipes)
    circleci_cfg = os.path.join(repo_path, '.circleci', 'config.yml')
    if os.path.exists(circleci_cfg):
        paths['circleci'].append(circleci_cfg)
    gitlab_ci = os.path.join(repo_path, '.gitlab-ci.yml')
    if os.path.exists(gitlab_ci):
        paths['gitlabci'].append(gitlab_ci)
    return paths


def _normalize_triggers(on_field: Any) -> str:
    if isinstance(on_field, str):
        return on_field
    if isinstance(on_field, list):
        return ", ".join(str(x) for x in on_field)
    if isinstance(on_field, dict):
        return ", ".join(sorted(on_field.keys()))
    return ""


def _collect_actions_uses(obj: Any) -> List[str]:
    """Collect all 'uses:' references under jobs -> steps."""
    uses: List[str] = []
    if not isinstance(obj, dict):
        return uses
    jobs = obj.get('jobs') or {}
    if isinstance(jobs, dict):
        for _, job in jobs.items():
            steps = (job or {}).get('steps') or []
            if not isinstance(steps, list):
                continue
            for step in steps:
                if isinstance(step, dict) and 'uses' in step:
                    uses.append(str(step['uses']))
    return uses


def _is_pinned_action(uses_ref: str) -> bool:
    """Consider @<40-hex> as pinned; version tags are treated as not strictly pinned."""
    m = re.search(r'@([A-Za-z0-9_.-]+)$', uses_ref)
    if not m:
        return False
    ref = m.group(1)
    return bool(re.fullmatch(r'[0-9a-fA-F]{40}', ref))


def parse_workflow_file(path: str) -> Dict[str, Any]:
    try:
        with open(path, 'r') as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        data = {}
    name = data.get('name') or Path(path).name
    triggers = _normalize_triggers(data.get('on'))
    permissions = data.get('permissions')
    concurrency = data.get('concurrency')
    uses = _collect_actions_uses(data)
    pinned = sum(1 for u in uses if _is_pinned_action(u))
    unpinned = len(uses) - pinned
    # Runner labels
    runner_labels: List[str] = []
    jobs = data.get('jobs') or {}
    if isinstance(jobs, dict):
        for _, job in jobs.items():
            runs_on = (job or {}).get('runs-on')
            if isinstance(runs_on, list):
                runner_labels.extend(str(x) for x in runs_on)
            elif isinstance(runs_on, str):
                runner_labels.append(runs_on)
    risk_flags: List[str] = []
    if permissions is None:
        risk_flags.append('no-permissions-declared')
    if 'pull_request_target' in (triggers or ''):
        risk_flags.append('uses-pull_request_target')
    if any(lbl for lbl in runner_labels if 'self-hosted' in lbl):
        risk_flags.append('self-hosted-runner')
    return {
        'name': name,
        'file': path,
        'triggers': triggers,
        'permissions': permissions,
        'concurrency': concurrency,
        'uses_total': len(uses),
        'uses_pinned': pinned,
        'uses_unpinned': unpinned,
        'runner_labels': list(sorted(set(runner_labels))),
        'risk_flags': risk_flags,
    }


def find_deployment_targets(workflow_data: Dict[str, Any], session: requests.Session, owner: str, repo: str) -> List[Dict[str, Any]]:
    """Detect deployment targets from workflow YAML and API artifacts."""
    deployments = []
    # Static YAML parsing (existing logic)
    jobs = workflow_data.get('jobs', {})
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            steps = job.get('steps', [])
            if isinstance(steps, list):
                for step in steps:
                    if isinstance(step, dict):
                        uses = step.get('uses')
                        run_cmd = step.get('run')
                        if uses and 'deploy' in uses.lower():
                            target = detect_target_from_uses(uses)
                            deployments.append({
                                'source': 'yaml-uses',
                                'step': step.get('name', ''),
                                'target': target or 'Unknown',
                                'environment': step.get('env', {}).get('ENV', ''),
                                'risk': 'Potential deployment risk'
                            })
                        if run_cmd and 'deploy' in run_cmd.lower():
                            target = detect_target_from_command(run_cmd)
                            deployments.append({
                                'source': 'yaml-run',
                                'step': step.get('name', ''),
                                'target': target or 'Unknown',
                                'environment': step.get('env', {}).get('ENV', ''),
                                'risk': 'Potential deployment risk'
                            })
    # Dynamic artifact parsing (new logic)
    workflows = list_workflows(session, owner, repo)
    for wf in workflows:
        wf_id = wf.get('id')
        if isinstance(wf_id, int):
            runs = list_recent_runs(session, owner, repo, wf_id, per_page=5)
            for run in runs:
                run_id = run.get('id')
                if run_id:
                    artifacts = fetch_artifacts(session, owner, repo, run_id)
                    for artifact in artifacts:
                        art_deployments = parse_artifact_for_deployments(session, artifact)
                        for art_dep in art_deployments:
                            deployments.append({
                                'source': 'artifact',
                                'artifact_name': art_dep['artifact_name'],
                                'target': art_dep['target'],
                                'environment': art_dep['environment'],
                                'risk': art_dep['risk']
                            })
    return deployments


def detect_target_from_uses(uses: str) -> str:
    """Infer deployment target from 'uses' action."""
    if 'aws-actions' in uses:
        return 'AWS (e.g., EC2, S3)'
    elif 'azure' in uses:
        return 'Azure (e.g., App Service)'
    elif 'kubectl' in uses or 'helm' in uses:
        return 'Kubernetes'
    return 'Unknown'


def detect_target_from_command(cmd: str) -> str:
    """Infer deployment target from 'run' command using regex."""
    if re.search(r'aws\s+s3|ec2', cmd, re.IGNORECASE):
        return 'AWS S3 or EC2'
    elif re.search(r'az\s+group|webapp', cmd, re.IGNORECASE):
        return 'Azure'
    elif re.search(r'kubectl|helm', cmd, re.IGNORECASE):
        return 'Kubernetes'
    return 'Unknown'


def fetch_artifacts(session: requests.Session, owner: str, repo: str, run_id: int) -> List[Dict[str, Any]]:
    """Fetch artifacts for a specific workflow run."""
    url = f"{config.GITHUB_API}/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts"
    try:
        resp = request_with_rate_limit(session, 'GET', url, timeout=30, logger=logging.getLogger('cicd.api'))
        resp.raise_for_status()
        return (resp.json() or {}).get('artifacts') or []
    except requests.exceptions.RequestException as e:
        logging.warning(f"Failed to fetch artifacts for run {run_id} in {owner}/{repo}: {e}")
        return []


def parse_artifact_for_deployments(session: requests.Session, artifact: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse artifact metadata and content for deployment targets."""
    deployments = []
    name = artifact.get('name', '')
    # Download and parse artifact content if available (simple string matching for now)
    if 'archive_download_url' in artifact:
        try:
            resp = request_with_rate_limit(session, 'GET', artifact['archive_download_url'], timeout=30, logger=logging.getLogger('cicd.api'))
            resp.raise_for_status()
            content = resp.text  # Or handle zip/binary if needed
            targets = detect_target_from_artifact_content(content)
            for target in targets:
                deployments.append({
                    'artifact_name': name,
                    'target': target['target'],
                    'environment': target.get('environment', ''),
                    'risk': target.get('risk', 'Potential deployment risk')
                })
        except requests.exceptions.RequestException as e:
            logging.warning(f"Failed to download artifact {name}: {e}")
    else:
        # Infer from metadata if download URL not present
        target = detect_target_from_artifact_name(name)
        if target:
            deployments.append({
                'artifact_name': name,
                'target': target,
                'environment': '',
                'risk': 'Potential deployment risk'
            })
    return deployments


def detect_target_from_artifact_name(name: str) -> str:
    """Infer deployment target from artifact name using regex."""
    if re.search(r's3|ec2|aws', name, re.IGNORECASE):
        return 'AWS (e.g., S3 or EC2)'
    elif re.search(r'azure|app-service', name, re.IGNORECASE):
        return 'Azure'
    elif re.search(r'k8s|kubernetes|helm', name, re.IGNORECASE):
        return 'Kubernetes'
    return 'Unknown'


def detect_target_from_artifact_content(content: str) -> List[Dict[str, Any]]:
    """Infer deployment targets from artifact content using regex."""
    targets = []
    if re.search(r'deployed to s3://|ec2-', content, re.IGNORECASE):
        targets.append({'target': 'AWS S3 or EC2', 'environment': 'N/A'})
    elif re.search(r'az webapp|deploy to azure', content, re.IGNORECASE):
        targets.append({'target': 'Azure', 'environment': 'N/A'})
    elif re.search(r'kubectl apply|helm upgrade', content, re.IGNORECASE):
        targets.append({'target': 'Kubernetes', 'environment': 'N/A'})
    return targets


# ---------------
# GitHub API data
# ---------------

def list_workflows(session: requests.Session, owner: str, repo: str) -> List[Dict[str, Any]]:
    url = f"{config.GITHUB_API}/repos/{owner}/{repo}/actions/workflows"
    try:
        resp = request_with_rate_limit(session, 'GET', url, timeout=30, logger=logging.getLogger('cicd.api'))
        resp.raise_for_status()
        return (resp.json() or {}).get('workflows') or []
    except requests.exceptions.RequestException as e:
        logging.warning(f"Failed to list workflows for {owner}/{repo}: {e}")
        return []


def list_recent_runs(session: requests.Session, owner: str, repo: str, workflow_id: int, per_page: int = 5) -> List[Dict[str, Any]]:
    url = f"{config.GITHUB_API}/repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs"
    params = {"per_page": per_page}
    try:
        resp = request_with_rate_limit(session, 'GET', url, params=params, timeout=30, logger=logging.getLogger('cicd.api'))
        resp.raise_for_status()
        return (resp.json() or {}).get('workflow_runs') or []
    except requests.exceptions.RequestException as e:
        logging.warning(f"Failed to list runs for workflow {workflow_id} in {owner}/{repo}: {e}")
        return []


# ---------
# Reporting
# ---------

def write_repo_report(repo: Dict[str, Any], repo_path: str, report_dir: str, ci_files: Dict[str, List[str]],
                      wf_parsed: List[Dict[str, Any]], api_workflows: List[Dict[str, Any]],
                      api_runs: Dict[int, List[Dict[str, Any]]], session: requests.Session) -> None:
    os.makedirs(report_dir, exist_ok=True)
    repo_name = repo['name']
    md_path = os.path.join(report_dir, f"{repo_name}_cicd.md")
    with open(md_path, 'w') as f:
        f.write(f"# CI/CD Report\n\n")
        f.write(f"**Repository:** {repo.get('full_name', repo_name)}\n\n")
        f.write(f"- Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- Default branch: {repo.get('default_branch','')}\n\n")
        # TOC
        f.write("- [Detected CI files](#detected-ci-files)\n")
        f.write("- [GitHub Actions (source)](#github-actions-source)\n")
        f.write("- [GitHub Actions (recent runs)](#github-actions-recent-runs)\n")
        f.write("- [External CI](#external-ci)\n")
        f.write("- [Deployment Targets](#deployment-targets)\n\n")

        # Detected CI files
        f.write("## Detected CI files\n\n")
        for key in ['github_workflows', 'jenkins', 'azure_pipelines', 'circleci', 'gitlabci']:
            files = ci_files.get(key) or []
            if not files:
                continue
            title = {
                'github_workflows': 'GitHub Actions Workflows',
                'jenkins': 'Jenkinsfile',
                'azure_pipelines': 'Azure Pipelines',
                'circleci': 'CircleCI',
                'gitlabci': 'GitLab CI',
            }[key]
            f.write(f"### {title}\n\n")
            for p in files:
                rel = os.path.relpath(p, repo_path)
                f.write(f"- `{rel}`\n")
            f.write("\n")

        # GitHub Actions (source parsed)
        if wf_parsed:
            f.write("## GitHub Actions (source)\n\n")
            f.write("| Workflow | File | Triggers | Permissions | Concurrency | Uses (pinned/unpinned) | Runner Labels | Risk Flags |\n")
            f.write("|----------|------|----------|-------------|-------------|------------------------|--------------|-----------|\n")
            for w in wf_parsed:
                perms = '(none)' if w['permissions'] is None else ('object' if isinstance(w['permissions'], dict) else str(w['permissions']))
                flags = ", ".join(w['risk_flags']) if w['risk_flags'] else ''
                rel = os.path.relpath(w['file'], repo_path)
                f.write(
                    f"| {w['name']} | `{rel}` | {w['triggers']} | {perms} | {w['concurrency'] or ''} | {w['uses_pinned']}/{w['uses_unpinned']} | "
                    f"{', '.join(w['runner_labels'])} | {flags} |\n"
                )
            f.write("\n")

        # GitHub Actions (API runs)
        if api_workflows:
            f.write("## GitHub Actions (recent runs)\n\n")
            f.write("| Workflow | Run ID | Event | Status | Conclusion | Branch | Actor | Duration | URL |\n")
            f.write("|----------|--------|-------|--------|------------|--------|-------|----------|-----|\n")
            wf_by_id = {w['id']: w for w in api_workflows}
            for wf_id, runs in api_runs.items():
                wf_name = (wf_by_id.get(wf_id, {}) or {}).get('name', str(wf_id))
                for run in runs or []:
                    started = run.get('run_started_at') or run.get('created_at')
                    updated = run.get('updated_at') or run.get('run_started_at')
                    duration = ''
                    try:
                        if started and updated:
                            t1 = datetime.datetime.fromisoformat(updated.replace('Z','+00:00'))
                            t0 = datetime.datetime.fromisoformat(started.replace('Z','+00:00'))
                            delta = t1 - t0
                            duration = str(delta)
                    except Exception:
                        pass
                    f.write(
                        f"| {wf_name} | {run.get('id')} | {run.get('event','')} | {run.get('status','')} | {run.get('conclusion','')} | "
                        f"{run.get('head_branch','')} | {run.get('actor',{}).get('login','')} | {duration} | {run.get('html_url','')} |\n"
                    )
            f.write("\n")

        # Deployment Targets
        deployments = find_deployment_targets(wf_parsed[0] if wf_parsed else {}, session, repo['owner']['login'], repo['name'])
        if deployments:
            f.write("## Deployment Targets and Risks\n\n")
            f.write("| Source | Step/Artifact | Target Resource | Environment | Risk Score | Mitigation Suggestions |\n")
            f.write("|--------|--------------|-----------------|-------------|-----------|-----------------------|\n")
            for dep in deployments:
                risk_score = 50  # Default; can be enhanced with scoring logic
                if 'risk' in dep and 'high' in dep['risk'].lower():
                    risk_score = 80
                mitigation = 'Review and pin dependencies; add authentication.'  # Can be context-specific
                f.write(f"| {dep.get('source', 'unknown')} | {dep.get('step', dep.get('artifact_name', ''))} | {dep.get('target', 'Unknown')} | {dep.get('environment', '')} | {risk_score} | {mitigation} |\n")
            f.write("\n")
        else:
            f.write("- No deployment targets detected.\n\n")

        # External CI summary
        f.write("## External CI\n\n")
        if not (ci_files.get('jenkins') or ci_files.get('azure_pipelines') or ci_files.get('circleci') or ci_files.get('gitlabci')):
            f.write("(none detected)\n")
        else:
            if ci_files.get('jenkins'):
                f.write("- Jenkinsfile present\n")
            if ci_files.get('azure_pipelines'):
                f.write("- Azure Pipelines yaml present\n")
            if ci_files.get('circleci'):
                f.write("- .circleci/config.yml present\n")
            if ci_files.get('gitlabci'):
                f.write("- .gitlab-ci.yml present\n")


def write_org_summary(report_root: str, per_repo_stats: List[Dict[str, Any]]) -> None:
    md = os.path.join(report_root, "ci_summary.md")
    with open(md, 'w') as f:
        f.write("# CI/CD Summary\n\n")
        f.write(f"**Organization:** {config.ORG_NAME}\n\n")
        f.write(f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("## Repositories\n\n")
        f.write("| Repo | Workflows | External CI | Unpinned Actions | Workflows missing permissions | Uses pull_request_target | Self-hosted |\n")
        f.write("|------|-----------:|-------------|------------------:|-----------------------------:|-------------------------:|-----------:|\n")
        for st in per_repo_stats:
            f.write(
                f"| {st['name']} | {st['wf_count']} | {st['ext_ci']} | {st['unpinned_total']} | {st['wf_missing_permissions']} | "
                f"{st['wf_pr_target']} | {st['wf_self_hosted']} |\n"
            )


# ---------
# Orchestration
# ---------

def process_repo(session: requests.Session, repo: Dict[str, Any], report_dir: str) -> Dict[str, Any]:
    repo_name = repo['name']
    repo_full = repo['full_name']
    logging.info(f"Processing repository: {repo_full}")
    repo_report_dir = os.path.join(report_dir, repo_name)
    os.makedirs(repo_report_dir, exist_ok=True)

    repo_path = clone_repo(repo)
    if not repo_path:
        logging.error(f"Failed to clone repository: {repo_full}")
        return {"name": repo_name, "skipped": True}

    try:
        # Source CI files
        ci_files = find_ci_files(repo_path)
        wf_parsed: List[Dict[str, Any]] = []
        for wf in ci_files.get('github_workflows') or []:
            wf_parsed.append(parse_workflow_file(wf))

        # API: list workflows and recent runs
        owner = repo_full.split('/')[0]
        workflows = list_workflows(session, owner, repo_name)
        runs_by_wf: Dict[int, List[Dict[str, Any]]] = {}
        for wf in workflows:
            wf_id = wf.get('id')
            if isinstance(wf_id, int):
                runs_by_wf[wf_id] = list_recent_runs(session, owner, repo_name, wf_id)

        # Write per-repo report
        write_repo_report(repo, repo_path, repo_report_dir, ci_files, wf_parsed, workflows, runs_by_wf, session)

        # Stats for org summary
        unpinned_total = sum(w.get('uses_unpinned', 0) for w in wf_parsed)
        wf_missing_permissions = sum(1 for w in wf_parsed if w.get('permissions') is None)
        wf_pr_target = sum(1 for w in wf_parsed if 'uses-pull_request_target' in (w.get('risk_flags') or []))
        wf_self_hosted = sum(1 for w in wf_parsed if 'self-hosted-runner' in (w.get('risk_flags') or []))
        ext_count = sum(1 for k in ['jenkins','azure_pipelines','circleci','gitlabci'] if (ci_files.get(k) or []))
        return {
            "name": repo_name,
            "wf_count": len(wf_parsed),
            "ext_ci": ext_count,
            "unpinned_total": unpinned_total,
            "wf_missing_permissions": wf_missing_permissions,
            "wf_pr_target": wf_pr_target,
            "wf_self_hosted": wf_self_hosted,
            "report_dir": repo_report_dir,
        }
    except Exception as e:
        logging.error(f"Error processing repo {repo_full}: {e}")
        return {"name": repo_name, "error": str(e)}
    finally:
        try:
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
        except Exception as e:
            logging.error(f"Error cleaning up {repo_full}: {e}")


def main():
    global config
    try:
        config = CICDConfig()
    except ValueError as e:
        print(f"Error: {e}")
        print("Please set GITHUB_TOKEN and GITHUB_ORG in your environment or .env")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Inventory CI/CD pipelines across GitHub repositories')
    parser.add_argument('--org', type=str, default=config.ORG_NAME, help=f'GitHub organization (default: {config.ORG_NAME})')
    parser.add_argument('--repo', type=str, help='Single repository (owner/repo or repo name)')
    parser.add_argument('--token', type=str, help='Personal access token (overrides env)')
    parser.add_argument('--output-dir', type=str, default=config.REPORT_DIR, help=f'Output directory (default: {config.REPORT_DIR})')
    parser.add_argument('--include-forks', action='store_true', help='Include forked repositories (default: on)')
    parser.add_argument('--include-archived', action='store_true', help='Include archived repositories (default: on)')
    parser.add_argument('-v', '--verbose', action='count', default=1, help='Increase verbosity')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress output')

    args = parser.parse_args()

    if args.quiet:
        args.verbose = 0
    setup_logging(args.verbose)

    if args.token:
        config.GITHUB_TOKEN = args.token
        config.HEADERS["Authorization"] = f"token {config.GITHUB_TOKEN}"

    if args.org and args.org != config.ORG_NAME:
        config.ORG_NAME = args.org
        logging.info(f"Using organization from CLI: {config.ORG_NAME}")

    if args.output_dir != config.REPORT_DIR:
        config.REPORT_DIR = os.path.abspath(args.output_dir)
        logging.info(f"Using output directory: {config.REPORT_DIR}")

    os.makedirs(config.REPORT_DIR, exist_ok=True)

    session = make_session()

    # Targets
    if args.repo:
        repo = get_single_repo(session, args.repo)
        if not repo:
            logging.error(f"Repository not found: {args.repo}")
            sys.exit(1)
        repos = [repo]
        include_forks = True
        include_archived = True
    else:
        logging.info(f"Fetching repositories for {config.ORG_NAME}")
        # Defaults include forks/archived to match scope confirmation
        include_forks = True if not args.include_forks else True
        include_archived = True if not args.include_archived else True
        repos = get_all_repos(session, include_forks=include_forks, include_archived=include_archived)
        if not repos:
            logging.error("No repositories found or accessible with the provided token.")
            sys.exit(1)
        logging.info(f"Found {len(repos)} repositories to scan")

    # Process repos
    stats: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_repo = {executor.submit(process_repo, session, repo, config.REPORT_DIR): repo for repo in repos}
        for future in concurrent.futures.as_completed(future_to_repo):
            repo = future_to_repo[future]
            try:
                st = future.result()
                if st:
                    stats.append(st)
            except Exception as e:
                logging.error(f"Error processing repository {repo['name']}: {e}")

    write_org_summary(config.REPORT_DIR, stats)

    # Clean up temp clone dir
    if hasattr(config, 'CLONE_DIR') and config.CLONE_DIR and os.path.exists(config.CLONE_DIR):
        try:
            shutil.rmtree(config.CLONE_DIR)
        except Exception as e:
            logging.error(f"Error cleaning up temporary directory: {e}")

    logging.info("CI/CD scan completed!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)
