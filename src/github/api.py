"""
GitHub API client for AuditGH.
"""
import logging
import time
from typing import Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .models import Repository, Contributor, LanguageStats


class GitHubAPI:
    """GitHub API client with rate limiting and retry logic."""
    
    BASE_URL = "https://api.github.com"
    
    def __init__(self, token: str, org_name: str, max_retries: int = 3):
        """Initialize the GitHub API client.
        
        Args:
            token: GitHub personal access token
            org_name: GitHub organization name
            max_retries: Maximum number of retries for failed requests
        """
        self.token = token
        self.org_name = org_name
        self.max_retries = max_retries
        self.session = self._create_session()
        self.logger = logging.getLogger(__name__)
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic and authentication."""
        session = requests.Session()
        retries = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504, 429],
            allowed_methods=["GET", "POST"]
        )
        session.mount("https://", HTTPAdapter(max_retries=retries))
        session.headers.update({
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AuditGH/1.0.0"
        })
        return session
    
    def _handle_rate_limit(self, response: requests.Response) -> None:
        """Handle GitHub API rate limiting."""
        if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers:
            remaining = int(response.headers['X-RateLimit-Remaining'])
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
            
            if remaining == 0:
                sleep_time = max(0, reset_time - time.time() + 5)  # Add 5s buffer
                self.logger.warning(
                    "Rate limit reached. Sleeping for %.1f seconds until %s",
                    sleep_time,
                    time.ctime(reset_time)
                )
                time.sleep(sleep_time)
                return True
        return False
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make an authenticated request to the GitHub API with rate limit handling."""
        url = f"{self.BASE_URL}/{endpoint.lstrip('/')}"
        
        while True:
            response = self.session.request(method, url, **kwargs)
            
            if not self._handle_rate_limit(response):
                break
        
        response.raise_for_status()
        return response
    
    def get_repositories(self, include_forks: bool = False, 
                        include_archived: bool = False) -> List[Repository]:
        """Get all repositories for the organization."""
        repos = []
        page = 1
        per_page = 100  # Maximum allowed by GitHub API
        
        while True:
            params = {
                'per_page': per_page,
                'page': page,
                'type': 'all'  # Get all repository types
            }
            
            response = self._make_request(
                'GET',
                f'orgs/{self.org_name}/repos',
                params=params
            )
            
            batch = response.json()
            if not batch:
                break
                
            for repo_data in batch:
                # Skip forks and archived repos based on parameters
                if (not include_forks and repo_data.get('fork')) or \
                   (not include_archived and repo_data.get('archived')):
                    continue
                    
                repo = Repository(
                    name=repo_data['name'],
                    full_name=repo_data['full_name'],
                    html_url=repo_data['html_url'],
                    description=repo_data['description'],
                    language=repo_data['language'],
                    created_at=repo_data['created_at'],
                    updated_at=repo_data['updated_at'],
                    pushed_at=repo_data['pushed_at'],
                    size=repo_data['size'],
                    stargazers_count=repo_data['stargazers_count'],
                    watchers_count=repo_data['watchers_count'],
                    forks_count=repo_data['forks_count'],
                    open_issues_count=repo_data['open_issues_count'],
                    is_fork=repo_data['fork'],
                    is_archived=repo_data['archived'],
                    is_disabled=repo_data['disabled'],
                    default_branch=repo_data['default_branch']
                )
                repos.append(repo)
            
            # Check if we've reached the last page
            if 'next' not in response.links:
                break
                
            page += 1
        
        return repos
    
    def get_contributors(self, repo_name: str) -> List[Contributor]:
        """Get top contributors for a repository."""
        try:
            response = self._make_request(
                'GET',
                f'repos/{self.org_name}/{repo_name}/contributors',
                params={'per_page': 5}  # Get top 5 contributors
            )
            
            contributors = []
            for contributor_data in response.json():
                contributor = Contributor(
                    login=contributor_data['login'],
                    contributions=contributor_data['contributions'],
                    avatar_url=contributor_data.get('avatar_url'),
                    html_url=contributor_data.get('html_url'),
                    type=contributor_data.get('type', 'User'),
                    site_admin=contributor_data.get('site_admin', False)
                )
                contributors.append(contributor)
                
            return contributors
            
        except requests.HTTPError as e:
            if e.response.status_code == 403:
                self.logger.warning("Insufficient permissions to fetch contributors for %s", repo_name)
            else:
                self.logger.warning("Failed to fetch contributors for %s: %s", repo_name, e)
            return []
    
    def get_languages(self, repo_name: str) -> LanguageStats:
        """Get language statistics for a repository."""
        try:
            response = self._make_request(
                'GET',
                f'repos/{self.org_name}/{repo_name}/languages'
            )
            
            stats = LanguageStats()
            for language, bytes_count in response.json().items():
                stats.add_language(language, bytes_count)
                
            return stats
            
        except requests.HTTPError as e:
            self.logger.warning("Failed to fetch languages for %s: %s", repo_name, e)
            return LanguageStats()
    
    def get_commit_activity(self, repo_name: str, since: str = None) -> Dict:
        """Get commit activity for a repository."""
        params = {}
        if since:
            params['since'] = since
            
        try:
            response = self._make_request(
                'GET',
                f'repos/{self.org_name}/{repo_name}/commits',
                params=params
            )
            return response.json()
            
        except requests.HTTPError as e:
            self.logger.warning("Failed to fetch commit activity for %s: %s", repo_name, e)
            return []
