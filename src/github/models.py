"""
Data models for GitHub API responses.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class Repository:
    """Repository information from GitHub API."""
    name: str
    full_name: str
    html_url: str
    description: Optional[str] = None
    language: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    pushed_at: Optional[str] = None
    size: int = 0
    stargazers_count: int = 0
    watchers_count: int = 0
    forks_count: int = 0
    open_issues_count: int = 0
    is_fork: bool = False
    is_archived: bool = False
    is_disabled: bool = False
    default_branch: str = "main"

    @property
    def last_updated(self) -> Optional[datetime]:
        """Get the last update time as a datetime object."""
        if self.pushed_at:
            return datetime.fromisoformat(self.pushed_at.replace('Z', '+00:00'))
        return None


@dataclass
class Contributor:
    """Repository contributor information."""
    login: str
    contributions: int
    avatar_url: Optional[str] = None
    html_url: Optional[str] = None
    type: str = "User"
    site_admin: bool = False


@dataclass
class LanguageStats:
    """Repository language statistics."""
    languages: Dict[str, int] = field(default_factory=dict)
    total_bytes: int = 0

    def add_language(self, language: str, bytes_count: int) -> None:
        """Add language data to the stats."""
        self.languages[language] = bytes_count
        self.total_bytes += bytes_count

    def get_percentage(self, language: str) -> float:
        """Get the percentage of code in a specific language."""
        if not self.total_bytes or language not in self.languages:
            return 0.0
        return (self.languages[language] / self.total_bytes) * 100
