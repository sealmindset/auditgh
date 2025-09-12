"""
Base scanner class for security scanners.
"""
import abc
import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


@dataclass
class Vulnerability:
    """Vulnerability information."""
    id: str
    title: str
    description: str
    severity: Severity
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_versions: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Result of a security scan."""
    scanner_name: str
    success: bool
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    error: Optional[str] = None
    raw_output: Optional[str] = None
    
    @property
    def has_vulnerabilities(self) -> bool:
        """Check if any vulnerabilities were found."""
        return len(self.vulnerabilities) > 0
    
    @property
    def critical_count(self) -> int:
        """Get the number of critical vulnerabilities."""
        return self._count_by_severity(Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        """Get the number of high severity vulnerabilities."""
        return self._count_by_severity(Severity.HIGH)
    
    @property
    def medium_count(self) -> int:
        """Get the number of medium severity vulnerabilities."""
        return self._count_by_severity(Severity.MEDIUM)
    
    @property
    def low_count(self) -> int:
        """Get the number of low severity vulnerabilities."""
        return self._count_by_severity(Severity.LOW)
    
    @property
    def info_count(self) -> int:
        """Get the number of informational findings."""
        return self._count_by_severity(Severity.INFO)
    
    def _count_by_severity(self, severity: Severity) -> int:
        """Count vulnerabilities by severity."""
        return sum(1 for v in self.vulnerabilities if v.severity == severity)


class BaseScanner(abc.ABC):
    """Abstract base class for all security scanners."""
    
    def __init__(self, name: str, description: str = ""):
        """Initialize the scanner.
        
        Args:
            name: Scanner name (e.g., "safety", "npm-audit")
            description: Optional description of the scanner
        """
        self.name = name
        self.description = description
        self.logger = logging.getLogger(f"scanner.{name.lower()}")
    
    @abc.abstractmethod
    def is_applicable(self, repo_path: str) -> bool:
        """Check if this scanner is applicable to the given repository.
        
        Args:
            repo_path: Path to the repository to scan
            
        Returns:
            bool: True if the scanner is applicable, False otherwise
        """
        pass
    
    @abc.abstractmethod
    def scan(self, repo_path: str, output_dir: str) -> ScanResult:
        """Run the security scan on the repository.
        
        Args:
            repo_path: Path to the repository to scan
            output_dir: Directory to store scan results and reports
            
        Returns:
            ScanResult: The scan results
        """
        pass
    
    def _run_command(self, command: List[str], cwd: str = None,
                    env: Dict[str, str] = None, timeout: int = 300) -> Tuple[int, str, str]:
        """Run a shell command and return the results.
        
        Args:
            command: Command to run as a list of strings
            cwd: Working directory for the command
            env: Environment variables to set for the command
            timeout: Command timeout in seconds
            
        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        try:
            self.logger.debug("Running command: %s", " ".join(command))
            result = subprocess.run(
                command,
                cwd=cwd,
                env=env or os.environ,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as e:
            self.logger.error("Command timed out after %d seconds: %s", timeout, e)
            return -1, "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            self.logger.exception("Error running command: %s", e)
            return -1, "", str(e)
    
    def _save_output(self, content: str, output_dir: str, filename: str) -> str:
        """Save scan output to a file.
        
        Args:
            content: Content to save
            output_dir: Directory to save the file in
            filename: Name of the file to create
            
        Returns:
            Path to the saved file
        """
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self.logger.debug("Saved output to %s", output_path)
            return output_path
        except Exception as e:
            self.logger.error("Failed to save output to %s: %s", output_path, e)
            return ""
    
    def _load_json(self, content: str) -> Any:
        """Safely parse JSON content."""
        try:
            return json.loads(content) if content else {}
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse JSON: %s", e)
            return {}
