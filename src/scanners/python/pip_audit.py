"""
Pip Audit scanner for Python dependencies.
"""
import json
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from ..base import BaseScanner, ScanResult, Vulnerability, Severity


class PipAuditScanner(BaseScanner):
    """Scanner for Python dependencies using pip-audit."""
    
    def __init__(self):
        """Initialize the pip-audit scanner."""
        super().__init__(
            name="pip-audit",
            description="Scan Python dependencies for known vulnerabilities using pip-audit"
        )
    
    def is_applicable(self, repo_path: str) -> bool:
        """Check if pip-audit is applicable to the repository."""
        # Check for Python dependency files
        python_files = [
            'requirements.txt',
            'requirements-dev.txt',
            'requirements/prod.txt',
            'requirements/dev.txt',
            'Pipfile',
            'pyproject.toml',
            'setup.py',
            'setup.cfg'
        ]
        
        for file in python_files:
            if os.path.exists(os.path.join(repo_path, file)):
                return True
        
        # Check for Python files that might import packages
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith('.py'):
                    return True
        
        return False
    
    def scan(self, repo_path: str, output_dir: str) -> ScanResult:
        """Run pip-audit scan on the repository."""
        result = ScanResult(scanner_name=self.name, success=False)
        
        # Find requirements file or use the current environment
        requirements_file = self._find_requirements_file(repo_path)
        
        # Build the pip-audit command
        cmd = ["pip-audit", "--format", "json"]
        
        if requirements_file:
            cmd.extend(["--requirement", requirements_file])
        else:
            # Scan the current environment if no requirements file is found
            cmd.append("--environment")
        
        # Run pip-audit
        returncode, stdout, stderr = self._run_command(cmd, cwd=repo_path)
        
        # Save raw output
        output_file = self._save_output(
            stdout or stderr,
            output_dir,
            f"{self.name}_output.json"
        )
        result.raw_output = output_file
        
        # Parse results
        if returncode not in [0, 1]:  # pip-audit returns 1 when vulnerabilities are found
            result.error = f"pip-audit failed with return code {returncode}: {stderr}"
            return result
        
        try:
            # Parse the JSON output
            data = json.loads(stdout) if stdout else {}
            
            # Extract vulnerabilities
            if isinstance(data, dict) and 'vulnerabilities' in data:
                for vuln in data['vulnerabilities']:
                    vulnerability = self._parse_vulnerability(vuln, requirements_file)
                    if vulnerability:
                        result.vulnerabilities.append(vulnerability)
            
            result.success = True
            
        except (json.JSONDecodeError, KeyError) as e:
            self.logger.error("Failed to parse pip-audit output: %s", e)
            result.error = f"Failed to parse pip-audit output: {str(e)}"
        
        return result
    
    def _find_requirements_file(self, repo_path: str) -> Optional[str]:
        """Find the most appropriate requirements file to scan."""
        # Check common requirements file locations
        possible_files = [
            'requirements.txt',
            'requirements/prod.txt',
            'requirements/requirements.txt',
            'requirements.in',
            'Pipfile',
            'pyproject.toml',
            'setup.py',
            'setup.cfg'
        ]
        
        for file in possible_files:
            path = os.path.join(repo_path, file)
            if os.path.exists(path):
                return path
        
        return None
    
    def _parse_vulnerability(self, vuln_data: Dict[str, Any], source_file: Optional[str]) -> Optional[Vulnerability]:
        """Parse a vulnerability from pip-audit JSON output."""
        try:
            # Extract package information
            package = vuln_data.get('name', '')
            version = vuln_data.get('installed_version', '')
            
            # Get the first CVE ID if available
            cve_id = None
            if vuln_data.get('aliases'):
                for alias in vuln_data['aliases']:
                    if alias.startswith('CVE-'):
                        cve_id = alias
                        break
            
            # Map pip-audit severity to our Severity enum
            severity_map = {
                'CRITICAL': Severity.CRITICAL,
                'HIGH': Severity.HIGH,
                'MODERATE': Severity.MEDIUM,
                'MEDIUM': Severity.MEDIUM,
                'LOW': Severity.LOW,
                'INFO': Severity.INFO
            }
            
            severity_str = vuln_data.get('severity', 'UNKNOWN').upper()
            severity = severity_map.get(severity_str, Severity.UNKNOWN)
            
            # Get fixed versions
            fixed_versions = []
            if 'fix_versions' in vuln_data:
                fixed_versions = vuln_data['fix_versions']
            
            # Get references
            references = []
            if 'references' in vuln_data:
                for ref in vuln_data['references']:
                    if 'url' in ref:
                        references.append(ref['url'])
            
            # Create vulnerability object
            return Vulnerability(
                id=vuln_data.get('id', cve_id or ''),
                title=f"{package} {version} - {vuln_data.get('description', 'Vulnerability').split('.')[0]}",
                description=vuln_data.get('description', 'No description available'),
                severity=severity,
                package_name=package,
                installed_version=version,
                fixed_versions=fixed_versions,
                references=references,
                file_path=source_file or '',
                cve_id=cve_id
            )
            
        except Exception as e:
            self.logger.error("Failed to parse vulnerability: %s", e)
            return None
