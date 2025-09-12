"""
Safety scanner for Python dependencies.
"""
import json
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from ..base import BaseScanner, ScanResult, Vulnerability, Severity


class SafetyScanner(BaseScanner):
    """Scanner for Python dependencies using Safety."""
    
    def __init__(self):
        """Initialize the Safety scanner."""
        super().__init__(
            name="safety",
            description="Safety checks Python dependencies for known security vulnerabilities"
        )
    
    def is_applicable(self, repo_path: str) -> bool:
        """Check if Safety is applicable to the repository."""
        # Check for common Python dependency files
        requirements_files = [
            'requirements.txt',
            'requirements-dev.txt',
            'requirements/prod.txt',
            'requirements/dev.txt',
            'Pipfile',
            'pyproject.toml',
            'setup.py'
        ]
        
        for file in requirements_files:
            if os.path.exists(os.path.join(repo_path, file)):
                return True
        
        # Check for Python files that might import packages
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith('.py'):
                    return True
        
        return False
    
    def scan(self, repo_path: str, output_dir: str) -> ScanResult:
        """Run Safety scan on the repository."""
        result = ScanResult(scanner_name=self.name, success=False)
        
        # Find requirements file
        requirements_file = self._find_requirements_file(repo_path)
        if not requirements_file:
            result.error = "No requirements file found"
            return result
        
        # Run safety check
        cmd = ["safety", "check", "--json", "--file", requirements_file]
        returncode, stdout, stderr = self._run_command(cmd, cwd=repo_path)
        
        # Save raw output
        output_file = self._save_output(
            stdout or stderr,
            output_dir,
            f"{self.name}_output.json"
        )
        result.raw_output = output_file
        
        # Parse results
        if returncode == 0 and not stdout.strip():
            # No vulnerabilities found
            result.success = True
            return result
        
        try:
            # Safety returns a list of vulnerabilities
            vulns = json.loads(stdout) if stdout else []
            
            for vuln in vulns:
                vulnerability = self._parse_vulnerability(vuln, requirements_file)
                if vulnerability:
                    result.vulnerabilities.append(vulnerability)
            
            result.success = True
            
        except (json.JSONDecodeError, KeyError) as e:
            self.logger.error("Failed to parse Safety output: %s", e)
            result.error = f"Failed to parse Safety output: {str(e)}"
        
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
            'setup.py'
        ]
        
        for file in possible_files:
            path = os.path.join(repo_path, file)
            if os.path.exists(path):
                return path
        
        # If no requirements file found, try to generate one
        return self._generate_requirements_file(repo_path)
    
    def _generate_requirements_file(self, repo_path: str) -> Optional[str]:
        """Generate a requirements.txt file using pip freeze."""
        requirements_path = os.path.join(repo_path, 'requirements-generated.txt')
        
        # Run pip freeze
        cmd = ["pip", "freeze", ">", requirements_path]
        returncode, _, _ = self._run_command(cmd, cwd=repo_path)
        
        if returncode == 0 and os.path.exists(requirements_path):
            return requirements_path
        
        return None
    
    def _parse_vulnerability(self, vuln_data: Dict[str, Any], source_file: str) -> Optional[Vulnerability]:
        """Parse a vulnerability from Safety JSON output."""
        try:
            # Safety vulnerability format
            package = vuln_data.get('dependency', '')
            version = vuln_data.get('installed_version', '')
            cve_id = vuln_data.get('cve')
            
            # Map Safety severity to our Severity enum
            severity_map = {
                'CRITICAL': Severity.CRITICAL,
                'HIGH': Severity.HIGH,
                'MEDIUM': Severity.MEDIUM,
                'LOW': Severity.LOW,
                'INFO': Severity.INFO
            }
            
            severity_str = vuln_data.get('severity', 'UNKNOWN').upper()
            severity = severity_map.get(severity_str, Severity.UNKNOWN)
            
            # Create vulnerability object
            return Vulnerability(
                id=vuln_data.get('id', ''),
                title=f"{package} {version} - {vuln_data.get('advisory', 'Vulnerability')}",
                description=vuln_data.get('advisory', 'No description available'),
                severity=severity,
                package_name=package,
                installed_version=version,
                fixed_versions=vuln_data.get('fixed_versions', []),
                references=vuln_data.get('vulnerable_spec', ''),
                file_path=source_file,
                cve_id=cve_id
            )
            
        except Exception as e:
            self.logger.error("Failed to parse vulnerability: %s", e)
            return None
