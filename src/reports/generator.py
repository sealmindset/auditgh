"""
Report generation for security scan results.
"""
import json
import logging
import os
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from jinja2 import Environment, FileSystemLoader

from ..scanners.base import ScanResult, Vulnerability, Severity


class ReportFormat(str, Enum):
    """Supported report formats."""
    MARKDOWN = "markdown"
    JSON = "json"
    HTML = "html"
    CONSOLE = "console"


class ReportGenerator:
    """Generate reports from security scan results."""
    
    def __init__(self, output_dir: str, format: ReportFormat = ReportFormat.MARKDOWN):
        """Initialize the report generator.
        
        Args:
            output_dir: Directory to save reports
            format: Output format for reports
        """
        self.output_dir = output_dir
        self.format = format
        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Configure logger
        self.logger = logging.getLogger(__name__)
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_report(
        self,
        repo_name: str,
        scan_results: List[ScanResult],
        repo_metadata: Optional[Dict[str, Any]] = None,
        custom_title: Optional[str] = None
    ) -> str:
        """Generate a report for the scan results.
        
        Args:
            repo_name: Name of the repository
            scan_results: List of scan results
            repo_metadata: Additional repository metadata
            custom_title: Custom title for the report
            
        Returns:
            Path to the generated report file
        """
        # Prepare data for the report
        report_data = self._prepare_report_data(repo_name, scan_results, repo_metadata, custom_title)
        
        # Generate report based on format
        if self.format == ReportFormat.JSON:
            return self._generate_json_report(report_data)
        elif self.format == ReportFormat.HTML:
            return self._generate_html_report(report_data)
        elif self.format == ReportFormat.CONSOLE:
            return self._generate_console_report(report_data)
        else:  # Default to Markdown
            return self._generate_markdown_report(report_data)
    
    def _prepare_report_data(
        self,
        repo_name: str,
        scan_results: List[ScanResult],
        repo_metadata: Optional[Dict[str, Any]] = None,
        custom_title: Optional[str] = None
    ) -> Dict[str, Any]:
        """Prepare data for the report."""
        # Calculate summary statistics
        total_vulnerabilities = sum(len(r.vulnerabilities) for r in scan_results)
        critical_vulns = sum(r.critical_count for r in scan_results)
        high_vulns = sum(r.high_count for r in scan_results)
        medium_vulns = sum(r.medium_count for r in scan_results)
        low_vulns = sum(r.low_count for r in scan_results)
        info_vulns = sum(r.info_count for r in scan_results)
        
        # Get current timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Prepare scan results data
        results_data = []
        for result in scan_results:
            vulns = []
            for vuln in result.vulnerabilities:
                vuln_dict = asdict(vuln)
                # Convert enum to string for serialization
                vuln_dict['severity'] = vuln.severity.value
                vulns.append(vuln_dict)
            
            results_data.append({
                'scanner_name': result.scanner_name,
                'success': result.success,
                'error': result.error,
                'vulnerability_count': len(result.vulnerabilities),
                'vulnerabilities': vulns,
                'has_vulnerabilities': result.has_vulnerabilities,
                'critical_count': result.critical_count,
                'high_count': result.high_count,
                'medium_count': result.medium_count,
                'low_count': result.low_count,
                'info_count': result.info_count
            })
        
        # Prepare report data
        return {
            'title': custom_title or f'Security Scan Report - {repo_name}',
            'repo_name': repo_name,
            'timestamp': timestamp,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulns': critical_vulns,
            'high_vulns': high_vulns,
            'medium_vulns': medium_vulns,
            'low_vulns': low_vulns,
            'info_vulns': info_vulns,
            'scan_results': results_data,
            'repo_metadata': repo_metadata or {},
            'has_vulnerabilities': total_vulnerabilities > 0
        }
    
    def _generate_markdown_report(self, data: Dict[str, Any]) -> str:
        """Generate a markdown report."""
        template = self.env.get_template('report.md.j2')
        report_content = template.render(**data)
        
        # Save to file
        filename = f"security_report_{data['repo_name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        output_path = os.path.join(self.output_dir, filename)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return output_path
    
    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate an HTML report."""
        template = self.env.get_template('report.html.j2')
        report_content = template.render(**data)
        
        # Save to file
        filename = f"security_report_{data['repo_name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        output_path = os.path.join(self.output_dir, filename)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return output_path
    
    def _generate_json_report(self, data: Dict[str, Any]) -> str:
        """Generate a JSON report."""
        # Convert data to JSON-serializable format
        def convert(obj):
            if isinstance(obj, (str, int, float, bool, type(None))):
                return obj
            elif isinstance(obj, list):
                return [convert(item) for item in obj]
            elif isinstance(obj, dict):
                return {str(k): convert(v) for k, v in obj.items()}
            elif hasattr(obj, '__dict__'):
                return convert(obj.__dict__)
            else:
                return str(obj)
        
        json_data = convert(data)
        
        # Save to file
        filename = f"security_report_{data['repo_name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output_path = os.path.join(self.output_dir, filename)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2)
        
        return output_path
    
    def _generate_console_report(self, data: Dict[str, Any]) -> str:
        """Generate a console-friendly report."""
        # This is a simplified version for console output
        lines = [
            f"\n{'=' * 80}",
            f"{data['title']}",
            f"Generated: {data['timestamp']}",
            "=" * 80,
            "\nSummary:",
            f"  • Critical: {data['critical_vulns']}",
            f"  • High: {data['high_vulns']}",
            f"  • Medium: {data['medium_vulns']}",
            f"  • Low: {data['low_vulns']}",
            f"  • Info: {data['info_vulns']}",
            "\n" + "=" * 80 + "\n"
        ]
        
        # Add details for each scanner
        for result in data['scan_results']:
            if result['has_vulnerabilities']:
                lines.extend([
                    f"\n{result['scanner_name'].upper()} - {len(result['vulnerabilities'])} vulnerabilities found:",
                    "-" * 60
                ])
                
                for vuln in result['vulnerabilities']:
                    lines.extend([
                        f"\n[{vuln['severity']}] {vuln['title']}",
                        f"Package: {vuln.get('package_name', 'N/A')} ({vuln.get('installed_version', 'N/A')})",
                        f"Fixed in: {', '.join(vuln.get('fixed_versions', ['Not specified']))}",
                        f"File: {vuln.get('file_path', 'N/A')}",
                        f"Description: {vuln['description']}",
                        "-" * 60
                    ])
        
        # Add footer
        if data['has_vulnerabilities']:
            lines.append("\nFor detailed information, please refer to the full report.")
        else:
            lines.append("\nNo vulnerabilities found!")
        
        # Save to file
        filename = f"security_report_{data['repo_name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        output_path = os.path.join(self.output_dir, filename)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        
        # Log the console output
        for line in lines:
            self.logger.info(line)
        
        return output_path
