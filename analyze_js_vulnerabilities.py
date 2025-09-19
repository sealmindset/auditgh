#!/usr/bin/env python3
"""
Analyze OSS reports for JavaScript dependencies and their vulnerabilities.
"""
import os
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Base directory containing OSS reports
REPORTS_DIR = "oss_reports"

def extract_js_vulnerabilities(report_path: str) -> Tuple[Dict, List[Dict]]:
    """Extract JavaScript dependencies and vulnerabilities from an OSS report."""
    js_deps = {}
    vulnerabilities = []
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Look for JavaScript/Node.js dependencies section
            js_section_match = re.search(
                r'## JavaScript/Node\.js Dependencies\n\n(.*?)(?:\n## |\Z)', 
                content, 
                re.DOTALL
            )
            
            if js_section_match:
                js_section = js_section_match.group(1)
                
                # Extract dependencies and their versions
                dep_matches = re.finditer(
                    r'- \*\*(.*?)\*\*: (\S+)', 
                    js_section
                )
                
                for match in dep_matches:
                    dep_name = match.group(1).strip()
                    dep_version = match.group(2).strip()
                    js_deps[dep_name] = dep_version
                
                # Extract vulnerabilities if present
                vuln_section = re.search(
                    r'### Vulnerabilities\n\n(.*?)(?:\n## |\Z)', 
                    content, 
                    re.DOTALL
                )
                
                if vuln_section:
                    vuln_entries = re.finditer(
                        r'#### (.*?)\n\*\*Severity\*\*: (.*?)\n\*\*CVSS\*\*: (.*?)\n\*\*Fixed in\*\*: (.*?)\n\*\*Affected versions\*\*: (.*?)\n\*\*Description\*\*: (.*?)(?=\n\*\*|\Z)',
                        vuln_section.group(1),
                        re.DOTALL
                    )
                    
                    for vuln in vuln_entries:
                        vulnerabilities.append({
                            'package': vuln.group(1).strip(),
                            'severity': vuln.group(2).strip(),
                            'cvss': vuln.group(3).strip(),
                            'fixed_in': vuln.group(4).strip(),
                            'affected_versions': vuln.group(5).strip(),
                            'description': vuln.group(6).strip()
                        })
    
    except Exception as e:
        print(f"Error processing {report_path}: {str(e)}")
    
    return js_deps, vulnerabilities

def main():
    """Main function to analyze all OSS reports."""
    reports_dir = Path(REPORTS_DIR)
    results = {}
    
    # Find all OSS report files
    report_files = list(reports_dir.glob('**/*_oss.md'))
    
    print(f"Found {len(report_files)} OSS reports to analyze...\n")
    
    # Process each report
    for report_path in report_files:
        repo_name = report_path.parent.name
        print(f"Analyzing {repo_name}...")
        
        js_deps, vulnerabilities = extract_js_vulnerabilities(str(report_path))
        
        if js_deps or vulnerabilities:
            results[repo_name] = {
                'js_dependencies': js_deps,
                'vulnerabilities': vulnerabilities
            }
    
    # Generate summary
    print("\n=== JavaScript Dependencies and Vulnerabilities Report ===\n")
    
    vulnerable_repos = []
    total_vulns = 0
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    
    for repo, data in results.items():
        if data['vulnerabilities']:
            vulnerable_repos.append(repo)
            total_vulns += len(data['vulnerabilities'])
            
            # Count vulnerabilities by severity
            for vuln in data['vulnerabilities']:
                severity = vuln['severity'].split()[0]  # Get just the severity level
                if severity in severity_counts:
                    severity_counts[severity] += 1
    
    # Print summary
    print(f"Total repositories with JavaScript dependencies: {len(results)}")
    print(f"Repositories with vulnerabilities: {len(vulnerable_repos)}")
    print(f"Total vulnerabilities found: {total_vulns}")
    print("\nVulnerabilities by severity:")
    for severity, count in severity_counts.items():
        if count > 0:
            print(f"- {severity}: {count}")
    
    # Print detailed report for each vulnerable repository
    if vulnerable_repos:
        print("\n=== Vulnerable Repositories ===\n")
        
        for repo in vulnerable_repos:
            data = results[repo]
            print(f"\nRepository: {repo}")
            print(f"Dependencies: {', '.join(data['js_dependencies'].keys())}")
            print(f"Vulnerabilities: {len(data['vulnerabilities'])}")
            
            for i, vuln in enumerate(data['vulnerabilities'], 1):
                print(f"\n  {i}. {vuln['package']} ({vuln['severity']})")
                print(f"     Affected versions: {vuln['affected_versions']}")
                print(f"     Fixed in: {vuln['fixed_in']}")
                print(f"     CVSS: {vuln['cvss']}")
                print(f"     Description: {vuln['description']}\n")
    
    # Save detailed report to a file
    with open('javascript_vulnerabilities_report.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\nDetailed report saved to: javascript_vulnerabilities_report.json")

if __name__ == "__main__":
    main()
