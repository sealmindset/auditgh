#!/usr/bin/env python3
"""
Analyze OSS reports for npm-related vulnerabilities.
"""
import os
import json
import re
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple

def find_oss_reports(directory: str) -> List[str]:
    """Find all OSS report markdown files."""
    return [
        os.path.join(root, file)
        for root, _, files in os.walk(directory)
        for file in files
        if file.endswith('_oss.md')
    ]

def extract_npm_vulnerabilities(report_path: str) -> Dict:
    """Extract npm-related vulnerabilities from a report."""
    result = {
        'repo': os.path.basename(os.path.dirname(report_path)).replace('_oss.md', ''),
        'npm_vulnerabilities': [],
        'total_vulnerabilities': 0
    }
    
    try:
        with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Look for npm audit or package.json related vulnerabilities
            npm_vuln_sections = re.findall(
                r'(?i)(?:npm|node\.?js|package\.json).*?vulnerabilit[^#]*?(?=#|\Z)',
                content,
                re.DOTALL
            )
            
            for section in npm_vuln_sections:
                # Extract vulnerability details
                vulns = re.finditer(
                    r'(?i)(CVE-\d+-\d+)|(GHSA-[\w-]+)|(\b(high|critical|medium|low)\b.*?vulnerability)',
                    section
                )
                
                for vuln in vulns:
                    result['npm_vulnerabilities'].append({
                        'id': vuln.group(1) or vuln.group(2) or 'Unknown',
                        'severity': vuln.group(3) or 'Unknown',
                        'context': ' '.join(vuln.group(0).split()[:20]) + '...'  # First 20 words for context
                    })
            
            # Count total vulnerabilities
            vuln_counts = re.findall(r'(\d+)\s+vulnerabilit', content, re.IGNORECASE)
            if vuln_counts:
                result['total_vulnerabilities'] = sum(map(int, vuln_counts))
                
    except Exception as e:
        print(f"Error processing {report_path}: {e}")
    
    return result

def main():
    oss_reports_dir = os.path.join(os.path.dirname(__file__), 'oss_reports')
    if not os.path.exists(oss_reports_dir):
        print(f"Error: {oss_reports_dir} directory not found")
        return
    
    print("Analyzing OSS reports for npm-related vulnerabilities...\n")
    
    reports = find_oss_reports(oss_reports_dir)
    if not reports:
        print("No OSS report files found.")
        return
    
    results = []
    for report in reports:
        result = extract_npm_vulnerabilities(report)
        if result['npm_vulnerabilities'] or result['total_vulnerabilities'] > 0:
            results.append(result)
    
    # Print results
    if results:
        print("Repositories with npm-related vulnerabilities:")
        print("=" * 80)
        
        for result in sorted(results, key=lambda x: len(x['npm_vulnerabilities']), reverse=True):
            print(f"\nRepository: {result['repo']}")
            print(f"Total Vulnerabilities: {result['total_vulnerabilities']}")
            print(f"npm-related Vulnerabilities: {len(result['npm_vulnerabilities'])}")
            
            if result['npm_vulnerabilities']:
                print("\n  npm-related Vulnerabilities:")
                for i, vuln in enumerate(result['npm_vulnerabilities'], 1):
                    print(f"  {i}. ID: {vuln['id']}")
                    print(f"     Severity: {vuln['severity']}")
                    print(f"     Context: {vuln['context']}")
            
            print("-" * 80)
    else:
        print("No npm-related vulnerabilities found in any reports.")
    
    # Save detailed report
    with open('npm_vulnerability_report.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\nDetailed report saved to: npm_vulnerability_report.json")

if __name__ == "__main__":
    main()
