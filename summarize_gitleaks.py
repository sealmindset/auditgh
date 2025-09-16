#!/usr/bin/env python3
"""
Summarize Gitleaks scan results into a single markdown report.

This script scans through all gitleaks report files (*_gitleaks.md) in the specified
directory and generates a consolidated summary report.
"""

import os
import re
import glob
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

def parse_gitleaks_report(file_path: str) -> List[Dict[str, str]]:
    """Parse a single gitleaks markdown report file and extract secrets."""
    secrets = []
    current_secret = {}
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        # Extract project name from file path
        project_dir = os.path.basename(os.path.dirname(file_path))
        
        for line in lines:
            line = line.strip()
            
            # Start of a new secret
            if line.startswith('### Secret '):
                if current_secret:
                    secrets.append(current_secret)
                current_secret = {'project': project_dir}
            
            # Extract file path
            elif line.startswith('- **File:** `'):
                file_path = line.split('`', 2)[1]
                current_secret['file'] = os.path.basename(file_path)
            
            # Extract line number
            elif line.startswith('- **Line:** '):
                current_secret['line'] = line.split(':', 1)[1].strip()
            
            # Extract secret details
            elif line.startswith('- **Match:** `'):
                match = line.split('`', 2)[1]
                # Clean up the match to key:value or key=value format
                match = match.strip("'\"`")
                
                # Handle different formats
                if ': ' in match:
                    key, value = match.split(': ', 1)
                    current_secret['key'] = key
                    current_secret['value'] = value.strip("'\"`")
                elif '=' in match:
                    key, value = match.split('=', 1)
                    current_secret['key'] = key
                    current_secret['value'] = value.strip("'\"`")
                else:
                    current_secret['key'] = 'secret'
                    current_secret['value'] = match
        
        # Add the last secret if exists
        if current_secret:
            secrets.append(current_secret)
            
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
    
    return secrets

def categorize_secret(secret: Dict[str, str]) -> str:
    """Categorize the secret based on common patterns."""
    key = secret.get('key', '').lower()
    value = secret.get('value', '').lower()
    
    # Check for common password indicators
    password_indicators = ['password', 'pwd', 'passwd', 'pass']
    if any(indicator in key for indicator in password_indicators):
        return 'password'
    
    # Check for common token indicators
    token_indicators = ['token', 'jwt', 'api[_-]?key', 'access[_-]?key', 'secret[_-]?key']
    if any(re.search(indicator, key) for indicator in token_indicators):
        return 'token'
    
    # Check for common API key patterns
    if re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', value):
        return 'uuid'
    
    # Default to 'secret' if no specific category matches
    return 'secret'

def generate_summary(reports_dir: str, output_file: str):
    """Generate a summary markdown report from all gitleaks reports."""
    # Find all gitleaks markdown files
    pattern = os.path.join(reports_dir, '**/*_gitleaks.md')
    report_files = glob.glob(pattern, recursive=True)
    
    if not report_files:
        print(f"No gitleaks report files found in {reports_dir}")
        return
    
    # Parse all reports
    all_secrets = []
    for report_file in report_files:
        secrets = parse_gitleaks_report(report_file)
        all_secrets.extend(secrets)
    
    if not all_secrets:
        print("No secrets found in any reports.")
        return
    
    # Categorize secrets
    secret_categories = defaultdict(int)
    for secret in all_secrets:
        category = categorize_secret(secret)
        secret_categories[category] += 1
    
    # Count unique projects with secrets
    projects_with_secrets = len({s['project'] for s in all_secrets if 'project' in s})
    
    # Generate markdown report
    with open(output_file, 'w', encoding='utf-8') as f:
        # Header
        f.write("# Gitleaks Scan Summary\n\n")
        
        # Summary statistics
        f.write("## Summary Statistics\n\n")
        f.write(f"- **Total projects with exposed secrets:** {projects_with_secrets}\n")
        f.write(f"- **Total secrets found:** {len(all_secrets)}\n")
        
        # Secret categories
        f.write("\n## Secret Categories\n\n")
        for category, count in sorted(secret_categories.items()):
            f.write(f"- **{category.capitalize()}s:** {count}\n")
        
        # Detailed findings
        f.write("\n## Detailed Findings\n\n")
        f.write("| Project | Line | File | Secret |\n")
        f.write("|---------|------|------|--------|\n")
        
        # Sort secrets by project, file, and line number (handle non-numeric line numbers)
        def get_sort_key(secret):
            try:
                line = int(secret.get('line', 0))
            except (ValueError, TypeError):
                line = 0
            return (secret.get('project', ''), secret.get('file', ''), line)
        
        all_secrets.sort(key=get_sort_key)
        
        for secret in all_secrets:
            project = secret.get('project', 'N/A')
            line = secret.get('line', 'N/A')
            file_name = secret.get('file', 'N/A')
            key = secret.get('key', 'secret')
            value = secret.get('value', '')
            
            # Truncate long values for better readability
            if len(value) > 50:
                value = value[:47] + '...'
            
            # Escape pipe characters in the secret value
            value = value.replace('|', '&#124;')
            
            f.write(f"| {project} | {line} | {file_name} | `{key}:{value}` |\n")
        
        # Footer
        f.write("\n---\n")
        f.write("*This report was automatically generated by summarize_gitleaks.py*\n")
    
    print(f"Summary report generated: {output_file}")
    print(f"Total projects with secrets: {projects_with_secrets}")
    print(f"Total secrets found: {len(all_secrets)}")
    for category, count in secret_categories.items():
        print(f"- {category.capitalize()}s: {count}")

def main():
    import argparse
    import traceback
    
    try:
        print("Starting gitleaks summary generation...")
        
        parser = argparse.ArgumentParser(description='Generate a summary report from gitleaks scan results')
        parser.add_argument('--input-dir', '-i', default='gitleaked', 
                          help='Directory containing the gitleaks reports (default: gitleaked)')
        parser.add_argument('--output-file', '-o', default='gitleaks_summary.md',
                          help='Output markdown file (default: gitleaks_summary.md)')
        parser.add_argument('--verbose', '-v', action='store_true',
                          help='Enable verbose output')
        
        args = parser.parse_args()
        
        if args.verbose:
            print(f"Input directory: {os.path.abspath(args.input_dir)}")
            print(f"Output file: {os.path.abspath(args.output_file)}")
        
        # Ensure input directory exists
        if not os.path.isdir(args.input_dir):
            print(f"Error: Input directory does not exist: {args.input_dir}")
            return 1
        
        # Ensure output directory exists
        output_dir = os.path.dirname(os.path.abspath(args.output_file)) or '.'
        os.makedirs(output_dir, exist_ok=True)
        
        if args.verbose:
            print(f"Generating summary report...")
        
        generate_summary(args.input_dir, args.output_file)
        
        if args.verbose:
            print("Summary report generated successfully!")
        
        return 0
        
    except Exception as e:
        print(f"Error: {str(e)}")
        if args.verbose:
            print("\nTraceback:")
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
