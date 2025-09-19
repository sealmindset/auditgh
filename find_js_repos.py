#!/usr/bin/env python3
"""
Search through markdown files in oss_reports to find repositories with package.json or package-lock.json.
"""
import os
import re
from pathlib import Path

def find_markdown_files(directory: str) -> list:
    """Find all markdown files in the specified directory."""
    md_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.md') and '_oss.md' in file:
                md_files.append(os.path.join(root, file))
    return md_files

def search_for_package_files(md_file: str) -> list:
    """Search a markdown file for package.json or package-lock.json mentions."""
    package_mentions = []
    try:
        with open(md_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            # Look for package.json or package-lock.json mentions
            matches = re.findall(r'(package(?:-lock)?\.json)', content, re.IGNORECASE)
            if matches:
                # Get the repo name from the file path
                repo_name = os.path.basename(os.path.dirname(md_file))
                return [repo_name] + list(set(matches))  # Remove duplicates
    except Exception as e:
        print(f"Error processing {md_file}: {e}")
    return []

def main():
    oss_reports_dir = os.path.join(os.path.dirname(__file__), 'oss_reports')
    if not os.path.exists(oss_reports_dir):
        print(f"Error: {oss_reports_dir} directory not found")
        return
    
    print("Searching for repositories with package.json or package-lock.json...\n")
    
    md_files = find_markdown_files(oss_reports_dir)
    if not md_files:
        print("No markdown files found in oss_reports directory.")
        return
    
    results = {}
    for md_file in md_files:
        package_info = search_for_package_files(md_file)
        if package_info and len(package_info) > 1:  # At least repo name and one package file
            repo_name = package_info[0]
            package_files = package_info[1:]
            results[repo_name] = package_files
    
    # Print results
    if results:
        print("Repositories with package.json or package-lock.json:")
        print("-" * 60)
        for repo, packages in sorted(results.items()):
            print(f"{repo}:")
            for pkg in sorted(packages):
                print(f"  - {pkg}")
            print()
    else:
        print("No repositories with package.json or package-lock.json found in markdown files.")

if __name__ == "__main__":
    main()
