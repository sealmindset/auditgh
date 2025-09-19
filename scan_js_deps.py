#!/usr/bin/env python3
"""
Scan repositories for JavaScript dependencies and check for vulnerabilities.
"""
import os
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set

# Directories to scan for JavaScript projects
SCAN_DIRS = [
    ".",  # Current directory
    "repos",  # Common directory for cloned repositories
]

def find_package_json_files(directory: str) -> List[str]:
    """Find all package.json files in the given directory."""
    package_jsons = []
    for root, _, files in os.walk(directory):
        if "node_modules" in root:
            continue
        if "package.json" in files:
            package_jsons.append(os.path.join(root, "package.json"))
    return package_jsons

def analyze_package_json(package_json_path: str) -> Optional[Dict]:
    """Analyze a package.json file for dependencies and potential issues."""
    try:
        with open(package_json_path, 'r') as f:
            data = json.load(f)
            
            # Extract relevant information
            result = {
                'path': package_json_path,
                'name': data.get('name', 'unknown'),
                'version': data.get('version', 'unknown'),
                'dependencies': data.get('dependencies', {}),
                'devDependencies': data.get('devDependencies', {}),
                'scripts': data.get('scripts', {}),
                'has_audit_script': 'audit' in data.get('scripts', {}),
                'has_ci_script': any(script in data.get('scripts', {}) 
                                   for script in ['test', 'ci', 'build'])
            }
            return result
    except Exception as e:
        print(f"Error analyzing {package_json_path}: {str(e)}")
        return None

def check_vulnerabilities(package_json_path: str) -> Dict:
    """Check for known vulnerabilities using npm audit."""
    result = {
        'vulnerabilities': {},
        'error': None
    }
    
    try:
        # Run npm audit --json
        dir_path = os.path.dirname(package_json_path)
        cmd = ["npm", "audit", "--json"]
        process = subprocess.Popen(
            cmd,
            cwd=dir_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()
        
        if process.returncode != 0 and not stdout:
            result['error'] = stderr or "Unknown error running npm audit"
            return result
            
        audit_result = json.loads(stdout)
        
        # Extract vulnerability information
        if 'vulnerabilities' in audit_result:
            for pkg_name, vuln_info in audit_result['vulnerabilities'].items():
                result['vulnerabilities'][pkg_name] = {
                    'severity': vuln_info.get('severity', 'unknown'),
                    'title': vuln_info.get('title', 'No title'),
                    'patched_versions': vuln_info.get('fix_available', {}).get('version', 'Not fixed'),
                    'via': [v.get('title', 'Unknown') for v in vuln_info.get('via', []) if isinstance(v, dict)]
                }
    
    except Exception as e:
        result['error'] = str(e)
    
    return result

def main():
    """Main function to scan for JavaScript projects and analyze them."""
    print("Scanning for JavaScript projects...\n")
    
    all_packages = []
    
    # Scan each directory for package.json files
    for scan_dir in SCAN_DIRS:
        if not os.path.exists(scan_dir):
            continue
            
        print(f"Scanning directory: {scan_dir}")
        package_jsons = find_package_json_files(scan_dir)
        
        for pkg_json in package_jsons:
            print(f"\nFound package.json: {pkg_json}")
            pkg_info = analyze_package_json(pkg_json)
            
            if pkg_info:
                print(f"  Project: {pkg_info['name']}@{pkg_info['version']}")
                print(f"  Dependencies: {len(pkg_info['dependencies'])}")
                print(f"  Dev Dependencies: {len(pkg_info['devDependencies'])}")
                
                # Check for vulnerabilities if npm is available
                if shutil.which('npm'):
                    print("  Checking for vulnerabilities...")
                    vulns = check_vulnerabilities(pkg_json)
                    
                    if vulns['error']:
                        print(f"  Error checking vulnerabilities: {vulns['error']}")
                    elif vulns['vulnerabilities']:
                        print(f"  Found {len(vulns['vulnerabilities'])} vulnerable packages:")
                        for pkg, info in vulns['vulnerabilities'].items():
                            print(f"    - {pkg}: {info['severity']} - {info['title']}")
                    else:
                        print("  No known vulnerabilities found.")
                else:
                    print("  npm not found. Skipping vulnerability check.")
                
                all_packages.append({
                    'path': pkg_json,
                    'info': pkg_info,
                    'vulnerabilities': vulns.get('vulnerabilities', {}) if 'vulns' in locals() else {}
                })
    
    # Generate a summary report
    print("\n=== Summary ===\n")
    print(f"Total JavaScript projects found: {len(all_packages)}")
    
    projects_with_vulns = [p for p in all_packages if p['vulnerabilities']]
    total_vulns = sum(len(p['vulnerabilities']) for p in projects_with_vulns)
    
    print(f"Projects with vulnerabilities: {len(projects_with_vulns)}")
    print(f"Total vulnerabilities found: {total_vulns}\n")
    
    if projects_with_vulns:
        print("Projects with vulnerabilities:")
        for project in projects_with_vulns:
            print(f"\n{project['info']['name']} ({project['path']}):")
            print(f"  Dependencies: {len(project['info']['dependencies'])}")
            print(f"  Vulnerabilities: {len(project['vulnerabilities'])}")
            
            # Group vulnerabilities by severity
            by_severity = {}
            for vuln in project['vulnerabilities'].values():
                sev = vuln['severity']
                by_severity[sev] = by_severity.get(sev, 0) + 1
            
            for sev, count in by_severity.items():
                print(f"    {sev}: {count}")
    
    # Save detailed report
    report = {
        'scan_timestamp': str(datetime.now()),
        'projects': all_packages
    }
    
    with open('javascript_deps_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("\nDetailed report saved to: javascript_deps_report.json")

if __name__ == "__main__":
    import shutil
    from datetime import datetime
    main()
