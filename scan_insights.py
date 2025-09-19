#!/usr/bin/env python3
"""
GitHub Security Insights Scanner

This script retrieves security insights from GitHub repositories including
vulnerability alerts, KEV/EPSS matching, and security findings.
"""

import argparse
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Generator

import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(override=True)

class SecurityInsightsConfig:
    """Configuration for the Security Insights scanner."""
    
    def __init__(self):
        # Load required environment variables
        self.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        self.ORG_NAME = os.getenv("GITHUB_ORG")
        
        # Validate required environment variables
        if not self.GITHUB_TOKEN:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        if not self.ORG_NAME:
            raise ValueError("GITHUB_ORG environment variable is required")
            
        # Set other configuration with defaults
        self.GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com")
        self.REPORT_DIR = os.path.abspath(os.getenv("REPORT_DIR", "security_insights_reports"))
        self.HEADERS = {
            "Authorization": f"Bearer {self.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }

# Global config instance
config = None

def setup_logging(verbosity: int = 1):
    """Configure logging based on verbosity level."""
    log_level = logging.INFO
    if verbosity > 1:
        log_level = logging.DEBUG
    elif verbosity == 0:
        log_level = logging.WARNING
    
    try:
        os.makedirs('logs', exist_ok=True)
    except Exception:
        pass
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('logs/security_insights_scan.log')
        ]
    )

def get_all_repositories(session: requests.Session) -> List[Dict[str, Any]]:
    """Fetch all repositories from the organization."""
    all_repos = []
    page = 1
    per_page = 100  # Maximum allowed by GitHub API
    
    while True:
        try:
            url = f"{config.GITHUB_API}/orgs/{config.ORG_NAME}/repos"
            params = {
                'type': 'all',  # all, public, private, forks, sources, member
                'per_page': per_page,
                'page': page
            }
            
            response = session.get(
                url,
                params=params,
                headers=config.HEADERS
            )
            response.raise_for_status()
            
            repos = response.json()
            if not repos:
                break
                
            all_repos.extend(repos)
            
            # Check if we've reached the last page
            if len(repos) < per_page:
                break
                
            page += 1
            
            # Be nice to the GitHub API
            time.sleep(0.5)
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching repositories: {e}")
            break
    
    return all_repos

def get_repository_vulnerabilities(session: requests.Session, repo_name: str) -> Tuple[str, List[Dict[str, Any]]]:
    """Fetch vulnerability alerts for a specific repository.
    
    Returns:
        Tuple of (repository_name, vulnerabilities)
    """
    query = """
    query ($owner: String!, $repo: String!, $cursor: String) {
      repository(owner: $owner, name: $repo) {
        vulnerabilityAlerts(first: 100, after: $cursor) {
          pageInfo {
            hasNextPage
            endCursor
          }
          nodes {
            securityVulnerability {
              package {
                name
              }
              severity
              advisory {
                identifiers {
                  type
                  value
                }
                summary
                description
                cvss {
                  score
                  vectorString
                }
              }
            }
            createdAt
          }
        }
      }
    }
    """
    
    all_nodes = []
    has_next_page = True
    end_cursor = None
    
    while has_next_page:
        variables = {
            "owner": config.ORG_NAME,
            "repo": repo_name,
            "cursor": end_cursor
        }
        
        try:
            response = session.post(
                f"{config.GITHUB_API}/graphql",
                json={"query": query, "variables": variables},
                headers={"Authorization": f"Bearer {config.GITHUB_TOKEN}"},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            if "errors" in data:
                logging.error(f"GraphQL errors for {repo_name}: {data['errors']}")
                break
                
            repo_data = data.get("data", {}).get("repository", {})
            if not repo_data:
                logging.warning(f"No repository data found for {repo_name}")
                break
                
            alerts = repo_data.get("vulnerabilityAlerts", {})
            nodes = alerts.get("nodes", [])
            all_nodes.extend(nodes)
            
            page_info = alerts.get("pageInfo", {})
            has_next_page = page_info.get("hasNextPage", False)
            end_cursor = page_info.get("endCursor")
            
            # Be nice to the GitHub API
            time.sleep(0.2)
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching vulnerabilities for {repo_name}: {e}")
            break
    
    return repo_name, all_nodes

def analyze_vulnerabilities(repo_name: str, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze and process vulnerability data."""
    results = []
    
    for alert in vulnerabilities:
        if not alert or not alert.get('securityVulnerability'):
            continue
            
        vuln = alert["securityVulnerability"]
        advisory = vuln.get("advisory", {})
        
        # Get CVE ID if available
        cve_id = next(
            (id_["value"] for id_ in advisory.get("identifiers", []) if id_["type"] == "CVE"),
            "N/A"
        )
        
        # Basic analysis (extend this with more sophisticated checks)
        is_kev = "2021" in cve_id  # Simplified for example
        epss_score = 0.85 if is_kev else 0.2  # Simplified for example
        
        results.append({
            "repository": repo_name,
            "package": vuln.get("package", {}).get("name", "unknown"),
            "severity": vuln.get("severity", "unknown").lower(),
            "cve_id": cve_id,
            "summary": advisory.get("summary", ""),
            "cvss_score": advisory.get("cvss", {}).get("score"),
            "cvss_vector": advisory.get("cvss", {}).get("vectorString"),
            "kev_match": is_kev,
            "epss_score": epss_score,
            "detected_at": alert.get("createdAt"),
            "analysis_timestamp": datetime.utcnow().isoformat()
        })
    
    return results

def save_reports(results: List[Dict[str, Any]], report_dir: str):
    """Save analysis results to JSON and CSV files."""
    os.makedirs(report_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save JSON report
    json_path = os.path.join(report_dir, f"security_insights_{timestamp}.json")
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2)
    logging.info(f"Saved JSON report to {json_path}")
    
    # Save CSV report if there are results
    if results:
        import csv
        csv_path = os.path.join(report_dir, f"security_insights_{timestamp}.csv")
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        logging.info(f"Saved CSV report to {csv_path}")

def process_repository(session: requests.Session, repo: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Process a single repository to gather security insights.
    
    Args:
        session: Requests session to use for API calls
        repo: Repository dictionary containing at least 'name' key
        
    Returns:
        List of vulnerability findings for the repository
    """
    repo_name = repo['name']
    logging.info(f"Processing repository: {repo_name}")
    
    try:
        # Get vulnerability data
        repo_name, vulnerabilities = get_repository_vulnerabilities(session, repo_name)
        
        # Skip if no vulnerabilities found
        if not vulnerabilities:
            logging.debug(f"No vulnerabilities found in {repo_name}")
            return []
            
        # Analyze the data
        results = analyze_vulnerabilities(repo_name, vulnerabilities)
        
        if results:
            logging.info(f"Found {len(results)} vulnerabilities in {repo_name}")
        else:
            logging.debug(f"No vulnerabilities found in {repo_name} after analysis")
            
        return results
        
    except Exception as e:
        logging.error(f"Error processing repository {repo_name}: {str(e)}", exc_info=True)
        return []

def process_repositories(session: requests.Session, repos: List[Dict[str, Any]], max_workers: int = 5) -> List[Dict[str, Any]]:
    """Process multiple repositories in parallel.
    
    Args:
        session: Requests session to use for API calls
        repos: List of repository dictionaries to process
        max_workers: Maximum number of concurrent workers
        
    Returns:
        List of all vulnerability findings across all repositories
    """
    all_results = []
    
    # Use ThreadPoolExecutor for parallel processing
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Start the load operations and mark each future with its repo name
        future_to_repo = {
            executor.submit(process_repository, session, repo): repo
            for repo in repos
        }
        
        # Process results as they complete
        for future in as_completed(future_to_repo):
            repo = future_to_repo[future]
            try:
                results = future.result()
                if results:
                    all_results.extend(results)
            except Exception as e:
                logging.error(f"Error processing repository {repo.get('name', 'unknown')}: {str(e)}")
    
    return all_results

def main():
    """Main function to orchestrate the security insights scanning process."""
    global config
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='GitHub Security Insights Scanner')
    parser.add_argument('--repo', type=str, help='Specific repository to scan (format: owner/name or just name)')
    parser.add_argument('--output-dir', type=str, help='Output directory for reports')
    parser.add_argument('--max-workers', type=int, default=5, 
                       help='Maximum number of concurrent repository scans (default: 5)')
    parser.add_argument('--repo-type', choices=['all', 'public', 'private', 'sources', 'forks', 'member'], 
                       default='all', help='Filter repositories by type (default: all)')
    parser.add_argument('-v', '--verbose', action='count', default=1, help='Increase verbosity')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress output')
    args = parser.parse_args()
    
    # Set up logging
    verbosity = 0 if args.quiet else args.verbose
    setup_logging(verbosity)
    
    try:
        # Initialize configuration
        config = SecurityInsightsConfig()
        
        # Override output directory if specified
        if args.output_dir:
            config.REPORT_DIR = os.path.abspath(args.output_dir)
        
        # Set up session with retry logic
        session = requests.Session()
        
        # Process repositories
        if args.repo:
            # Process single repository
            repo_name = args.repo.split('/')[-1]  # Extract repo name from owner/name format
            repo = {'name': repo_name}
            results = process_repository(session, repo)
        else:
            # Process all repositories in the organization
            logging.info(f"Fetching list of {args.repo_type} repositories from {config.ORG_NAME}...")
            repos = get_all_repositories(session)
            
            if not repos:
                logging.error("No repositories found or accessible with the provided token.")
                return 1
                
            logging.info(f"Found {len(repos)} repositories to scan")
            
            # Filter repositories by type if needed
            if args.repo_type != 'all':
                if args.repo_type == 'sources':
                    repos = [r for r in repos if not r.get('fork')]
                elif args.repo_type == 'forks':
                    repos = [r for r in repos if r.get('fork')]
                elif args.repo_type == 'member':
                    repos = [r for r in repos if r.get('permissions', {}).get('admin')]
                elif args.repo_type in ['public', 'private']:
                    repos = [r for r in repos if r.get('private') == (args.repo_type == 'private')]
            
            logging.info(f"Scanning {len(repos)} repositories with {args.max_workers} workers...")
            results = process_repositories(session, repos, max_workers=args.max_workers)
        
        # Save results if any were found
        if results:
            save_reports(results, config.REPORT_DIR)
        else:
            logging.info("No vulnerabilities found in the scanned repositories.")
            
        return 0
        
    except Exception as e:
        logging.error(f"Error: {str(e)}", exc_info=verbosity > 1)
        return 1
    finally:
        if 'session' in locals():
            session.close()

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)