"""
AuditGH - A tool for auditing GitHub repositories for security vulnerabilities.
"""
import argparse
import concurrent.futures
import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any

from dotenv import load_dotenv

# Import our modules
from .github.api import GitHubAPI
from .github.models import Repository
from .scanners import (
    SafetyScanner,
    PipAuditScanner,
    # Add other scanners here as they're implemented
)
from .reports import ReportGenerator, ReportFormat

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('auditgh.log')
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_CONFIG = {
    'github_org': 'sleepnumberinc',
    'output_dir': 'reports',
    'temp_dir': tempfile.mkdtemp(prefix='auditgh_'),
    'max_workers': 4,
    'include_forks': False,
    'include_archived': False,
    'report_format': 'markdown',
    'scanners': ['safety', 'pip-audit'],
}


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Audit GitHub repositories for security vulnerabilities.')
    
    # GitHub options
    github_group = parser.add_argument_group('GitHub Options')
    github_group.add_argument('--org', default=DEFAULT_CONFIG['github_org'],
                            help=f'GitHub organization (default: {DEFAULT_CONFIG["github_org"]})')
    github_group.add_argument('--token', help='GitHub personal access token (default: GITHUB_TOKEN env var)')
    github_group.add_argument('--repo', help='Specific repository to scan (format: owner/name)')
    github_group.add_argument('--include-forks', action='store_true', default=DEFAULT_CONFIG['include_forks'],
                            help='Include forked repositories (default: False)')
    github_group.add_argument('--include-archived', action='store_true', default=DEFAULT_CONFIG['include_archived'],
                            help='Include archived repositories (default: False)')
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('--scanners', nargs='+', default=DEFAULT_CONFIG['scanners'],
                          choices=['all', 'safety', 'pip-audit'],  # Add more as implemented
                          help='Scanners to run (default: safety pip-audit)')
    scan_group.add_argument('--max-workers', type=int, default=DEFAULT_CONFIG['max_workers'],
                          help=f'Maximum number of parallel scans (default: {DEFAULT_CONFIG["max_workers"]})')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output-dir', default=DEFAULT_CONFIG['output_dir'],
                            help=f'Output directory for reports (default: {DEFAULT_CONFIG["output_dir"]})')
    output_group.add_argument('--format', default=DEFAULT_CONFIG['report_format'],
                            choices=['markdown', 'html', 'json', 'console'],
                            help=f'Report format (default: {DEFAULT_CONFIG["report_format"]})')
    output_group.add_argument('--keep-temp', action='store_true',
                            help='Keep temporary files after scanning (default: False)')
    
    # Other options
    other_group = parser.add_argument_group('Other Options')
    other_group.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    other_group.add_argument('--debug', action='store_true', help='Enable debug output')
    other_group.add_argument('--version', action='version', version='%(prog)s 0.1.0')
    
    return parser.parse_args()


def configure_logging(verbose: bool = False, debug: bool = False):
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('auditgh.log')
        ]
    )


def get_github_token(token: Optional[str] = None) -> str:
    """Get GitHub token from args or environment."""
    if token:
        return token
    
    token = os.getenv('GITHUB_TOKEN')
    if not token:
        logger.error("GitHub token not provided. Use --token or set GITHUB_TOKEN environment variable.")
        sys.exit(1)
    
    return token


def get_scanners(scanner_names: List[str]):
    """Get scanner instances based on names."""
    scanners = []
    scanner_map = {
        'safety': SafetyScanner,
        'pip-audit': PipAuditScanner,
        # Add more scanners here as they're implemented
    }
    
    if 'all' in scanner_names:
        scanner_names = list(scanner_map.keys())
    
    for name in scanner_names:
        if name in scanner_map:
            scanners.append(scanner_map[name]())
        else:
            logger.warning("Unknown scanner: %s", name)
    
    if not scanners:
        logger.error("No valid scanners specified")
        sys.exit(1)
    
    return scanners


def clone_repository(repo: Repository, temp_dir: str) -> Optional[str]:
    """Clone a repository to a temporary directory."""
    try:
        repo_dir = os.path.join(temp_dir, repo.name)
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir)
        
        # Create a shallow clone to save time and space
        cmd = ["git", "clone", "--depth", "1", repo.clone_url, repo_dir]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error("Failed to clone repository %s: %s", repo.full_name, result.stderr)
            return None
        
        return repo_dir
    except Exception as e:
        logger.error("Error cloning repository %s: %s", repo.full_name, str(e))
        return None


def scan_repository(repo: Repository, scanners: List[Any], temp_dir: str, output_dir: str) -> Dict[str, Any]:
    """Scan a single repository with all configured scanners."""
    logger.info("Scanning repository: %s", repo.full_name)
    
    # Create output directory for this repository
    repo_output_dir = os.path.join(output_dir, repo.name)
    os.makedirs(repo_output_dir, exist_ok=True)
    
    # Clone the repository
    repo_path = clone_repository(repo, temp_dir)
    if not repo_path:
        return {
            'name': repo.name,
            'full_name': repo.full_name,
            'url': repo.html_url,
            'success': False,
            'error': 'Failed to clone repository',
            'scans': []
        }
    
    # Run all scanners
    scan_results = []
    for scanner in scanners:
        if not scanner.is_applicable(repo_path):
            logger.debug("Skipping scanner %s for %s (not applicable)", scanner.name, repo.full_name)
            continue
        
        logger.info("Running %s scan on %s", scanner.name, repo.full_name)
        try:
            result = scanner.scan(repo_path, repo_output_dir)
            scan_results.append({
                'scanner': scanner.name,
                'success': result.success,
                'has_vulnerabilities': result.has_vulnerabilities,
                'vulnerability_count': len(result.vulnerabilities),
                'critical_count': result.critical_count,
                'high_count': result.high_count,
                'medium_count': result.medium_count,
                'low_count': result.low_count,
                'info_count': result.info_count,
                'error': result.error,
                'raw_output': result.raw_output
            })
        except Exception as e:
            logger.exception("Error running %s scan on %s", scanner.name, repo.full_name)
            scan_results.append({
                'scanner': scanner.name,
                'success': False,
                'error': str(e)
            })
    
    # Clean up the cloned repository
    shutil.rmtree(repo_path, ignore_errors=True)
    
    return {
        'name': repo.name,
        'full_name': repo.full_name,
        'url': repo.html_url,
        'success': any(r.get('success', False) for r in scan_results),
        'scans': scan_results
    }


def generate_summary_report(results: List[Dict[str, Any]], output_dir: str, format: str = 'markdown') -> str:
    """Generate a summary report of all scan results."""
    # Calculate summary statistics
    total_repos = len(results)
    successful_scans = sum(1 for r in results if r.get('success', False))
    failed_scans = total_repos - successful_scans
    
    total_vulnerabilities = 0
    critical_vulns = 0
    high_vulns = 0
    medium_vulns = 0
    low_vulns = 0
    info_vulns = 0
    
    for result in results:
        for scan in result.get('scans', []):
            total_vulnerabilities += scan.get('vulnerability_count', 0)
            critical_vulns += scan.get('critical_count', 0)
            high_vulns += scan.get('high_count', 0)
            medium_vulns += scan.get('medium_count', 0)
            low_vulns += scan.get('low_count', 0)
            info_vulns += scan.get('info_count', 0)
    
    # Prepare report data
    report_data = {
        'title': 'AuditGH Security Scan Summary',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_repositories': total_repos,
        'successful_scans': successful_scans,
        'failed_scans': failed_scans,
        'total_vulnerabilities': total_vulnerabilities,
        'critical_vulns': critical_vulns,
        'high_vulns': high_vulns,
        'medium_vulns': medium_vulns,
        'low_vulns': low_vulns,
        'info_vulns': info_vulns,
        'results': results,
        'has_vulnerabilities': total_vulnerabilities > 0
    }
    
    # Generate the report
    report_generator = ReportGenerator(output_dir, ReportFormat(format))
    report_path = report_generator.generate_report(
        'summary',
        report_data,
        custom_title='AuditGH Security Scan Summary'
    )
    
    return report_path


def main():
    """Main entry point for the application."""
    # Parse command line arguments
    args = parse_args()
    
    # Configure logging
    configure_logging(args.verbose, args.debug)
    
    # Get GitHub token
    token = get_github_token(args.token)
    
    # Initialize GitHub client
    github = GitHubAPI(token, args.org)
    
    # Get scanners
    scanners = get_scanners(args.scanners)
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Get repositories to scan
    if args.repo:
        # Single repository mode
        if '/' in args.repo:
            # Full repo name (owner/name)
            owner, repo_name = args.repo.split('/', 1)
            repo = github.get_repository(f"{owner}/{repo_name}")
            if not repo:
                logger.error("Repository not found: %s", args.repo)
                sys.exit(1)
            repositories = [repo]
        else:
            # Just repo name, use the configured org
            repo = github.get_repository(f"{args.org}/{args.repo}")
            if not repo:
                logger.error("Repository not found: %s/%s", args.org, args.repo)
                sys.exit(1)
            repositories = [repo]
    else:
        # Scan all repositories in the organization
        try:
            repositories = github.get_repositories(
                include_forks=args.include_forks,
                include_archived=args.include_archived
            )
            logger.info("Found %d repositories in organization %s", len(repositories), args.org)
        except Exception as e:
            logger.error("Failed to fetch repositories: %s", str(e))
            sys.exit(1)
    
    if not repositories:
        logger.warning("No repositories found matching the criteria")
        return
    
    # Create temporary directory for repository clones
    temp_dir = tempfile.mkdtemp(prefix='auditgh_repos_')
    logger.debug("Using temporary directory: %s", temp_dir)
    
    try:
        # Scan repositories in parallel
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:
            # Start the scan operations and mark each future with its repo
            future_to_repo = {
                executor.submit(scan_repository, repo, scanners, temp_dir, args.output_dir): repo
                for repo in repositories
            }
            
            for future in concurrent.futures.as_completed(future_to_repo):
                repo = future_to_repo[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.get('success', False):
                        logger.info("Completed scan for %s", repo.full_name)
                    else:
                        logger.warning("Scan failed for %s: %s", repo.full_name, result.get('error', 'Unknown error'))
                except Exception as e:
                    logger.exception("Error scanning repository %s", repo.full_name)
                    results.append({
                        'name': repo.name,
                        'full_name': repo.full_name,
                        'url': repo.html_url,
                        'success': False,
                        'error': str(e)
                    })
        
        # Generate summary report
        summary_report_path = generate_summary_report(results, args.output_dir, args.format)
        logger.info("Summary report generated: %s", summary_report_path)
        
        # Log the scan summary
        logger.info("\n" + "=" * 80)
        logger.info("AuditGH Scan Summary")
        logger.info("=" * 80)
        logger.info("Total repositories scanned: %d", len(repositories))
        logger.info("Successful scans: %d", sum(1 for r in results if r.get('success', False)))
        logger.info("Failed scans: %d", sum(1 for r in results if not r.get('success', True)))
        logger.info("Total vulnerabilities found: %d", 
                   sum(r.get('vulnerability_count', 0) for r in results))
        logger.info("=" * 80)
        logger.info("Detailed report available at: %s", os.path.abspath(summary_report_path))
        
    finally:
        # Clean up temporary directory
        if not args.keep_temp and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
