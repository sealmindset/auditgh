Modify the seed_org.sh script to accept scan type arguments and ensure it's using the Docker compose PostgreSQL instance for storing the results of the scans.
Ensure the seed_org.sh script is using the arugments of the scanners the information is written into the Docker compose of the PostgreSQL database instance and not to the local system host.
Ensure to use the Docker compose to run the scanners to seed the database.
Run the seed script directly (if the setup was already ran before) or fall back to force the setup to continue (if it's stuck) by type 'y' and press Enter if it's waiting for confirmation.
The script is using a bash feature (case modification) that's not compatible with the current shell. Update the script to work with basic POSIX shell features to fix the issue and make the script more portable.

#!/usr/bin/env bash
# seed_org.sh - Seed the portal DB with the org's projects scan data
#
# Requirements:
# - .env in repo root with: GITHUB_ORG, GITHUB_TOKEN, POSTGRES_* (for stack bring-up)
# - Docker Desktop with Compose v2
#
# Usage:
#   ./seed_org.sh [SCAN_TYPES...] [OPTIONS]
#
# Scan Types (if none specified, runs all except --codeql and --oss):
#   --contributors   Scan for repository contributors and their commits
#   --linecount      Run line count analysis
#   --cicd           Scan for CI/CD configurations
#   --gitleaks       Run GitLeaks secret scanning
#   --binaries       Scan for binary files
#   --terraform      Scan Terraform configurations
#   --hardcoded-ips  Scan for hardcoded IP addresses
#   --codeql         Run CodeQL analysis (excluded by default due to time)
#   --oss            Run OSS dependency scanning (excluded by default due to time)
#
# Options:
#   --max-recent-commits=NUM  Maximum number of recent commits to process (default: 100)
#   --mode=container|host     Run in container or host mode (default: container)
#   --postgrest-url=URL       Override PostgREST URL
#   --help                    Show this help message
#
# Examples:
#   # Run all default scans
#   ./seed_org.sh
#   
#   # Run specific scans
#   ./seed_org.sh --contributors --linecount --cicd
#   
#   # Run with custom parameters
#   ./seed_org.sh --max-recent-commits=50 --mode=host --postgrest-url=http://localhost:3001
#   
#   # Environment variables (overridden by command line):
#   #   GITHUB_ORG, GITHUB_TOKEN, MAX_RECENT_COMMITS, SEED_MODE, SEED_POSTGREST_URL
#   GITHUB_ORG=myorg GITHUB_TOKEN=mytoken ./seed_org.sh

set -Eeuo pipefail

PROJECT_NAME=${PROJECT_NAME:-portal}
COMPOSE_FILE=${COMPOSE_FILE:-docker-compose.portal.yml}
if [[ -f ./.env ]]; then
  COMPOSE="docker compose --env-file ./.env -p ${PROJECT_NAME} -f ${COMPOSE_FILE}"
else
  COMPOSE="docker compose -p ${PROJECT_NAME} -f ${COMPOSE_FILE}"
fi

info()  { echo "[seed] $*"; }
warn()  { echo "[seed][warn] $*"; }
error() { echo "[seed][error] $*" >&2; }
require() { command -v "$1" >/dev/null 2>&1 || { error "'$1' is required"; exit 1; }; }

load_env() {
  if [[ ! -f ./.env ]]; then
    error ".env not found in repo root. Create it with GITHUB_ORG and GITHUB_TOKEN."
    exit 1
  fi
  info "Loading .env"
  set -a; . ./.env; set +a
  # Fallbacks for alternative environment names
  : "${GITHUB_TOKEN:=${GH_TOKEN:-}}"
  : "${GITHUB_ORG:=${GH_ORG:-}}"
}

wait_for_postgrest() {
  local url="$1"
  info "Waiting for PostgREST at ${url} (60s timeout)"
  if command -v curl >/dev/null 2>&1; then
    for i in {1..60}; do
      if curl -fsS "${url}" >/dev/null; then
        info "PostgREST is up."
        return 0
      fi
      sleep 1
    done
    error "PostgREST did not become ready within 60s. Check: ${COMPOSE} logs -f postgrest"
    exit 1
  else
    # Fallback: simple sleep if curl is missing
    sleep 5
  fi
}

preflight_db_init() {
  local init_dir="./db/portal_init"
  if [[ -d "${init_dir}" ]]; then
    chmod 755 "${init_dir}" || true
    find "${init_dir}" -type f -name '*.sql' -exec chmod 644 {} + 2>/dev/null || true
  fi
}

verify_env() {
  local missing=()
  [[ -z "${GITHUB_ORG:-}" ]] && missing+=(GITHUB_ORG)
  [[ -z "${GITHUB_TOKEN:-}" ]] && missing+=(GITHUB_TOKEN)
  if (( ${#missing[@]} > 0 )); then
    error "Missing required env vars: ${missing[*]} (check .env)"
    exit 1
  fi
}

verify_summary() {
  if ! command -v curl >/dev/null 2>&1; then
    warn "curl not found; skipping verification summary"
    return 0
  fi
  local base="$1"
  info "Verifying via PostgREST at ${base}"
  # Count projects
  local resp1 count1
  resp1=$(curl -sS -D - -H "Prefer: count=exact" "${base}/projects?select=id" || true)
  count1=$(printf "%s" "$resp1" | tr -d '\r' | awk -F'/' 'BEGIN{IGNORECASE=1} /^Content-Range:/ {print $2}' | awk '{print $1}' | tail -1)
  # Count contributor summaries if view exists
  local resp2 count2
  resp2=$(curl -sS -D - -H "Prefer: count=exact" "${base}/contributors_summary?select=id" || true)
  count2=$(printf "%s" "$resp2" | tr -d '\r' | awk -F'/' 'BEGIN{IGNORECASE=1} /^Content-Range:/ {print $2}' | awk '{print $1}' | tail -1)
  info "Summary: projects=${count1:-unknown} contributors_summary=${count2:-unknown}"
}

parse_args() {
  # Default values
  local max_recent_commits=${MAX_RECENT_COMMITS:-100}
  local mode=${SEED_MODE:-container}
  local postgrest_url=""
  
  # Default scan types (all except codeql and oss)
  # Using separate variables for compatibility
  SCAN_CONTRIBUTORS=0
  SCAN_LINECOUNT=0
  SCAN_CICD=0
  SCAN_GITLEAKS=0
  SCAN_BINARIES=0
  SCAN_TERRAFORM=0
  SCAN_HARDCODED_IPS=0
  SCAN_CODEQL=0
  SCAN_OSS=0
  
  # Parse command line arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --help)
        grep -A 100 '^# Usage:' "$0" | tail -n +2 | head -n -1 | sed 's/^# //'
        exit 0
        ;;
      --max-recent-commits=*)
        max_recent_commits="${1#*=}"
        shift
        ;;
      --mode=*)
        mode="${1#*=}"
        if [[ "$mode" != "container" && "$mode" != "host" ]]; then
          error "Invalid mode: $mode. Must be 'container' or 'host'"
          exit 1
        fi
        shift
        ;;
      --postgrest-url=*)
        postgrest_url="${1#*=}"
        shift
        ;;
      --*)
        # Handle scan type flags
        local scan_type="${1#--}"
        # Convert kebab-case to UPPER_SNAKE_CASE (portable version)
        local var_name=$(echo "SCAN_${scan_type}" | tr '-' '_' | tr '[:lower:]' '[:upper:]')
        
        # Check if this is a valid scan type
        if [[ -z "${!var_name+x}" ]]; then
          error "Unknown scan type: $1"
          exit 1
        fi
        # Set the variable to 1 (enabled)
        eval "$var_name=1"
        shift
        ;;
      *)
        error "Unknown argument: $1"
        exit 1
        ;;
    esac
  done
  
  # If no scan types specified, use defaults (all except codeql and oss)
  local has_scans=0
  for var in SCAN_CONTRIBUTORS SCAN_LINECOUNT SCAN_CICD SCAN_GITLEAKS \
             SCAN_BINARIES SCAN_TERRAFORM SCAN_HARDCODED_IPS SCAN_CODEQL SCAN_OSS; do
    if [[ "${!var}" -eq 1 ]]; then
      has_scans=1
      break
    fi
  done
  
  if [[ "$has_scans" -eq 0 ]]; then
    SCAN_CONTRIBUTORS=1
    SCAN_LINECOUNT=1
    SCAN_CICD=1
    SCAN_GITLEAKS=1
    SCAN_BINARIES=1
    SCAN_TERRAFORM=1
    SCAN_HARDCODED_IPS=1
  fi
  
  # Set up PostgREST URL if not provided
  if [[ -z "$postgrest_url" ]]; then
    if [[ -n "${SEED_POSTGREST_URL:-}" ]]; then
      postgrest_url="$SEED_POSTGREST_URL"
    elif [[ "$mode" == "host" ]]; then
      postgrest_url="http://localhost:3001"
    else
      postgrest_url="http://postgrest:3000"
    fi
  fi
  
  # Export variables
  export MAX_RECENT_COMMITS="$max_recent_commits"
  export SEED_MODE="$mode"
  export SEED_POSTGREST_URL="$postgrest_url"
  
  # Export all scan variables
  export SCAN_CONTRIBUTORS SCAN_LINECOUNT SCAN_CICD SCAN_GITLEAKS \
         SCAN_BINARIES SCAN_TERRAFORM SCAN_HARDCODED_IPS SCAN_CODEQL SCAN_OSS
  
  # Print configuration
  info "Configuration:"
  info "  Mode: $mode"
  info "  PostgREST URL: $postgrest_url"
  info "  Max recent commits: $max_recent_commits"
  info "  Enabled scans:"
  if [[ "$SCAN_CONTRIBUTORS" -eq 1 ]]; then info "    - contributors"; fi
  if [[ "$SCAN_LINECOUNT" -eq 1 ]]; then info "    - linecount"; fi
  if [[ "$SCAN_CICD" -eq 1 ]]; then info "    - cicd"; fi
  if [[ "$SCAN_GITLEAKS" -eq 1 ]]; then info "    - gitleaks"; fi
  if [[ "$SCAN_BINARIES" -eq 1 ]]; then info "    - binaries"; fi
  if [[ "$SCAN_TERRAFORM" -eq 1 ]]; then info "    - terraform"; fi
  if [[ "$SCAN_HARDCODED_IPS" -eq 1 ]]; then info "    - hardcoded-ips"; fi
  if [[ "$SCAN_CODEQL" -eq 1 ]]; then info "    - codeql"; fi
  if [[ "$SCAN_OSS" -eq 1 ]]; then info "    - oss"; fi
}

run_scan() {
  local scan_name="$1"
  local script_name="$2"
  shift 2
  
  # Convert scan name to UPPER_SNAKE_CASE for variable name (portable version)
  local var_name=$(echo "SCAN_${scan_name}" | tr '[:lower:]' '[:upper:]')
  
  # Check if the scan is enabled
  if [[ -z "${!var_name+x}" || "${!var_name}" -ne 1 ]]; then
    info "Skipping $scan_name scan (not enabled)"
    return 0
  fi
  
  info "Running $scan_name scan..."
  if [[ "$SEED_MODE" == "container" ]]; then
    ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
      "python $script_name \"\$@\"" -- "$@"
{{ ... }}
    if command -v python3 >/dev/null 2>&1; then
      python3 "./$script_name" "$@"
    else
      python "./$script_name" "$@"
    fi
  fi
}

main() {
  # Parse command line arguments
  parse_args "$@"
  
  info "Checking prerequisites"
  require docker
  if ! docker compose version >/dev/null 2>&1; then
    error "Docker Compose v2 is required."
    exit 1
  fi

  load_env
  verify_env
  preflight_db_init

  info "Seeding mode='${SEED_MODE}' using PostgREST='${SEED_POSTGREST_URL}'"

  # Bring up core services when running container mode
  if [[ "${SEED_MODE}" == "container" ]]; then
    info "Bringing up core services (db, postgrest)"
    ${COMPOSE} up -d --remove-orphans db postgrest
    # Wait on host-mapped PostgREST for visibility as well
    wait_for_postgrest "${POSTGREST_VERIFY_URL:-http://localhost:3001}"
    info "Building scanner image (if needed)"
    ${COMPOSE} build scanner
  else
    # Host mode assumes PostgREST is already up on the provided URL
    wait_for_postgrest "${SEED_POSTGREST_URL}"
  fi

  info "Seeding org='${GITHUB_ORG}' with MAX_RECENT_COMMITS=${MAX_RECENT_COMMITS}"

  # Common arguments for all scans
  local common_args=(
    "--org" "${GITHUB_ORG}"
    "--token" "${GITHUB_TOKEN}"
    "--postgrest-url" "${SEED_POSTGREST_URL}"
    "--include-archived" "--include-forks"
  )
  
  # Run enabled scans
  if [[ "$SCAN_CONTRIBUTORS" -eq 1 ]]; then
    run_scan "contributors" "scan_contributor.py" \
      --init-projects-to-postgrest \
      --persist-contributors \
      --persist-commits \
      --max-recent-commits "${MAX_RECENT_COMMITS}" \
      -v "${common_args[@]}"
  fi
  
  if [[ "$SCAN_LINECOUNT" -eq 1 ]]; then
    run_scan "linecount" "scan_linecount.py" \
      --persist \
      -v "${common_args[@]}"
  fi
  
  if [[ "$SCAN_CICD" -eq 1 ]]; then
    run_scan "cicd" "scan_cicd.py" \
      --persist \
      -v "${common_args[@]}"
  fi
  
  if [[ "$SCAN_GITLEAKS" -eq 1 ]]; then
    run_scan "gitleaks" "scan_gitleaks.py" \
      --persist \
      -v "${common_args[@]}"
  fi
  
  if [[ "$SCAN_BINARIES" -eq 1 ]]; then
    run_scan "binaries" "scan_binaries.py" \
      --persist \
      -v "${common_args[@]}"
  fi
  
  if [[ "$SCAN_TERRAFORM" -eq 1 ]]; then
    run_scan "terraform" "scan_terraform.py" \
      --persist \
      -v "${common_args[@]}"
  fi
  
  if [[ "$SCAN_HARDCODED_IPS" -eq 1 ]]; then
    run_scan "hardcoded_ips" "scan_hardcoded_ips.py" \
      --persist \
      -v "${common_args[@]}"
  fi
  
  if [[ "$SCAN_CODEQL" -eq 1 ]]; then
    warn "CodeQL scan is enabled. This may take a long time to complete."
    run_scan "codeql" "scan_codeql.py" \
      --persist \
      -v "${common_args[@]}"
  fi
  
  if [[ "$SCAN_OSS" -eq 1 ]]; then
    warn "OSS dependency scan is enabled. This may take a long time to complete."
    run_scan "oss" "scan_oss.py" \
      --persist \
      -v "${common_args[@]}"
  fi

  # Verify using a host-reachable PostgREST endpoint if available
  verify_summary "${POSTGREST_VERIFY_URL:-http://localhost:3001}"
  info "Done."
}

# Call main function with all arguments
main "$@"
