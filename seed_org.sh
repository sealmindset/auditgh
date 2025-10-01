#!/bin/sh
# seed_org.sh - Seed the portal DB with an entire org's projects, contributors, and recent commits
# Excludes CodeQL and OSS scans. Persists via PostgREST, not direct DB writes.
#
# Requirements:
# - .env in repo root with: GITHUB_ORG, GITHUB_TOKEN, POSTGRES_* (for stack bring-up)
# - Docker Desktop with Compose v2
#
# Usage:
#   ./seed_org.sh                                      # defaults: MAX_RECENT_COMMITS=100, SEED_MODE=container
#   MAX_RECENT_COMMITS=200 ./seed_org.sh
#   SEED_MODE=host ./seed_org.sh                       # run Python locally against host PostgREST
#   SEED_POSTGREST_URL=http://localhost:3001 ./seed_org.sh  # override PostgREST URL
#   PROJECT_NAME=portal COMPOSE_FILE=docker-compose.portal.yml ./seed_org.sh

set -eu

PROJECT_NAME=${PROJECT_NAME:-portal}
COMPOSE_FILE=${COMPOSE_FILE:-docker-compose.portal.yml}
if [ -f ./.env ]; then
  COMPOSE="docker compose --env-file ./.env -p ${PROJECT_NAME} -f ${COMPOSE_FILE}"
else
  COMPOSE="docker compose -p ${PROJECT_NAME} -f ${COMPOSE_FILE}"
fi

info()  { echo "[seed] $*"; }
warn()  { echo "[seed][warn] $*"; }
error() { echo "[seed][error] $*" >&2; }
require() { command -v "$1" >/dev/null 2>&1 || { error "'$1' is required"; exit 1; }; }

load_env() {
  if [ ! -f ./.env ]; then
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
  url="$1"
  info "Waiting for PostgREST at ${url} (60s timeout)"
  if command -v curl >/dev/null 2>&1; then
    i=0
    while [ "$i" -lt 60 ]; do
      if curl -fsS "${url}" >/dev/null; then
        info "PostgREST is up."
        return 0
      fi
      sleep 1
      i=$((i+1))
    done
    error "PostgREST did not become ready within 60s. Check: ${COMPOSE} logs -f postgrest"
    return 1
  else
    # Fallback: simple sleep if curl is missing
    sleep 5
  fi
}

preflight_db_init() {
  init_dir="./db/portal_init"
  if [ -d "${init_dir}" ]; then
    chmod 755 "${init_dir}" || true
    find "${init_dir}" -type f -name '*.sql' -exec chmod 644 {} + 2>/dev/null || true
  fi
}

verify_env() {
  missing=""
  [ -z "${GITHUB_ORG:-}" ] && missing="${missing} GITHUB_ORG"
  [ -z "${GITHUB_TOKEN:-}" ] && missing="${missing} GITHUB_TOKEN"
  if [ -n "${missing}" ]; then
    error "Missing required env vars:${missing} (check .env)"
    exit 1
  fi
}

verify_summary() {
  if ! command -v curl >/dev/null 2>&1; then
    warn "curl not found; skipping verification summary"
    return 0
  fi
  base="$1"
  info "Verifying via PostgREST at ${base}"
  # Count projects
  resp1=""; count1=""
  resp1=$(curl -sS -D - -H "Prefer: count=exact" "${base}/projects?select=id" || true)
  count1=$(printf "%s" "$resp1" | tr -d '\r' | awk -F'/' 'BEGIN{IGNORECASE=1} /^Content-Range:/ {print $2}' | awk '{print $1}' | tail -1)
  # Count contributor summaries if view exists
  resp2=""; count2=""
  resp2=$(curl -sS -D - -H "Prefer: count=exact" "${base}/contributors_summary?select=id" || true)
  count2=$(printf "%s" "$resp2" | tr -d '\r' | awk -F'/' 'BEGIN{IGNORECASE=1} /^Content-Range:/ {print $2}' | awk '{print $1}' | tail -1)
  info "Summary: projects=${count1:-unknown} contributors_summary=${count2:-unknown}"
}

# Ensure PostgREST up; if not, try forcing setup non-interactively
ensure_stack_ready() {
  verify_url="${POSTGREST_VERIFY_URL:-http://localhost:3001}"
  if ! wait_for_postgrest "${verify_url}"; then
    warn "PostgREST not reachable at ${verify_url}. Attempting to run setup.sh non-interactively..."
    if [ -x ./setup.sh ]; then
      CONFIRM=1 ./setup.sh || true
      # Wait again
      wait_for_postgrest "${verify_url}" || { error "PostgREST still not ready after setup"; exit 1; }
    else
      error "setup.sh not found or not executable; cannot recover automatically"
      exit 1
    fi
  fi
}

# Parse CLI flags (POSIX sh). Supported:
# --mode=container|host, --postgrest-url=URL, --max-recent-commits=N
# Scan toggles (enable when present):
# --contributors --linecount --engagement --gitleaks --binaries --terraform --hardcoded-ips --codeql --oss
parse_args() {
  MRC="${MAX_RECENT_COMMITS:-100}"
  SEED_MODE="${SEED_MODE:-container}"
  SEED_POSTGREST_URL="${SEED_POSTGREST_URL:-}"
  SCAN_CONTRIBUTORS=0
  SCAN_LINECOUNT=0
  SCAN_ENGAGEMENT=0
  SCAN_GITLEAKS=0
  SCAN_BINARIES=0
  SCAN_TERRAFORM=0
  SCAN_HARDCODED_IPS=0
  SCAN_CODEQL=0
  SCAN_OSS=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help)
        grep -A 200 '^# Usage:' "$0" | sed '1d;s/^# //'; exit 0 ;;
      --max-recent-commits=*) MRC="${1#*=}" ;;
      --mode=*) SEED_MODE="${1#*=}" ;;
      --postgrest-url=*) SEED_POSTGREST_URL="${1#*=}" ;;
      --contributors) SCAN_CONTRIBUTORS=1 ;;
      --linecount) SCAN_LINECOUNT=1 ;;
      --engagement) SCAN_ENGAGEMENT=1 ;;
      --gitleaks) SCAN_GITLEAKS=1 ;;
      --binaries) SCAN_BINARIES=1 ;;
      --terraform) SCAN_TERRAFORM=1 ;;
      --hardcoded-ips) SCAN_HARDCODED_IPS=1 ;;
      --codeql) SCAN_CODEQL=1 ;;
      --oss) SCAN_OSS=1 ;;
      *) error "Unknown argument: $1"; exit 1 ;;
    esac
    shift
  done
  # If no scan toggles provided, enable defaults (all except codeql, oss)
  has_any=$((SCAN_CONTRIBUTORS+SCAN_LINECOUNT+SCAN_ENGAGEMENT+SCAN_GITLEAKS+SCAN_BINARIES+SCAN_TERRAFORM+SCAN_HARDCODED_IPS+SCAN_CODEQL+SCAN_OSS))
  if [ "$has_any" -eq 0 ]; then
    SCAN_CONTRIBUTORS=1
    SCAN_LINECOUNT=1
    SCAN_ENGAGEMENT=1
    SCAN_GITLEAKS=1
    SCAN_BINARIES=1
    SCAN_TERRAFORM=1
    SCAN_HARDCODED_IPS=1
    SCAN_CODEQL=0
    SCAN_OSS=0
  fi
}

main() {
  info "Checking prerequisites"
  require docker
  if ! docker compose version >/dev/null 2>&1; then
    error "Docker Compose v2 is required."
    exit 1
  fi

  load_env
  verify_env
  preflight_db_init
  parse_args "$@"

  # Decide mode and PostgREST URL
  mode="${SEED_MODE:-container}"
  if [ -n "${SEED_POSTGREST_URL:-}" ]; then
    pg_url="${SEED_POSTGREST_URL}"
  else
    if [ "${mode}" = "host" ]; then
      pg_url="http://localhost:3001"
    else
      pg_url="http://postgrest:3000"
    fi
  fi
  info "Seeding mode='${mode}' using PostgREST='${pg_url}'"

  # Bring up core services when running container mode
  if [ "${mode}" = "container" ]; then
    info "Bringing up core services (db, postgrest)"
    ${COMPOSE} up -d --remove-orphans db postgrest
    # Ensure readiness or force setup
    ensure_stack_ready
    info "Building scanner image (if needed)"
    ${COMPOSE} build scanner
  else
    # Host mode assumes PostgREST is already up on the provided URL
    wait_for_postgrest "${pg_url}" || { error "PostgREST not reachable at ${pg_url}"; exit 1; }
  fi

  mrc="${MRC}"
  info "Seeding org='${GITHUB_ORG}' with MAX_RECENT_COMMITS=${mrc}"

  if [ "${mode}" = "container" ]; then
    # Contributors (persist via PostgREST)
    if [ "${SCAN_CONTRIBUTORS}" = "1" ]; then
      ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
        "python scan_contributor.py \
           --org \"${GITHUB_ORG}\" \
           --token \"${GITHUB_TOKEN}\" \
           --init-projects-to-postgrest \
           --postgrest-url ${pg_url} \
           --include-archived --include-forks \
           --persist-contributors --persist-commits \
           --max-recent-commits ${mrc} -v"
    fi
    # Linecount (persist LOC)
    if [ "${SCAN_LINECOUNT}" = "1" ]; then
      ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
        "python scan_linecount.py \
           --org \"${GITHUB_ORG}\" \
           --token \"${GITHUB_TOKEN}\" \
           --include-archived --include-forks \
           --persist-loc \
           --postgrest-url ${pg_url} -v"
    fi
    # Engagement (stars/forks/watchers) persist
    if [ "${SCAN_ENGAGEMENT}" = "1" ]; then
      ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
        "python scan_engagement.py \
           --org \"${GITHUB_ORG}\" \
           --token \"${GITHUB_TOKEN}\" \
           --include-archived --include-forks \
           --persist \
           --postgrest-url ${pg_url} -v"
    fi
    # Gitleaks (persist)
    if [ "${SCAN_GITLEAKS}" = "1" ]; then
      ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
        "python scan_gitleaks.py \
           --org \"${GITHUB_ORG}\" \
           --token \"${GITHUB_TOKEN}\" \
           --include-archived --include-forks \
           --persist \
           --postgrest-url ${pg_url} -v"
    fi
    # Binaries (reports only)
    if [ "${SCAN_BINARIES}" = "1" ]; then
      ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
        "python scan_binaries.py \
           --org \"${GITHUB_ORG}\" \
           --token \"${GITHUB_TOKEN}\" \
           --include-archived --include-forks -v"
    fi
    # Terraform (reports only)
    if [ "${SCAN_TERRAFORM}" = "1" ]; then
      ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
        "python scan_terraform.py \
           --org \"${GITHUB_ORG}\" \
           --token \"${GITHUB_TOKEN}\" \
           --include-archived --include-forks -v"
    fi
    # Hardcoded IPs (reports only)
    if [ "${SCAN_HARDCODED_IPS}" = "1" ]; then
      ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
        "python scan_hardcoded_ips.py \
           --org \"${GITHUB_ORG}\" \
           --token \"${GITHUB_TOKEN}\" \
           --include-archived --include-forks -v"
    fi
    # CodeQL (reports only; can be long)
    if [ "${SCAN_CODEQL}" = "1" ]; then
      ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
        "python scan_codeql.py \
           --org \"${GITHUB_ORG}\" \
           --token \"${GITHUB_TOKEN}\" -v"
    fi
    # OSS (reports only)
    if [ "${SCAN_OSS}" = "1" ]; then
      ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
        "python scan_oss.py \
           --org \"${GITHUB_ORG}\" \
           --token \"${GITHUB_TOKEN}\" \
           --include-archived --include-forks -v"
    fi
  else
    error "Host mode is not supported for seeding; use --mode=container"
    exit 1
  fi

  # Verify using a host-reachable PostgREST endpoint if available
  verify_summary "${POSTGREST_VERIFY_URL:-http://localhost:3001}"
  info "Done."
}

main "$@"
