#!/usr/bin/env bash
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

  # Decide mode and PostgREST URL
  local mode
  mode=${SEED_MODE:-container}
  local pg_url
  if [[ -n "${SEED_POSTGREST_URL:-}" ]]; then
    pg_url="${SEED_POSTGREST_URL}"
  else
    if [[ "${mode}" == "host" ]]; then
      pg_url="http://localhost:3001"
    else
      pg_url="http://postgrest:3000"
    fi
  fi
  info "Seeding mode='${mode}' using PostgREST='${pg_url}'"

  # Bring up core services when running container mode
  if [[ "${mode}" == "container" ]]; then
    info "Bringing up core services (db, postgrest)"
    ${COMPOSE} up -d --remove-orphans db postgrest
    # Wait on host-mapped PostgREST for visibility as well
    wait_for_postgrest "${POSTGREST_VERIFY_URL:-http://localhost:3001}"
    info "Building scanner image (if needed)"
    ${COMPOSE} build scanner
  else
    # Host mode assumes PostgREST is already up on the provided URL
    wait_for_postgrest "${pg_url}"
  fi

  local mrc
  mrc=${MAX_RECENT_COMMITS:-100}
  info "Seeding org='${GITHUB_ORG}' with MAX_RECENT_COMMITS=${mrc} (contributors + recent commits; no CodeQL/OSS)"

  if [[ "${mode}" == "container" ]]; then
    ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
      "python scan_contributor.py \
         --org \"${GITHUB_ORG}\" \
         --token \"${GITHUB_TOKEN}\" \
         --init-projects-to-postgrest \
         --postgrest-url ${pg_url} \
         --include-archived --include-forks \
         --persist-contributors --persist-commits \
         --max-recent-commits ${mrc} -v"
  else
    # Host mode: run python locally
    if command -v python3 >/dev/null 2>&1; then
      python3 ./scan_contributor.py \
        --org "${GITHUB_ORG}" \
        --token "${GITHUB_TOKEN}" \
        --init-projects-to-postgrest \
        --postgrest-url "${pg_url}" \
        --include-archived --include-forks \
        --persist-contributors --persist-commits \
        --max-recent-commits ${mrc} -v
    else
      python ./scan_contributor.py \
        --org "${GITHUB_ORG}" \
        --token "${GITHUB_TOKEN}" \
        --init-projects-to-postgrest \
        --postgrest-url "${pg_url}" \
        --include-archived --include-forks \
        --persist-contributors --persist-commits \
        --max-recent-commits ${mrc} -v
    fi
  fi

  # Verify using a host-reachable PostgREST endpoint if available
  verify_summary "${POSTGREST_VERIFY_URL:-http://localhost:3001}"
  info "Done."
}

main "$@"
