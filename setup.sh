#!/usr/bin/env bash
# setup.sh - Fresh DB init + one-time seed + bring portal up
# - Destroys the portal DB volume (dev only!), re-creates it, applies init SQL
# - Brings up the portal stack (-p portal)
# - Optionally seeds projects via GitHub (requires GITHUB_ORG/TOKEN in .env)

set -Eeuo pipefail

PROJECT_NAME=${PROJECT_NAME:-portal}
COMPOSE_FILE=${COMPOSE_FILE:-docker-compose.portal.yml}
# If .env exists, pass it explicitly to docker compose for interpolation
if [[ -f ./.env ]]; then
  COMPOSE="docker compose --env-file ./.env -p ${PROJECT_NAME} -f ${COMPOSE_FILE}"
else
  COMPOSE="docker compose -p ${PROJECT_NAME} -f ${COMPOSE_FILE}"
fi
VOLUME_NAME="${PROJECT_NAME}_pg_data"
CONFIRM=${CONFIRM:-}

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Error: '$1' is required but not installed or not on PATH" >&2
    exit 1
  }
}

info()  { echo "[setup] $*"; }
warn()  { echo "[setup][warn] $*"; }
error() { echo "[setup][error] $*" >&2; }

confirm_or_exit() {
  if [[ -n "$CONFIRM" ]]; then return 0; fi
  read -r -p "This will DELETE Docker volume '${VOLUME_NAME}' and reinitialize the database. Continue? [y/N] " ans || true
  case "${ans:-}" in
    y|Y|yes|YES) ;; 
    *) info "Aborted."; exit 0;;
  esac
}

wait_for_postgrest() {
  if ! command -v curl >/dev/null 2>&1; then
    warn "curl not found; skipping PostgREST readiness check"
    return 0
  fi
  info "Waiting for PostgREST at http://localhost:3001 (60s timeout)"
  for i in {1..60}; do
    if curl -fsS http://localhost:3001 >/dev/null; then
      info "PostgREST is up."
      return 0
    fi
    sleep 1
  done
  error "PostgREST did not become ready within 60s. Check logs: ${COMPOSE} logs -f postgrest"
}

seed_projects() {
  # Uses the 'seeder' service image (auditgh-scanner:latest) to run scan_contributor.py ONCE
  local org token
  org=${GITHUB_ORG:-}
  token=${GITHUB_TOKEN:-}
  if [[ -z "$org" || -z "$token" ]]; then
    warn "GITHUB_ORG/GITHUB_TOKEN not set in environment/.env; skipping project seeding"
    return 0
  fi
  info "Seeding projects for org/user '${org}' via PostgREST"
  # Build the scanner image if missing
  ${COMPOSE} build scanner
  # Run the seeder command once (override the looping entrypoint)
  ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
    "python scan_contributor.py \
       --org \"${org}\" \
       --token \"${token}\" \
       --init-projects-to-postgrest \
       --postgrest-url http://postgrest:3000 \
       --include-archived --include-forks \
       --persist-contributors --persist-commits \
       --max-recent-commits 100 \
       --init-only -v"
}

main() {
  info "Checking prerequisites..."
  require docker
  if ! docker compose version >/dev/null 2>&1; then
    error "Docker Compose v2 is required (use 'docker compose'). Please upgrade Docker Desktop."
    exit 1
  fi

  if [[ ! -f .env ]]; then
    warn ".env not found. Consider running './bootstrap.sh' first to create it."
  else
    info "Loading .env into environment"
    set -a
    . ./.env
    set +a
  fi

  confirm_or_exit

  info "Stopping portal stack (if running)"
  ${COMPOSE} down --remove-orphans || true

  info "Removing DB volume '${VOLUME_NAME}'"
  docker volume rm "${VOLUME_NAME}" || true

  info "Bringing up portal stack fresh"
  ${COMPOSE} up -d --remove-orphans

  wait_for_postgrest

  seed_projects

  info "Done."
  info "Portal web:    http://localhost:5173"
  info "PostgREST API: http://localhost:3001"
  info "Server logs:   ${COMPOSE} logs -f server"
}

main "$@"
