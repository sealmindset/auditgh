#!/usr/bin/env bash
# setup.sh - Fresh DB init + one-time seed + bring portal up
# - Destroys the portal DB volume (dev only!), re-creates it, applies init SQL
# - Brings up the portal stack (-p portal)
# - Optionally seeds projects via GitHub (requires GITHUB_ORG/TOKEN in .env)

set -Eeuo pipefail

PROJECT_NAME=${PROJECT_NAME:-portal}
# Enable optional AI stack (ollama) by default; set ENABLE_AI=0 to disable
ENABLE_AI=${ENABLE_AI:-1}
# Default Ollama model to ensure is available
AI_MODEL=${AI_MODEL:-qwen2.5:3b}

# Seed engagement snapshot (stars, forks, watchers, open issues) via scan_engagement.py
seed_engagement() {
  local org token
  org=${GITHUB_ORG:-}
  token=${GITHUB_TOKEN:-}
  if [[ -z "$org" || -z "$token" ]]; then
    warn "GITHUB_ORG/GITHUB_TOKEN not set in environment/.env; skipping engagement seeding"
    return 0
  fi
  info "Seeding engagement snapshot for '${org}' via PostgREST"
  ${COMPOSE} build scanner
  ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
    "python scan_engagement.py \
       --org \"${org}\" \
       --token \"${token}\" \
       --persist \
       --postgrest-url http://postgrest:3000 \
       --max-workers ${ENGAGEMENT_MAX_WORKERS:-3} -v"
}

# Extract total count from a curl -D - response's Content-Range header
_extract_count() {
  # reads full curl output (headers+body) on stdin
  # returns the total after '/' in Content-Range: e.g., "0-9/52" -> 52
  # if not found, prints empty string
  tr -d '\r' | awk -F'/' 'BEGIN{IGNORECASE=1} /^Content-Range:/ {print $2}' | awk '{print $1}' | tail -1
}

# Verify languages and LOC were persisted; non-fatal and prints a short summary
verify_seed() {
  if ! command -v curl >/dev/null 2>&1; then
    warn "curl not found; skipping verification"
    return 0
  fi
  local base
  base=${POSTGREST_VERIFY_URL:-http://localhost:3001}
  info "Verifying persisted data via PostgREST at ${base} (non-fatal checks)"

  # Count projects with primary_language set
  local resp1 primary_lang_count
  resp1=$(curl -sS -D - -H "Prefer: count=exact" "${base}/projects?select=id&primary_language=is.not.null" || true)
  primary_lang_count=$(printf "%s" "$resp1" | _extract_count)
  if [[ -z "$primary_lang_count" ]]; then
    warn "Could not determine count of projects with primary_language (no Content-Range)."
  fi

  # Count projects with total_loc > 0
  local resp2 loc_count
  resp2=$(curl -sS -D - -H "Prefer: count=exact" "${base}/projects?select=id&total_loc=gt.0" || true)
  loc_count=$(printf "%s" "$resp2" | _extract_count)
  if [[ -z "$loc_count" ]]; then
    warn "Could not determine count of projects with total_loc>0 (no Content-Range)."
  fi

  # Count total project_languages rows
  local resp3 lang_rows
  resp3=$(curl -sS -D - -H "Prefer: count=exact" "${base}/project_languages?select=id" || true)
  lang_rows=$(printf "%s" "$resp3" | _extract_count)
  if [[ -z "$lang_rows" ]]; then
    warn "Could not determine count of project_languages rows (no Content-Range)."
  fi

  # Engagement: projects with stars set; projects with stars > 0
  local resp4 stars_set resp5 stars_gt0
  resp4=$(curl -sS -D - -H "Prefer: count=exact" "${base}/projects?select=id&stars=is.not.null" || true)
  stars_set=$(printf "%s" "$resp4" | _extract_count)
  if [[ -z "$stars_set" ]]; then
    warn "Could not determine count of projects with stars set (no Content-Range)."
  fi
  resp5=$(curl -sS -D - -H "Prefer: count=exact" "${base}/projects?select=id&stars=gt.0" || true)
  stars_gt0=$(printf "%s" "$resp5" | _extract_count)
  if [[ -z "$stars_gt0" ]]; then
    warn "Could not determine count of projects with stars>0 (no Content-Range)."
  fi

  # Engagement: total snapshot rows
  local resp6 snap_rows
  resp6=$(curl -sS -D - -H "Prefer: count=exact" "${base}/project_engagement_snapshots?select=id" || true)
  snap_rows=$(printf "%s" "$resp6" | _extract_count)
  if [[ -z "$snap_rows" ]]; then
    warn "Could not determine count of project_engagement_snapshots rows (no Content-Range)."
  fi

  echo ""
  info "Verification summary:"
  info "- Projects with primary_language set: ${primary_lang_count:-unknown}"
  info "- Projects with total_loc > 0:       ${loc_count:-unknown}"
  info "- project_languages rows total:      ${lang_rows:-unknown}"
  info "- Projects with stars set:           ${stars_set:-unknown}"
  info "- Projects with stars > 0:           ${stars_gt0:-unknown}"
  info "- engagement snapshot rows total:    ${snap_rows:-unknown}"
}
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

confirm_or_exit() {
  if [[ -n "$CONFIRM" ]]; then return 0; fi
  read -r -p "This will DELETE Docker volume '${VOLUME_NAME}' and reinitialize the database. Continue? [y/N] " ans || true
  case "${ans:-}" in
    y|Y|yes|YES) ;;
    *) info "Aborted."; exit 0;;
  esac
}

# Ensure .env exists to support docker compose variable interpolation (never overwrite)
ensure_env() {
  if [[ ! -f .env ]]; then
    if [[ -f .env.sample ]]; then
      info ".env not found; creating from .env.sample"
      cp .env.sample .env
    else
      warn ".env and .env.sample not found; proceeding without env file"
    fi
  else
    info ".env found"
  fi
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

# Wait for server /health to be ready (best-effort)
wait_for_server() {
  if ! command -v curl >/dev/null 2>&1; then
    warn "curl not found; skipping server readiness check"
    return 0
  fi
  info "Waiting for Server at http://localhost:8080/health (60s timeout)"
  for i in {1..60}; do
    if curl -fsS http://localhost:8080/health >/dev/null; then
      info "Server is up."
      return 0
    fi
    sleep 1
  done
  warn "Server did not become ready within 60s. Check logs: ${COMPOSE} logs -f server"
}

# Ensure the Ollama model exists inside the container (if AI enabled)
ensure_ollama_model() {
  if [[ "${ENABLE_AI}" != "1" ]]; then return 0; fi
  # Verify ollama service is running before attempting pull
  local cid
  cid=$(${COMPOSE} --profile ai ps -q ollama 2>/dev/null || true)
  if [[ -n "${cid}" ]]; then
    info "Ensuring Ollama model '${AI_MODEL}' is available"
    # Pull is idempotent; -T avoids TTY issues on CI/Windows shells
    ${COMPOSE} --profile ai exec -T ollama ollama pull "${AI_MODEL}" || warn "Ollama pull failed; model may already be present or network blocked"
  else
    warn "Ollama service not running; skipped model ensure"
  fi
}

# Ensure host bind directories exist to avoid Docker creating root-owned dirs
ensure_host_dirs() {
  for d in oss_reports terraform_reports binaries_reports runs ollama; do
    if [[ ! -d "./$d" ]]; then
      info "Creating host directory: ./$d"
      mkdir -p "./$d"
    fi
  done
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

# Seed programming languages (bytes) to PostgREST via scan_oss.py
seed_languages() {
  local org token
  org=${GITHUB_ORG:-}
  token=${GITHUB_TOKEN:-}
  if [[ -z "$org" || -z "$token" ]]; then
    warn "GITHUB_ORG/GITHUB_TOKEN not set in environment/.env; skipping language seeding"
    return 0
  fi
  info "Seeding repository languages (bytes) for '${org}' via PostgREST"
  # Ensure latest scanner image (harmless if already built)
  ${COMPOSE} build scanner
  ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
    "python scan_oss.py \
       --org \"${org}\" \
       --token \"${token}\" \
       --use-graphql \
       --include-archived --include-forks \
       --enable-syft \
       --enable-grype \
       --grype-scan-mode both \
       --parse-osv-cvss \
       --persist-languages \
       --postgrest-url http://postgrest:3000 \
       --max-workers ${OSS_MAX_WORKERS:-3} -v"
}

# Seed SAST-relevant LOC and file counts per language via scan_linecount.py
seed_loc() {
  local org token
  org=${GITHUB_ORG:-}
  token=${GITHUB_TOKEN:-}
  if [[ -z "$org" || -z "$token" ]]; then
    warn "GITHUB_ORG/GITHUB_TOKEN not set in environment/.env; skipping LOC seeding"
    return 0
  fi
  info "Seeding per-language LOC/files for '${org}' via PostgREST"
  # Ensure latest scanner image (harmless if already built)
  ${COMPOSE} build scanner
  ${COMPOSE} run --rm --no-deps --entrypoint sh seeder -lc \
    "python scan_linecount.py \
       --org \"${org}\" \
       --token \"${token}\" \
       --include-archived --include-forks \
       --persist-loc \
       --postgrest-url http://postgrest:3000 \
       --max-workers ${LINECOUNT_MAX_WORKERS:-3} \
       --use-cloc -v"
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

  # Ensure env exists (create from sample if missing; never overwrite existing)
  ensure_env
  # Ensure host bind directories exist for mounts in compose
  ensure_host_dirs
  # Re-evaluate COMPOSE to include --env-file if .env now exists
  if [[ -f ./.env ]]; then
    COMPOSE="docker compose --env-file ./.env -p ${PROJECT_NAME} -f ${COMPOSE_FILE}"
  else
    COMPOSE="docker compose -p ${PROJECT_NAME} -f ${COMPOSE_FILE}"
  fi

  info "Bringing up portal stack fresh"
  if [[ "${ENABLE_AI}" == "1" ]]; then
    info "Starting with AI profile (ollama) enabled"
    ${COMPOSE} --profile ai up -d --remove-orphans db postgrest server web ollama
  else
    ${COMPOSE} up -d --remove-orphans db postgrest server web
  fi

  wait_for_postgrest
  wait_for_server
  ensure_ollama_model

  seed_projects
  # Seed LOC/files first so project_languages gets created; then OSS adds bytes
  seed_loc
  seed_engagement

  # Print non-fatal verification summary
  verify_seed

  info "Done."
  info "Portal web:    http://localhost:5173"
  info "PostgREST API: http://localhost:3001"
  info "Server logs:   ${COMPOSE} logs -f server"
}

main "$@"
