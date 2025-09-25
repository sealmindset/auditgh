#!/usr/bin/env bash
# start.sh - start the full portal stack services
# Brings up: db, postgrest, server, web, scanner

set -Eeuo pipefail

PROJECT_NAME=${PROJECT_NAME:-portal}
COMPOSE_FILE=${COMPOSE_FILE:-docker-compose.portal.yml}
COMPOSE="docker compose -p ${PROJECT_NAME} -f ${COMPOSE_FILE}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Error: '$1' is required but not installed or not on PATH" >&2
    exit 1
  }
}

info()  { echo "[start] $*"; }
error() { echo "[start][error] $*" >&2; }

main() {
  info "Checking prerequisites..."
  require docker
  if ! docker compose version >/dev/null 2>&1; then
    error "Docker Compose v2 is required (use 'docker compose', not 'docker-compose'). Please upgrade Docker Desktop."
    exit 1
  fi

  info "Starting services: db postgrest server web scanner"
  info "Command: ${COMPOSE} up -d --remove-orphans db postgrest server web scanner"
  ${COMPOSE} up -d --remove-orphans db postgrest server web scanner

  if command -v curl >/dev/null 2>&1; then
    info "Waiting for Server on http://localhost:8080/health (60s timeout)"
    ok=false
    for i in {1..5}; do
      if curl -fsS http://localhost:8080/health >/dev/null; then
        ok=true; break
      fi
      sleep 1
    done
    if [[ ${ok} != true ]]; then
      error "Server did not become ready within 60s. Check logs: ${COMPOSE} logs -f server"
      exit 1
    fi
  else
    info "curl not found; skipping readiness wait."
  fi

  # Post-start health checks
  fail=0
  info "Running health checks..."

  # DB readiness via pg_isready inside container
  if ${COMPOSE} exec -T db pg_isready -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-security_portal}" >/dev/null 2>&1; then
    info "[ok] db: pg_isready"
  else
    error "[fail] db: pg_isready"
    fail=1
  fi

  # PostgREST HTTP check
  if curl -fsS http://localhost:3001 >/dev/null; then
    info "[ok] postgrest: http://localhost:3001"
  else
    error "[fail] postgrest: http://localhost:3001"
    fail=1
  fi

  # Server health endpoint
  if curl -fsS http://localhost:8080/health >/dev/null; then
    info "[ok] server: http://localhost:8080/health"
  else
    error "[fail] server: http://localhost:8080/health"
    fail=1
  fi

  # Web (nginx) root
  if curl -fsS http://localhost:5173 >/dev/null; then
    info "[ok] web: http://localhost:5173"
  else
    error "[fail] web: http://localhost:5173"
    fail=1
  fi

  # Scanner image presence (best-effort)
  if docker image inspect auditgh-scanner:latest >/dev/null 2>&1; then
    info "[ok] scanner image: auditgh-scanner:latest"
  else
    error "[warn] scanner image missing; server will build on-demand"
  fi

  if [[ ${fail} -ne 0 ]]; then
    error "One or more health checks failed. See logs with: ${COMPOSE} logs"
    exit 1
  fi
  info "All services healthy."

  info "Web (portal):  http://localhost:5173"
  info "Server:        http://localhost:8080"
  info "PostgREST:     http://localhost:3001"
  info "DB:            localhost:5434 (inside container: db:5432)"
  info "Logs:          ${COMPOSE} logs -f"
}

main "$@"
