#!/usr/bin/env bash
# prepare_bind_dirs.sh - Create host-side bind directories for Docker Compose mounts
# Usage: ./prepare_bind_dirs.sh

set -euo pipefail

GREEN='\033[0;32m'
NC='\033[0m'

# Resolve repo root (directory containing this script)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

msg() { echo -e "${GREEN}$*${NC}"; }

create_dir() {
  local dir="$1"
  if [[ ! -d "$dir" ]]; then
    mkdir -p "$dir"
    msg "Created: $dir"
  else
    msg "Exists:  $dir"
  fi
}

msg "Preparing Docker bind directories under: $REPO_ROOT"
create_dir "$REPO_ROOT/ci_reports"
create_dir "$REPO_ROOT/codeql_reports"
create_dir "$REPO_ROOT/oss_reports"
create_dir "$REPO_ROOT/secrets_reports"
create_dir "$REPO_ROOT/hardcoded_ips_reports"
create_dir "$REPO_ROOT/terraform_reports"
create_dir "$REPO_ROOT/contributors_reports"
create_dir "$REPO_ROOT/binaries_reports"
create_dir "$REPO_ROOT/linecount_reports"
create_dir "$REPO_ROOT/markdown"
create_dir "$REPO_ROOT/logs"

msg "All bind directories are ready."
