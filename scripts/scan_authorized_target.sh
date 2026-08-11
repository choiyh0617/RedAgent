#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${PENTESTFLOW_ENV_FILE:-.env.authorized-target}"
TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: scripts/scan_authorized_target.sh <target-url>"
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing env file: $ENV_FILE"
  echo "Copy .env.authorized-target.example to $ENV_FILE and edit the allowed hosts."
  exit 1
fi

if [[ ! -d ".venv" ]]; then
  echo "Missing virtual environment: $ROOT_DIR/.venv"
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

export PENTESTFLOW_LLM_TIMEOUT_SECONDS="${PENTESTFLOW_LLM_TIMEOUT_SECONDS:-60}"
export PENTESTFLOW_ANALYSIS_PROMPT_VERSION="${PENTESTFLOW_ANALYSIS_PROMPT_VERSION:-v3}"

echo "Target: $TARGET"
echo "Allowed hosts: ${PENTESTFLOW_ALLOWED_HOSTS:-unset}"
echo "Allowed networks: ${PENTESTFLOW_ALLOWED_NETWORKS:-unset}"
echo

.venv/bin/python -m app.main scan "$TARGET"
