#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -d ".venv" ]]; then
  echo "Missing virtual environment: $ROOT_DIR/.venv"
  echo "Create it first, then install requirements."
  exit 1
fi

MODEL="${PENTESTFLOW_OLLAMA_SMALL_MODEL:-llama3.2:latest}"
export PENTESTFLOW_OLLAMA_SMALL_MODEL="${PENTESTFLOW_OLLAMA_SMALL_MODEL:-$MODEL}"
export PENTESTFLOW_OLLAMA_LARGE_MODEL="${PENTESTFLOW_OLLAMA_LARGE_MODEL:-$MODEL}"
export PENTESTFLOW_LLM_TIMEOUT_SECONDS="${PENTESTFLOW_LLM_TIMEOUT_SECONDS:-60}"
export PENTESTFLOW_ANALYSIS_PROMPT_VERSION="${PENTESTFLOW_ANALYSIS_PROMPT_VERSION:-v3}"
export PENTESTFLOW_ALLOWED_HOSTS="${PENTESTFLOW_ALLOWED_HOSTS:-127.0.0.1,localhost}"

if ! command -v ollama >/dev/null 2>&1; then
  echo "Ollama is not installed."
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is not installed."
  exit 1
fi

if ! ollama list >/dev/null 2>&1; then
  echo "Ollama server is not responding. Start it with: ollama serve"
  exit 1
fi

if ! ollama list | awk '{print $1}' | grep -qx "$MODEL"; then
  echo "Ollama model '$MODEL' is not installed."
  echo "Run: ollama pull $MODEL"
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -qx 'pentestflow-juice-shop'; then
  if docker ps -a --format '{{.Names}}' | grep -qx 'pentestflow-juice-shop'; then
    docker start pentestflow-juice-shop >/dev/null
  else
    docker run -d --rm --name pentestflow-juice-shop -p 3000:3000 bkimminich/juice-shop >/dev/null
  fi
fi

echo "Rebuilding knowledge base..."
.venv/bin/python -m app.main knowledge rebuild

echo
echo "Running PentestFlow against Juice Shop..."
.venv/bin/python -m app.main scan http://127.0.0.1:3000
