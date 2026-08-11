#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

if [[ ! -f ".env.local" ]]; then
  cp .env.local.example .env.local
fi

if [[ ! -f ".env.authorized-target" ]]; then
  cp .env.authorized-target.example .env.authorized-target
fi

echo "Setup complete."
echo "Run: ./scripts/pentestflow.sh demo"
