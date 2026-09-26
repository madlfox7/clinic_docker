#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
VENV_DIR=".venv-tests"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Run this script from WSL with Docker Desktop running." >&2
  exit 1
fi

TEST_PYTHON=python3
if { [ ! -x "$VENV_DIR/bin/python" ] || [ ! -f "$VENV_DIR/bin/activate" ]; } \
  && python3 -m venv "$VENV_DIR" >/dev/null 2>&1 \
  && [ -x "$VENV_DIR/bin/python" ] && [ -f "$VENV_DIR/bin/activate" ]; then
  source "$VENV_DIR/bin/activate"
  TEST_PYTHON=python
fi

if [ "$TEST_PYTHON" = python ]; then
  python -m pip install -r tests/requirements.txt
else
  if ! python3 -m pip --version >/dev/null 2>&1; then
    echo "Python venv/ensurepip and pip are unavailable. Install python3-venv or python3-pip in WSL." >&2
    exit 1
  fi
  echo "Python venv is unavailable; installing test packages for the current WSL user."
  python3 -m pip install --user -r tests/requirements.txt
fi

echo "Starting the local clinic stack (database volume will be preserved)..."
docker compose up -d --build

echo "Waiting for http://localhost:8080 ..."
ready=false
for attempt in $(seq 1 30); do
  if "$TEST_PYTHON" -c 'import urllib.request; urllib.request.urlopen("http://localhost:8080/", timeout=1)' >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done

if [ "$ready" != true ]; then
  echo "The clinic app did not become available at http://localhost:8080." >&2
  docker compose logs --tail=40 api
  exit 1
fi

echo "Running stage 4 tests against the local database. Tests create and cancel temporary appointments."
"$TEST_PYTHON" -m pytest -v tests/test_stage4.py "$@"
