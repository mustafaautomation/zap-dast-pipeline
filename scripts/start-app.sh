#!/usr/bin/env bash
# Start the notes app in the background and wait until /health answers.
# Usage: scripts/start-app.sh [insecure]
set -euo pipefail
if [[ "${1:-}" == "insecure" ]]; then export NOTES_INSECURE=1; fi
export NOTES_HOST=0.0.0.0 NOTES_PORT=8000
nohup uv run --frozen notes-app > app.log 2>&1 &
for _ in $(seq 1 30); do
  if curl -fsS http://localhost:8000/health > /dev/null; then echo "app is up"; exit 0; fi
  sleep 1
done
echo "app did not start"; cat app.log; exit 1
