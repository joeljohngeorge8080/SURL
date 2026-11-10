#!/usr/bin/env bash
# Pull-based deploy: run by surl-deploy.timer every minute. Fetches the latest
# deploy branch and image from GHCR and restarts the stack only if the image
# changed. No inbound access or CI secrets needed (SSH can stay locked down).
set -euo pipefail

REPO_DIR="${SURL_DIR:-$HOME/SURL}"
BRANCH="${SURL_BRANCH:-deploy}"
COMPOSE=(docker compose -f docker-compose.prod.yml)

cd "$REPO_DIR"
git fetch --quiet origin "$BRANCH"
git merge --ff-only --quiet "origin/$BRANCH" || echo "WARN: repo not fast-forwardable, keeping local files"

image_id() { docker image inspect --format '{{.Id}}' "ghcr.io/joeljohngeorge8080/surl:${SURL_TAG:-deploy}" 2>/dev/null || true; }
before="$(image_id)"
"${COMPOSE[@]}" pull --quiet
after="$(image_id)"

running="$(docker inspect --format '{{.State.Running}}' surl_api 2>/dev/null || echo false)"
if [ "$before" != "$after" ] || [ "$running" != "true" ]; then
  echo "deploying image ${after:0:19}"
  "${COMPOSE[@]}" up -d --remove-orphans
  # Healthcheck gate: fail the unit (visible in journalctl) if it doesn't come up.
  for _ in $(seq 1 30); do
    [ "$(docker inspect --format '{{.State.Health.Status}}' surl_api)" = healthy ] && { echo "healthy"; docker image prune -f >/dev/null; exit 0; }
    sleep 5
  done
  echo "ERROR: surl_api not healthy after deploy" >&2
  exit 1
fi
