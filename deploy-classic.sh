#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# The platform deliberately uses Docker's classic builder.  Keep the local
# layer cache: never add --no-cache and never prune as part of deployment.
export DOCKER_BUILDKIT=0
export COMPOSE_DOCKER_CLI_BUILD=0
export COMPOSE_BAKE=false

docker build -t yunzhou-control-api ./backend
docker tag yunzhou-control-api yunzhou-control-worker
docker build -t yunzhou-control-web ./frontend
docker compose up -d --no-build
docker compose ps
