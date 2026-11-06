#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# The platform deliberately uses Docker's classic builder.  Keep the local
# layer cache: never add --no-cache and never prune as part of deployment.
export DOCKER_BUILDKIT=0
export COMPOSE_DOCKER_CLI_BUILD=0
export COMPOSE_BAKE=false

proxy_args=()
if [[ -n "${BUILD_HTTP_PROXY:-}" ]]; then
  proxy_args+=(--build-arg "HTTP_PROXY=${BUILD_HTTP_PROXY}" --build-arg "HTTPS_PROXY=${BUILD_HTTP_PROXY}")
fi

docker build -t yunzhou-control-backend:latest ./backend
docker build "${proxy_args[@]}" -t yunzhou-control-web:latest ./frontend
docker compose up -d --no-build
docker compose ps
