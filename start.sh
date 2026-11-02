#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Starting existing images must not trigger an implicit BuildKit/buildx build.
docker compose up -d --no-build
docker compose ps
