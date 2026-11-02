#!/usr/bin/env bash
cd /data/yunzhou-control
docker compose ps
echo
docker compose logs --tail=50 api worker
