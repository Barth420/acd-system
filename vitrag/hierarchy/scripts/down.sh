#!/usr/bin/env bash
# down.sh: stop the hierarchy lab. Add --volumes to also drop the database and logs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
FLAGS=()
for a in "$@"; do [ "$a" = "--volumes" ] && FLAGS+=(-v); done
docker compose --profile wazuh down "${FLAGS[@]}"
