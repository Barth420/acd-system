#!/usr/bin/env bash
# up.sh: start the hierarchy lab (project acd-hierarchy). Refuses to run next to the old lab.
#   scripts/up.sh              default stack (no Wazuh)
#   scripts/up.sh --wazuh      also start the Wazuh containers (profile `wazuh`; needs ~3 GB RAM)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# the old lab (vitrag/docker-compose.yml, project acd-phase1; minimal-mode uses acd-phase1-minimal) publishes 5002 and 8080
OLD=$(docker ps -q --filter "label=com.docker.compose.project=acd-phase1" --filter "label=com.docker.compose.project=acd-phase1-minimal" 2>/dev/null || true)
OLD="$OLD$(docker ps -q --filter "label=com.docker.compose.project=acd-phase1-minimal" 2>/dev/null || true)"
if [ -n "$(echo "$OLD" | tr -d '[:space:]')" ]; then
  echo "ERROR: the old lab (project acd-phase1 / acd-phase1-minimal) is running. It publishes host ports 5002 and 8080, which this stack needs."
  echo "       Stop it first:  docker compose -f vitrag/docker-compose.yml down   (or minimal-mode/docker-compose.minimal.yml)"
  exit 1
fi

PROFILES=()
for a in "$@"; do [ "$a" = "--wazuh" ] && PROFILES+=(--profile wazuh); done
docker compose "${PROFILES[@]}" up -d --build
if [ "${#PROFILES[@]}" -gt 0 ]; then docker compose stop forwarder; echo "Wazuh profile: now run scripts/start-wazuh.sh to load the rules/config into the manager (the log forwarder is stopped, forwarder-wazuh takes over)."; fi
echo "Gateway: http://127.0.0.1:8080   Controller: http://127.0.0.1:8100 (console: /ui)   Alert sink: http://127.0.0.1:8099"
