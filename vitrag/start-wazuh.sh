#!/bin/bash
set -euo pipefail

COMPOSE_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$COMPOSE_DIR"

MANAGER="acd-wazuh-manager"
INDEXER="acd-wazuh-indexer"

# ── 1. Start all containers ──────────────────────────────────────────────────
echo "[1/6] Starting containers..."
docker compose up -d

# ── 2. Wait for the manager container to be running ──────────────────────────
echo "[2/6] Waiting for Wazuh manager to be running (up to 90s)..."
for i in $(seq 1 45); do
  STATUS=$(docker inspect --format '{{.State.Status}}' "$MANAGER" 2>/dev/null || echo "missing")
  if [ "$STATUS" = "running" ]; then
    echo "  Manager container running (${i}x2s elapsed)"
    break
  fi
  sleep 2
done
# Give Wazuh internals a moment to init before we cp
sleep 10

# ── 3. Inject ossec.conf into the volume ────────────────────────────────────
# The named volume wazuh_etc:/var/ossec/etc shadows the file bind mount, so
# we must docker cp to update the volume copy on every start.
echo "[3/6] Injecting ossec.conf into the wazuh_etc volume..."
docker cp wazuh/ossec.conf "$MANAGER":/var/ossec/etc/ossec.conf

# ── 4. Create required dirs/files that ossec.conf references ─────────────────
echo "[4/6] Ensuring required directories and list files exist..."
docker exec "$MANAGER" bash -c "
  mkdir -p /var/ossec/etc/shared/default /var/ossec/etc/lists/amazon
  touch /var/ossec/etc/shared/ar.conf \
        /var/ossec/etc/lists/audit-keys \
        /var/ossec/etc/lists/amazon/aws-eventnames \
        /var/ossec/etc/lists/security-eventchannel
  chown -R wazuh:wazuh /var/ossec/etc/lists/ /var/ossec/etc/shared/
"

# ── 5. OpenSearch security initialisation ────────────────────────────────────
echo "[5/6] Initialising OpenSearch security (safe to re-run)..."
docker exec "$INDEXER" bash -c "
  JAVA_HOME=/usr/share/wazuh-indexer/jdk \
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
    -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig \
    -icl -nhnv \
    -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
    -cert  /usr/share/wazuh-indexer/certs/admin.pem \
    -key   /usr/share/wazuh-indexer/certs/admin-key.pem \
    -h 127.0.0.1 -p 9200
" || echo "  OpenSearch init returned non-zero (may already be initialised) — continuing"

# ── 6. Restart Wazuh inside manager to reload ossec.conf + rules ─────────────
echo "[6/6] Restarting Wazuh services to pick up new config and rules..."
docker exec "$MANAGER" /var/ossec/bin/wazuh-control restart

echo ""
echo "============================================================"
echo " Wazuh ready."
echo " Dashboard   : https://localhost:5601"
echo " Credentials : admin / SecretPassword"
echo " API         : https://localhost:55000  (wazuh-wui / MyS3cr37P450r.*-)"
echo "============================================================"
