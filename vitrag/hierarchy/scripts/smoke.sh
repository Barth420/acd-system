#!/usr/bin/env bash
# smoke.sh: bring the stack up, hit every service, and check request ids reach the logs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
"$(dirname "${BASH_SOURCE[0]}")/up.sh"
GW=http://127.0.0.1:8080
fail() { echo "SMOKE FAIL: $*"; exit 1; }

echo "waiting for the gateway..."
for _ in $(seq 1 60); do curl -sf "$GW/healthz" >/dev/null && break; sleep 2; done
curl -sf "$GW/healthz" >/dev/null || fail "gateway not answering"

echo "--- direct health of every Flask service (inside the containers; they are not published)"
for s in auth_api:5000 product_api:5001 order_api:5002 search_api:5003 queue:5004; do
  name=${s%%:*}; port=${s##*:}
  docker exec "acd-h-$name" python -c "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:$port/healthz',timeout=3); sys.exit(0 if r.status==200 else 1)" \
    || fail "$name /healthz"
  echo "ok  $name"
done
docker exec acd-h-database pg_isready -U appuser -d acd_lab >/dev/null || fail "database"; echo "ok  database"
docker exec acd-h-cache redis-cli ping | grep -q PONG || fail "cache"; echo "ok  cache"

echo "--- journeys through the gateway"
TOK=$(curl -sf -X POST "$GW/auth/login" -H 'Content-Type: application/json' -d '{"username":"alice","password":"password"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')
[ -n "$TOK" ] || fail "login"
curl -sf "$GW/api/products?id=1" >/dev/null || fail "product view"
curl -sf "$GW/search?q=wid" >/dev/null || fail "search"
RID=$(curl -si -X POST "$GW/orders" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{"product_id":1,"qty":1}' | tr -d '\r' | awk -F': ' 'tolower($1)=="x-request-id"{print $2}')
[ -n "$RID" ] || fail "order / no X-Request-ID"
sleep 1

echo "--- request id $RID in the logs of every hop"
for c in nginx order_api queue; do
  docker exec "acd-h-$c" sh -c "grep -rq 'rid=$RID' /var/log/acd" || fail "rid not found in $c logs"
  echo "ok  $c logged rid=$RID"
done
echo "--- tier networks: tier-2 services must not be reachable from the gateway"
docker exec acd-h-nginx sh -c "nc -z -w 2 database 5432" && fail "gateway can reach the database directly" || echo "ok  gateway cannot reach database"
echo "SMOKE PASSED"
