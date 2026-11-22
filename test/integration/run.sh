#!/usr/bin/env bash
# One streamed call through Envoy to the mock provider.
# Pass: the client, trusting only the gateway CA, reads the whole stream (end_turn), and the
# processor's transaction record shows it parsed the same stream. Two refusals are checked
# too: a Host header that is not the decrypted name, and a passthrough name that resolves
# to loopback.
set -euo pipefail
cd "$(dirname "$0")"
export ENVOY_VERSION="${ENVOY_VERSION:-v1.40.2}"
COMPOSE=(docker compose -f compose.yaml)

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "--- logs (failure)"; "${COMPOSE[@]}" logs --no-color --tail 80 || true
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

./make-envoy-config.sh
"${COMPOSE[@]}" build
"${COMPOSE[@]}" up -d
echo "--- envoy version"
"${COMPOSE[@]}" exec -T envoy envoy --version | grep -F "/${ENVOY_VERSION#v}/"

echo "--- streamed call"
"${COMPOSE[@]}" run --rm -T client | tee generated/client.json
grep -q '"stop_reason":"end_turn"' generated/client.json
grep -q '"message_stop":true' generated/client.json

echo "--- processor record"
sleep 1
"${COMPOSE[@]}" logs --no-color --no-log-prefix processor | grep '"msg":"transaction"' | tail -1 | tee generated/record.json
grep -q '"stop_reason":"end_turn"' generated/record.json
grep -Eq '"sse_events":[1-9]' generated/record.json

echo "--- a Host header that differs from the decrypted name is refused"
"${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:443 --ca /certs/ca.crt \
  --host-header attacker.example --expect-status 404 --wait 0

echo "--- a name that resolves to loopback does not loop through the listener"
if "${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:443 --ca /certs/ca.crt --host localhost --wait 0; then
  echo "FAIL: a passthrough to loopback completed"; exit 1
fi
sleep 3
# Without the loop guard this count runs into the hundreds within a second.
hops=$("${COMPOSE[@]}" logs --no-color --no-log-prefix envoy | grep -c '"kind":"passthrough"' || true)
echo "passthrough connections logged: $hops"
[ "$hops" -le 5 ]

echo "--- envoy access log"
"${COMPOSE[@]}" logs --no-color --no-log-prefix envoy | grep '"kind":"access"' | tail -1
echo "PASS"
