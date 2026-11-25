#!/usr/bin/env bash
# One streamed call through Envoy to the mock provider.
# Pass: the client, trusting only the gateway CA, reads the whole stream (end_turn), and the
# processor's transaction record shows it parsed the same stream and named the pod. The
# processor runs a test evaluator: a request for "denied-model" gets its 403. Its policy
# objects come from policies.yaml; a request to a decrypted host they do not list is refused. Refusals
# checked too: a Host header that is not the decrypted name, a passthrough name that
# resolves to loopback, and a connection that is not in the connection table. A client
# must not be able to choose the address the processor looks it up by, with an
# X-Forwarded-For header or a PROXY protocol header. The shipped processor image must
# refuse to start without the kernel tables.
#
# SDK=1 runs the SDK job instead: the processor removes the first tool or
# function call of each response (-remove-first-tool), and the Python and Node
# provider SDKs stream three scenarios through Envoy, trusting only the gateway
# CA. test/sdk/check.py checks what they saw.
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
mkdir -p generated
"${COMPOSE[@]}" build

if [ "${SDK:-}" = 1 ]; then
  export IT_POLICIES=./policies-sdk.yaml PROCESSOR_EDIT=--remove-first-tool
  "${COMPOSE[@]}" --profile sdk build sdk-python sdk-node
  "${COMPOSE[@]}" up -d
  echo "--- SDKs on streams with the first tool call removed"
  # Retries: the first run can race Envoy's listener coming up.
  for _ in 1 2 3; do
    "${COMPOSE[@]}" --profile sdk run --rm -T sdk-python > generated/sdk-python.jsonl && break
    sleep 2
  done
  "${COMPOSE[@]}" --profile sdk run --rm -T sdk-node > generated/sdk-node.jsonl
  cat generated/sdk-python.jsonl generated/sdk-node.jsonl
  echo "--- an edited response that ends in trailers keeps its last event"
  # s4-a-trailers: the tool is removed, the last event's blank line is a lone CR, and the
  # body ends with a trailer, so the processor must flush the editor before the trailers.
  "${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:443 --ca /certs/ca.crt \
    --model s4-a-trailers | tee generated/trailers.json
  grep -q '"message_stop":true' generated/trailers.json
  sleep 1
  "${COMPOSE[@]}" logs --no-color --no-log-prefix processor | grep '"msg":"transaction"' | tail -1 | tee generated/trailers-record.json
  grep -q '"ended":"trailers"' generated/trailers-record.json

  "${COMPOSE[@]}" --profile sdk run --rm -T -v "$PWD/generated:/out:ro" sdk-python \
    python check.py /out/sdk-python.jsonl /out/sdk-node.jsonl
  echo "PASS"
  exit 0
fi

"${COMPOSE[@]}" --profile tools build processor-image
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
grep -q '"pod":"it-pod"' generated/record.json

echo "--- no request_position: the processor cannot prove it saw a connection's first request"
grep -q '"protocol":"HTTP/2"' generated/record.json
"${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:443 --ca /certs/ca.crt --http1 --repeat 3 >/dev/null
sleep 1
"${COMPOSE[@]}" logs --no-color --no-log-prefix processor | grep '"msg":"transaction"' | tail -3 > generated/http1-records.jsonl
[ "$(grep -c '"protocol":"HTTP/1.1"' generated/http1-records.jsonl)" = 3 ]
if grep -q '"request_position"' generated/record.json generated/http1-records.jsonl; then
  echo "FAIL: a record has a request_position"; exit 1
fi

echo "--- the test evaluator blocks a request for the denied model, with its DenyResponse"
"${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:443 --ca /certs/ca.crt \
  --model denied-model --expect-status 403 --wait 0 | tee generated/denied.json
grep -q 'denied by the integration test evaluator' generated/denied.json
sleep 1
"${COMPOSE[@]}" logs --no-color --no-log-prefix processor | grep '"msg":"transaction"' | tail -1 | tee generated/denied-record.json
grep -q '"rule":"it.denied-model"' generated/denied-record.json
grep -q '"ended":"denied"' generated/denied-record.json

echo "--- a decrypted host that no policy decrypts is refused by the decrypt-list guard"
"${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:443 --ca /certs/ca.crt \
  --host api.openai.com --expect-status 403 --wait 0 | tee generated/not-decrypted.json
grep -q 'request blocked by the gateway' generated/not-decrypted.json
sleep 1
"${COMPOSE[@]}" logs --no-color --no-log-prefix processor | grep '"msg":"transaction"' | tail -1 | tee generated/not-decrypted-record.json
grep -q '"rule":"framework.host-not-decrypted"' generated/not-decrypted-record.json

echo "--- a Host header that differs from the decrypted name is refused"
# The decrypt-list guard refuses it at the request headers, before Envoy's router would
# answer 404: no policy decrypts the name the Host header gives.
"${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:443 --ca /certs/ca.crt \
  --host-header attacker.example --expect-status 403 --wait 0
sleep 1
"${COMPOSE[@]}" logs --no-color --no-log-prefix processor | grep '"msg":"transaction"' | tail -1 | tee generated/host-header.json
grep -q '"authority":"attacker.example"' generated/host-header.json
grep -q '"rule":"framework.host-not-decrypted"' generated/host-header.json

echo "--- a name that resolves to loopback does not loop through the listener"
if "${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:443 --ca /certs/ca.crt --host localhost --wait 0; then
  echo "FAIL: a passthrough to loopback completed"; exit 1
fi
sleep 3
# Without the loop guard this count runs into the hundreds within a second.
hops=$("${COMPOSE[@]}" logs --no-color --no-log-prefix envoy | grep -c '"kind":"passthrough"' || true)
echo "passthrough connections logged: $hops"
[ "$hops" -le 5 ]

echo "--- the address the processor sees is the socket's, whatever the client claims"
forged=198.51.100.77
"${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:443 --ca /certs/ca.crt --x-forwarded-for "$forged" >/dev/null
# With a PROXY line in front, the bytes are not a TLS ClientHello, so the call must fail.
if "${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:443 --ca /certs/ca.crt --wait 0 \
    --proxy-header "PROXY TCP4 $forged 192.0.2.1 4242 443" >/dev/null 2>&1; then
  echo "FAIL: a connection that starts with a PROXY protocol header was served"; exit 1
fi
sleep 1
"${COMPOSE[@]}" logs --no-color --no-log-prefix processor | grep '"msg":"transaction"' > generated/records.jsonl
if grep -F "$forged" generated/records.jsonl; then
  echo "FAIL: the processor saw the address the client claimed"; exit 1
fi

echo "--- a connection that is not in the connection table is refused"
PROCESSOR_MODE=--reject-all "${COMPOSE[@]}" up -d --force-recreate processor
# --no-deps: otherwise compose sees the processor's changed command and recreates it.
"${COMPOSE[@]}" run --rm -T --no-deps client streamcheck --addr envoy:443 --ca /certs/ca.crt --expect-status 403 --wait 30s
"${COMPOSE[@]}" logs --no-color --no-log-prefix processor | grep '"msg":"transaction"' | tail -1 | tee generated/rejected.json
grep -q '"reject_reason":"no_connection_entry"' generated/rejected.json
"${COMPOSE[@]}" up -d --force-recreate processor

echo "--- the shipped processor image does not start without the kernel tables"
if out=$(docker run --rm sandbox-gateway/processor:it 2>&1); then
  echo "FAIL: the processor started with no connection tables"; exit 1
fi
echo "$out" | tail -1
echo "$out" | grep -q 'open the connection tables'

echo "--- envoy access log"
"${COMPOSE[@]}" logs --no-color --no-log-prefix envoy | grep '"kind":"access"' | tail -1
echo "PASS"
