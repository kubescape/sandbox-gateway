#!/usr/bin/env bash
# One streamed call through Envoy to the mock provider.
# Pass: the client, trusting only the gateway CA, reads the whole stream (end_turn), and the
# processor's transaction record shows it parsed the same stream and named the pod. The
# processor runs a test evaluator: a request for "denied-model" gets its 403. Its policy
# objects come from policies.yaml; a request to a decrypted host they do not list is refused. Refusals
# checked too: a Host header that is not the decrypted name, a passthrough connection
# with no recorded destination, and a connection that is not in the connection table. A client
# must not be able to choose the address the processor looks it up by, with an
# X-Forwarded-For header or a PROXY protocol header. The shipped processor image must
# refuse to start without the kernel tables.
set -euo pipefail
cd "$(dirname "$0")"
export ENVOY_VERSION="${ENVOY_VERSION:-v1.40.2}"
export IT_TAG="${IT_TAG:-it}"
COMPOSE=(docker compose -p "${IT_PROJECT:-sandbox-gateway-it}" -f compose.yaml)

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
"${COMPOSE[@]}" --profile tools build processor-image
"${COMPOSE[@]}" up -d
echo "--- original-destination stand-in"
for _ in $(seq 1 60); do
  "${COMPOSE[@]}" logs --no-color origdst 2>/dev/null | grep -q 'attached: SO_ORIGINAL_DST' && break
  sleep 1
done
"${COMPOSE[@]}" logs --no-color --no-log-prefix origdst | tail -3
"${COMPOSE[@]}" logs --no-color origdst | grep -q 'attached: SO_ORIGINAL_DST'
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

echo "--- a pod is decrypted only for the hosts its own policy names"
# other-pod's policy names api.openai.com. It is decrypted for that host: the leaf is the
# gateway's. (The 403 is the processor's decrypt-list guard, which knows only it-pod.)
"${COMPOSE[@]}" run --rm -T client-other streamcheck --addr envoy:18443 --ca /certs/ca.crt \
  --host api.openai.com --expect-status 403 --wait 0 | tee generated/other-decrypted.json
grep -q '"leaf_issuer":"Kubescape Sandbox Gateway' generated/other-decrypted.json
# It asks for api.anthropic.com, which only it-pod's policy names. It must be passed
# through: the certificate it sees is the mock's own, not a gateway leaf.
if out=$("${COMPOSE[@]}" run --rm -T client-other streamcheck --addr envoy:18443 --ca /certs/ca.crt \
    --host api.anthropic.com --wait 0 2>&1); then
  echo "FAIL: other-pod was decrypted for a host only another pod's policy names"; exit 1
fi
echo "$out" | tail -1
echo "$out" | grep -q 'certificate is valid for mock-internal'

echo "--- a source that is no pod on the node gets no chain"
if out=$("${COMPOSE[@]}" run --rm -T client-unknown streamcheck --addr envoy:18443 --ca /certs/ca.crt --wait 0 2>&1); then
  echo "FAIL: an unknown source was served"; exit 1
fi
echo "$out" | tail -1
echo "$out" | grep -Eq 'connection reset|EOF'

echo "--- the health listener: three paths, each answered by its own process"
# Prints httpget's result line: "<status> <body>", or "000 <error>" with no HTTP answer.
# --no-deps: a plain "run" would start a service this script stopped on purpose.
health() { "${COMPOSE[@]}" run --rm -T --no-deps "$1" httpget "http://envoy:18444$2" 2>&1 | grep -E '^[0-9]{3} ' | tail -1 || true; }
health client /healthz/envoy | tee generated/health-envoy.txt
grep -q '^200 ok' generated/health-envoy.txt
health client /healthz/processor | tee generated/health-processor.txt
grep -q '^200 .*"evaluator":"available"' generated/health-processor.txt
health client /healthz/certs | tee generated/health-certs.txt
grep -Eq '^200 \{"canDecrypt":true,"decryptValidUntil":"20[0-9T:.Z-]+","rootFingerprint":"[0-9a-f]{64}"\}' generated/health-certs.txt
health client /quitquitquit | tee generated/health-other.txt
grep -q '^404' generated/health-other.txt

echo "--- the health listener refuses a source that is not on the node"
out=$(health client-unknown /healthz/envoy)
echo "$out"
echo "$out" | grep -Eq '^000 .*(connection reset|EOF)'

echo "--- the test evaluator blocks a request for the denied model, with its DenyResponse"
"${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:18443 --ca /certs/ca.crt \
  --model denied-model --expect-status 403 --wait 0 | tee generated/denied.json
grep -q 'denied by the integration test evaluator' generated/denied.json
sleep 1
"${COMPOSE[@]}" logs --no-color --no-log-prefix processor | grep '"msg":"transaction"' | tail -1 | tee generated/denied-record.json
grep -q '"rule":"it.denied-model"' generated/denied-record.json
grep -q '"ended":"denied"' generated/denied-record.json

echo "--- a decrypted host that no policy decrypts is refused by the decrypt-list guard"
"${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:18443 --ca /certs/ca.crt \
  --host api.openai.com --expect-status 403 --wait 0 | tee generated/not-decrypted.json
grep -q 'request blocked by the gateway' generated/not-decrypted.json
sleep 1
"${COMPOSE[@]}" logs --no-color --no-log-prefix processor | grep '"msg":"transaction"' | tail -1 | tee generated/not-decrypted-record.json
grep -q '"rule":"framework.host-not-decrypted"' generated/not-decrypted-record.json

echo "--- a Host header that differs from the decrypted name is refused"
# The decrypt-list guard refuses it at the request headers, before Envoy's router would
# answer 404: no policy decrypts the name the Host header gives.
"${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:18443 --ca /certs/ca.crt \
  --host-header attacker.example --expect-status 403 --wait 0
sleep 1
"${COMPOSE[@]}" logs --no-color --no-log-prefix processor | grep '"msg":"transaction"' | tail -1 | tee generated/host-header.json
grep -q '"authority":"attacker.example"' generated/host-header.json
grep -q '"rule":"framework.host-not-decrypted"' generated/host-header.json

echo "--- a passthrough connection goes to its original destination, whatever the SNI"
# The name resolves to loopback and to nothing the mock serves. The connection must still
# land on the mock, where the connection table says this pod was going.
if out=$("${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:18443 --ca /certs/ca.crt --host localhost --wait 0 2>&1); then
  echo "FAIL: a passthrough connection was served a certificate the client trusts"; exit 1
fi
echo "$out" | tail -1
echo "$out" | grep -q 'certificate is valid for mock-internal'
# Envoy logs a passthrough connection when it closes, which can trail the client's exit.
for _ in $(seq 1 20); do
  "${COMPOSE[@]}" logs --no-color --no-log-prefix envoy | grep '"kind":"passthrough"' | grep '"sni":"localhost"' | tail -1 > generated/passthrough.json || true
  [ -s generated/passthrough.json ] && break
  sleep 1
done
cat generated/passthrough.json
grep -q '"upstream_host":"172.30.0.30:443"' generated/passthrough.json
grep -q '"orig_dst":"172.30.0.30:443"' generated/passthrough.json

echo "--- a passthrough connection with no recorded destination is reset"
if out=$("${COMPOSE[@]}" run --rm -T client-noentry streamcheck --addr envoy:18443 --ca /certs/ca.crt --host pypi.org --wait 0 2>&1); then
  echo "FAIL: a connection with no entry in the connection table was forwarded"; exit 1
fi
echo "$out" | tail -1
echo "$out" | grep -Eq 'connection reset|EOF'

echo "--- the address the processor sees is the socket's, whatever the client claims"
forged=198.51.100.77
"${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:18443 --ca /certs/ca.crt --x-forwarded-for "$forged" >/dev/null
# With a PROXY line in front, the bytes are not a TLS ClientHello, so the call must fail.
if "${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:18443 --ca /certs/ca.crt --wait 0 \
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
"${COMPOSE[@]}" run --rm -T --no-deps client streamcheck --addr envoy:18443 --ca /certs/ca.crt --expect-status 403 --wait 30s
"${COMPOSE[@]}" logs --no-color --no-log-prefix processor | grep '"msg":"transaction"' | tail -1 | tee generated/rejected.json
grep -q '"reject_reason":"no_connection_entry"' generated/rejected.json
"${COMPOSE[@]}" up -d --force-recreate processor

echo "--- the shipped processor image does not start without the kernel tables"
if out=$(docker run --rm "sandbox-gateway/processor:$IT_TAG" 2>&1); then
  echo "FAIL: the processor started with no connection tables"; exit 1
fi
echo "$out" | tail -1
echo "$out" | grep -q 'open the connection tables'

echo "--- one process down fails its own health path and not the other two"
"${COMPOSE[@]}" stop processor >/dev/null 2>&1
health client /healthz/processor | tee generated/health-processor-down.txt
grep -q '^503' generated/health-processor-down.txt
health client /healthz/envoy | grep -q '^200 ok'
health client /healthz/certs | grep -q '^200 '
"${COMPOSE[@]}" start processor >/dev/null 2>&1
"${COMPOSE[@]}" stop node-controller >/dev/null 2>&1
health client /healthz/certs | tee generated/health-certs-down.txt
grep -q '^503' generated/health-certs-down.txt
health client /healthz/envoy | grep -q '^200 ok'
for _ in $(seq 1 20); do health client /healthz/processor | grep -q '^200 ' && break; sleep 1; done
health client /healthz/processor | grep -q '^200 '

echo "--- an Envoy that starts while the node controller is down opens no listener"
"${COMPOSE[@]}" stop envoy >/dev/null 2>&1
# --no-deps, or compose would bring the node controller back with it.
"${COMPOSE[@]}" up -d --no-deps envoy >/dev/null 2>&1
sleep 5
if "${COMPOSE[@]}" ps --status running --services | grep -qx node-controller; then
  echo "FAIL: the node controller is running; this check needs it down"; exit 1
fi
"${COMPOSE[@]}" ps --status running --services | grep -qx envoy
out=$(health client /healthz/envoy)
echo "$out"
echo "$out" | grep -q '^000 ' # no HTTP answer: nothing listens on the health port
"${COMPOSE[@]}" start node-controller >/dev/null 2>&1
for _ in $(seq 1 30); do health client /healthz/envoy | grep -q '^200 ok' && break; sleep 1; done
health client /healthz/envoy | grep -q '^200 ok'
# The redirect listener is back with it: a decrypted call works again.
"${COMPOSE[@]}" run --rm -T --no-deps client streamcheck --addr envoy:18443 --ca /certs/ca.crt --wait 30s | tail -1 | grep -q '"stop_reason":"end_turn"'

echo "--- envoy access log"
"${COMPOSE[@]}" logs --no-color --no-log-prefix envoy | grep '"kind":"access"' | tail -1
echo "PASS"
