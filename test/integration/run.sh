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
#
# The node controller's rules are watched too: a pod is decrypted only for its own names, a
# passthrough connection goes to its original destination, the health listener's three
# paths, an SNI flood, chains added and removed under live connections with a cap of
# three names, leaf renewal, a node controller restart under a live connection, an SDS
# outage, and a change of root.
#
# SDK=1 runs the SDK job instead: the processor removes the first tool or
# function call of each response (-remove-first-tool), and the Python and Node
# provider SDKs stream three scenarios through Envoy, trusting only the gateway
# CA. test/sdk/check.py checks what they saw.
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
mkdir -p generated
"${COMPOSE[@]}" build

if [ "${SDK:-}" = 1 ]; then
  export IT_POLICIES=./policies-sdk.yaml PROCESSOR_EDIT=--remove-first-tool
  "${COMPOSE[@]}" --profile sdk build sdk-python sdk-node
  "${COMPOSE[@]}" up -d
  for _ in $(seq 1 60); do
    "${COMPOSE[@]}" logs --no-color origdst 2>/dev/null | grep -q 'attached: SO_ORIGINAL_DST' && break
    sleep 1
  done
  # Envoy gets its listeners from the node controller after it starts. streamcheck
  # retries until a streamed call goes through as it-pod; the SDK clients try once.
  echo "--- the redirect listener serves it-pod"
  "${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:18443 --ca /certs/ca.crt --wait 60s >/dev/null
  echo "--- SDKs on streams with the first tool call removed"
  "${COMPOSE[@]}" --profile sdk run --rm -T sdk-python > generated/sdk-python.jsonl
  "${COMPOSE[@]}" --profile sdk run --rm -T sdk-node > generated/sdk-node.jsonl
  cat generated/sdk-python.jsonl generated/sdk-node.jsonl
  echo "--- an edited response that ends in trailers keeps its last event"
  # s4-a-trailers: the tool is removed, the last event's blank line is a lone CR, and the
  # body ends with a trailer, so the processor must flush the editor before the trailers.
  "${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:18443 --ca /certs/ca.crt \
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
echo "--- original-destination stand-in"
for _ in $(seq 1 60); do
  "${COMPOSE[@]}" logs --no-color origdst 2>/dev/null | grep -q 'attached: SO_ORIGINAL_DST' && break
  sleep 1
done
"${COMPOSE[@]}" logs --no-color --no-log-prefix origdst | tail -3
"${COMPOSE[@]}" logs --no-color origdst | grep -q 'attached: SO_ORIGINAL_DST'
started=$(date +%s)

# Helpers for the checks below. Each prints httpget's result line: "<status> <body>".
result() { grep -E '^[0-9]{3} ' | tail -1 || true; }
# The node controller's debug stats: host set, names, counters.
# Asked from sock-probe, which has no fixed address: the client containers do, and only
# one container can hold an address at a time, so nothing else may run as "client" while
# a held connection is open from it.
ncstats() { "${COMPOSE[@]}" run --rm -T --no-deps sock-probe httpget http://node-controller:9101/stats 2>&1 | result; }
# Envoy stats by filter, over its admin socket.
envoystat() { "${COMPOSE[@]}" run --rm -T --no-deps sock-probe httpget -unix /run/sandbox-gateway/envoy-admin.sock "http://admin/stats?filter=$1" 2>&1 | grep -v Container || true; }
# A DNS sighting, posted the way node-agent will.
sight() { "${COMPOSE[@]}" run --rm -T --no-deps sock-probe httpget -unix /run/kubescape-sandbox/gateway.sock -post "{\"name\":\"$1\",\"addresses\":[\"172.30.0.30\"],\"bindingIds\":[1]}" http://gateway/v1/sightings 2>&1 | result; }
# Waits until the node controller's stats match a pattern, up to 60 seconds.
until_stats() { for _ in $(seq 1 60); do ncstats | grep -Eq "$1" && return 0; sleep 1; done; echo "timed out waiting for: $1"; ncstats; return 1; }
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
"${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:18443 --ca /certs/ca.crt --http1 --repeat 3 >/dev/null
sleep 1
"${COMPOSE[@]}" logs --no-color --no-log-prefix processor | grep '"msg":"transaction"' | tail -3 > generated/http1-records.jsonl
[ "$(grep -c '"protocol":"HTTP/1.1"' generated/http1-records.jsonl)" = 3 ]
if grep -q '"request_position"' generated/record.json generated/http1-records.jsonl; then
  echo "FAIL: a record has a request_position"; exit 1
fi

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

echo "--- a 1,500-name SNI flood mints nothing"
before=$(ncstats)
mem_before=$(envoystat '^server.memory_allocated$' | grep -Eo '[0-9]+$' | tail -1)
"${COMPOSE[@]}" run --rm -T --no-deps client sniflood --target envoy:18443 --n 1500 --c 16 --domain flood.anthropic.com \
  --envoy-admin http://unused.invalid --sds-debug http://node-controller:9101 > generated/flood.json 2>generated/flood.log
tail -1 generated/flood.log
after=$(ncstats)
mem_after=$(envoystat '^server.memory_allocated$' | grep -Eo '[0-9]+$' | tail -1)
field() { echo "$1" | grep -Eo "$2" | head -1; }
# No leaf, no chain and no name came from an SNI.
[ "$(field "$before" '"leaves":[0-9]+')" = "$(field "$after" '"leaves":[0-9]+')" ]
[ "$(field "$before" '"names":\[[^]]*\]')" = "$(field "$after" '"names":\[[^]]*\]')" ]
[ "$(field "$before" '"pushes":[0-9]+')" = "$(field "$after" '"pushes":[0-9]+')" ]
echo "envoy memory_allocated: $mem_before -> $mem_after bytes"
[ $((mem_after - mem_before)) -lt $((32 * 1024 * 1024)) ]

echo "--- adding a chain does not drain a live connection"
"${COMPOSE[@]}" run --rm -T --no-deps client tlshold --addr envoy:18443 --ca /certs/ca.crt --host api.anthropic.com --hold 12s > generated/hold-add.txt 2>/dev/null &
hold=$!
sleep 3
sight a.learned.example.com | tee generated/sight-a.txt
grep -q '^200 {"changed":true}' generated/sight-a.txt
until_stats '"names":\[[^]]*"a\.learned\.example\.com"'
wait "$hold" || true
cat generated/hold-add.txt
grep -q '^alive ' generated/hold-add.txt
# The new chain is live: it-pod is decrypted for the learned name (the 403 is the
# processor's guard, whose own policy file does not list it).
"${COMPOSE[@]}" run --rm -T --no-deps client streamcheck --addr envoy:18443 --ca /certs/ca.crt \
  --host a.learned.example.com --expect-status 403 --wait 20s | tee generated/learned-a.json
grep -q '"leaf_issuer":"Kubescape Sandbox Gateway' generated/learned-a.json
# other-pod's policy has no such pattern: for it the name is passed through.
if out=$("${COMPOSE[@]}" run --rm -T --no-deps client-other streamcheck --addr envoy:18443 --ca /certs/ca.crt --host a.learned.example.com --wait 0 2>&1); then
  echo "FAIL: a learned name was decrypted for a pod whose policy has no pattern for it"; exit 1
fi
echo "$out" | grep -q 'certificate is valid for mock-internal'
envoystat 'listener_manager.(listener_in_place_updated|total_filter_chains_draining|total_listeners_draining)$' | tee generated/listener-stats.txt
grep -Eq 'listener_in_place_updated: [1-9]' generated/listener-stats.txt
grep -q 'total_listeners_draining: 0' generated/listener-stats.txt

echo "--- a busy chain is kept: the cap is full and the only learned name has a connection"
"${COMPOSE[@]}" run --rm -T --no-deps client tlshold --addr envoy:18443 --ca /certs/ca.crt --host a.learned.example.com --hold 16s > generated/hold-busy.txt 2>/dev/null &
hold=$!
sleep 3
sight b.learned.example.com | tee generated/sight-b.txt
grep -q '^200 {"changed":false}' generated/sight-b.txt
sleep 8 # more than one reconcile
ncstats | tee generated/busy-stats.txt
grep -Eq '"names":\[[^]]*"a\.learned\.example\.com"' generated/busy-stats.txt
if grep -q '"b\.learned\.example\.com"' generated/busy-stats.txt; then echo "FAIL: the cap of three was exceeded"; exit 1; fi
grep -q '"OverCap":1' generated/busy-stats.txt
grep -q '"Evictions":0' generated/busy-stats.txt
wait "$hold" || true
cat generated/hold-busy.txt
grep -q '^alive ' generated/hold-busy.txt

echo "--- an idle chain is removed, and the waiting name takes its place"
until_stats '"names":\[[^]]*"b\.learned\.example\.com"'
ncstats | tee generated/evicted-stats.txt
if grep -q '"a\.learned\.example\.com"' generated/evicted-stats.txt; then echo "FAIL: the evicted name is still in the set"; exit 1; fi
grep -q '"Evictions":1' generated/evicted-stats.txt
grep -q '"OverCap":0' generated/evicted-stats.txt
"${COMPOSE[@]}" run --rm -T --no-deps client streamcheck --addr envoy:18443 --ca /certs/ca.crt \
  --host b.learned.example.com --expect-status 403 --wait 20s | grep -q '"leaf_issuer":"Kubescape Sandbox Gateway'
# The evicted name's chain is gone: it is passed through again.
if out=$("${COMPOSE[@]}" run --rm -T --no-deps client streamcheck --addr envoy:18443 --ca /certs/ca.crt --host a.learned.example.com --wait 0 2>&1); then
  echo "FAIL: an evicted name is still decrypted"; exit 1
fi
echo "$out" | grep -q 'certificate is valid for mock-internal'

echo "--- a renewed leaf is served without a restart, and decryptValidUntil moves with it"
# Leaves live 40 seconds here. Past that, the first leaf of every name has expired.
elapsed=$(( $(date +%s) - started ))
[ "$elapsed" -ge 45 ] || sleep $((45 - elapsed))
health client /healthz/certs | tee generated/health-certs-later.txt
first=$(grep -Eo '"decryptValidUntil":"[^"]+"' generated/health-certs.txt)
later=$(grep -Eo '"decryptValidUntil":"[^"]+"' generated/health-certs-later.txt)
echo "$first -> $later"
[ -n "$later" ] && [ "$first" != "$later" ]
"${COMPOSE[@]}" run --rm -T --no-deps client streamcheck --addr envoy:18443 --ca /certs/ca.crt --wait 0 | tail -1 | grep -q '"stop_reason":"end_turn"'
ncstats | grep -Eo '"renewed":[0-9]+' | tee generated/renewed.txt
grep -Eq '"renewed":[1-9]' generated/renewed.txt

echo "--- a node controller restart keeps the chains Envoy holds, and the connections on them"
# b.learned.example.com was learned from a sighting. The new process never sees that
# sighting; it has to take the chain back from Envoy before it publishes anything.
# Envoy keeps a removed chain on its draining count for the whole drain time, so the
# check is that the restart adds none, not that the count is zero.
draining() { envoystat 'listener_manager.total_filter_chains_draining$' | grep -Eo '[0-9]+$' | tail -1; }
draining_before=$(draining)
"${COMPOSE[@]}" run --rm -T --no-deps client tlshold --addr envoy:18443 --ca /certs/ca.crt --host b.learned.example.com --hold 20s > generated/hold-restart.txt 2>/dev/null &
hold=$!
sleep 3
"${COMPOSE[@]}" stop node-controller >/dev/null 2>&1
"${COMPOSE[@]}" up -d --no-deps node-controller >/dev/null 2>&1
until_stats '"lds":\{"acked":"[0-9a-f]+"'
ncstats | tee generated/restart-stats.txt
grep -Eq '"names":\[[^]]*"b\.learned\.example\.com"' generated/restart-stats.txt
"${COMPOSE[@]}" logs --no-color --no-log-prefix node-controller | grep -q 'adopted the chains Envoy already holds'
draining_after=$(draining)
echo "filter chains draining: $draining_before -> $draining_after"
[ -n "$draining_after" ] && [ "$draining_after" -le "$draining_before" ]
wait "$hold" || true
cat generated/hold-restart.txt
grep -q '^alive ' generated/hold-restart.txt
# The adopted chain is still mapped to the pod whose pattern covers it.
"${COMPOSE[@]}" run --rm -T --no-deps client streamcheck --addr envoy:18443 --ca /certs/ca.crt \
  --host b.learned.example.com --expect-status 403 --wait 20s | grep -q '"leaf_issuer":"Kubescape Sandbox Gateway'

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
# With the SDS server down a call still works: Envoy holds the leaf, no handshake waits on SDS.
"${COMPOSE[@]}" run --rm -T --no-deps client streamcheck --addr envoy:18443 --ca /certs/ca.crt --wait 0 | tail -1 | grep -q '"stop_reason":"end_turn"'

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

echo "--- rootFingerprint changes when the intermediate moves to a new root"
fp_before=$(health client /healthz/certs | grep -Eo '"rootFingerprint":"[0-9a-f]{64}"')
"${COMPOSE[@]}" stop node-controller >/dev/null 2>&1
"${COMPOSE[@]}" run --rm -T --no-deps new-root >/dev/null 2>&1
"${COMPOSE[@]}" up -d --no-deps node-controller >/dev/null 2>&1
for _ in $(seq 1 30); do health client /healthz/certs | grep -q '^200 ' && break; sleep 1; done
fp_after=$(health client /healthz/certs | grep -Eo '"rootFingerprint":"[0-9a-f]{64}"')
echo "$fp_before -> $fp_after"
[ -n "$fp_after" ] && [ "$fp_before" != "$fp_after" ]
# Envoy now serves leaves under the new root: a client that trusts only the new one verifies.
"${COMPOSE[@]}" run --rm -T --no-deps client streamcheck --addr envoy:18443 --ca /certs/ca.crt --wait 30s | tail -1 | grep -q '"stop_reason":"end_turn"'

echo "--- envoy access log"
"${COMPOSE[@]}" logs --no-color --no-log-prefix envoy | grep '"kind":"access"' | tail -1
echo "PASS"
