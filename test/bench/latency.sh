#!/usr/bin/env bash
# What the gateway adds to a streamed call (plan task 6.5). latbench sends the
# same streamed Messages request BENCH_RUNS times (default 200) straight to the
# mock's TLS listener and through Envoy and the processor, each on a new
# connection, and reports percentiles per path. This prints, for time to first
# token (TTFT) and the gap between events, the p99 of the proxied path minus
# the direct path, and exits non-zero above 10 ms for TTFT or 1 ms for the gap.
set -euo pipefail
cd "$(dirname "$0")/../integration"
export ENVOY_VERSION="${ENVOY_VERSION:-v1.40.2}"
# Its own compose project, so an integration run elsewhere on the same Docker daemon
# cannot stop this stack mid-measurement.
COMPOSE=(docker compose -p "${BENCH_PROJECT:-sandbox-gateway-bench}" -f compose.yaml -f ../bench/compose.yaml)

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then "${COMPOSE[@]}" logs --no-color --tail 40 || true; fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

./make-envoy-config.sh >/dev/null
"${COMPOSE[@]}" build -q
"${COMPOSE[@]}" up -d
# Wait until a proxied call works, so the first measured runs do not race startup.
for _ in $(seq 30); do
  "${COMPOSE[@]}" run --rm -T client streamcheck --addr envoy:443 --ca /certs/ca.crt --wait 0 >/dev/null 2>&1 && break
  sleep 1
done
out=$("${COMPOSE[@]}" --profile bench run --rm -T latbench)
echo "$out"
# The processor's own time per response chunk, from its records: what it adds to
# each event, without the scheduling noise of the two paths.
"${COMPOSE[@]}" logs --no-color --no-log-prefix processor | grep '"msg":"transaction"' | python3 -c '
import json, sys
mx, avg = [], []
for line in sys.stdin:
    r = json.loads(line)["record"]
    if r.get("response_chunks"):
        mx.append(r["chunk_proc_max_us"]); avg.append(r["chunk_proc_avg_us"])
mx.sort(); avg.sort()
if mx:
    print("processor time per chunk: mean of per-call averages %.0f us, p99 of per-call maxima %d us, over %d calls"
          % (sum(avg) / len(avg), mx[int(0.99 * (len(mx) - 1))], len(mx)))
'

echo "$out" | python3 -c '
import json, sys
r = json.load(sys.stdin)
d, p = r["direct"], r["proxied"]
dt, pt = d["ttft"]["p99_ms"], p["ttft"]["p99_ms"]
dg, pg = d["event_gap"]["p99_ms"], p["event_gap"]["p99_ms"]
print("runs: direct %d, proxied %d" % (d["runs"], p["runs"]))
print("TTFT p99: direct %.2f ms, proxied %.2f ms, added %+.2f ms (budget 10)" % (dt, pt, pt - dt))
print("event gap p99: direct %.2f ms, proxied %.2f ms, added %+.2f ms (budget 1)" % (dg, pg, pg - dg))
ok = pt - dt <= 10 and pg - dg <= 1 and d["runs"] > 0 and p["runs"] > 0
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
'
