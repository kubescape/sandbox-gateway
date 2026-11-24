#!/usr/bin/env bash
# Smoke test of the shipped processor image in kind (plan task 5.4).
#
# The integration stack runs a fixture build against stub maps and a static
# policy source. This runs the image this repo ships: as its own user, against
# maps pinned in the node's bpffs, with a service account against a real API
# server. The account starts with no RBAC, so the informers cannot list and
# the health path must answer 503; once list and watch are granted they sync
# and it must answer 200. Last, the same image with no maps must not start.
set -euo pipefail
cd "$(dirname "$0")/../.."
CLUSTER=sandbox-gateway-smoke
NODE="$CLUSTER-control-plane"
KIND=(go run sigs.k8s.io/kind@v0.27.0)
# Every call names the kind cluster's context, so nothing here touches another cluster.
KUBECTL=(kubectl --context "kind-$CLUSTER")
SOCK=/run/kubescape-sandbox/processor-health.sock

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "--- state (failure)"
    "${KUBECTL[@]}" -n smoke get pods -o wide || true
    "${KUBECTL[@]}" -n smoke describe pods || true
    for c in processor probe; do "${KUBECTL[@]}" -n smoke logs processor -c "$c" --tail 60 || true; done
    "${KUBECTL[@]}" -n smoke logs pinmaps || true
  fi
  "${KIND[@]}" delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

echo "--- images"
docker build -q -f build/Dockerfile.processor --build-arg image_version=smoke -t sandbox-gateway/processor:smoke .
docker build -q -f test/Dockerfile -t sandbox-gateway/test-fixtures:smoke .

echo "--- cluster"
"${KIND[@]}" create cluster --name "$CLUSTER" --wait 120s
docker exec "$NODE" sh -c 'mount | grep -q "on /sys/fs/bpf type bpf" || mount -t bpf bpf /sys/fs/bpf'
"${KIND[@]}" load docker-image --name "$CLUSTER" sandbox-gateway/processor:smoke sandbox-gateway/test-fixtures:smoke

echo "--- policy CRDs and one policy, from the pinned kubescape/storage"
STORAGE=$(go list -m -f '{{.Dir}}' github.com/kubescape/storage)
"${KUBECTL[@]}" apply -f "$STORAGE/artifacts/sandboxpolicy/sandboxpolicy.crd.yaml" \
  -f "$STORAGE/artifacts/sandboxpolicy/clustersandboxpolicy.crd.yaml"
"${KUBECTL[@]}" wait --for condition=established --timeout 60s \
  crd/sandboxpolicies.kubescape.io crd/clustersandboxpolicies.kubescape.io
"${KUBECTL[@]}" apply -f test/smoke/setup.yaml
# The example names namespace "agents"; create it so the object lands as written.
"${KUBECTL[@]}" create namespace agents --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f -
"${KUBECTL[@]}" apply -f "$STORAGE/artifacts/sandboxpolicy/sandboxpolicy-http.example.yaml"

echo "--- pin the maps in the node's bpffs"
"${KUBECTL[@]}" -n smoke wait --for=jsonpath='{.status.phase}'=Succeeded pod/pinmaps --timeout 120s
"${KUBECTL[@]}" -n smoke logs pinmaps

echo "--- the shipped image, with no RBAC yet"
"${KUBECTL[@]}" apply -f test/smoke/processor.yaml
"${KUBECTL[@]}" -n smoke wait --for=condition=Ready pod/processor --timeout 120s
health() { "${KUBECTL[@]}" -n smoke exec processor -c probe -- healthget "$SOCK" || true; }
got=""
for _ in $(seq 60); do
  got=$(health)
  case "$got" in
    503*) break ;;
    200*) echo "FAIL: healthy before the informers could list: $got"; exit 1 ;;
  esac
  sleep 1
done
echo "$got"
case "$got" in 503*) ;; *) echo "FAIL: want 503 before the first sync"; exit 1 ;; esac

echo "--- grant list and watch: the informers sync and the health path answers 200"
"${KUBECTL[@]}" apply -f test/smoke/rbac.yaml
for _ in $(seq 120); do
  got=$(health)
  case "$got" in 200*) break ;; esac
  sleep 1
done
echo "$got"
case "$got" in 200*) ;; *) echo "FAIL: want 200 after the sync"; exit 1 ;; esac
echo "$got" | grep -q '"evaluator":"unavailable"'

echo "--- the same image without the maps does not start"
"${KUBECTL[@]}" -n smoke wait --for=jsonpath='{.status.phase}'=Failed pod/processor-nomaps --timeout 120s
"${KUBECTL[@]}" -n smoke logs processor-nomaps | tail -1
"${KUBECTL[@]}" -n smoke logs processor-nomaps | grep -q 'open the connection tables'

echo "PASS"
