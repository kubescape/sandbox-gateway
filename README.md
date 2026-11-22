# sandbox-gateway

A per-node L7 egress gateway for the Kubescape AI sandbox. It sits between sandboxed pods and AI providers: Envoy terminates the pod's TLS with a certificate minted for that hostname, an external processor reads the request and the streamed response, and the bytes go on to the provider unchanged.

This repo holds the gateway's node controller, its processor and the Envoy config. The eBPF redirect that sends pod connections here lives in [kubescape/node-agent](https://github.com/kubescape/node-agent). Rule evaluation is pluggable through `pkg/plugin`. The processor built here has no evaluator wired in: it parses and records traffic, makes no decisions and blocks nothing.

## Status

Early. The code was seeded from an audit-only proof of concept and has not been released. Flag names, socket paths and the plugin interface will change.

Envoy 1.40 is the minimum version. CI runs 1.40.2.

## What is here

| Path | What it is |
| --- | --- |
| `cmd/node-controller` | SDS server. Mints a leaf certificate per hostname for Envoy, only for names in the node's host set. |
| `cmd/processor` | Envoy external processor (`ext_proc`, full duplex streamed). Finds the pod that sent each request, parses requests and streamed responses, runs the stall watchdog, writes one record per transaction. See [docs/features/processor.md](docs/features/processor.md). |
| `pkg/plugin` | The interface a rule evaluator implements. First cut. |
| `internal/sds`, `internal/ca`, `internal/hostset` | SDS protocol, certificate minting, and the set of hosts the node may decrypt (exact hosts, plus pattern hosts seen in DNS, capped per node). |
| `internal/extproc`, `internal/app` | The processor itself, and the code that wires and runs it. |
| `internal/conntable`, `internal/lookup` | Who sent a request: the connection and bindings tables node-agent pins, and node-agent's workload lookup. |
| `internal/sse`, `internal/streamfmt`, `internal/renumber`, `internal/eventstream`, `internal/wsframe`, `pkg/jsonscan` | Stream parsing: server-sent events, the Anthropic and OpenAI stream formats, removing and renumbering streamed items, AWS event stream (Bedrock), WebSocket frames, and request JSON fields. |
| `internal/otlpemit` | Sends transaction records as OTLP logs. |
| `deploy/envoy/envoy.yaml` | The Envoy config. |
| `test/` | Test fixtures (`mock-anthropic`, `sniflood`, `latbench`, `streamcheck`, `processor-it`) and the integration stack. |

## Build and test

You need Go 1.26 or newer. The integration test also needs Docker.

```bash
go build ./...
```

```bash
go test -race ./...
```

The integration test builds the images, starts the node controller and a processor build with a stub connection table (`test/processor-it`) next to Envoy 1.40.2 and a mock provider, and makes one streamed call through the gateway. The client trusts only the gateway's CA, so the call fails unless Envoy served a certificate the node controller minted. It also checks refusals: a request whose `Host` header is not a decrypted name, a passthrough name that resolves to loopback, and a connection that is not in the connection table. It checks that the shipped processor image will not start without the tables.

```bash
test/integration/run.sh
```

To build the images by hand:

```bash
docker build -f build/Dockerfile.node-controller -t sandbox-gateway-node-controller .
```

```bash
docker build -f build/Dockerfile.processor -t sandbox-gateway-processor .
```

## Running the images

Both images run as a non-root user (uid 65532). Each creates its unix socket with mode 0660 and, when `SANDBOX_GATEWAY_SOCKET_GID` is set, hands it to that group so Envoy can connect. Envoy's official image runs with gid 101, so set the variable to `101` and add 101 as a supplementary group of the container. `test/integration/compose.yaml` shows the full setup.

The processor reads the connection tables node-agent pins under `/sys/fs/bpf/kubescape-sandbox/http/` and will not start without them, so it needs `CAP_BPF` and the bpffs mount. It also asks node-agent who owns a connection over `/run/kubescape-sandbox/lookup.sock`.

The debug HTTP servers (`-debug-addr`) have no authentication and listen on loopback by default. Keep them there.

## Envoy notes

The admin interface is bound to loopback. It has no authentication and can stop Envoy, so do not expose it on an address a pod can reach.

Set `node.id` and `node.cluster` in the bootstrap. Without them Envoy 1.40.2 passes `--mode validate` and then aborts on the first TLS handshake, when the on-demand certificate lookup opens its SDS subscription.

The config lists every decrypted hostname as its own filter chain and prefetches its certificate. Do not replace the list with a wildcard: a client could then make the node mint a certificate for any name under it.

## Contributing

Kubescape keeps its project documents in one place, and the files in this repo point there: [contributing](CONTRIBUTING.md), [code of conduct](CODE_OF_CONDUCT.md), [governance](GOVERNANCE.md), [maintainers](MAINTAINERS.md), [community](COMMUNITY.md), [adopters](ADOPTERS.md).

To report a vulnerability, follow [SECURITY.md](SECURITY.md). Do not open a public issue for it.

## License

Apache 2.0. See [LICENSE](LICENSE).
