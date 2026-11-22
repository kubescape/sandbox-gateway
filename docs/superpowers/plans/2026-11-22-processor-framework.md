---
type: intent
status: active
owner: amirmalka
scope: repo
---

# Processor framework implementation plan (SUB-9948)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the seeded processor into the framework the gateway ships: it identifies each connection from the kernel table, hands every request to a pluggable evaluator with the workload's policy sections, enforces the evaluator's verdict under the fail-posture rules, and writes one verdict record per transaction.

**Architecture:** `internal/extproc` stays the ext_proc server in `FULL_DUPLEX_STREAMED` mode. Around it sit small packages with one job each: the kernel tables, the workload lookup client, the policy informer, the staleness clock, the stream editors and the record. The evaluator plugs in through `pkg/plugin`; a build that registers none passes every request and reports `evaluator: unavailable`.

**Tech stack:** Go 1.27 toolchain, `envoyproxy/go-control-plane` (ext_proc v3), `cilium/ebpf` (pinned maps), `k8s.io/client-go` dynamic informers, `kubescape/storage` for the `SandboxPolicy` types, OTLP logs over HTTP, Envoy 1.40.2 in the integration job.

**Spec:** the L7 egress gateway design (sections "Processor", "What the PoC proved", design decision 7) and ticket T5 of its implementation plan, with the shared contracts C1, C2, C5, C6, C7 and C11. Contract names are fixed. If a task finds it has to change one, it stops and reports.

## Global constraints

- Envoy floor 1.40. The integration job runs v1.40.2.
- Latency budget: +10 ms p99 time to first token, +1 ms p99 per streamed chunk, measured with `test/latbench`.
- One identity source: the `conns` table, keyed on the pod socket's address and port, which Envoy reports as `source.address`. The processor never trusts an identity the client sends. A PROXY protocol identity is ignored and flagged.
- A connection with no `conns` entry is rejected.
- Bodies are parsed as streams. A 30 MiB prompt stays under 16 MiB of processor memory.
- Policy counts as stale after five minutes without a source. That value and the watchdog budget are flags; the defaults are 5m and 3s.
- A degraded decision follows the pod's fail posture, read from the `bindings` table and never from the cached sections.
- Records carry no bodies.
- Commits are signed off and every code commit updates the doc under `docs/` that describes what it changed.

## Decisions this plan makes

The ticket leaves these open. Each is small, and each is stated here so a reviewer can reject it.

1. Wire layout of the pinned maps. C1 gives the fields and their order, not the padding. This plan fixes natural C alignment: `conns` key 18 bytes (16-byte address, `u16` port, host byte order), `conns` value 40 bytes (`u64` cgroup, `u32` pid, `u32` binding, 16-byte address, `u16` port, 6 bytes of padding), `bindings` value 8 bytes (`u32` binding, `u8` posture, `u8` gate, 2 bytes of padding). `Open` checks the key and value sizes of the pinned maps and refuses to start on a mismatch. The node-agent redirect work has to match this or tell us.
2. How a build links an evaluator. `pkg/plugin.Register` is called from an `init` function. `pkg/processor.Main()` is the whole program; a build with an evaluator is a `main` package that imports its evaluator and calls `Main`. `cmd/processor` does the same with no import.
3. Health and evaluator state. The processor serves `GET /healthz/processor` on the unix socket `/run/kubescape-sandbox/processor-health.sock`. It answers 503 until the first informer sync, then 200 with `{"evaluator":"available|unavailable","degradedDecisions":N}`. C4 fixes only the path and the 200; the body is how the node controller learns the two values it writes into the node status.
4. What runs without an evaluator. Identity and the decrypt-list guard still run. Nothing else decides: in particular a `deny` pod with no cached policy is not blocked, because with no evaluator nothing is enforced for any pod.
5. The decrypt-list guard blocks in every mode. A request whose host is not in the workload's decrypt list means traffic was decrypted that no policy names. It fails with a plain 403 from the framework, whatever the rule modes say, unless the decision is degraded on an `allow` pod. This refuses on `allow` pods too, on purpose: the fail posture is for the gateway being unavailable, and this is the gateway having decrypted something it should have passed through, a fault in the chain match. A degraded decision on an `allow` pod passes, because there the decrypt list itself may be out of date.
6. A slow evaluator fails the request. `Evaluate` gets a context that ends at the watchdog budget. Past it the request is refused with the evaluator's `DenyResponse`, rule `framework.evaluator-timeout`. A panic in the evaluator is recovered and treated the same way.
7. `fail_open_window` and `destination_state`. `fail_open_window` is true when the binding's gate is not `redirecting` at request time. The processor only sees decrypted traffic, so it writes `inspected` or `blocked`; `passthrough` and `none` are written by other components.
8. Removal has no rule and no flag. The editor runs only when a filter is set in `app.Config`, which only the test program does.
9. The request scanner is written new here, test first. Nothing is copied from the proof of concept's policy package.

## Open items that need an answer

1. `HTTPSection` does not exist yet. C6 and C11 use `v1alpha1.HTTPSection` from `kubescape/storage`. On 2026-11-22 the storage `main` branch has no `http` section and SUB-9943 is in To Do. PRs 2 and 3 below do not need the type. PRs 4, 5 and 6 do. The recommendation is to land the storage types first and pin PR 4 to that commit. The fallback, if the storage change slips, is to pin a pseudo-version of its branch. That is temporary: it is not a reproducible build and breaks if the branch is rewritten, so it is replaced by the merge commit on storage `main` as soon as the change merges, before PR 4 leaves draft. A local stand-in type would guess field names that are not fixed yet, so this plan does not use one.
2. `request_position` on HTTP/2. C7 asks for the HTTP/2 stream id. Envoy's ext_proc attributes do not obviously carry it. Task 6.1 is a short spike. If Envoy cannot supply it, work stops there and the question goes back to the contract owner, because the backend join depends on that field.

## Pull requests

Each PR is a draft against `main` with SUB-9948 in the title. They stack in this order; a later branch contains the earlier ones until those merge.

| PR | Branch | Contents | Needs |
|---|---|---|---|
| 1 | `docs/SUB-9948-processor-plan` | This plan | none |
| 2 | `feat/SUB-9948-stream-parsers` | Request JSON scanner, OpenAI stream tracking, removal and renumbering | none |
| 3 | `feat/SUB-9948-identity` | `conns` and `bindings` readers, lookup client, `conns` miss rejection, integration stubs | none |
| 4 | `feat/SUB-9948-plugin` | C6 interface and registry, request-side block, watchdog through the evaluator, `evaluator: unavailable` | PR 3, storage types |
| 5 | `feat/SUB-9948-policy-source` | C11 informer, staleness, degraded decisions, decrypt-list guard, health path | PR 4 |
| 6 | `feat/SUB-9948-records` | C7 records, memory test, SDK renumbering job, test evaluator in the integration job, latency bench | PRs 2 and 5 |

## File structure

| Path | Responsibility | PR |
|---|---|---|
| `pkg/jsonscan/` | Streaming scan of a JSON request body for top-level string fields | 2 |
| `internal/streamfmt/` | Recognise Anthropic, OpenAI chat and OpenAI Responses events; track items and the stop reason | 2 |
| `internal/renumber/` | Drop a streamed item and renumber what follows | 2 |
| `internal/conntable/` | Read `conns` and `bindings` (replaces `internal/attrmap`) | 3 |
| `internal/lookup/` | C2 client with a per-cgroup cache | 3 |
| `internal/app/` | Wire the parts and run the gRPC server; takes interfaces so tests can stub | 3 |
| `test/processor-it/` | Test program: `app.Run` with stub tables, and later a test evaluator | 3, 4, 6 |
| `pkg/plugin/` | C6 types and the registry | 4 |
| `pkg/processor/` | `Main()` | 4 |
| `internal/policysource/` | Informer on both policy kinds, C11 resolution | 5 |
| `internal/stale/` | When a workload's policy became stale | 5 |
| `internal/extproc/decide.go` | The decision table below, as one pure function | 5 |
| `internal/record/` | The C7 record and its OTLP attributes | 6 |
| `docs/features/processor.md` | What the processor does, updated in every code PR | 3 to 6 |

## Review focus

Conditions the spec implies and no ticket test names. Each is pinned to a task below.

1. A `conns` key is reused by another pod after the first connection closes. Expected: the second connection gets its own identity. Nothing is cached by address and port. Task 3.2.
2. The same pod address arrives as `10.0.0.5:4242` and as `[::ffff:10.0.0.5]:4242`. Expected: one key. Task 3.1.
3. The connection is in `conns` but the lookup answers 404 because the pod was unbound in between. Expected: rejected, like a miss. Task 3.3.
4. The evaluator panics or never returns. Expected: that request fails closed, and the processor keeps serving others. Task 4.3.
5. A request with no body, or one that ends in trailers. Expected: `Classify` sees an empty or complete body and the request is still decided. Task 4.2.

---

## PR 2: stream parsers

### Task 2.1: request JSON scanner

**Files:** create `pkg/jsonscan/jsonscan.go`, `pkg/jsonscan/jsonscan_test.go`.

**Produces:**

```go
// Fields reads a JSON object from r and returns the string values of the named
// top-level keys. It reads r to the end, keeps no more than maxValue bytes per
// value, and never holds the document.
func Fields(r io.Reader, maxValue int, keys ...string) (map[string]string, error)
```

- [ ] Write failing tests: `TestTopLevelModel` (`{"model":"m","messages":[...]}` returns `m`); `TestNestedKeyIgnored` (a `model` key inside `messages` is not returned); `TestEscapedString` (`"claude"` returns `claude`); `TestEverySplitPoint` (the same body through `iotest.OneByteReader` and split at each offset gives the same result); `TestNotAnObject` (an array returns no fields and no error); `TestTruncated` (returns `io.ErrUnexpectedEOF`); `TestValueOverMax` (a value longer than `maxValue` is absent from the map); `TestConstantMemory` (a 30 MiB string value before `model`, read through a generator reader, allocates under 1 MiB, checked with `testing.AllocsPerRun` and `runtime.MemStats`).
- [ ] Run `go test ./pkg/jsonscan/`; expect a build failure.
- [ ] Implement a byte-level state machine over a 32 KiB read buffer (depth counter, in-string and escape flags, current top-level key). Do not use `encoding/json.Decoder`: its `Token` allocates each string in full.
- [ ] Run the tests; expect PASS. Commit.

### Task 2.2: stream formats

**Files:** create `internal/streamfmt/streamfmt.go`, `streamfmt_test.go`; modify `internal/extproc/server.go` (the `track` method and `openBlocks` move here).

**Produces:**

```go
type Format int
const (Unknown Format = iota; Anthropic; OpenAIChat; OpenAIResponses)

// Item is one streamed content item, as seen at its first event.
type Item struct { Format Format; Index int; Kind, Name string }

type Tracker struct { Format Format; StopReason string; Done bool }
func (t *Tracker) Event(ev sse.Event) // sets Format on the first recognised event
func (t *Tracker) Open() []int        // indexes of items started and not stopped
func Detect(ev sse.Event) Format
```

Detection: a `type` starting `message_` or `content_block_` is Anthropic; `"object":"chat.completion.chunk"` is OpenAI chat; a `type` starting `response.` is OpenAI Responses. `StopReason` is `delta.stop_reason`, `choices[0].finish_reason` or the `response.completed` status. `Done` is set by `message_stop`, `data: [DONE]` or `response.completed`.

- [ ] Write failing tests, one table per format, fed from the event sequences the mock already serves (`test/mock-anthropic/scenarios.go`, baselines `s4-a-baseline`, `s4-o-baseline`, `s4-r-baseline`): format detected, stop reason, `Done`, and `Open()` empty at the end.
- [ ] Implement. Replace `txn.track` and `txn.openBlocks` in `internal/extproc/server.go` with a `streamfmt.Tracker`.
- [ ] Run `go test ./internal/...`; the existing `internal/extproc` tests still pass. Commit.

### Task 2.3: removal and renumbering

**Files:** create `internal/renumber/renumber.go`, `renumber_test.go`.

**Produces:**

```go
type Filter func(streamfmt.Item) (remove bool)

type Editor struct{ /* ... */ }
func New(remove Filter) *Editor
// Feed returns the bytes to forward for this chunk. It holds back an
// incomplete trailing event.
func (e *Editor) Feed(chunk []byte) []byte
func (e *Editor) Flush() []byte
```

Rules. The filter is asked once per item, at `content_block_start`, at the first `tool_calls` delta for an index, or at `response.output_item.added`. Every event of a removed item is dropped. Indexes after it go down by the number removed before them: `index` for Anthropic, `tool_calls[].index` for OpenAI chat, `output_index` for Responses, where `sequence_number` is also rewritten to stay contiguous. An event that needs no change is forwarded byte for byte. The stop reason is not rewritten.

- [ ] Write failing tests: `TestNothingRemovedIsByteIdentical` (all three baselines, split at every offset); `TestAnthropicRemoveMiddle` (text 0, tool 1, text 2 with the tool removed gives text 0, text 1, and equals the mock's `s4-a-renumbered` events); `TestOpenAIChatRemoveFirstCall` (equals `s4-o-renumbered`); `TestResponsesRemoveFunctionCall` (equals `s4-r-renumbered`, sequence numbers contiguous); `TestRemoveTwo` (indexes drop by two); `TestPartialEventHeld` (a chunk that ends mid-event forwards nothing of that event until it completes); `TestUnknownFormatPassesThrough`.
- [ ] Implement on top of `sse.Parser` (use `Event.End` to cut the original bytes) and `streamfmt.Detect`. Re-serialise only the events whose index changes.
- [ ] Fix the `ineffassign` finding in `internal/sse/sse.go` and drop its exclusion from `.golangci.yml`.
- [ ] Run `go test -race ./...` and the linter. Commit. Open PR 2.

---

## PR 3: identity

### Task 3.1: kernel tables

**Files:** create `internal/conntable/conntable.go`, `layout.go`, `open_linux.go`, `open_other.go`, tests beside them; delete `internal/attrmap/`.

**Produces:**

```go
type Key struct { Addr netip.Addr; Port uint16 }
func ParseKey(sourceAddress string) (Key, error) // unmaps v4-mapped addresses

type Conn struct { CgroupID uint64; PID, BindingID uint32; OrigDst netip.AddrPort }
type Binding struct { BindingID uint32; Posture string; Gate uint8 } // Posture: "allow" | "deny"

type Table interface {
    Conn(Key) (Conn, bool, error)
    Binding(cgroupID uint64) (Binding, bool, error)
}
// Open opens conns and bindings under dir, read-only.
func Open(dir string) (Table, error)
const DefaultDir = "/sys/fs/bpf/kubescape-sandbox/http"
```

- [ ] Write failing tests in `layout_test.go` (pure, any OS): `TestKeyBytes` (IPv4 `10.0.0.5:4242` encodes as the v4-mapped 16 bytes then the port in host order, 18 bytes); `TestParseKeyMapped` (review focus 2: `10.0.0.5:4242` and `[::ffff:10.0.0.5]:4242` give equal keys); `TestConnValueRoundTrip` (40 bytes); `TestBindingValue` (posture byte 0 is `allow`, 1 is `deny`, any other value is an error).
- [ ] Write `open_linux_test.go` (`//go:build linux`, skipped unless root): create both maps with the plan's sizes, pin them under a temp bpffs directory, insert one entry each, read them back through `Open`; `TestOpenRejectsWrongSizes`.
- [ ] Implement. Run `go test ./internal/conntable/`. Add a step to the `integration` job in `.github/workflows/pr-created.yaml`: `sudo -E env "PATH=$PATH" go test -run 'TestOpen' ./internal/conntable/`. Commit.

### Task 3.2: lookup client

**Files:** create `internal/lookup/lookup.go`, `lookup_test.go`.

**Produces:**

```go
type PolicyRef struct { UID string `json:"uid"`; Generation int64 `json:"generation"` }
type Workload struct {
    Namespace, Pod, Container string
    Controller struct{ Kind, Name string }
    BindingID uint32
    Policies []PolicyRef
}
var ErrNotBound = errors.New("lookup: cgroup is not bound")

func New(socket string, refresh time.Duration, now func() time.Time) *Client
// Workload returns the cached answer when the socket fails. failingSince is
// zero while the socket answers.
func (c *Client) Workload(ctx context.Context, cgroupID uint64) (w Workload, failingSince time.Time, err error)
const DefaultSocket = "/run/kubescape-sandbox/lookup.sock"
```

The cache is keyed on the cgroup id only (review focus 1). An entry older than `refresh` (flag, default 5s) is fetched again; if that fetch fails the old entry is returned with `failingSince` set to the first failure. A 404 removes the entry and returns `ErrNotBound`.

- [ ] Write failing tests against an `httptest` server on a unix socket: `TestDecodesC2` (the C2 body maps onto every field); `TestNotBound`; `TestCachedWithinRefresh` (one request for two calls); `TestServesCacheWhenSocketDown` (after the server closes, the same workload comes back and `failingSince` is the time of the first failed fetch, not the latest); `TestNoCacheNoSocket` (error, zero workload); `TestRecoveryClearsFailingSince`.
- [ ] Implement with an injected clock. Run the tests. Commit.

### Task 3.3: key the server on the kernel table

**Files:** modify `internal/extproc/server.go`, `server_test.go`; create `internal/app/app.go`, `test/processor-it/main.go`; modify `cmd/processor/main.go`, `build/Dockerfile.processor`, `test/Dockerfile`, `test/integration/compose.yaml`, `test/integration/run.sh`; create `docs/features/processor.md`; update `README.md`.

**Consumes:** `conntable.Table`, `lookup.Client`.

**Produces:** in `extproc.Config`, `Conns conntable.Table` and `Lookup func(ctx context.Context, cgroupID uint64) (lookup.Workload, time.Time, error)` replace `AttrLookup`. `app.Config{Listen string; Conns conntable.Table; Lookup ...; ChunkBudget time.Duration; ...}` and `app.Run(ctx context.Context, c app.Config) error`.

Behaviour at request headers: parse `source.address`, look up `conns`, then `bindings`, then the workload. A parse failure, a `conns` miss, a missing binding or `ErrNotBound` ends the request with an immediate 403 and a record with `Ended: "rejected"`. Each cause has its own reason in `Details` and on the record (`no_source_address`, `no_connection_entry`, `not_bound`, ...); the list is in `docs/features/processor.md`. A lookup that fails with nothing cached does not reject: the record carries the kernel half of the identity and the error. An identity in the `kubescape.sandbox.attribution` metadata is never used; the record gets `ppv2_ignored`.

- [ ] Write failing tests in `server_test.go` with fake `Table` and lookup: `TestConnsMissRejected`; `TestUnboundCgroupRejected` (review focus 3); `TestNoSourceAddressRejected`; `TestIdentityFromTable` (the record carries namespace, pod, container, controller, binding id, posture, original destination); `TestPPv2IgnoredAndFlagged` (a forged identity in the metadata does not change the record's workload); `TestSecondRequestSameConnection` (same key twice: one `Conn` call per request, lookup served from its cache).
- [ ] Implement. Move flag parsing and wiring from `cmd/processor/main.go` into `internal/app`; `cmd/processor` opens `conntable.Open(conntable.DefaultDir)` and exits non-zero if the maps are missing. It does not require the lookup socket at start: a node-agent restart must not stop the processor, and lookups are cached for that case.
- [ ] `test/processor-it/main.go`: `app.Run` with an in-memory `Table` that answers any source address with one fixed connection and binding (posture from `--posture`, default `allow`), and a lookup stub that returns one fixed workload. Build it into the fixtures image. Point the `processor` service in `test/integration/compose.yaml` at it, and add a second run with `--reject-all` that asserts the client gets a 403.
- [ ] Run `go test -race ./...` and `test/integration/run.sh`. Commit. Open PR 3.

---

## PR 4: the evaluator seam

### Task 4.1: C6 types and registry

**Files:** rewrite `pkg/plugin/plugin.go`; create `pkg/plugin/registry.go`, `registry_test.go`; add `github.com/kubescape/storage` to `go.mod`.

**Produces:** the `Workload`, `PolicyRef`, `PolicySection`, `Request`, `Verdict` and `Evaluator` declarations exactly as contract C6 writes them, plus:

```go
// Register installs the evaluator for this build. It panics on nil and on a second call.
func Register(e Evaluator)
// Registered returns the evaluator, or nil when the build has none.
func Registered() Evaluator
```

- [ ] Write failing tests: `TestNoneRegistered`; `TestRegisterTwicePanics`; `TestRegisterNilPanics`; a compile-time assertion that a test type with the four C6 methods satisfies `Evaluator`.
- [ ] Replace the first-cut types (`Action`, `Decision`, `Scan`, the two-method `Evaluator`). Run `go build ./...`; `internal/extproc` fails to build until task 4.2. Commit the two tasks together.

### Task 4.2: classify, evaluate, block

**Files:** modify `internal/extproc/server.go`, `server_test.go`; create `internal/extproc/fake_evaluator_test.go`.

**Consumes:** C6; `lookup.Workload`; `conntable.Binding`.

Flow for one request. At headers the server builds `plugin.Workload` (posture from the binding) and starts `Classify(host, path, body)` in a goroutine, with `body` the read end of an `io.Pipe`. Each request chunk is written to the pipe and forwarded one chunk behind, as the seeded enforce path does. At end of stream, or at trailers, the pipe is closed, `Classify` returns, and `Evaluate` is called with the `Request`. The request is blocked when `Verdict.Action == "deny"` and `Verdict.Mode == "enforce"`: the held chunk is dropped and the answer is an immediate response built from `DenyResponse(provider, verdict)`. Otherwise the held chunk is released. `Sections` is empty and `Degraded` is false until PR 5. With no evaluator none of this runs and chunks are not held.

- [ ] Write failing tests with a fake evaluator that records its calls: `TestClassifySeesWholeBody` (body split in three chunks); `TestRequestReachesEvaluator` (host, method, path, headers, model, `HasModel`, workload and posture match what was sent); `TestEnforceDenyUsesDenyResponse` (status, headers and body come from the fake, and the last data chunk was never forwarded); `TestAuditDenyPasses` (`Mode: "audit"` forwards everything; the record has `would_deny`); `TestNoBodyStillDecided` and `TestTrailersStillDecided` (review focus 5); `TestWebSocketUpgradeDecidedOnHeaders` (`Classify` gets an empty body and frames are not fed to it); `TestNoEvaluatorPassesEverything` (kept from the seed).
- [ ] Implement. Delete `denyResponse`, the `Enforce` config field and `RuleUnevaluatedUpgrade`.
- [ ] Run `go test -race ./internal/extproc/`. Commit with task 4.1.

### Task 4.3: watchdog through the evaluator

**Files:** modify `internal/extproc/server.go`, `server_test.go`; create `pkg/processor/processor.go`; modify `cmd/processor/main.go`, `internal/app/app.go`.

- [ ] Write failing tests: `TestWatchdogEndsStallWithStreamError` (stall fault, budget 200 ms: the response ends with the bytes the fake's `StreamError(provider, "watchdog")` returns, within 1 s); `TestWatchdogUnderFiveSecondsAtDefault` (default budget, stream ends in under 5 s); `TestWatchdogNoEvaluatorEndsStream` (end of stream, no frame); `TestSlowEvaluateFailsRequest` and `TestEvaluatorPanicFailsRequest` (review focus 4: the request gets `DenyResponse` with rule `framework.evaluator-timeout`, and a second request on a new stream succeeds).
- [ ] Implement. Delete `watchdogErrorEvent`. Set the `--chunk-budget` default to 3s.
- [ ] `pkg/processor.Main()` parses flags and calls `app.Run` with `plugin.Registered()`. `cmd/processor/main.go` becomes a call to it. The start-up log line and `/debug/vars` report `evaluator` as `available` or `unavailable`; test `TestEvaluatorUnavailableReported` in `internal/app`.
- [ ] `test/processor-it` gains `--evaluator`, which registers a test evaluator: it denies a request whose model is `denied-model`, in the mode given by `--mode`, with a fixed JSON 403. `run.sh` adds a call with that model and asserts the 403 body.
- [ ] Update `docs/features/processor.md` and the `pkg/plugin` row in `README.md`. Run all tests and the integration script. Commit. Open PR 4.

---

## PR 5: policy source and degraded decisions

### Task 5.1: informer

**Files:** create `internal/policysource/source.go`, `source_test.go`.

**Produces:**

```go
func New(client dynamic.Interface, now func() time.Time) *Source
func (s *Source) Run(ctx context.Context)
func (s *Source) Synced() bool
// LostSince is zero while both informers are connected.
func (s *Source) LostSince() time.Time
// Resolve returns the http section of each referenced object the cache holds.
// A reference whose UID is cached at another generation yields the cached copy
// and counts as outdated. A UID that is absent counts as missing.
func (s *Source) Resolve(refs []plugin.PolicyRef) (sections []plugin.PolicySection, outdated, missing int)
```

Two dynamic informers, `sandboxpolicies` and `clustersandboxpolicies`, with the group and version taken from `v1alpha1.SchemeGroupVersion`. Objects are converted with `runtime.DefaultUnstructuredConverter` and indexed by UID. An object with no `http` section resolves to a section with a zero `HTTP` value. `LostSince` is set by the informers' watch error handler and cleared on the next successful list or event.

- [ ] Write failing tests with `dynamicfake`: `TestResolveExactlyNamedObjects` (three objects cached, two referenced: exactly those two sections come back, with `Ref` and `Mode` set); `TestOutdatedGeneration`; `TestMissingUID`; `TestNotSyncedBeforeFirstList`; `TestClusterAndNamespacedKinds`; `TestLostSinceSetAndCleared`.
- [ ] Implement. Run the tests. Commit.

### Task 5.2: staleness and the decision table

**Files:** create `internal/stale/stale.go`, `stale_test.go`, `internal/extproc/decide.go`, `decide_test.go`; export `hostset.Match(pattern, host string) bool` from `internal/hostset/hostset.go`.

**Produces:**

```go
// stale
func New(limit time.Duration, now func() time.Time) *Tracker
// Observe records what one request saw for a workload and reports whether its
// decision is degraded.
func (t *Tracker) Observe(cgroupID uint64, lookupFailingSince, informerLostSince time.Time, unresolved bool) (degraded bool)

// extproc
type input struct {
    HasEvaluator bool; Posture string; Sections, Unresolved int
    Stale, HostInDecryptList bool; Verdict plugin.Verdict
}
type outcome struct { Block, Degraded, CallEvaluate bool; Rule string }
func decide(in input) outcome
```

`Observe` keeps, per cgroup, the time a reference first failed to resolve, and clears it when all resolve. The workload is stale since the earliest non-zero of the three times; it is degraded when that is `limit` or more ago.

The table `decide` implements, first match wins:

| Condition | Evaluate | Block | Degraded |
|---|---|---|---|
| No covering section cached, evaluator present, posture `deny` | no | yes, rule `framework.no-cached-policy` | yes |
| No covering section cached (posture `allow`, or no evaluator) | no | no | yes |
| Host not in the decrypt list, not degraded or posture `deny` | no | yes, rule `framework.host-not-decrypted` | as computed |
| Host not in the decrypt list, degraded, posture `allow` | no | no | yes |
| No evaluator | no | no | as computed |
| Verdict deny and enforce, not degraded | yes | yes | no |
| Verdict deny and enforce, degraded, posture `deny` | yes | yes | yes |
| Verdict deny and enforce, degraded, posture `allow` | yes | no, recorded as would-deny | yes |
| Anything else | yes | no | as computed |

Degraded is true when the tracker says so. A reference that does not resolve starts the tracker's clock (`unresolved`), so a workload with some of its references missing is decided from the ones that resolve and is degraded five minutes later, as for any other lost source. Only the nothing-cached rows are degraded at once. With no evaluator the only row that can block is the decrypt-list guard (decision 4). The decrypt list is the union over the cached sections of `decrypt.exactHosts` and the names matching `decrypt.hostPatterns`, minus `decrypt.passthrough`.

- [ ] Write failing tests for `stale`: `TestFreshIsNotDegraded`; `TestDegradedAfterFiveMinutes` (4m59s no, 5m yes, for each of the three causes); `TestUnresolvedClockStartsAtFirstMiss`; `TestRecoveryResets`.
- [ ] Write `decide_test.go` as one table test with a row per line above, plus `TestPostureFromBindingNotSections` (sections say `onUnavailable: deny`, posture `allow`, degraded: not blocked; and the reverse: blocked), `TestNoEvaluatorDenyPodNothingCachedPasses`, and `TestOneMissingReferenceOfTwoNotDegradedAtOnce`.
- [ ] Implement both. Commit.

### Task 5.3: wire it in, and the health path

**Files:** modify `internal/extproc/server.go`, `server_test.go`, `internal/app/app.go`, `test/processor-it/main.go`, `test/integration/run.sh`, `docs/features/processor.md`.

`extproc.Config` gains `Policies interface{ Resolve(...); LostSince() time.Time }` and `Stale *stale.Tracker`. The server fills `Request.Sections` and `Request.Degraded` and applies `decide`. `app.Run` builds the dynamic client from the in-cluster config, starts the source, and serves the health socket from decision 3. A degraded decision increments the counter the health body reports.

- [ ] Write failing tests: `TestSectionsOfExactlyTheNamedObjects`; `TestMissingReferenceDegradesAfterFiveMinutes` (fake clock); `TestDegradedDoesNotBlockAllowPod`; `TestDegradedStillBlocksDenyPod`; `TestDenyPodNothingCachedBlocked` and `TestAllowPodNothingCachedPasses` (both records degraded on the first request); `TestPostureComesFromBindings`; `TestHostOutsideDecryptListFails`; in `internal/app`, `TestHealthFailsUntilFirstSync` (503, then 200 with the evaluator state) and `TestDegradedCounterInHealthBody`.
- [ ] Implement. `test/processor-it` gets a static policy source from a YAML file of policy objects, so the integration job needs no API server; `run.sh` adds a call to a host outside the decrypt list and asserts the 403.
- [ ] Run all tests and the integration script. Commit. Open PR 5.

---

## PR 6: records, proofs and the bench

### Task 6.1: spike, `request_position`

- [ ] Find how the processor learns the HTTP/2 stream id of a request: read the Envoy 1.40 ext_proc attribute list and try `request_attributes` candidates against the integration stack with an HTTP/2 client that opens three streams. For HTTP/1.1, confirm that counting requests per `connection.id` gives the ordinal.
- [ ] Write the result into `docs/features/processor.md`. If no stream id is available, stop and report (open item 2).

### Task 6.2: the C7 record

**Files:** create `internal/record/record.go`, `record_test.go`; modify `internal/extproc/server.go`, `internal/otlpemit/otlpemit.go`, `internal/app/app.go`.

**Produces:** `record.Record` with one field per C7 attribute and `func (r Record) Attrs() map[string]any`, whose keys are the C7 names verbatim: `crd_uid`, `crd_revision`, `rule`, `origin`, `verdict`, `mode`, `would_deny`, `tier`, `fail_posture`, `provider`, `model`, `destination_state`, `degraded`, `fail_open_window`, `upstream_content_encoding`, `namespace`, `pod`, `container`, `controller_kind`, `controller_name`, `conn_local_addr`, `conn_local_port`, `orig_dst`, `request_position`. Stream counters and timings stay, under a `gateway.` prefix.

- [ ] Write failing tests: `TestAttrsMatchC7` (a full record produces exactly the C7 keys plus `gateway.*`, with `tier` equal to `gateway`); `TestContentEncodingOnlyWhenNotIdentity`; `TestNoBodyBytesInRecord` (a request and response with a marker string: the marker is in no attribute); in `internal/extproc`, `TestOneRecordPerTransaction` for allowed, blocked, rejected and watchdog endings, `TestDegradedMarkedOnRecord`, and `TestFailOpenWindowFromGate`.
- [ ] Implement. Replace `extproc.Record` and `recordAttrs`; drop the `account` resource attribute and the `egress-gateway-poc` scope name from `internal/otlpemit`. Commit.

### Task 6.3: memory proof

**Files:** create `internal/extproc/memory_test.go`.

- [ ] `TestThirtyMiBPromptUnder16MiB`: a fake evaluator whose `Classify` uses `jsonscan.Fields`, enforce mode, a 30 MiB body sent in 64 KiB chunks from one reused buffer over `bufconn`. A sampler reads `runtime.MemStats.HeapAlloc` every millisecond; peak minus the baseline after `runtime.GC()` is under 16 MiB. Fix whatever it finds. Commit.

### Task 6.4: SDKs on renumbered streams

**Files:** create `test/sdk/s4_sdks.py`, `test/sdk/s4_sdks.mjs`, `test/sdk/Dockerfile.python`, `test/sdk/Dockerfile.node`, `test/sdk/check.py`; modify `test/processor-it/main.go`, `test/integration/compose.yaml`, `test/integration/run.sh`, `.github/workflows/pr-created.yaml`.

- [ ] `test/processor-it` gains `--remove-first-tool`, which sets a `renumber.Filter` that removes the first tool or function call item of a response.
- [ ] Port the two S4 scripts, reduced to the baseline scenarios (`s4-a-baseline`, `s4-o-baseline`, `s4-r-baseline`), each in raw-iterator and helper mode. Pin anthropic 2.6.0 and openai 3.46.0 for Python, `@anthropic-ai/sdk` 1.6.0 and `openai` 7.53.0 for Node. The clients reach the mock through Envoy and trust only the gateway CA.
- [ ] `check.py` asserts every run's outcome is `ok`, that the tool call is gone and that the remaining indexes are contiguous from 0.
- [ ] Add the SDK run to `run.sh` behind `SDK=1` and a job `SDK streams` to the workflow. Run it locally. Commit.

### Task 6.5: latency

**Files:** create `test/bench/latency.sh`, `test/bench/compose.yaml`; update `docs/features/processor.md`, `README.md`.

- [ ] `latency.sh` starts the integration stack with the test evaluator in enforce mode and the mock on a TLS listener streaming 40 deltas 20 ms apart, runs `latbench -n 200` and prints, for TTFT and event gap, the p99 of the proxied path minus the direct path. It exits non-zero above 10 ms or 1 ms.
- [ ] Run it three times locally. Record the numbers and the machine in the PR description and in `docs/features/processor.md`. If it is over budget, profile before changing anything.
- [ ] Final check: `go test -race ./...`, the linter, `test/integration/run.sh`, `SDK=1 test/integration/run.sh`. Open PR 6.

## Ticket coverage

| Ticket line | Task |
|---|---|
| ext_proc server keyed on the downstream remote address, C2 lookup, miss rejected, PPv2 ignored | 3.1, 3.2, 3.3 |
| Streaming parsers: request JSON, SSE in both formats, event-stream, WebSocket | 2.1, 2.2 (event-stream and WebSocket came with the seed and keep their tests) |
| Per-chunk watchdog with `StreamError`, under 5 s | 4.3 |
| Request-side block with `DenyResponse` | 4.2 |
| Removal and renumbering | 2.3, 6.4 |
| Policy source C11, posture from `bindings`, health before first sync, no cached object | 5.1, 5.2, 5.3 |
| Plugin interface C6 with a registry, `evaluator: unavailable` | 4.1, 4.3 |
| Staleness and degraded decisions | 5.2, 5.3 |
| Second guard | 5.2, 5.3 |
| Records C7 | 6.1, 6.2 |
| Tests in the ticket's list | each named in the task that owns the code; memory 6.3, SDKs 6.4 |
| Done when: image with a test evaluator against Envoy; latency inside budget | 4.3, 5.3, 6.5 |

Out of scope here: the Envoy listener changes (health listener, removing the PROXY protocol filter, source restriction), writing `SandboxGatewayNodeStatus`, any real evaluator, and rewriting the stop reason after a removal.
