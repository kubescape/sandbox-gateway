"""Checks the SDK runs on streams the processor edited (s4_sdks.py, s4_sdks.mjs).

Reads their JSON lines from the files given and exits non-zero on any failure.
The processor removed the first tool or function call of each response, so:

- every run's outcome is ok: no SDK raised on the edited stream;
- the removed call is gone and the remaining indexes run from 0 with no gap;
- Anthropic: the second text block, index 2 upstream, reaches the SDK as
  index 1, and the stop reason is still tool_use (the processor does not
  rewrite it);
- in helper mode, the helper's final object (the final message, completion or
  response) does not hold the removed item.
"""
import json
import sys

failures = []


def check(cond, run, what):
    if not cond:
        failures.append(f"{run['sdk']} {run['scenario']} {run['mode']}: {what}: {json.dumps(run)}")


def contiguous(xs):
    return sorted(set(xs)) == list(range(len(set(xs))))


runs = []
for path in sys.argv[1:]:
    with open(path) as f:
        runs += [json.loads(line) for line in f if line.strip().startswith("{\"scenario\"")]

expected = {(s, sdk, m) for sdk in ("py", "ts") for s in ("a", "o", "r") for m in ("raw", "helper")}
seen = set()
for r in runs:
    lang = "py" if r["sdk"].endswith("-py") or "-py " in r["sdk"] else "ts"
    seen.add((r["scenario"][3], lang, r["mode"]))
    check(r["outcome"] == "ok", r, "the SDK raised")
    if r["outcome"] != "ok":
        continue
    kind = r["scenario"][:4]
    if kind == "s4-a" and r["mode"] == "raw":
        check(r["starts"] == [[0, "text"], [1, "text"]], r, "blocks are not text 0, text 1")
        check(contiguous(r["indexes"]), r, "indexes have a gap")
        check(r["stop_reason"] == "tool_use", r, "stop reason changed")
    elif kind == "s4-a":
        check(r["content"] == ["text", "text"], r, "final message is not two text blocks")
        check(r["texts"] == ["Let me look.", "Done."], r, "the second text block is not the one upstream sent at index 2")
        check(r["stop_reason"] == "tool_use", r, "stop reason changed")
    elif kind == "s4-o" and r["mode"] == "raw":
        check(r["calls"] == [[0, "call_b"]], r, "call_a not removed, or call_b not renumbered to 0")
        check(r["finish_reason"] == "tool_calls", r, "finish reason changed")
    elif kind == "s4-o":
        check(r["tool_calls"] == ["call_b"], r, "final completion still holds the removed call")
    elif kind == "s4-r" and r["mode"] == "raw":
        check(r["added"] == [[0, "message"]], r, "function call not removed, or message not renumbered to 0")
        check(r["sequence_numbers"] == list(range(len(r["sequence_numbers"]))), r, "sequence numbers not contiguous from 0")
        check(r["last"] == "response.completed", r, "stream did not complete")
        check(r["completed_output"] == ["message"], r, "response.completed output still holds the removed item")
    elif kind == "s4-r":
        check(r["status"] == "completed" and r["output"] == ["message"], r, "final response still holds the removed item")

for missing in sorted(expected - seen):
    failures.append(f"no run for scenario {missing[0]}, {missing[1]}, {missing[2]}")

for f in failures:
    print("FAIL", f)
print(f"{len(runs)} runs, {len(failures)} failures")
sys.exit(1 if failures else 0)
