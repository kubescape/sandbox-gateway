"""What the Python SDKs see of a stream the processor edited.

The processor runs with -remove-first-tool, so the first tool or function call
of each response is removed and the items after it renumbered. Each scenario
(the model name picks the mock's script) runs twice: the raw event iterator and
the SDK's accumulating stream helper. One JSON line per run, which check.py
reads. The clients reach the mock through Envoy and trust only the gateway CA.
"""
import json
import os
import sys

import anthropic
import httpx2
import openai

CA = os.environ.get("GATEWAY_CA", "/certs/ca.crt")
MSG = [{"role": "user", "content": "run ls"}]

ac = anthropic.Anthropic(api_key="sk-ant-mock", max_retries=0, timeout=20,
                         http_client=httpx2.Client(verify=CA))
oc = openai.OpenAI(api_key="sk-mock", max_retries=0, timeout=20,
                   http_client=httpx2.Client(verify=CA))


def run(scenario, sdk, mode, fn):
    out = {"scenario": scenario, "sdk": sdk, "mode": mode}
    try:
        out.update(fn())
        out["outcome"] = "ok"
    except Exception as e:  # noqa: BLE001 - report whatever the SDK raised
        out["outcome"] = f"{type(e).__name__}: {str(e)[:160]}"
    print(json.dumps(out), flush=True)


def a_raw(m):
    starts, indexes, stop = [], [], None
    for ev in ac.messages.create(model=m, max_tokens=64, messages=MSG, stream=True):
        if ev.type == "content_block_start":
            starts.append([ev.index, ev.content_block.type])
        if ev.type.startswith("content_block_"):
            indexes.append(ev.index)
        if ev.type == "message_delta":
            stop = ev.delta.stop_reason
    return {"starts": starts, "indexes": indexes, "stop_reason": stop}


def a_helper(m):
    with ac.messages.stream(model=m, max_tokens=64, messages=MSG) as s:
        for _ in s:
            pass
        f = s.get_final_message()
    return {"stop_reason": f.stop_reason, "content": [b.type for b in f.content],
            "texts": [b.text for b in f.content if b.type == "text"]}


def o_raw(m):
    calls, finish = [], None
    for ch in oc.chat.completions.create(model=m, messages=MSG, stream=True):
        c = ch.choices[0]
        for tc in c.delta.tool_calls or []:
            if tc.id:
                calls.append([tc.index, tc.id])
        finish = c.finish_reason or finish
    return {"calls": calls, "finish_reason": finish}


def o_helper(m):
    with oc.chat.completions.stream(model=m, messages=MSG) as s:
        for _ in s:
            pass
        f = s.get_final_completion()
    c = f.choices[0]
    return {"finish_reason": c.finish_reason, "tool_calls": [t.id for t in (c.message.tool_calls or [])]}


def r_raw(m):
    added, seqs, last, final = [], [], None, None
    for ev in oc.responses.create(model=m, input="run ls", stream=True):
        seqs.append(ev.sequence_number)
        last = ev.type
        if ev.type == "response.output_item.added":
            added.append([ev.output_index, ev.item.type])
        if ev.type == "response.completed":
            final = [o.type for o in ev.response.output]
    return {"added": added, "sequence_numbers": seqs, "last": last, "completed_output": final}


def r_helper(m):
    with oc.responses.stream(model=m, input="run ls") as s:
        for _ in s:
            pass
        f = s.get_final_response()
    return {"status": f.status, "output": [o.type for o in f.output]}


run("s4-a-text-tool-text", "anthropic-py", "raw", lambda: a_raw("s4-a-text-tool-text"))
run("s4-a-text-tool-text", "anthropic-py", "helper", lambda: a_helper("s4-a-text-tool-text"))
run("s4-o-baseline", "openai-py chat", "raw", lambda: o_raw("s4-o-baseline"))
run("s4-o-baseline", "openai-py chat", "helper", lambda: o_helper("s4-o-baseline"))
run("s4-r-baseline", "openai-py responses", "raw", lambda: r_raw("s4-r-baseline"))
run("s4-r-baseline", "openai-py responses", "helper", lambda: r_helper("s4-r-baseline"))
print(json.dumps({"versions": {"anthropic": anthropic.__version__, "openai": openai.__version__}}), file=sys.stderr)
