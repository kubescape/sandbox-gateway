// What the Node SDKs see of a stream the processor edited: the same scenarios,
// modes and output as s4_sdks.py. Both SDKs fetch through an undici connector
// that trusts only the gateway CA and, standing in for the redirect, sends
// connections to the providers' hosts on port 443 to GATEWAY_ADDR (Envoy's
// redirect listener). The URL, SNI and Host header stay the provider's.
import Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";
import { readFileSync } from "node:fs";
import { Agent, buildConnector, fetch as undiciFetch } from "undici";

const [gwHost, gwPort] = (process.env.GATEWAY_ADDR ?? "envoy:18443").split(":");
const providers = new Set(["api.anthropic.com", "api.openai.com"]);
const tls = buildConnector({ ca: readFileSync(process.env.GATEWAY_CA ?? "/certs/ca.crt") });
const agent = new Agent({
  connect: (opts, cb) => {
    const redirect = providers.has(opts.hostname) && String(opts.port || 443) === "443";
    tls(redirect ? { ...opts, hostname: gwHost, port: gwPort, servername: opts.hostname } : opts, cb);
  },
});
const fetch = (url, init) => undiciFetch(url, { ...init, dispatcher: agent });

const MSG = [{ role: "user", content: "run ls" }];
const ac = new Anthropic({ maxRetries: 0, timeout: 20000, apiKey: "sk-ant-mock", fetch });
const oc = new OpenAI({ maxRetries: 0, timeout: 20000, apiKey: "sk-mock", fetch });

async function run(scenario, sdk, mode, fn) {
  const out = { scenario, sdk, mode };
  try { Object.assign(out, await fn()); out.outcome = "ok"; }
  catch (e) { out.outcome = `${e.constructor.name}: ${String(e.message).slice(0, 160)}`; }
  console.log(JSON.stringify(out));
}

async function aRaw(m) {
  const starts = [], indexes = []; let stop = null;
  for await (const ev of await ac.messages.create({ model: m, max_tokens: 64, messages: MSG, stream: true })) {
    if (ev.type === "content_block_start") starts.push([ev.index, ev.content_block.type]);
    if (ev.type.startsWith("content_block_")) indexes.push(ev.index);
    if (ev.type === "message_delta") stop = ev.delta.stop_reason;
  }
  return { starts, indexes, stop_reason: stop };
}

async function aHelper(m) {
  const f = await ac.messages.stream({ model: m, max_tokens: 64, messages: MSG }).finalMessage();
  return { stop_reason: f.stop_reason, content: f.content.map((b) => b.type),
    texts: f.content.filter((b) => b.type === "text").map((b) => b.text) };
}

async function oRaw(m) {
  const calls = []; let fin = null;
  for await (const ch of await oc.chat.completions.create({ model: m, messages: MSG, stream: true })) {
    const c = ch.choices[0];
    for (const t of c.delta.tool_calls ?? []) if (t.id) calls.push([t.index, t.id]);
    fin = c.finish_reason ?? fin;
  }
  return { calls, finish_reason: fin };
}

async function oHelper(m) {
  const f = await oc.chat.completions.stream({ model: m, messages: MSG }).finalChatCompletion();
  const c = f.choices[0];
  return { finish_reason: c.finish_reason, tool_calls: (c.message.tool_calls ?? []).map((t) => t.id) };
}

async function rRaw(m) {
  const added = [], seqs = []; let last = null, final = null;
  for await (const ev of await oc.responses.create({ model: m, input: "run ls", stream: true })) {
    seqs.push(ev.sequence_number); last = ev.type;
    if (ev.type === "response.output_item.added") added.push([ev.output_index, ev.item.type]);
    if (ev.type === "response.completed") final = ev.response.output.map((o) => o.type);
  }
  return { added, sequence_numbers: seqs, last, completed_output: final };
}

async function rHelper(m) {
  const f = await oc.responses.stream({ model: m, input: "run ls" }).finalResponse();
  return { status: f.status, output: f.output.map((o) => o.type) };
}

await run("s4-a-text-tool-text", "anthropic-ts", "raw", () => aRaw("s4-a-text-tool-text"));
await run("s4-a-text-tool-text", "anthropic-ts", "helper", () => aHelper("s4-a-text-tool-text"));
await run("s4-o-baseline", "openai-ts chat", "raw", () => oRaw("s4-o-baseline"));
await run("s4-o-baseline", "openai-ts chat", "helper", () => oHelper("s4-o-baseline"));
await run("s4-r-baseline", "openai-ts responses", "raw", () => rRaw("s4-r-baseline"));
await run("s4-r-baseline", "openai-ts responses", "helper", () => rHelper("s4-r-baseline"));
const ver = (p) => JSON.parse(readFileSync(`node_modules/${p}/package.json`, "utf8")).version;
console.error(JSON.stringify({ versions: { anthropic: ver("@anthropic-ai/sdk"), openai: ver("openai"), node: process.version } }));
