import { Env, Provider, ProviderModel, VirtualKey } from "./types";
import { KVManager } from "./kv";
import { getAdapterForProvider } from "./providers";

// ---------------------------------------------------------------------------
// SSE re-assembly proxy (spec 4.10 / failure mode #14).
//
// Cloudflare's network can split a streamed SSE chunk mid-record — e.g. a
// tool_call fragment like `{"choices":[{"delta":{"tool_calls":[{"id":"call_`
// arrives in one chunk and `,"function":{"name":"get"}}]}]}]}` in the next.
// Naively piping provider bytes straight through (response.body.pipeTo) can
// relay those split fragments to the client, corrupting function-calling and
// producing a blank/broken tool result.
//
// This proxy reads the provider stream byte-by-byte into a line buffer, emits
// ONLY complete `data: ...` lines, and rewrites each through the standard
// OpenAI SSE envelope. Because we re-parse every chunk as JSON and re-emit a
// clean, single-line `data:` event, a tool call split across network packets
// is reassembled into a valid event before the client ever sees it.
//
// We also force `Accept-Encoding: identity` on the way out and attach `cf`
// cache-disable options so Cloudflare's edge does not gzip/re-chunk/transform
// the relayed stream.
// ---------------------------------------------------------------------------
// Hardened response headers for any streamed (SSE) response relayed to the
// client. These are the core of spec 4.10 / failure mode #14: Cloudflare's
// edge will gzip / re-chunk / buffer a streamed response if not explicitly
// told not to, and that transformation is exactly what corrupts mid-stream
// tool-call and web-search fragments. Identity encoding + no-transform +
// X-Accel-Buffering:no + cf cache disable keep the relayed bytes pristine.
function sseResponseHeaders(): Record<string, string> {
  return {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    "Content-Encoding": "identity",
    "Accept-Encoding": "identity",
    "X-Accel-Buffering": "no",
    "Access-Control-Allow-Origin": "*",
  };
}

// Shared SSE re-assembly core. Reads an OpenAI-format SSE byte stream
// (already normalized by an adapter into `data: {...}` lines) and re-emits
// ONLY complete, JSON-valid `data:` events. A tool_call fragment split across
// network packets is recombined into a valid event before the client ever sees
// it. This is the single place that guarantees Cloudflare cannot mangle
// function calling — both the OpenAI adapter and the Gemini/Claude adapters
// now funnel through here.
function pipeHardenedSSE(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  writer: WritableStreamDefaultWriter<Uint8Array>
): void {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  // Buffer for a partial SSE line that spans multiple network chunks.
  let lineBuffer = "";
  let sentDone = false;
  let aborted = false;

  // Buffer for a `data:` payload that arrived SPLIT ACROSS network chunks and
  // could NOT yet be parsed as JSON. The naive approach would DROP such a line,
  // which is the residual "blank/missing tool-call" risk: a tool_call or
  // web-search fragment split mid-JSON by Cloudflare's edge would be lost.
  // Instead we HOLD the partial payload and keep prepending the next chunk's
  // bytes until it parses into valid JSON, then emit it. This fully closes the
  // mangling gap. Bounded by MAX_PENDING_BYTES so a broken provider can't grow
  // it without limit (if exceeded we give up and drop, same safe fallback).
  let pendingData: string | null = null;
  const MAX_PENDING_BYTES = 2 * 1024 * 1024; // 2 MB per in-flight event — far above any real tool_call.

  // Try to parse + emit a `data:` payload. Returns true if the payload was
  // successfully parsed and emitted (or was [DONE]); false if it's still an
  // incomplete fragment that should be buffered for more bytes.
  function tryEmit(payload: string): boolean {
    if (payload === "[DONE]") {
      if (!sentDone) { writer.write(encoder.encode("data: [DONE]\n\n")); sentDone = true; }
      return true;
    }
    try {
      const parsed = JSON.parse(payload);
      if (parsed.choices && Array.isArray(parsed.choices)) {
        for (const choice of parsed.choices) {
          if (choice.delta) {
            if (Array.isArray(choice.delta.content)) {
              let textContent = "";
              for (const item of choice.delta.content) {
                if (typeof item === 'string') textContent += item;
                else if (item.text) textContent += item.text;
              }
              choice.delta.content = textContent || "";
            } else if (choice.delta.content === null) {
              choice.delta.content = "";
            }
          }
        }
      }
      writer.write(encoder.encode(`data: ${JSON.stringify(parsed)}\n\n`));
      return true;
    } catch {
      return false; // incomplete fragment — caller should buffer it
    }
    writer.write(encoder.encode(`data: ${payload}\n\n`));
    return true;
  }

  // If the CLIENT disconnects (cancels our outgoing stream), abandon the
  // upstream read loop and cancel the provider's subrequest so we don't keep
  // a dangling fetch open (Cloudflare bills/limits subrequests; an orphaned
  // upstream read is a silent resource leak under client disconnect).
  const onClientClose = () => {
    aborted = true;
    try { reader.cancel().catch(() => {}); } catch {}
  };
  // If the CLIENT cancels/disconnects the outgoing stream, the writable side's
  // `closed` promise rejects. Hook into it to abort the upstream read loop and
  // cancel the provider subrequest so we don't leave a dangling fetch open.
  const closed = (writer as any).closed as Promise<void> | undefined;
  if (closed && typeof closed.then === "function") {
    closed.then(undefined, onClientClose);
  }

  (async () => {
    try {
      while (true) {
        if (aborted) break;
        const { done, value } = await reader.read();
        if (done) break;
        lineBuffer += decoder.decode(value, { stream: true });

        // Split on newlines; keep the tail (incomplete line) in the buffer.
        let nl: number;
        while ((nl = lineBuffer.indexOf("\n")) !== -1) {
          let line = lineBuffer.slice(0, nl);
          lineBuffer = lineBuffer.slice(nl + 1);
          if (line.endsWith("\r")) line = line.slice(0, -1);

          const trimmed = line.trim();
          if (!trimmed) continue;
          if (!trimmed.startsWith("data:")) continue;

          // If we already hold a partial fragment from a previous chunk, prepend
          // it so a tool_call/web-search event split across packets is
          // reconstructed before we attempt to parse.
          let payload = trimmed.slice(5).trim();
          if (pendingData !== null) {
            payload = pendingData + payload;
            pendingData = null;
          }

          // Try to emit. If the payload is still an incomplete JSON fragment
          // (parse failed), buffer it and wait for the next chunk instead of
          // dropping it — this is what eliminates the missing-tool-call risk.
          if (!tryEmit(payload)) {
            if (payload.length <= MAX_PENDING_BYTES) {
              pendingData = payload;
            }
            // Else: fragment exceeds the safety cap — give up (drop) to avoid
            // unbounded memory. Same safe fallback as before, but only after
            // genuinely exhausting the reconstruction attempt.
          }
        }
      }
      // Flush any trailing complete-looking buffer line.
      const tail = lineBuffer.trim();
      if (tail.startsWith("data:")) {
        let payload = tail.slice(5).trim();
        if (pendingData !== null) { payload = pendingData + payload; pendingData = null; }
        if (payload && payload !== "[DONE]") {
          tryEmit(payload); // emits if parseable, else safely ignored
        }
      }
      // If a fragment was still pending at stream end and never completed, drop
      // it cleanly (do not forward corruption). The [DONE] below still closes.
      if (pendingData !== null) pendingData = null;
      if (!sentDone) { await writer.write(encoder.encode("data: [DONE]\n\n")); sentDone = true; }
    } catch (e) {
      // If the upstream stream dies mid-tool-call, end the stream cleanly so
      // the client never hangs on a half-open connection.
      if (!sentDone) { try { await writer.write(encoder.encode("data: [DONE]\n\n")); } catch {} }
    } finally {
      try { await writer.close(); } catch {}
    }
  })();
}

// Proxy a provider's raw streaming Response through the hardened SSE pipeline.
// Used by the OpenAI-compatible adapter (router fetches the provider directly).
function proxySSE(providerResponse: Response): Response {
  const { readable, writable } = new TransformStream();
  const reader = providerResponse.body!.getReader();
  const writer = writable.getWriter();
  pipeHardenedSSE(reader, writer);

  const init: any = { headers: sseResponseHeaders() };
  // Disable Cloudflare caching/transformation of the response.
  init.cf = { cacheTtl: 0, cacheEverything: false };

  return new Response(readable, init);
}

// Proxy an already-normalized OpenAI-format SSE byte stream (produced inside a
// provider adapter, e.g. Gemini/Claude which map their native streams into
// OpenAI chunks) through the same hardened pipeline. This guarantees Gemini &
// Claude streaming get the IDENTICAL anti-mangling protection as OpenAI
// providers — previously their adapters built their own TransformStream and
// omitted the identity/cf headers, leaving tool calls vulnerable to Cloudflare
// edge re-encoding (spec 4.10 gap).
function proxyNormalizedSSE(normalizedStream: ReadableStream<Uint8Array>): Response {
  const { readable, writable } = new TransformStream();
  const reader = normalizedStream.getReader();
  const writer = writable.getWriter();
  pipeHardenedSSE(reader, writer);

  const init: any = { headers: sseResponseHeaders() };
  init.cf = { cacheTtl: 0, cacheEverything: false };

  return new Response(readable, init);
}

// Export so provider adapters can reuse the exact same hardened SSE relay.
export { proxyNormalizedSSE };

// ---------------------------------------------------------------------------
// In-memory state (per Worker instance / isolate).
// This intentionally does NOT use KV: Workers can be invoked many times per
// second, and writing to KV on every failed request would blow the free-tier
// KV write quota. Transient failure tracking lives only here, in memory, for
// the lifetime of the isolate. Persisted health state is owned solely by the
// Cron health checks (cron.ts).
// ---------------------------------------------------------------------------

// modelKey -> timestamp until which this (provider,model) should be skipped.
// These maps are module-level and live for the isolate's lifetime, so without
// eviction a busy gateway would accumulate entries forever. We cap them and
// sweep expired entries whenever they grow past a threshold (cheap, O(n)).
const cooldownUntil = new Map<string, number>();
// per-virtual-key sliding window counters for rate limiting (no KV writes).
const vkRequestTimes = new Map<string, number[]>();

// ---------------------------------------------------------------------------
// Live "reputation" tracker (per isolate, in memory ONLY — no KV reads/writes).
//
// WHY: routing must NOT depend on KV health data (`status` / `avgLatencyMs` from
// `provider_model:*` entries). That data is (a) stale/unreliable — "a model works
// but the website can't handle it" means health says one thing, reality another —
// and (b) the cron probe batch that produces it drains the KV write quota. Instead
// we LEARN live: every chat attempt updates a per-(provider,model) reputation
// record, and selection prefers models with recent successes and avoids ones with
// recent failures. This is fully KV-free and self-correcting.
// ---------------------------------------------------------------------------
interface Reputation {
  ok: number;
  fail: number;
  lastOk: number;
  lastFail: number;
}
const reputation = new Map<string, Reputation>();

// Record a successful attempt for a (provider,model).
function recordSuccess(p: string, m: string): void {
  const k = modelKey(p, m);
  const r = reputation.get(k) || { ok: 0, fail: 0, lastOk: 0, lastFail: 0 };
  r.ok++;
  r.lastOk = Date.now();
  reputation.set(k, r);
  sweepReputation();
}

// Record a failed attempt for a (provider,model).
function recordFailure(p: string, m: string): void {
  const k = modelKey(p, m);
  const r = reputation.get(k) || { ok: 0, fail: 0, lastOk: 0, lastFail: 0 };
  r.fail++;
  r.lastFail = Date.now();
  reputation.set(k, r);
  sweepReputation();
}

function statusBaseScore(status?: string, networkIssueSuspected?: boolean): number {
  if (networkIssueSuspected) return 400; // Gives candidate models that work on user's device high priority
  if (status === "working") return 500;
  if (status === "degraded") return 200;
  if (status === "untested") return 100;
  if (status === "broken") return -500;
  return 0;
}

// Selection score: higher = tried first. Combines static health status with
// live in-memory success/failure ratio so working models rank top on cold isolates
// while live successes/failures dynamically adjust ranking.
function reputationScore(p: string, m: string, now: number, status?: string, networkIssueSuspected?: boolean): number {
  const baseStatus = statusBaseScore(status, networkIssueSuspected);
  const r = reputation.get(modelKey(p, m));
  let speedBonus = 0;
  const lowerM = m.toLowerCase();
  if (lowerM.includes("flash") || lowerM.includes("mini") || lowerM.includes("instant") || lowerM.includes("fast") || lowerM.includes("8b")) {
    speedBonus = 150;
  }
  if (!r) return baseStatus + speedBonus;
  const okRecency = r.lastOk ? Math.max(0, 1 - (now - r.lastOk) / (1000 * 60 * 30)) : 0; // fresh ok within 30m
  const failRecency = r.lastFail ? Math.max(0, 1 - (now - r.lastFail) / (1000 * 60 * 10)) : 0; // fresh fail within 10m
  const base = (r.ok - r.fail) * 15;
  return baseStatus + speedBonus + base + okRecency * 300 - failRecency * 600;
}

// Hard ceilings to keep per-isolate memory bounded over long uptimes.
const COOLDOWN_MAP_MAX = 4096;
const VK_MAP_MAX = 4096;
const REPUTATION_MAP_MAX = 4096;

// Drop expired cooldowns (and, if still over the cap, oldest entries) so the
// map can't grow without bound across an isolate's lifetime.
function sweepCooldowns(now: number): void {
  if (cooldownUntil.size <= COOLDOWN_MAP_MAX) {
    for (const [k, until] of cooldownUntil) {
      if (until <= now) cooldownUntil.delete(k);
    }
    return;
  }
  // Over cap: clear everything already expired, then evict oldest until under.
  for (const [k, until] of cooldownUntil) {
    if (until <= now) cooldownUntil.delete(k);
  }
  if (cooldownUntil.size > COOLDOWN_MAP_MAX) {
    const entries = [...cooldownUntil.entries()].sort((a, b) => a[1] - b[1]);
    for (const [k] of entries.slice(0, cooldownUntil.size - COOLDOWN_MAP_MAX)) {
      cooldownUntil.delete(k);
    }
  }
}

// Drop empty/fully-expired rate-limit windows and evict oldest keys past cap.
function sweepRateLimitWindows(now: number): void {
  if (vkRequestTimes.size <= VK_MAP_MAX) {
    for (const [k, times] of vkRequestTimes) {
      if (times.length === 0 || now - times[times.length - 1] >= 60 * 1000) {
        vkRequestTimes.delete(k);
      }
    }
    return;
  }
  for (const [k, times] of vkRequestTimes) {
    if (times.length === 0 || now - times[times.length - 1] >= 60 * 1000) {
      vkRequestTimes.delete(k);
    }
  }
  if (vkRequestTimes.size > VK_MAP_MAX) {
    const keys = [...vkRequestTimes.keys()].slice(0, vkRequestTimes.size - VK_MAP_MAX);
    for (const k of keys) vkRequestTimes.delete(k);
  }
}

// Bound the reputation map the same way (cheap O(n) sweep, only when over cap).
function sweepReputation(): void {
  if (reputation.size <= REPUTATION_MAP_MAX) return;
  const entries = [...reputation.entries()].sort((a, b) => (a[1].lastOk || 0) - (b[1].lastOk || 0));
  for (const [k] of entries.slice(0, reputation.size - REPUTATION_MAP_MAX)) {
    reputation.delete(k);
  }
}

const modelKey = (p: string, m: string) => `${p}:${m}`;
const COOLDOWN_MS = 5 * 60 * 1000; // 5 minutes

// Per-isolate rotating index used as a deterministic, request-scoped load
// spreader. We deliberately avoid Math.random() in the model sort tiebreak:
// a random tiebreak re-orders equal candidates on EVERY request, which causes
// model "flapping" (the same conversation's turns can hit different models,
// and creates no stable balancing). Instead we advance this counter once per
// request and use it as a stable rotation offset so equal-cost models are
// still fanned out across requests but ordered consistently within a request.
let loadRotate = 0;
function nextRotate(): number {
  loadRotate = (loadRotate + 1) >>> 0;
  return loadRotate;
}

// Tiny stable string hash (FNV-1a-ish) so we can deterministically order
// models by their id without Math.random(). Same input → same number, always.
function hashKey(providerId: string, modelId: string): number {
  let h = 2166136261;
  const s = `${providerId}:${modelId}`;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

// Health data older than this is considered "stale": we still trust it enough
// to route to the model (never hard-block per spec 4.3.1), but we deprioritize
// it so freshly-probed models are preferred. Purely an in-memory ordering
// signal — no extra KV reads/writes on the hot path.
const STALE_MS = 24 * 60 * 60 * 1000; // 24 hours

function isStaleHealth(m: ProviderModel): boolean {
  return m.lastChecked > 0 && Date.now() - m.lastChecked > STALE_MS;
}

// Robust check if a model is vision capable
function isVisionModel(m: ProviderModel): boolean {
  // If actively probed/tested (lastChecked > 0), trust the probed result!
  if (m.lastChecked > 0) {
    return m.supportsVision === true;
  }
  if (m.supportsVision === true) return true;

  // Fallback to pattern matching ONLY for unprobed (lastChecked === 0) models.
  const id = m.modelId.toLowerCase();
  if (id.includes("-text") || id.includes("text-only") || id.includes("instruct-text")) {
    return false;
  }
  return (
    id.includes("vision") ||
    id.includes("-vl") ||
    id.includes("llava") ||
    id.includes("pixtral") ||
    id.includes("paligemma") ||
    id.includes("multimodal") ||
    id.includes("gpt-4o") ||
    id.includes("gemini-1.5") ||
    id.includes("gemini-2.0") ||
    id.includes("claude-3-5") ||
    id.includes("claude-3-opus") ||
    id.includes("claude-3-sonnet") ||
    id.includes("claude-3-haiku")
  );
}

// Robust check if a model is multimodal (via probed flags or known model ID keywords)
function isMultimodalModel(m: ProviderModel): boolean {
  // If actively probed/tested (lastChecked > 0), trust the probed flags!
  if (m.lastChecked > 0) {
    return m.supportsVision === true || m.supportsDocument === true || m.supportsAudio === true;
  }
  if (m.supportsVision || m.supportsDocument || m.supportsAudio) return true;
  return isVisionModel(m);
}

function isInCooldown(p: string, m: string): boolean {
  const until = cooldownUntil.get(modelKey(p, m));
  return until !== undefined && until > Date.now();
}

function putInCooldown(p: string, m: string, ms = COOLDOWN_MS): void {
  cooldownUntil.set(modelKey(p, m), Date.now() + ms);
  // Keep the map bounded (see sweepCooldowns). Cheap: only runs when we add.
  sweepCooldowns(Date.now());
}

export class GatewayRouter {
  private kv: KVManager;

  constructor(env: Env) {
    this.kv = new KVManager(env);
  }

  // Rate-limit check (in-memory only, no KV writes). Returns true if allowed.
  //
  // SCOPE NOTE: this counter lives in the current Worker isolate's memory, so
  // it throttles a single key within one isolate. Under Cloudflare's autoscaling
  // a key's traffic can be spread across multiple isolates, each with its own
  // counter, so this is a BEST-EFFORT per-isolate guard — not a global ceiling.
  // A truly global limit would require a KV/Durable-Object write per request,
  // which this project deliberately avoids to protect the free-tier quota. The
  // per-isolate check still stops the most common abuse (a single client
  // hammering one warm isolate) and is cheap.
  private checkRateLimit(vk: VirtualKey): boolean {
    const limit = vk.rateLimit?.requestsPerMin;
    if (!limit || limit <= 0) return true;
    const now = Date.now();
    const windowMs = 60 * 1000;
    const times = vkRequestTimes.get(vk.key) || [];
    // Drop entries older than the window.
    const recent = times.filter(t => now - t < windowMs);
    recent.push(now);
    // Cap the stored array so a perpetually-throttled key can't grow it without
    // bound across the isolate's lifetime.
    if (recent.length > limit * 2 + 8) recent.splice(0, recent.length - (limit + 8));
    vkRequestTimes.set(vk.key, recent);
    // Periodically evict stale/empty windows so the per-key map can't grow
    // without bound across a long-lived isolate (see sweepRateLimitWindows).
    sweepRateLimitWindows(now);
    return recent.length <= limit;
  }

  async handleChatCompletions(request: Request, ctx?: ExecutionContext): Promise<Response> {
    const authHeader = request.headers.get("Authorization") || "";
    if (!authHeader.startsWith("Bearer ")) {
      return new Response(JSON.stringify({ error: { message: "Missing Authorization header" } }), { 
        status: 401, 
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } 
      });
    }

    const keyString = authHeader.replace("Bearer ", "").trim();
    const vk = await this.kv.getVirtualKey(keyString);

    if (!vk || !vk.active) {
      const message = (vk && vk.disabledQuote) ? vk.disabledQuote : "Invalid or revoked virtual key";
      
      let isStreaming = false;
      try {
        const clonedRequest = request.clone();
        const body = await clonedRequest.json() as any;
        isStreaming = body.stream === true;
      } catch (e) {}

      await this.kv.logTraffic({
        timestamp: Date.now(),
        virtualKey: vk ? vk.key : "unknown",
        providerId: "gateway",
        modelId: "auth",
        status: 401,
        latencyMs: 0,
        errorType: "provider_error" // 'unauthorized' is not in the allowed union
      }, ctx);

      if (isStreaming) {
         const id = "chatcmpl-" + Date.now();
         const chunk1 = JSON.stringify({id, object:"chat.completion.chunk", created: Math.floor(Date.now()/1000), model:"mock", choices:[{index:0, delta:{role:"assistant", content:message}, finish_reason:null}]});
         const chunk2 = JSON.stringify({id, object:"chat.completion.chunk", created: Math.floor(Date.now()/1000), model:"mock", choices:[{index:0, delta:{}, finish_reason:"stop"}]});
         const streamData = `data: ${chunk1}\n\ndata: ${chunk2}\n\ndata: [DONE]\n\n`;
         
         return new Response(streamData, {
           status: 200,
           headers: {
             "Content-Type": "text/event-stream",
             "Cache-Control": "no-cache",
             "Connection": "keep-alive",
             "Access-Control-Allow-Origin": "*"
           }
         });
      } else {
         const jsonResponse = {
           id: "chatcmpl-" + Date.now(),
           object: "chat.completion",
           created: Math.floor(Date.now()/1000),
           model: "mock",
           choices: [{
             index: 0,
             message: { role: "assistant", content: message },
             finish_reason: "stop"
           }],
           usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
         };
         
         return new Response(JSON.stringify(jsonResponse), {
           status: 200,
           headers: {
             "Content-Type": "application/json",
             "Access-Control-Allow-Origin": "*"
           }
         });
      }
    }

    // Bug #6: per-virtual-key rate limiting (in-memory, no KV writes).
    if (!this.checkRateLimit(vk)) {
      return new Response(JSON.stringify({ error: { message: "Rate limit exceeded for this virtual key. Try again shortly." } }), { 
        status: 429, 
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } 
      });
    }

    let body: any;
    try {
      body = await request.json();
    } catch {
      return new Response(JSON.stringify({ error: { message: "Invalid JSON body" } }), { 
        status: 400, 
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } 
      });
    }

    const needsVision = this.hasImageContent(body.messages || [], body);
    const needsTools = Array.isArray(body.tools) && body.tools.length > 0;
    const isStreaming = body.stream === true;

    const allProviders = await this.kv.getAllProviders();
    const allModels = await this.kv.getProviderModels();
    const requestedModel = body.model || "";

    // Decide how to treat the client's model label. The alias is "just a label"
    // (spec 4.1.3) and OpenAI-compatible clients routinely send default names
    // like "gpt-4"/"claude-3" that match no real backend model. In both those
    // cases we serve from the key's allowed pool using capability-based routing
    // — we must NOT hard-fail just because the label isn't a known model id.
    // We only do a strict model-id match when the client explicitly named a
    // REAL backend model we actually have.
    const isAliasRequest = requestedModel === vk.modelAlias;
    const isKnownModelRequest = requestedModel !== "" &&
      allModels.some(mm => mm.modelId === requestedModel);
    // "alias mode" = serve-any-from-pool (capability routing), used for the
    // alias, unknown labels, and always under Smart+.
    const aliasMode = vk.smartPlus || isAliasRequest || !isKnownModelRequest;

    // Session stickiness: pin a single model for the life of a conversation so a
    // long chat doesn't flip models between turns (which would make the AI change
    // persona/behavior mid-session). Session id comes from X-Conversation-Id
    // header or body.conversation_id; falls back to a deterministic hash of the
    // conversation's first user message so each chat thread stays pinned to its
    // model without colliding with other chats under the same key.
    const stickyEnabled = await this.kv.isStickyModelsEnabled();
    const firstMsg = Array.isArray(body.messages) && body.messages.length > 0 ? body.messages[0] : null;
    const firstMsgText = firstMsg ? (typeof firstMsg.content === 'string' ? firstMsg.content : JSON.stringify(firstMsg.content)) : "";
    const threadHash = firstMsgText ? hashKey(vk.key, firstMsgText.slice(0, 100)).toString() : vk.key;
    const sessionId = request.headers.get("X-Conversation-Id")
      || (body.conversation_id || "")
      || threadHash;
    const stickyKey = `sticky:${vk.key}:${sessionId}`;
    let pinnedModelId: string | null = null;
    if (stickyEnabled) {
      pinnedModelId = await this.kv.getStickyModel(stickyKey);
    }

    // Shared eligibility predicate (capability + targeting + provider checks).
    // NOTE: routing is now KV-HEALTH-INDEPENDENT. We do NOT exclude models by
    // `status` (working/broken/untested) — health data is stale/unreliable and
    // its probe batch drains the KV quota. Instead, live in-memory reputation
    // (see reputationScore) drives selection order, and transient failures just
    // cooldown the model and fall through. Every active model is a live candidate.
    const isEligible = (m: ProviderModel): boolean => {
      if (!m.active) return false;
      if (vk.allowedProviders.length && !vk.allowedProviders.includes(m.providerId)) return false;
      if (vk.allowedModels.length && !vk.allowedModels.includes(m.modelId)) return false;

      // multimodalRestrict: when ON, this key may ONLY use multimodal models —
      // i.e. a model that supports ANY of vision / document / audio. Plain
      // text-only models are excluded. The capability flags are advisory (set by
      // the optional cron probe); if a model has no flag recorded we can't prove
      // it's multimodal, so we exclude it too (safe default — a text-only model
      // wrongly admitted would just be a wasted attempt). If NO multimodal model
      // is eligible at all, the caller falls back to allowing any model so the
      // key still works (see below).
      if (vk.multimodalRestrict) {
        if (!isMultimodalModel(m)) return false;
      }

      // Capability-aware routing (spec 4.3.1): we only EXCLUDE a model when its
      // capability was explicitly probed AND found false (status working/degraded
      // but supportsX is false). An unprobed (untested) model is allowed through;
      // if the provider truly can't do it, the provider rejects and we fail over.
      // This keeps the client experience "doesn't matter which model" — the
      // request shape is always OpenAI-compatible and the gateway always
      // attempts the call regardless of backend.
      const isKnownHealthy = m.status === 'working' || m.status === 'degraded';
      if (needsVision && !isVisionModel(m)) return false;
      if (needsTools && m.lastChecked > 0 && isKnownHealthy && !m.supportsTools) return false;
      if (isStreaming && m.lastChecked > 0 && isKnownHealthy && !m.supportsStreaming) return false;

      // Model targeting logic:
      // - Smart+ ON, OR the alias was requested, OR the label is unknown →
      //   "alias mode": serve any allowed model, sorted by reputation below.
      // - Otherwise the client named a REAL backend model id → strict match.
      if (!aliasMode && m.modelId !== requestedModel) return false;

      const p = allProviders.find(p => p.id === m.providerId);
      if (!p || !p.active) return false;

      // Skip models currently in transient cooldown (no KV read/write here).
      if (isInCooldown(m.providerId, m.modelId)) return false;

      return true;
    };

    // Build the eligible pool. If multimodalRestrict is ON, ONLY multimodal models are allowed.
    let eligibleModels = allModels.filter(m => isEligible(m));

    // If a pinned model is still eligible, move it to the front so the whole
    // conversation keeps using the same model. We only force it when it's
    // actually eligible+healthy; otherwise we let normal selection/failover pick.
    if (pinnedModelId) {
      const idx = eligibleModels.findIndex(m => m.modelId === pinnedModelId);
      if (idx > 0) {
        const [pinned] = eligibleModels.splice(idx, 1);
        eligibleModels.unshift(pinned);
      } else if (idx === -1) {
        // Pinned model is no longer eligible (disabled/broken/in cooldown) —
        // drop the pin locally so we don't keep trying a dead model; normal
        // selection takes over. We do NOT write to KV here: that would be a
        // per-request KV write (expensive on the free tier). The stale KV pin
        // is harmless — it's ignored because the model is ineligible, and will
        // be overwritten on the next successful pin (or expire via its 24h TTL).
        pinnedModelId = null;
      }
    }

    if (eligibleModels.length === 0) {
      // Explain *why* nothing matched so the client (and admin) isn't left with
      // a silent blank. Common causes: multimodalRestrict with no vision model,
      // or all models still untested/broken.
      let reason = "No eligible models available.";
      const anyActive = allModels.filter(m => m.active).length > 0;
      if (!anyActive) {
        reason = "No active models. Add a provider and run a health check.";
      } else if (vk.multimodalRestrict && needsVision) {
        reason = "Multimodal Restrict is enabled but no vision-capable model is currently healthy.";
      } else if (needsVision || needsTools || isStreaming) {
        reason = "Every available model was probed and confirmed NOT to support the required capability (vision/tools/streaming), or all are broken/inactive.";
      } else if (allModels.every(m => m.status === "broken" || m.status === "untested")) {
        // Distinguish a Cloudflare-edge network issue from a truly broken model.
        const netSuspect = allModels.some(m => m.networkIssueSuspected);
        if (netSuspect) {
          reason = "All models are untested/broken. A Cloudflare network issue is suspected (these models work outside Cloudflare) — re-run health checks; if it persists, the provider may be blocking Cloudflare's egress IPs.";
        } else {
          reason = "All models are untested or broken. Run a health check to populate status.";
        }
      }
      return new Response(JSON.stringify({ error: { message: reason } }), { 
        status: 503, 
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } 
      });
    }

    // Compute this request's rotation offset ONCE, BEFORE the sort, so the
    // deterministic load-spread tiebreak (below) actually uses a fresh, valid
    // value. Previously rotateOffset was declared AFTER sort(), so it was
    // `undefined` during comparison and the whole tiebreak collapsed to NaN
    // (a no-op). Computing it first makes equal-cost models fan out across
    // requests consistently and prevents model "flapping".
    const rotateOffset = nextRotate();

    eligibleModels.sort((a, b) => {
      // 0. Sticky session: if this chat thread has a pinned model that is healthy, keep using it!
      if (pinnedModelId) {
        if (a.modelId === pinnedModelId && b.modelId !== pinnedModelId) return -1;
        if (b.modelId === pinnedModelId && a.modelId !== pinnedModelId) return 1;
      }

      // 1. Client explicitly named a REAL backend model → prioritize it.
      if (!aliasMode && requestedModel) {
        if (a.modelId === requestedModel && b.modelId !== requestedModel) return -1;
        if (b.modelId === requestedModel && a.modelId !== requestedModel) return 1;
      }

      // Prioritize confirmed vision models when the request includes vision content
      if (needsVision) {
        const aVis = a.supportsVision === true;
        const bVis = b.supportsVision === true;
        if (aVis && !bVis) return -1;
        if (bVis && !aVis) return 1;
      }
      if (vk.multimodalRestrict) {
        const aMM = a.supportsVision === true || a.supportsDocument === true || a.supportsAudio === true;
        const bMM = b.supportsVision === true || b.supportsDocument === true || b.supportsAudio === true;
        if (aMM && !bMM) return -1;
        if (bMM && !aMM) return 1;
      }

      // LIVE reputation ordering (KV-HEALTH-INDEPENDENT). We do NOT rank by
      // `status` / `avgLatencyMs` from KV — that data is stale and its probe
      // batch drains the KV quota. Instead we rank by the in-memory reputation
      // score: models with recent successes rank first, models with recent
      // failures are pushed back. This makes the gateway self-correct live:
      // a model that just worked is preferred; one that just failed (timeout,
      // 403, 5xx, malformed) is cooled down and deprioritized. A model with no
      // history scores 0 (neutral) and gets a fair first try.
      const now = Date.now();
      const aScore = reputationScore(a.providerId, a.modelId, now, a.status, a.networkIssueSuspected);
      const bScore = reputationScore(b.providerId, b.modelId, now, b.status, b.networkIssueSuspected);
      if (aScore !== bScore) return bScore - aScore; // higher score first

      // Tiebreak: prefer models whose capability flags suggest they can satisfy
      // the request (more capabilities = more likely to handle tools/vision/etc.
      // without a provider-side reject). This is advisory only — every model here
      // is already eligible, so it just nudges ordering, never blocks.
      const aCaps = (a.supportsTools ? 1 : 0) + (a.supportsVision ? 1 : 0) + (a.supportsWebSearch ? 1 : 0) + (a.supportsStreaming ? 1 : 0) + (a.supportsDocument ? 1 : 0) + (a.supportsAudio ? 1 : 0);
      const bCaps = (b.supportsTools ? 1 : 0) + (b.supportsVision ? 1 : 0) + (b.supportsWebSearch ? 1 : 0) + (b.supportsStreaming ? 1 : 0) + (b.supportsDocument ? 1 : 0) + (b.supportsAudio ? 1 : 0);
      if (aCaps !== bCaps) return bCaps - aCaps;

      // Deterministic load spread instead of Math.random() (prevents flapping).
      // Equal-cost models are ordered by a stable per-request rotation offset
      // so consecutive requests fan out across the pool consistently.
      return ((hashKey(a.providerId, a.modelId) + rotateOffset) % 1e9) -
             ((hashKey(b.providerId, b.modelId) + rotateOffset) % 1e9);
    });

    // Bug #3: Two-tier fallback.
    // Tier 1: try every eligible model on the SAME provider before crossing to
    // a different provider. Tier 2: move to the next provider and repeat.
    const providerGroups: Record<string, ProviderModel[]> = {};
    for (const m of eligibleModels) {
      if (!providerGroups[m.providerId]) providerGroups[m.providerId] = [];
      providerGroups[m.providerId].push(m);
    }
    const providerIds = Object.keys(providerGroups);

    let lastErrorType: string | null = null;

    // Fast failover deadline (18s total) so the client app (Chatbox/browser)
    // never experiences a 15-20s timeout while waiting for hung providers.
    const FAIL_OVER_DEADLINE_MS = 18000;
    const failOverDeadline = Date.now() + FAIL_OVER_DEADLINE_MS;

    for (const pid of providerIds) {
      const provider = allProviders.find(p => p.id === pid)!;
      const adapter = getAdapterForProvider(provider);

      for (const model of providerGroups[pid]) {
        if (Date.now() > failOverDeadline) break;
        const start = Date.now();
        try {
          const controller = new AbortController();
          // FAST FAILOVER: 7s cap per model (2.5s for local). If candidate #1 hangs or stalls,
          // it is aborted at 7s, penalized in reputation (-600), and Candidate #2 succeeds instantly.
          const isLocal = provider.baseUrl.includes("localhost") || provider.baseUrl.includes("127.0.0.1");
          const modelTimeoutMs = isLocal ? 2500 : 7000;
          const timeoutId = setTimeout(() => controller.abort(), modelTimeoutMs);

          const response = await adapter.fetchChatCompletion(provider, model, body, undefined, controller.signal);
          clearTimeout(timeoutId);

          if (response.ok) {
            // Pin this model for the session so subsequent turns of the same
            // conversation keep using it (no mid-chat model flip). If we arrived
            // here via failover (pinned model was dead), this re-pins to the
            // working fallback so the rest of the chat stays consistent.
            if (stickyEnabled && pinnedModelId !== model.modelId) {
              await this.kv.putStickyModel(stickyKey, model.modelId);
              pinnedModelId = model.modelId;
            }

            // Defensive guard (spec 4.10 / failure mode #6): a dead or wrong
            // provider URL can return a 200 with HTML or an empty body. Passing
            // that straight through to the client produces a "blank" response,
            // which is exactly the bug we must avoid. Validate it is real
            // OpenAI-format JSON; if not, treat as a malformed response and fall
            // through to the next candidate instead of returning garbage.
            if (!isStreaming) {
              const ct = response.headers.get("content-type") || "";
              const text = await response.text().catch(() => "");
              const parsed = (() => { try { return JSON.parse(text); } catch { return null; } })();
              // A 200 from a dead/wrong provider URL often carries HTML or an empty
              // body (or a non-OpenAI JSON blob). We must NEVER pass that through as
              // a "successful" chat completion — that's the classic blank-response
              // bug ("model works but the website can't handle it"). Accept the body
              // ONLY if it parses as a real OpenAI-style response: either a choices
              // array (completion or chunk), or a provider error object/string, or
              // an Anthropic-style {type:"error"}. We explicitly REJECT:
              //   - empty body (text length 0)
              //   - HTML (starts with '<' or a non-JSON content-type) — a wrong URL
              //   - a JSON blob with neither `choices` nor a recognized `error`
              // Content-type alone is NOT sufficient evidence — a provider can send
              // `application/json` with a non-OpenAI payload, so we validate shape.
              const isHtml = text.trimStart().startsWith("<") || (ct && !ct.includes("json") && !ct.includes("text/event-stream") && !ct.includes("application/octet"));
              const hasChoices = parsed !== null && Array.isArray(parsed.choices);
              const hasError = parsed !== null &&
                ((parsed.error && (typeof parsed.error === "object" || typeof parsed.error === "string")) ||
                 parsed.type === "error");
              const isValidOpenAI = text.length > 0 && !isHtml && (hasChoices || hasError);
              if (!isValidOpenAI) {
                // Not a usable OpenAI response: cooldown this (provider,model) and
                // fall through to the next candidate instead of returning garbage.
                // Also record the failure in live reputation so we don't keep
                // preferring a model the gateway can't parse ("works but the
                // website can't handle it").
                putInCooldown(pid, model.modelId);
                recordFailure(pid, model.modelId);
                lastErrorType = "malformed_response";
                await this.kv.logTraffic({
                  timestamp: Date.now(), virtualKey: vk.key, providerId: pid, modelId: model.modelId,
                  status: response.status, latencyMs: Date.now() - start, errorType: "malformed_response" as any
                }, ctx);
                continue;
              }
              // If the provider returned an error object/string, surface it clearly.
              if (parsed.error && !Array.isArray(parsed.choices)) {
                recordSuccess(pid, model.modelId);
                return new Response(JSON.stringify(parsed), {
                  status: 200,
                  headers: { "Content-Type": "application/json", "Content-Encoding": "identity", "Access-Control-Allow-Origin": "*" }
                });
              }
              // Return the valid JSON (re-wrap with correct content-type if needed).
              if (parsed && parsed.choices && Array.isArray(parsed.choices)) {
                for (const choice of parsed.choices) {
                  if (choice.message) {
                    if (Array.isArray(choice.message.content)) {
                      let textContent = "";
                      for (const item of choice.message.content) {
                        if (typeof item === 'string') textContent += item;
                        else if (item.text) textContent += item.text;
                      }
                      choice.message.content = textContent || "";
                    } else if (choice.message.content === null) {
                      choice.message.content = "";
                    }
                  }
                }
              }
              const finalText = JSON.stringify(parsed);
              recordSuccess(pid, model.modelId);
              return new Response(finalText, {
                status: 200,
                headers: { "Content-Type": "application/json", "Content-Encoding": "identity", "Access-Control-Allow-Origin": "*" }
              });
            }

            await this.kv.logTraffic({
              timestamp: Date.now(), virtualKey: vk.key, providerId: pid, modelId: model.modelId,
              status: response.status, latencyMs: Date.now() - start
            }, ctx);

            // Live success: this (provider,model) answered. Record it so reputation
            // prefers it next time (KV-health-independent learning).
            recordSuccess(pid, model.modelId);

            // 4.10 Proper stream proxying with SSE re-assembly so Cloudflare's
            // network cannot mangle tool-call / web-search fragments.
            if (isStreaming && response.body) {
              // Guard against a "wrong URL returns 200 HTML" for streaming: if the
              // content-type is HTML/non-SSE, this is not a real stream — fall
              // through to the next candidate instead of returning a blank stream.
              const sct = response.headers.get("content-type") || "";
              const looksHtml = sct.includes("text/html") || sct.includes("xml");
              if (looksHtml) {
                putInCooldown(pid, model.modelId);
                recordFailure(pid, model.modelId);
                lastErrorType = "malformed_response";
                await this.kv.logTraffic({
                  timestamp: Date.now(), virtualKey: vk.key, providerId: pid, modelId: model.modelId,
                  status: response.status, latencyMs: Date.now() - start, errorType: "malformed_response" as any
                }, ctx);
                continue;
              }
              return proxySSE(response);
            }

            const h = new Headers(response.headers);
            h.set("Access-Control-Allow-Origin", "*");
            return new Response(response.body, { status: response.status, statusText: response.statusText, headers: h });
          }

          // Non-OK: classify and cooldown IN MEMORY only (no KV write).
          let errorType: string;
          if (response.status === 401) {
            // 401 = the PROVIDER API KEY is invalid/expired. This is provider-wide:
            // every model on this provider will reject, so there is no point trying
            // the others. Report it clearly and stop. (403 is handled separately —
            // it is almost always model-specific, see below.)
            errorType = "auth_error";
            // Short cooldown just to avoid hammering a dead key this invocation.
            putInCooldown(pid, model.modelId, 60 * 1000);
            // Capture the provider's actual error text for the admin/traffic log.
            let providerMsg = "";
            try { const t = await response.text(); providerMsg = t.slice(0, 300); } catch {}
            lastErrorType = errorType;
            await this.kv.logTraffic({
              timestamp: Date.now(), virtualKey: vk.key, providerId: pid, modelId: model.modelId,
              status: response.status, latencyMs: Date.now() - start, errorType: errorType as any
            }, ctx);
            // If this is the LAST eligible candidate, return a clear auth error
            // rather than the generic "all providers exhausted" blank.
            const isLast = providerIds.indexOf(pid) === providerIds.length - 1 &&
                           providerGroups[pid].indexOf(model) === providerGroups[pid].length - 1;
            if (isLast) {
              return new Response(JSON.stringify({
                error: { message: `Provider authentication failed (${response.status}). Check the API key for provider "${provider.name}".`, provider_error: providerMsg }
              }), {
                status: 502,
                headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
              });
            }
            break; // Provider key is dead — skip remaining models on this provider.
          } else if (response.status === 403) {
            // 403 here is almost always MODEL-SPECIFIC (e.g. Ollama's
            // "this model requires a subscription", or a gated model). It does NOT
            // mean the provider key is bad — other models on the SAME provider work
            // fine. Previously this did `break`, which abandoned the whole provider
            // and produced the intermittent "sometimes no response" symptom: a 403
            // model sorted ahead of a working one would 502 the entire call. Now we
            // cooldown ONLY this model and CONTINUE to the next candidate.
            errorType = "auth_error";
            putInCooldown(pid, model.modelId, 60 * 1000);
            let providerMsg = "";
            try { const t = await response.text(); providerMsg = t.slice(0, 300); } catch {}
            lastErrorType = errorType;
            await this.kv.logTraffic({
              timestamp: Date.now(), virtualKey: vk.key, providerId: pid, modelId: model.modelId,
              status: response.status, latencyMs: Date.now() - start, errorType: errorType as any
            }, ctx);
            continue; // try the next eligible model — do NOT break the provider
          } else if (response.status === 429) {
              errorType = "rate_limited";
              if (model.networkIssueSuspected) {
                // This model is known to be throttled on Cloudflare's egress IP
                // (works on the admin's own system). A live 429 here is the same
                // per-IP rate limit, not a real quota exhaustion — use a SHORT
                // cooldown so the very next request can retry (possibly via the
                // resolveOverride re-route) instead of blacklisting it for 10 min.
                putInCooldown(pid, model.modelId, 30 * 1000);
              } else {
                putInCooldown(pid, model.modelId, 10 * 60 * 1000); // longer cooldown for genuine rate limits
              }
            } else if (response.status >= 500) {
            // 5xx from ONE model does NOT mean the whole provider is down — other
            // models on the same provider are often healthy. Previously this
            // `break`ed the provider, which is exactly what caused intermittent
            // failures when the first sorted model had a transient 5xx. Now we
            // cooldown this model and CONTINUE to the next candidate; we only give
            // up if every candidate is exhausted (or the fail-over deadline hits).
            errorType = "provider_error";
            putInCooldown(pid, model.modelId);
          } else {
            errorType = "malformed_response";
            putInCooldown(pid, model.modelId);
          }
          lastErrorType = errorType;

          // Live failure: record it in reputation so this (provider,model) is
          // deprioritized next time (KV-health-independent learning). The model is
          // also cooled down above so we don't immediately retry it this request.
          recordFailure(pid, model.modelId);

          await this.kv.logTraffic({
            timestamp: Date.now(), virtualKey: vk.key, providerId: pid, modelId: model.modelId,
            status: response.status, latencyMs: Date.now() - start, errorType: errorType as any
          }, ctx);

        } catch (err: any) {
          // Bug #2: reliable network-vs-timeout classification.
          // fetch() failures in the Workers runtime throw a TypeError, and the
          // AbortController timeout throws an AbortError. Both are reliable
          // signals, unlike matching on err.message strings.
          const isAbort = err && err.name === "AbortError";
          const isNetwork = err && err.name === "TypeError"; // fetch network failure
          let errorType: string;
          if (isAbort) {
            errorType = "timeout";
          } else if (isNetwork) {
            errorType = "network_layer"; // Cloudflare-side network issue (spec 4.9)
            // 4.9 mitigation: one retry with adjusted cf options, same model.
            try {
              const retryController = new AbortController();
              const retryTimeoutId = setTimeout(() => retryController.abort(), 7000);
              const resRetry = await adapter.fetchChatCompletion(provider, model, body, { cacheTtl: 0, cacheEverything: false, resolveOverride: "cloudflare-dns.com" } as any, retryController.signal);
              clearTimeout(retryTimeoutId);
              if (resRetry.ok) {
                await this.kv.logTraffic({
                  timestamp: Date.now(), virtualKey: vk.key, providerId: pid, modelId: model.modelId,
                  status: resRetry.status, latencyMs: Date.now() - start
                }, ctx);
                if (stickyEnabled && pinnedModelId !== model.modelId) {
                  await this.kv.putStickyModel(stickyKey, model.modelId);
                  pinnedModelId = model.modelId;
                }
                // Same defensive + anti-mangling handling as the main path.
                if (isStreaming && resRetry.body) {
                  return proxySSE(resRetry);
                }
                if (!isStreaming) {
                  const rt = await resRetry.text().catch(() => "");
                  const rp = (() => { try { return JSON.parse(rt); } catch { return null; } })();
                  if (rp && (Array.isArray(rp.choices) || rp.error)) {
                    return new Response(rt, { status: 200, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
                  }
                }
                const hr = new Headers(resRetry.headers);
                hr.set("Access-Control-Allow-Origin", "*");
                return new Response(resRetry.body, { status: resRetry.status, statusText: resRetry.statusText, headers: hr });
              }
            } catch (e) { /* ignore retry failure, fall through */ }
          } else {
            errorType = "timeout";
          }
          // Cooldown IN MEMORY only — never persist transient failures to KV.
          putInCooldown(pid, model.modelId);
          lastErrorType = errorType;
          // Live failure: record in reputation so this model is deprioritized.
          recordFailure(pid, model.modelId);

          await this.kv.logTraffic({
            timestamp: Date.now(), virtualKey: vk.key, providerId: pid, modelId: model.modelId,
            status: 0, latencyMs: Date.now() - start, errorType: errorType as any
          }, ctx);

          if (errorType === "timeout" || errorType === "network_layer") {
            // A single Cloudflare-edge blip or a slow model (e.g. one averaging
            // ~19s against the 20s timeout) used to `break` the WHOLE provider here,
            // which is the other half of the "sometimes no response" bug: the first
            // sorted model times out and every working model behind it is skipped.
            // Now we cooldown ONLY this model and CONTINUE to the next candidate.
            // The overall fail-over deadline (FAIL_OVER_DEADLINE_MS) bounds the worst
            // case so we never blow the Worker limit while hopping between models.
            // We only stop early if the deadline has already passed (checked at the
            // top of the inner loop) or every candidate is exhausted.
            continue;
          }
        }
      }
    }

    return new Response(JSON.stringify({ error: { message: "All providers exhausted. Service temporarily unavailable." }, error_type: lastErrorType }), { 
      status: 503, 
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } 
    });
  }

  private hasImageContent(messages: any[], body?: any): boolean {
    if (body) {
      if (Array.isArray(body.images) && body.images.length > 0) return true;
      if (body.image) return true;
    }
    for (const msg of (messages || [])) {
      if (msg.image_url || msg.image || msg.images) return true;
      if (Array.isArray(msg.content)) {
        for (const block of msg.content) {
          if (
            block.type === "image_url" ||
            block.type === "image" ||
            block.image_url ||
            block.image ||
            block.inlineData ||
            block.inline_data
          ) return true;
        }
      } else if (typeof msg.content === "string") {
        if (msg.content.includes("data:image/") || msg.content.includes("data:application/pdf")) return true;
      }
    }
    return false;
  }
}
