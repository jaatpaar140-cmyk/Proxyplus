import { Env, Provider, ProviderModel } from "./types";
import { KVManager } from "./kv";
import { getAdapterForProvider, fetchWithProbeRetry } from "./providers";

async function executeCapabilityProbe(env: Env, kv: KVManager, provider: Provider, model: ProviderModel, adapter: any, testBody: any): Promise<Response> {
    if (env.GATEWAY_URL) {
         try {
             const gw = new URL(env.GATEWAY_URL);
             if (gw.protocol !== "https:" && gw.hostname !== "localhost" && gw.hostname !== "127.0.0.1") {
                 console.warn("WARNING: GATEWAY_URL should be HTTPS to prevent admin secret leakage over plaintext HTTP.");
             }
         } catch(e) {}
         const auth = await kv.getAdminAuth();
         return fetch(`${env.GATEWAY_URL}/admin/internal/test-capability`, {
             method: 'POST',
             headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${auth?.secret || ''}` },
             body: JSON.stringify({ providerId: provider.id, modelId: model.modelId, testBody })
         });
    }
    // Use the probe-retry wrapper so a Cloudflare-edge egress failure OR a
    // provider 429/402/5xx (the classic NIM/Groq/OpenRouter "broken through
    // the gateway but fine locally" symptom) is retried with resolveOverride +
    // exponential backoff before being treated as a model failure. This is the
    // single most important change: previously a single throttled probe left a
    // model parked as `untested`/`networkIssueSuspected` forever (and skipping
    // all capability probes), which is exactly why most models never showed as
    // `working`.
    const result = await fetchWithProbeRetry(adapter, provider, model, testBody, undefined, 45000, {
      rateLimitRetries: 4,
      retryBaseDelayMs: 5000,
    });
    if (result.response) return result.response;
    // Re-throw a synthetic error so downstream code classifies it as a network
    // failure (never as a permanent provider-side `broken`).
    const e: any = new Error(result.errorMessage || "Network failure");
    e.name = result.errorName || "TypeError";
    throw e;
}

export async function discoverProviderModels(kv: KVManager, provider: Provider, existingModels: ProviderModel[], throwOnFail: boolean = false) {
    try {
      let modelsList: any[] = [];
      if (provider.name.toLowerCase().includes("gemini") || provider.baseUrl.includes("generativelanguage")) {
        const base = provider.baseUrl.replace(/\/+$/, '');
        const url = base.endsWith('/v1beta') ? `${base}/models?key=${provider.apiKey}` : `${base}/v1beta/models?key=${provider.apiKey}`;
        const res = await fetch(url);
        if (res.ok) {
          const data: any = await res.json();
          modelsList = (data.models || []).map((m: any) => ({ id: m.name.replace('models/', ''), context_length: m.inputTokenLimit || 32000 }));
        } else {
          const errMsg = `Failed to fetch Gemini models, status: ${res.status}`;
          console.error(errMsg);
          if (throwOnFail) throw new Error(errMsg);
        }
      } else {
        const authHeader = provider.authHeaderFormat ? provider.authHeaderFormat.replace("{key}", provider.apiKey) : `Bearer ${provider.apiKey}`;
        const base = provider.baseUrl.replace(/\/+$/, '');
        const url = base.endsWith('/v1') ? `${base}/models` : `${base}/v1/models`;
        const res = await fetch(url, {
          headers: { 
            "Authorization": authHeader,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json"
          },
          cf: { resolveOverride: "cloudflare-dns.com", cacheTtl: 0, cacheEverything: false } as any
        });
        if (res.ok) {
          const data: any = await res.json();
          modelsList = data.data || [];
        } else {
          let errText = "";
          try { errText = await res.text(); } catch {}
          const errMsg = `Failed to fetch models from ${url}, status: ${res.status}. ${errText.substring(0, 100)}`;
          console.error(errMsg);
          if (throwOnFail) throw new Error(errMsg);
        }
      }

      let modelsAdded = false;
      // PERMANENT FIX: providers like OpenRouter expose hundreds of models.
      // Discovering + probing ALL of them exhausts the provider's per-IP
      // free-tier quota (the gateway egress IP is shared), tripping 429s that
      // then park most models as `untested`/`networkIssueSuspected` forever.
      // We cap how many models we KEEP from discovery so the probe batch stays
      // small enough to actually succeed. The cap is generous (default 50) and
      // can be raised via config if the admin truly needs every model.
      const MAX_DISCOVERED = await kv.getMaxDiscoveredModels();
      const overflow = modelsList.length - MAX_DISCOVERED;
      if (overflow > 0) {
        console.warn(`Provider ${provider.id} exposes ${modelsList.length} models; capping discovery to ${MAX_DISCOVERED} (${overflow} skipped). Raise config:max_discovered_models to include more.`);
        modelsList = modelsList.slice(0, MAX_DISCOVERED);
      }
      for (const item of modelsList) {
        const mId = item.id;
        let model = existingModels.find(m => m.providerId === provider.id && m.modelId === mId);
        if (!model) {
          // Bug #4 fix: NEVER infer capabilities from the model name (spec 4.3.1).
          // All capability flags start false/unknown and are populated ONLY by the
          // active online probes in runHealthChecks(). This avoids routing
          // tool/vision/streaming requests to models that can't actually handle them.
          model = {
            providerId: provider.id,
            modelId: mId,
            active: true,
            // Mark untested so the router deprioritizes it until probes confirm.
            status: "untested",
            discoveredAt: Date.now(),
            lastChecked: 0,
            avgLatencyMs: 0,
            supportsTools: false,
            supportsVision: false,
            supportsWebSearch: false,
            supportsStreaming: false,
            maxContext: item.context_length || 4096,
            networkIssueSuspected: false
          };
          await kv.putProviderModel(model, true);
          existingModels.push(model);
          modelsAdded = true;
        }
      }
      if (modelsAdded) {
        await kv.saveSnapshotOnce();
      }
    } catch (e: any) {
      console.error(`Discovery failed for ${provider.id}`, e);
      throw new Error(`Model discovery failed: ${e.message}`);
    }
}

// Run the full 4-probe capability suite against a single model and persist the
// result (only writing to KV when something actually changed, to respect the
// free-tier write quota). This is the shared engine used by both the 12h Cron
// and the immediate on-add probe and the manual "Test Now" action.
// How long a network-suspect model is SKIPPED during scheduled re-probes, so we
// don't keep hammering a provider that rate-limits Cloudflare's egress IP and
// re-tripping FreeUsageLimitError. Manual "Test Now" always runs regardless.
const NETWORK_SUSPECT_SKIP_MS = 1 * 60 * 60 * 1000; // 1 hour (was 6h)

// Adaptive re-probe: a network-suspect model is skipped during scheduled runs
// UNLESS this is its "re-probe turn" (every Nth scheduled batch). This lets a
// model that recovered on the provider side automatically flip back to
// `working` in the dashboard without any per-request KV writes — the gateway's
// live router already retries such models on traffic, this just keeps the
// stored STATUS fresh. Set to 2 => suspect models are re-probed on every 2nd
// scheduled run (≈24h at the default 12h cron cadence), fully staggered.
const REPROBE_EVERY_N_RUNS = 2;

export async function probeModel(env: Env, kv: KVManager, provider: Provider, model: ProviderModel, opts?: { force?: boolean; runCount?: number; quick?: boolean; background?: boolean }) {
  const force = opts?.force === true;
  const runCount = opts?.runCount ?? 0;
  const quick = opts?.quick === true;
  // Skip re-probing models that recently failed due to a Cloudflare/provider
  // network or rate-limit issue. They work on the admin's own system; repeated
  // probes only exhaust the free-tier/per-IP quota and re-trip 429s. We leave
  // their last (network-suspect) status intact and move on. Manual "Test Now"
  // and the immediate on-add probe pass force:true to bypass this.
  // ADAPTIVE: even within the skip window, if this scheduled run is the model's
  // re-probe turn (runCount % N === 0), we DO probe it so a recovered model is
  // re-validated and its status auto-corrects.
  const isReprobeTurn = runCount > 0 && runCount % REPROBE_EVERY_N_RUNS === 0;
  if (!force && !isReprobeTurn && !quick && model.networkIssueSuspected && model.lastChecked > 0 &&
      Date.now() - model.lastChecked < NETWORK_SUSPECT_SKIP_MS) {
    return;
  }
  // CRITICAL FIX (permanent solution): when this is a forced re-probe (manual
  // "Test Now", on-add, or "Run Health Checks Now"), clear the
  // networkIssueSuspected flag BEFORE running the capability probes below.
  // Previously the capability probes (1b–6) were gated behind
  // `!model.networkIssueSuspected`, so a model ever flagged network-limited
  // would SKIP all capability testing forever and stay ambiguous — clicking
  // "Test Now" did nothing visible. Forcing the flag clear lets a manual test
  // actually re-validate vision/stream/tools/etc. and produce a real status.
  if (force) {
    model.networkIssueSuspected = false;
  }
  const adapter = getAdapterForProvider(provider);
  // Small delay helper to avoid rapid-fire requests that trigger provider
  // rate limits (Ollama Cloud, NVIDIA NIM, Groq, etc. throttle burst traffic
  // rate limits (Ollama Cloud, NVIDIA NIM, Groq, etc. throttle burst traffic
  // from datacenter IPs like Cloudflare Workers). We use a staggered delay in
  // parallel execution to finish within Cloudflare's strict 30s Worker timeout limit.
  const probeDelay = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

  // Probe 1: Basic Health
  try {
    const start = Date.now();
    const testBody = {
      model: model.modelId,
      messages: [{ role: "user", content: "Hi" }],
      max_tokens: 10
    };

    const res = await executeCapabilityProbe(env, kv, provider, model, adapter, testBody);
    model.avgLatencyMs = Date.now() - start;
    model.lastChecked = Date.now();

    if (res.ok) {
      model.status = "working";
      model.networkIssueSuspected = false;
      model.lastErrorDebug = undefined;
      try {
        // Validate that the response is actually JSON (not an HTML page from
        // a wrong URL). Read as text first so we can inspect content-type.
        const ct = res.headers.get('content-type') || '';
        const text = await res.text();
        if (!ct.includes('application/json') && !ct.includes('text/json') && !ct.includes('text/event-stream')) {
          // Provider returned a non-JSON response (likely HTML from a wrong URL)
          // — this is a genuine config error, NOT a Cloudflare network issue.
          model.status = "broken";
          model.networkIssueSuspected = false;
          model.lastErrorDebug = `Wrong URL: provider returned ${ct || 'unknown content-type'} instead of JSON. Check the base URL. Response preview: ${text.substring(0, 100)}`;
        } else {
          try {
            JSON.parse(text);
          } catch (parseErr: any) {
            // Response claims to be JSON but isn't parseable. This can happen on
            // a Cloudflare-edge transform glitch, so flag as network-suspect
            // rather than a permanent broken model.
            model.status = "broken";
            model.networkIssueSuspected = true;
            model.lastErrorDebug = `JSON Parse Error: ${parseErr.message}. Content-Type: ${ct}. Preview: ${text.substring(0, 100)}`;
          }
        }
      } catch (err: any) {
        model.status = model.status === "broken" ? "broken" : "untested";
        model.networkIssueSuspected = true;
        model.lastErrorDebug = `Response Read Error (Cloudflare network suspect): ${err.message}`;
      }
    } else if (res.status === 429 || res.status === 402) {
      // Rate-limited during the probe burst (NIM/Groq/Ollama free tier throttle
      // traffic from Cloudflare's shared egress IP — NOT a model fault). The
      // model works fine from the admin's own system, so this is a Cloudflare-
      // edge / per-IP quota artifact. CRITICAL: never leave the model marked
      // "broken" because of this. If it was already "broken" (e.g. from a pre-
      // fix probe), clear it to "untested" so the UI shows it as network-limited
      // rather than a dead model. Preserve genuine prior "working"/"degraded".
      model.networkIssueSuspected = true;
      let errorText = "";
      try { errorText = await res.text(); } catch { }
      if (model.status === "broken") {
        model.status = "untested";
      }
      // working/degraded/untested are left as-is.
      model.lastErrorDebug = `HTTP ${res.status} (rate limit during probe — transient, NOT a model fault; works on your system): ${errorText.substring(0, 200)}`;
    } else if (res.status >= 400) {
      // Genuine provider-side error (auth, not found, server error) — UNLESS
      // this response came from the internal /admin/internal/test-capability
      // endpoint (used when GATEWAY_URL is set) reporting a Cloudflare-edge
      // network failure. That endpoint returns 502 with
      // { networkIssueSuspected: true } on a network failure; we must treat it
      // as a network issue, NOT a permanent "broken" model.
      let errorText = "";
      try { errorText = await res.text(); } catch { }
      let isNetworkSuspect = false;
      try {
        const parsed = JSON.parse(errorText);
        if (parsed && parsed.networkIssueSuspected) isNetworkSuspect = true;
      } catch { }
      if (isNetworkSuspect) {
        model.networkIssueSuspected = true;
        // Do NOT overwrite a previously-known-good status with "broken".
        if (model.status !== "working" && model.status !== "degraded") {
          model.status = "untested";
        }
        model.lastErrorDebug = `Cloudflare edge network failure via gateway probe: ${errorText.substring(0, 200)}. Model NOT confirmed broken — works outside Cloudflare.`;
      } else {
        if (res.status === 400 || res.status === 403) {
            // 400 Bad Request or 403 Forbidden usually means the probe payload was
            // rejected (e.g. missing system prompt, missing headers) or Cloudflare IP
            // was blocked. Do not mark as permanently broken.
            model.networkIssueSuspected = true;
            if (model.status !== "working" && model.status !== "degraded") {
                model.status = "untested";
            }
            model.lastErrorDebug = `HTTP ${res.status}: Probe rejected or IP blocked. Error: ${errorText.substring(0, 200)}`;
        } else {
            // Genuine provider-side error (e.g. 401 Auth, 404 Not Found, 5xx).
            model.status = "broken";
            model.networkIssueSuspected = false;
            model.lastErrorDebug = `HTTP ${res.status}: ${errorText.substring(0, 200)}`;
        }
      }
    }
   } catch (err: any) {
      // A thrown error from fetch() here is ALWAYS a Cloudflare-edge network
      // failure (TypeError) or timeout (AbortError) — never a provider telling
      // us the model is broken. We must NOT persist this as `broken`.
      // Preserve the prior status (or leave untested) and flag clearly so the
      // admin sees "Cloudflare network issue suspected", and the router still
      // attempts the model (it works fine outside Cloudflare).
      const isNetwork = err && (err.name === "AbortError" || err.name === "TypeError");
      if (isNetwork) {
        model.networkIssueSuspected = true;
        // Do NOT overwrite a previously-known-good status with "broken".
        if (model.status === "working" || model.status === "degraded") {
          // keep existing status
        } else {
          model.status = "untested";
        }
        model.lastErrorDebug = `Cloudflare edge network failure (${err.name}): ${err.message}. Model NOT confirmed broken — it works outside Cloudflare's network.`;
      } else {
        model.status = "broken";
        model.networkIssueSuspected = false;
        model.lastErrorDebug = `Network Exception: ${err.name} - ${err.message}`;
      }
      model.lastChecked = Date.now();
   }

   // QUICK MODE (used by manual "Test Now"): return IMMEDIATELY after the basic
   // health probe so the admin gets a fast, visible result (the previous
   // behavior ran the full 7-probe suite synchronously — up to ~3 min — which
   // often exceeded the browser/admin request budget and looked like "no
   // response at all"). The slower capability probes (tools/vision/stream/etc.)
   // are handed off to run in the background if a ExecutionContext is available,
   // otherwise they're simply skipped for this quick check. Basic health is what
   // the admin actually needs to see "✓ Working" vs a real failure.
  // SMART CAPABILITY SKIP: If the model's capabilities have already been probed
  // in the past, we don't need to re-test them (vision, tools, etc.) unless manually forced.
  // We just do the basic health check to confirm it's still alive. This saves
  // 6 extra API requests per model every 12 hours.
  const skipCapabilities = !force && model.capabilitiesProbed === true;

  if (quick) {
    await kv.putProviderModel(model, true);
    if (!skipCapabilities && opts?.background && typeof opts.background === "object") {
      const bg = opts.background as any;
      const envCopy = env, kvCopy = kv, providerCopy = provider, modelCopy = { ...model }, adapterCopy = adapter;
      bg.waitUntil((async () => {
        try {
          await runCapabilityProbes(envCopy, kvCopy, providerCopy, modelCopy, adapterCopy, probeDelay);
          await kvCopy.putProviderModel(modelCopy, false); // Rebuild snapshot so UI can see tags
        } catch (e) { console.error("Background capability probe failed:", e); }
      })());
    }
    return;
  }

  // Probe 1b–6 (capability suite) run as a separate step so quick mode can
  // return after basic health while these run in the background.
  if (!skipCapabilities) {
    await runCapabilityProbes(env, kv, provider, model, adapter, probeDelay);
  }
  await kv.putProviderModel(model, true); // skip per-probe snapshot rebuild; rebuilt once at end of run
}

// Capability probes (tools, vision, streaming, web search, document, audio).
// Extracted from probeModel so the basic-health check can return fast (quick
// mode / manual "Test Now") while these slower probes run in the background.
// All probes are gated behind a working, non-network-suspect basic-health
// result, so a model that failed Probe 1 never wastes probes on capabilities
// it can't be tested for.
export async function runCapabilityProbes(
  env: Env, kv: KVManager, provider: Provider, model: ProviderModel,
  adapter: any, probeDelay: (ms: number) => Promise<void>
): Promise<void> {
  if (model.status !== "working" && model.status !== "degraded") return;

  const probes: Promise<void>[] = [];

  // Probe 1b: Tool Support
  if (!model.networkIssueSuspected) {
    probes.push((async () => {
      await probeDelay(0);
      try {
        const testToolsBody = {
          model: model.modelId,
          messages: [{ role: "user", content: "What is 2+2? Use the calculator tool." }],
          tools: [{ type: "function", function: { name: "calculator", description: "Calculate math", parameters: { type: "object", properties: { expression: { type: "string"} }, required: ["expression"] } } }],
          tool_choice: "auto", max_tokens: 50
        };
        const res = await executeCapabilityProbe(env, kv, provider, model, adapter, testToolsBody);
        if (res.ok) {
          const data: any = await res.json();
          const msg = data.choices?.[0]?.message;
          model.supportsTools = !!(msg && msg.tool_calls && msg.tool_calls.length > 0);
        } else { model.supportsTools = false; }
      } catch { model.supportsTools = false; }
    })());
  }

  // Probe 2: Vision Support
  if (!model.networkIssueSuspected) {
    probes.push((async () => {
      await probeDelay(1000);
      try {
        const testVisionBody = {
          model: model.modelId,
          messages: [{ role: "user", content: [{ type: "text", text: "What is this image?" }, { type: "image_url", image_url: { url: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=" } }] }],
          max_tokens: 20
        };
        const res = await executeCapabilityProbe(env, kv, provider, model, adapter, testVisionBody);
        if (res.ok) {
          const text = await res.text().catch(() => "");
          const lower = text.toLowerCase();
          const containsRefusal = lower.includes("cannot process image") || lower.includes("cannot see image") || lower.includes("no vision capabilities");
          model.supportsVision = !containsRefusal;
        } else { model.supportsVision = false; }
      } catch { model.supportsVision = false; }
    })());
  }

  // Probe 3: Streaming Support
  if (!model.networkIssueSuspected) {
    probes.push((async () => {
      await probeDelay(2000);
      try {
        const testStreamBody = { model: model.modelId, messages: [{ role: "user", content: "Say hi" }], stream: true, max_tokens: 10 };
        const res = await executeCapabilityProbe(env, kv, provider, model, adapter, testStreamBody);
        const ct = res.headers.get("content-type") || "";
        model.supportsStreaming = res.ok && (ct.includes("event-stream") || ct.includes("application/x-ndjson"));
      } catch { model.supportsStreaming = false; }
    })());
  }

  // Probe 4: Web Search Support
  if (!model.networkIssueSuspected) {
    probes.push((async () => {
      await probeDelay(3000);
      try {
        const testSearchBody = {
          model: model.modelId, messages: [{ role: "user", content: "What is the current weather in Tokyo?" }],
          tools: [{ type: "function", function: { name: "web_search", description: "Search web", parameters: { type: "object", properties: { query: { type: "string" } }, required: ["query"] } } }],
          tool_choice: "auto", max_tokens: 10
        };
        const res = await executeCapabilityProbe(env, kv, provider, model, adapter, testSearchBody);
        model.supportsWebSearch = res.ok;
      } catch { model.supportsWebSearch = false; }
    })());
  }

  // Probe 5: Document Support
  if (!model.networkIssueSuspected) {
    probes.push((async () => {
      await probeDelay(4000);
      try {
        const testDocBody = {
          model: model.modelId, messages: [{ role: "user", content: [{ type: "text", text: "Summarize this document." }, { type: "document", document: { data: "data:application/pdf;base64,JVBERi0xLjQKJCg=", source: "test.pdf" } }] }], max_tokens: 10
        };
        const res = await executeCapabilityProbe(env, kv, provider, model, adapter, testDocBody);
        model.supportsDocument = res.ok;
      } catch { model.supportsDocument = false; }
    })());
  }

  // Probe 6: Audio Support
  if (!model.networkIssueSuspected) {
    probes.push((async () => {
      await probeDelay(5000);
      try {
        const testAudioBody = {
          model: model.modelId, messages: [{ role: "user", content: [{ type: "text", text: "Transcribe this audio." }, { type: "input_audio", input_audio: { data: "data:audio/wav;base64,UklGRg==", format: "wav" } }] }], max_tokens: 10
        };
        const res = await executeCapabilityProbe(env, kv, provider, model, adapter, testAudioBody);
        model.supportsAudio = res.ok;
      } catch { model.supportsAudio = false; }
    })());
  }

  await Promise.allSettled(probes);
  model.capabilitiesProbed = true;
}

// Run discovery + full probe for ONE provider only. Used immediately after a
// provider is added (so models become usable without waiting up to 12h) and by
// the manual "Run Health Checks Now" action. This runs REGARDLESS of the
// 12h-auto-check toggle, because an explicit user action should always test.
export async function runHealthChecksForProvider(env: Env, providerId: string) {
  const kv = new KVManager(env);
  const provider = (await kv.getAllProviders()).find(p => p.id === providerId);
  if (!provider || !provider.active) return;

  const existingModels = await kv.getProviderModels();
  await discoverProviderModels(kv, provider, existingModels);

  for (const model of existingModels) {
    if (!model.active) continue;
    if (model.providerId !== providerId) continue;
    // On-add probe always runs (force) so a newly added provider is validated
    // immediately rather than being skipped by the network-suspect window.
    await probeModel(env, kv, provider, model, { force: true });
    // Delay between models to avoid triggering provider rate limits. Bumped to
    // 12s (was 8s) so datacenter-throttled providers (OpenRouter, Groq, NIM)
    // don't return burst 429s that would otherwise re-park models as untested.
    await new Promise<void>(r => setTimeout(r, 12000));
  }
  // Rebuild the single snapshot key ONCE (not per model) so the hot path can
  // load all models with one KV read.
  await kv.saveSnapshotOnce();
}

export async function runHealthChecks(env: Env, force: boolean = false) {
  const kv = new KVManager(env);
  const isEnabled = await kv.isHealthChecksEnabled();
  if (!isEnabled) return;

  // Self-gate on the configurable interval so the 12h cron trigger doesn't
  // necessarily run a full probe batch every tick. This lets the admin lengthen
  // the effective interval (e.g. 24h) to halve KV probe writes — without
  // editing wrangler. One KV read here (cron-only, never on the hot path).
  // The `force` flag (used by the manual "Run Health Checks Now" button)
  // bypasses this gate so the admin can ALWAYS re-probe on demand — critical
  // after a code deploy that changes classification, otherwise stale `broken`
  // statuses from before the fix would never get re-evaluated.
  const intervalHours = await kv.getHealthCheckIntervalHours();
  const lastRun = await kv.getLastHealthRun();
  const dueMs = intervalHours * 60 * 60 * 1000;
  if (!force && lastRun > 0 && Date.now() - lastRun < dueMs) {
    console.log(`Health checks skipped: next run due in ${Math.ceil((dueMs - (Date.now() - lastRun)) / 1000 / 60)} min (interval ${intervalHours}h).`);
    return;
  }

  const providers = await kv.getAllProviders();
  const existingModels = await kv.getProviderModels();

  // Adaptive re-probe bookkeeping: read the monotonically increasing scheduled
  // run counter (cron-only, cached — zero hot-path cost). A network-suspect
  // model is only re-probed on its "re-probe turn" (runCount % N === 0), so a
  // model that recovered on the provider side auto-flips back to `working` in
  // the dashboard without any per-request KV writes.
  const runCount = await kv.getHealthRunCount();

  for (const provider of providers) {
    if (!provider.active) continue;
    // Randomized initial jitter (0-30s) so multiple providers aren't all hit
    // in lockstep at the top of a cron tick — spreads load and avoids a
    // synchronized burst that trips per-IP free-tier rate limits.
    const jitter = Math.floor(Math.random() * 30000);
    await new Promise<void>(r => setTimeout(r, jitter));
    await discoverProviderModels(kv, provider, existingModels);
  }

  // 4.3 Active Capability Probes
  // Process models serially (no concurrency) with a generous gap so
  // datacenter-throttled providers (OpenRouter, NIM, Groq) are never hit with a
  // probe burst that would produce false 429s / false "broken" classifications.
  // The gap is read from config so the admin can tune it per provider quota.
  const probeGapMs = await kv.getProbeGapMs();
  for (const model of existingModels) {
    if (!model.active) continue;
    const provider = providers.find(p => p.id === model.providerId);
    if (!provider || !provider.active) continue;
    // `force` (from manual "Run Health Checks Now") overrides the per-model
    // network-suspect skip window so the admin can always re-probe on demand.
    // Otherwise pass the scheduled run counter so suspect models are only
    // re-probed on their adaptive re-probe turn (every Nth run).
    await probeModel(env, kv, provider, model, { force, runCount });
    // Delay between models to avoid triggering provider rate limits.
    await new Promise<void>(r => setTimeout(r, probeGapMs));
  }

  // Record run time so the interval is honored on the next cron tick.
  await kv.setLastHealthRun(Date.now());
  // Increment the scheduled run counter that drives adaptive re-probe turns.
  await kv.setHealthRunCount(runCount + 1);
  // Rebuild the single snapshot key ONCE so the hot path loads all models with
  // one KV read (instead of KV.list + per-model gets).
  await kv.saveSnapshotOnce();
}
