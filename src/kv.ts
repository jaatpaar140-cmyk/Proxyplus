import { Env, Provider, ProviderModel, VirtualKey, TrafficLog } from "./types";

// ---------------------------------------------------------------------------
// Per-isolate in-memory cache for the (rarely-changing) provider / model /
// virtual-key lists.
//
// WHY: previously every chat request called getAllProviders() + getProviderModels()
// which each did a paginated KV.list PLUS one KV.get per item. With N models that
// is ~2 list + (providers+models) get operations PER REQUEST. On Cloudflare's
// free tier (100K KV reads/day) that exhausts the quota in under a minute under
// real traffic and the gateway starts throttling — the exact "KV reads eat my
// limit" problem.
//
// FIX: cache these lists in memory for a short TTL (per Worker isolate). Admin
// writes invalidate the relevant cache immediately, so changes show up at once
// and we still cut KV reads by ~99% under load. One get per virtual key is still
// done per request (cheap, single key) but can also be cached.
// ---------------------------------------------------------------------------
const CACHE_TTL_MS = 60 * 1000; // 60s — fresh enough, safe for KV quota.

let providerCacheData: Provider[] | null = null;
let providerCacheExpires = 0;

let modelCacheData: ProviderModel[] | null = null;
let modelCacheExpires = 0;

const vkCache = new Map<string, { value: VirtualKey | null; expires: number }>();

// In-memory caches for per-request hot-path reads that otherwise hit KV on
// EVERY chat request (wasting the free-tier read quota). These change rarely,
// so a 60s TTL is safe and cuts the per-request KV cost to ~0 when warm.
const stickyEnabledCache: { value: boolean; expires: number } = { value: true, expires: 0 };
const stickyModelCache = new Map<string, { value: string | null; expires: number }>();

// Traffic-logging toggle is checked on the hot path of EVERY chat request.
// Without caching it forces one KV read per request — pure free-tier waste
// when logging is off (the default). Mirror the other config flags with a
// TTL cache so the per-request cost is zero when warm.
const trafficLoggingCache: { value: boolean; expires: number } = { value: false, expires: 0 };

// Health-check interval (hours) controls how often the 12h cron is allowed to
// actually run its probe batch. Cached so reading it never costs a KV read on
// the hot path (it's only consulted by the Cron handler).
const healthIntervalCache: { value: number; expires: number } = { value: 12, expires: 0 };

// Traffic-log TTL (retention). Read on the hot path only when logging is
// enabled; cached so a warm isolate costs zero KV reads per request.
const trafficTtlCache: { value: number; expires: number } = { value: 604800, expires: 0 };

function cacheValid(expires: number): boolean {
  return expires > Date.now();
}

// ---------------------------------------------------------------------------
// Single-key snapshot of all providers + models.
//
// WHY: the hot chat path used to do `KV.list` + one `KV.get` PER model (~204 KV
// reads on a cold isolate with 200 models). That is the ONE remaining KV cost
// on the request path and it can blow past the free-tier read quota on a busy
// gateway. Instead we keep a single `snapshot:all` key holding the full list,
// written by the admin whenever providers/models change. The hot path reads
// ONE key; if the snapshot is missing we fall back to the list+get method and
// rebuild it. This takes the cold-start cost from ~204 reads to ~1.
// ---------------------------------------------------------------------------
const SNAPSHOT_KEY = "snapshot:all";

function invalidateLists(): void {
  providerCacheExpires = 0;
  modelCacheExpires = 0;
  stickyEnabledCache.expires = 0;
}

export const activeSockets = new Set<WebSocket>();
export const globalRecentLogs: TrafficLog[] = [];

export function broadcastLog(log: TrafficLog) {
  const msg = JSON.stringify(log);
  for (const ws of activeSockets) {
    try {
      ws.send(msg);
    } catch (e) {
      activeSockets.delete(ws);
    }
  }
}

export class KVManager {

  constructor(private env: Env) {}

  async getVirtualKey(key: string): Promise<VirtualKey | null> {
    const cached = vkCache.get(key);
    if (cached && cacheValid(cached.expires)) return cached.value;
    const data = await this.env.KV.get(`virtual_key:${key}`);
    const parsed = data ? JSON.parse(data) : null;
    vkCache.set(key, { value: parsed, expires: Date.now() + CACHE_TTL_MS });
    return parsed;
  }

  async putVirtualKey(vk: VirtualKey): Promise<void> {
    await this.env.KV.put(`virtual_key:${vk.key}`, JSON.stringify(vk));
    vkCache.delete(vk.key);
  }

  async deleteVirtualKey(key: string): Promise<void> {
    await this.env.KV.delete(`virtual_key:${key}`);
    vkCache.delete(key);
  }

  // Paginated KV key listing. KV.list() returns at most 1000 keys and may set
  // list_complete=false; without cursor iteration, models/keys beyond the first
  // page are silently dropped (latent correctness bug). This helper walks all
  // pages. Read-only — no extra KV writes, safe for the free-tier quota.
  private async listAllKeys(prefix: string): Promise<string[]> {
    const keys: string[] = [];
    let cursor: string | undefined;
    do {
      const opts: any = { prefix };
      if (cursor) opts.cursor = cursor;
      const list = await this.env.KV.list(opts);
      for (const k of list.keys) keys.push(k.name);
      cursor = list.list_complete ? undefined : list.cursor;
    } while (cursor);
    return keys;
  }

  async getAllVirtualKeys(): Promise<VirtualKey[]> {
    const keys = await this.listAllKeys("virtual_key:");
    const vks: VirtualKey[] = [];
    for (const name of keys) {
      const data = await this.env.KV.get(name);
      if (data) vks.push(JSON.parse(data));
    }
    return vks;
  }

  async getAllProviders(): Promise<Provider[]> {
    if (providerCacheData && cacheValid(providerCacheExpires)) return providerCacheData;
    // Fast path: load the whole list from a single snapshot key instead of
    // KV.list + one get per provider. Falls back to the list method if missing.
    const snapped = await this.tryLoadSnapshot();
    if (snapped) {
      providerCacheData = snapped.providers;
      modelCacheData = snapped.models;
      providerCacheExpires = Date.now() + CACHE_TTL_MS;
      modelCacheExpires = Date.now() + CACHE_TTL_MS;
      return providerCacheData;
    }
    const keys = await this.listAllKeys("provider:");
    const providers: Provider[] = [];
    for (const name of keys) {
      if (name.startsWith("provider_model:")) continue;
      const data = await this.env.KV.get(name);
      if (data) providers.push(JSON.parse(data));
    }
    providerCacheData = providers;
    providerCacheExpires = Date.now() + CACHE_TTL_MS;
    // Snapshot was missing — build it now (best-effort) so the NEXT cold load
    // on this or another isolate is a single KV read instead of ~204.
    await this.saveSnapshot();
    return providers;
  }

  async putProvider(provider: Provider): Promise<void> {
    await this.env.KV.put(`provider:${provider.id}`, JSON.stringify(provider));
    invalidateLists();
    await this.saveSnapshot();
  }

  async deleteProvider(id: string): Promise<void> {
    await this.env.KV.delete(`provider:${id}`);
    // Also delete associated models
    const models = await this.getProviderModels(id);
    for (const m of models) {
      await this.env.KV.delete(`provider_model:${id}:${m.modelId}`);
    }
    invalidateLists();
    await this.saveSnapshot();
  }

  async getProviderModels(providerId?: string): Promise<ProviderModel[]> {
    if (!providerId && modelCacheData && cacheValid(modelCacheExpires)) return modelCacheData;
    // Fast path via snapshot (only when loading the full, un-filtered list).
    if (!providerId) {
      const snapped = await this.tryLoadSnapshot();
      if (snapped) {
        modelCacheData = snapped.models;
        modelCacheExpires = Date.now() + CACHE_TTL_MS;
        return modelCacheData;
      }
    }
    const prefix = providerId ? `provider_model:${providerId}:` : "provider_model:";
    const keys = await this.listAllKeys(prefix);
    const models: ProviderModel[] = [];
    for (const name of keys) {
      const data = await this.env.KV.get(name);
      if (data) models.push(JSON.parse(data));
    }
    if (!providerId) {
      modelCacheData = models;
      modelCacheExpires = Date.now() + CACHE_TTL_MS;
    }
    return models;
  }

  // Read the single snapshot key. Returns {providers, models} or null if absent
  // or unparseable. One KV read instead of ~204.
  private async tryLoadSnapshot(): Promise<{ providers: Provider[]; models: ProviderModel[] } | null> {
    try {
      const raw = await this.env.KV.get(SNAPSHOT_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed.providers) || !Array.isArray(parsed.models)) return null;
      return { providers: parsed.providers, models: parsed.models };
    } catch {
      return null;
    }
  }

  // Rebuild + write the snapshot from current KV state. Best-effort: a failure
  // here must never break the admin write that triggered it.
  private async saveSnapshot(): Promise<void> {
   try {
      const providers = await this.listAllKeys("provider:");
      const provList: Provider[] = [];
      for (const name of providers) {
        if (name.startsWith("provider_model:")) continue;
        const data = await this.env.KV.get(name);
        if (data) provList.push(JSON.parse(data));
      }
      const modelKeys = await this.listAllKeys("provider_model:");
      const modelList: ProviderModel[] = [];
      const chunkSize = 20;
      for (let i = 0; i < modelKeys.length; i += chunkSize) {
        const chunk = modelKeys.slice(i, i + chunkSize);
        const dataVals = await Promise.all(chunk.map(k => this.env.KV.get(k)));
        for (const data of dataVals) {
          if (data) modelList.push(JSON.parse(data));
        }
      }
      await this.env.KV.put(SNAPSHOT_KEY, JSON.stringify({ providers: provList, models: modelList, ts: Date.now() }));
    } catch (e) {
      console.error("saveSnapshot failed:", e);
    }
  }

  // Public wrapper so bulk writers (cron) can rebuild the snapshot exactly once
  // after a batch of model writes, instead of on every individual write.
  async saveSnapshotOnce(): Promise<void> {
    await this.saveSnapshot();
  }

  async putProviderModel(model: ProviderModel, skipSnapshot = false): Promise<void> {
    await this.env.KV.put(`provider_model:${model.providerId}:${model.modelId}`, JSON.stringify(model));
    invalidateLists();
    // The cron probe batch writes every model many times; rebuilding the
    // snapshot on each write would be hugely wasteful. Callers doing bulk
    // writes (cron) pass skipSnapshot=true and rebuild once at the end.
    if (!skipSnapshot) await this.saveSnapshot();
  }

  async logTraffic(log: TrafficLog, ctx?: ExecutionContext): Promise<void> {
    broadcastLog(log);
    // IN-MEMORY RECENT LOGS (Zero KV Writes consumed)
    globalRecentLogs.unshift(log);
    while (globalRecentLogs.length > 50) globalRecentLogs.pop();

    try {
      const enabled = await this.isTrafficLoggingEnabled();
      if (!enabled) return;

      const ttl = await this.getTrafficTtl();
      ctx?.waitUntil(this.env.KV.put(`traffic_log:${log.timestamp}:${log.virtualKey}`, JSON.stringify(log), { expirationTtl: ttl }));
    } catch (e) {
      console.error("Failed to log traffic:", e);
    }
  }

  async getRecentTraffic(): Promise<TrafficLog[]> {
    // Return in-memory logs (Zero KV Reads consumed)
    return globalRecentLogs;
  }

  async getTrafficLogs(limit: number = 500): Promise<TrafficLog[]> {
    // Keys are written as `traffic_log:${ts}:${id}`, so KV.list returns them
    // in ascending (oldest-first) order. A busy gateway can accumulate huge
    // numbers of logs; fetching ALL of them with Promise.all is a memory and
    // latency bomb. Instead we walk pages and STOP once we have `limit` of the
    // newest entries (we read the tail of the listing, which is the newest).
    const desired = Math.max(1, Math.min(limit, 5000));
    const keys: string[] = [];
    let cursor: string | undefined;
    do {
      const opts: any = { prefix: "traffic_log:", limit: 1000 };
      if (cursor) opts.cursor = cursor;
      const list = await this.env.KV.list(opts);
      // Prepend so that `keys` ends up oldest -> newest across pages.
      keys.unshift(...list.keys.map(k => k.name));
      cursor = list.list_complete ? undefined : list.cursor;
      // Once we have more than enough newest keys, we can stop paging — the
      // remaining older pages are irrelevant for the dashboard.
      if (keys.length >= desired) break;
    } while (cursor);

    // Keep only the newest `desired` keys.
    const newestKeys = keys.slice(-desired);

    const fetchPromises = newestKeys.map(key => this.env.KV.get(key));
    const dataList = await Promise.all(fetchPromises);

    const logs: TrafficLog[] = [];
    for (const data of dataList) {
      if (data) {
        try {
          const parsed = JSON.parse(data);
          if (Array.isArray(parsed)) {
            logs.push(...parsed);
          } else {
            logs.push(parsed);
          }
        } catch (e) {
          console.error("Failed to parse traffic log entry:", e);
        }
      }
    }
    // Sort by timestamp descending (newest first)
    logs.sort((a, b) => b.timestamp - a.timestamp);
    return logs;
  }

  async getAdminAuth(): Promise<{ hash: string; secret: string } | null> {
    try {
      const data = await this.env.KV.get("config:admin_auth");
      return data ? JSON.parse(data) : null;
    } catch (e) {
      console.error("KV Read Error:", e);
      return null;
    }
  }

  async setAdminAuth(hash: string, secret: string): Promise<void> {
    await this.env.KV.put("config:admin_auth", JSON.stringify({ hash, secret }));
  }

  async getTrafficTtl(): Promise<number> {
    if (cacheValid(trafficTtlCache.expires)) return trafficTtlCache.value;
    const data = await this.env.KV.get("config:traffic_ttl");
    const ttl = data ? parseInt(data, 10) : 604800;
    trafficTtlCache.value = ttl;
    trafficTtlCache.expires = Date.now() + CACHE_TTL_MS;
    return ttl;
  }

  async setTrafficTtl(ttlSeconds: number): Promise<void> {
    await this.env.KV.put("config:traffic_ttl", ttlSeconds.toString());
    // Write-through so the next request in this isolate is free + consistent.
    trafficTtlCache.value = ttlSeconds;
    trafficTtlCache.expires = Date.now() + CACHE_TTL_MS;
  }

  async clearAllTrafficLogs(): Promise<void> {
    let list = await this.env.KV.list({ prefix: "traffic_log:" });
    while (true) {
      const keys = list.keys.map(k => k.name);
      for (let i = 0; i < keys.length; i += 50) {
        const batch = keys.slice(i, i + 50);
        await Promise.all(batch.map(k => this.env.KV.delete(k)));
      }
      if (list.list_complete) break;
      list = await this.env.KV.list({ prefix: "traffic_log:", cursor: list.cursor });
    }
  }

  async isTrafficLoggingEnabled(): Promise<boolean> {
    if (cacheValid(trafficLoggingCache.expires)) return trafficLoggingCache.value;
    const data = await this.env.KV.get("config:traffic_logging_enabled");
    // Default to FALSE to protect the Cloudflare KV free-tier write quota:
    // every chat request would otherwise write a traffic_log entry to KV.
    // Admin can enable it from the dashboard Settings tab when needed.
    const enabled = data === null ? false : data === "true";
    trafficLoggingCache.value = enabled;
    trafficLoggingCache.expires = Date.now() + CACHE_TTL_MS;
    return enabled;
  }

  async setTrafficLoggingEnabled(enabled: boolean): Promise<void> {
    await this.env.KV.put("config:traffic_logging_enabled", enabled ? "true" : "false");
    // Write-through so the next request in this isolate is free + consistent.
    trafficLoggingCache.value = enabled;
    trafficLoggingCache.expires = Date.now() + CACHE_TTL_MS;
  }

  async getStickyModel(key: string): Promise<string | null> {
    const cached = stickyModelCache.get(key);
    if (cached && cacheValid(cached.expires)) return cached.value;
    const data = await this.env.KV.get(key);
    stickyModelCache.set(key, { value: data, expires: Date.now() + CACHE_TTL_MS });
    return data;
  }

  async putStickyModel(key: string, modelId: string): Promise<void> {
    await this.env.KV.put(key, modelId, { expirationTtl: 86400 });
    // Write through to cache so the next read in this isolate is free.
    stickyModelCache.set(key, { value: modelId, expires: Date.now() + CACHE_TTL_MS });
  }

  async isStickyModelsEnabled(): Promise<boolean> {
    if (cacheValid(stickyEnabledCache.expires)) return stickyEnabledCache.value;
    const data = await this.env.KV.get("config:sticky_models_enabled");
    const enabled = data === null ? true : data === "true"; // default to true
    stickyEnabledCache.value = enabled;
    stickyEnabledCache.expires = Date.now() + CACHE_TTL_MS;
    return enabled;
  }

  async setStickyModelsEnabled(enabled: boolean): Promise<void> {
    await this.env.KV.put("config:sticky_models_enabled", enabled ? "true" : "false");
    stickyEnabledCache.value = enabled;
    stickyEnabledCache.expires = Date.now() + CACHE_TTL_MS;
  }

  async isHealthChecksEnabled(): Promise<boolean> {
    const data = await this.env.KV.get("config:health_checks_enabled");
    return data === null ? true : data === "true"; // default to true
  }

  async setHealthChecksEnabled(enabled: boolean): Promise<void> {
    await this.env.KV.put("config:health_checks_enabled", enabled ? "true" : "false");
  }

  // How many hours must pass between automatic health-check batches. The cron
  // trigger still fires every 12h, but runHealthChecks() self-gates on this so
  // you can lengthen the interval (e.g. 24h) to halve KV probe writes without
  // touching wrangler. Default 12h. Cached — zero hot-path KV cost.
  async getHealthCheckIntervalHours(): Promise<number> {
    if (cacheValid(healthIntervalCache.expires)) return healthIntervalCache.value;
    const data = await this.env.KV.get("config:health_check_interval");
    const hours = data ? parseInt(data, 10) : 12;
    const clamped = Number.isFinite(hours) && hours >= 1 ? hours : 12;
    healthIntervalCache.value = clamped;
    healthIntervalCache.expires = Date.now() + CACHE_TTL_MS;
    return clamped;
  }

  async setHealthCheckIntervalHours(hours: number): Promise<void> {
    const clamped = Number.isFinite(hours) && hours >= 1 ? Math.floor(hours) : 12;
    await this.env.KV.put("config:health_check_interval", clamped.toString());
    healthIntervalCache.value = clamped;
    healthIntervalCache.expires = Date.now() + CACHE_TTL_MS;
  }

  // Timestamp (ms) of the last successful health-check batch. Used to honor the
  // configurable interval without running every cron tick. One KV write per
  // batch — not on the hot path.
  async getLastHealthRun(): Promise<number> {
    const data = await this.env.KV.get("config:last_health_run");
    return data ? parseInt(data, 10) : 0;
  }

  async setLastHealthRun(ts: number): Promise<void> {
    await this.env.KV.put("config:last_health_run", ts.toString());
  }

  // Maximum number of models to KEEP from a provider's /models discovery list.
  // Providers like OpenRouter expose hundreds of models. We used to cap this at
  // 50 to avoid 429 bursts, but the new probe-retry (fetchWithProbeRetry,
  // re-routed egress + backoff) handles rate limits gracefully, so we now keep
  // ALL discovered models by default (cap 1000). The cap is still configurable
  // for admins who want to limit the probe batch size. Cached (zero hot-path
  // cost).
  async getMaxDiscoveredModels(): Promise<number> {
    if (cacheValid(maxDiscoveredCache.expires)) return maxDiscoveredCache.value;
    const data = await this.env.KV.get("config:max_discovered_models");
    const n = data ? parseInt(data, 10) : 1000;
    const clamped = Number.isFinite(n) && n >= 1 ? n : 1000;
    maxDiscoveredCache.value = clamped;
    maxDiscoveredCache.expires = Date.now() + CACHE_TTL_MS;
    return clamped;
  }

  async setMaxDiscoveredModels(n: number): Promise<void> {
    const clamped = Number.isFinite(n) && n >= 1 ? Math.floor(n) : 1000;
    await this.env.KV.put("config:max_discovered_models", clamped.toString());
    maxDiscoveredCache.value = clamped;
    maxDiscoveredCache.expires = Date.now() + CACHE_TTL_MS;
  }

  // Gap (ms) between consecutive model probes during a health-check batch. A
  // larger gap avoids bursting the provider's per-IP rate limit (which is what
  // produced the mass 429 -> `untested` problem). Default 12000ms. Cached.
  async getProbeGapMs(): Promise<number> {
    if (cacheValid(probeGapCache.expires)) return probeGapCache.value;
    const data = await this.env.KV.get("config:probe_gap_ms");
    const n = data ? parseInt(data, 10) : 12000;
    const clamped = Number.isFinite(n) && n >= 1000 ? n : 12000;
    probeGapCache.value = clamped;
    probeGapCache.expires = Date.now() + CACHE_TTL_MS;
    return clamped;
  }

  async setProbeGapMs(ms: number): Promise<void> {
    const clamped = Number.isFinite(ms) && ms >= 1000 ? Math.floor(ms) : 12000;
    await this.env.KV.put("config:probe_gap_ms", clamped.toString());
    probeGapCache.value = clamped;
    probeGapCache.expires = Date.now() + CACHE_TTL_MS;
  }

  // Monotonically increasing counter of scheduled health-check batches. Drives
  // the adaptive re-probe turn for network-suspect models (every Nth run) so a
  // recovered model auto-flips back to `working` without per-request KV writes.
  // One KV read per batch (cron-only, cached). Default 0.
  async getHealthRunCount(): Promise<number> {
    if (cacheValid(healthRunCountCache.expires)) return healthRunCountCache.value;
    const data = await this.env.KV.get("config:health_run_count");
    const n = data ? parseInt(data, 10) : 0;
    const clamped = Number.isFinite(n) && n >= 0 ? n : 0;
    healthRunCountCache.value = clamped;
    healthRunCountCache.expires = Date.now() + CACHE_TTL_MS;
    return clamped;
  }

  async setHealthRunCount(n: number): Promise<void> {
    const clamped = Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0;
    await this.env.KV.put("config:health_run_count", clamped.toString());
    healthRunCountCache.value = clamped;
    healthRunCountCache.expires = Date.now() + CACHE_TTL_MS;
  }
}

const maxDiscoveredCache: { value: number; expires: number } = { value: 1000, expires: 0 };
const probeGapCache: { value: number; expires: number } = { value: 12000, expires: 0 };
const healthRunCountCache: { value: number; expires: number } = { value: 0, expires: 0 };
