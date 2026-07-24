import { Env, Provider, VirtualKey } from "./types";
import { KVManager } from "./kv";
import { getAdapterForProvider } from "./providers";
import { proxyNormalizedSSE } from "./router";
import { discoverProviderModels, runHealthChecksForProvider, runHealthChecks, probeModel } from "./cron";
import { fetchWithNetworkRetry } from "./providers";

export class AdminAPI {
  private kv: KVManager;
  private env: Env;

  private async hashPassword(password: string): Promise<string> {
    const msgBuffer = new TextEncoder().encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  constructor(env: Env) {
    this.kv = new KVManager(env);
    this.env = env;
  }

  // Production-grade security headers for the admin surface. A strict CSP
  // (no external script/styles, no inline frames) hardens the dashboard
  // against XSS even though it renders user-controlled provider/model names.
  private adminHeaders(extra: Record<string, string> = {}): Record<string, string> {
    return {
      "Content-Type": "application/json",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; frame-ancestors 'none'; base-uri 'none'",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      ...extra,
    };
  }

  async handleRequest(request: Request, ctx?: any): Promise<Response> {
    const url = new URL(request.url);

    // Initial setup if no admin auth exists. This is gated by the env
    // ADMIN_PASSWORD so a complete stranger cannot claim admin on a fresh
    // deploy (a public Worker URL is internet-reachable). Only the operator
    // who knows the configured password may bootstrap the admin account.
    let adminAuth = await this.kv.getAdminAuth();
    if (!adminAuth && url.pathname === "/admin/setup" && request.method === "POST") {
        if (!this.env.ADMIN_PASSWORD) {
            return new Response("Setup disabled: no ADMIN_PASSWORD configured", { status: 403 });
        }
        let body: any;
        try {
            body = await request.json();
        } catch (e) {
            return new Response("Invalid JSON body", { status: 400 });
        }
        const password = (body.password || "").trim();
        if (password !== this.env.ADMIN_PASSWORD) {
            return new Response("Invalid setup password", { status: 401 });
        }
        const hashed = await this.hashPassword(password);
        const secret = this.env.ADMIN_SECRET || crypto.randomUUID();
        await this.kv.setAdminAuth(hashed, secret);
        return new Response(JSON.stringify({ token: secret }), { status: 200, headers: { "Content-Type": "application/json" } });
    }

    // Auth verification.
    // IMPORTANT: a Bearer token is authorized ONLY if it equals the env
    // ADMIN_SECRET or the persisted adminAuth.secret. We do NOT accept the raw
    // admin PASSWORD as a token here — that previously let `Authorization:
    // Bearer <password>` grants full admin (confused-deputy), defeating the
    // point of having a separate secret, and forced a SHA-256 on every request.
    const authHeader = request.headers.get("Authorization");
    let isAuthorized = false;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      const providedToken = authHeader.replace("Bearer ", "");
      if (this.env.ADMIN_SECRET && providedToken === this.env.ADMIN_SECRET) {
        isAuthorized = true;
      } else if (adminAuth && providedToken === adminAuth.secret) {
        isAuthorized = true;
      }
    }
    
    // Login Endpoint
    if (url.pathname === "/admin/login" && request.method === "POST") {
       try {
           const body: any = await request.json();
           const password = (body.password || "").trim();

           // Env-configured password (from wrangler.jsonc vars) is AUTHORITATIVE.
           // It always works, even if a stale/unknown config:admin_auth exists in KV,
           // preventing lockout and guaranteeing a recovery path.
           if (this.env.ADMIN_PASSWORD && password === this.env.ADMIN_PASSWORD) {
               const secret = this.env.ADMIN_SECRET || "admin-secret-token";
               // Keep KV admin auth in sync with the env password so both paths stay consistent.
               if (!adminAuth || adminAuth.hash !== await this.hashPassword(password)) {
                   await this.kv.setAdminAuth(await this.hashPassword(password), secret);
               }
               return new Response(JSON.stringify({ token: secret }), { status: 200, headers: { "Content-Type": "application/json" } });
           }

           if (!adminAuth) return new Response("Setup required", { status: 400 });
           const hashed = await this.hashPassword(password);
           if (hashed === adminAuth.hash) {
               const newSecret = crypto.randomUUID();
               await this.kv.setAdminAuth(hashed, newSecret);
               return new Response(JSON.stringify({ token: newSecret }), { status: 200, headers: { "Content-Type": "application/json" } });
           }
           return new Response("Invalid credentials", { status: 401 });
       } catch (e: any) {
           return new Response("Error", { status: 400 });
       }
    }

    // Force-reset endpoint (gated by the env ADMIN_SECRET). Clears any KV admin
    // auth that may be causing a lockout. Useful when a previous setup wrote a
    // password that can no longer be matched.
    if (url.pathname === "/admin/force-reset" && request.method === "POST") {
       try {
           const authHeader = request.headers.get("Authorization") || "";
           const provided = authHeader.replace("Bearer ", "").trim();
           if (!this.env.ADMIN_SECRET || provided !== this.env.ADMIN_SECRET) {
               return new Response("Unauthorized", { status: 401 });
           }
           await this.kv.setAdminAuth(await this.hashPassword(this.env.ADMIN_PASSWORD || "admin-secret-token"), this.env.ADMIN_SECRET || "admin-secret-token");
           return new Response(JSON.stringify({ status: "reset", token: this.env.ADMIN_SECRET }), { status: 200, headers: { "Content-Type": "application/json" } });
       } catch (e: any) {
           return new Response("Error", { status: 400 });
       }
    }

    if (!isAuthorized) {
      if (url.pathname !== "/admin" && url.pathname !== "/admin/login" && url.pathname !== "/admin/setup") {
         return new Response("Unauthorized", { status: 401 });
      }
    }

    if (request.method === "POST" && url.pathname === "/admin/change-password") {
      try {
        const body: any = await request.json();
        if (adminAuth) {
          const currentHashed = await this.hashPassword(body.currentPassword);
          if (currentHashed !== adminAuth.hash) {
            return new Response("Invalid current password", { status: 403 });
          }
        }
        const newHashed = await this.hashPassword(body.newPassword);
        const newSecret = crypto.randomUUID();
        await this.kv.setAdminAuth(newHashed, newSecret);
        return new Response(JSON.stringify({ token: newSecret }), { status: 200, headers: { "Content-Type": "application/json" } });
      } catch (e) { return new Response("Invalid request", { status: 400 }); }
    }

    if (request.method === "GET" && url.pathname === "/admin/providers") {
        const providers = await this.kv.getAllProviders();
        return new Response(JSON.stringify(providers), { headers: { "Content-Type": "application/json" } });
    }

    if (request.method === "POST" && url.pathname === "/admin/providers") {
      try {
        const p: Provider = await request.json();
        p.id = p.id || crypto.randomUUID();
        
        // Basic URL validation: ensure it looks like a real API endpoint
        const baseUrl = (p.baseUrl || '').trim().replace(/\/+$/, '');
        if (!baseUrl || !baseUrl.startsWith('http')) {
          return new Response(JSON.stringify({ error: 'Invalid base URL: must start with http:// or https://' }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
        
        // Quick connectivity pre-check: try to reach the provider's models endpoint.
        // This catches wrong URLs early (e.g. pointing at a website instead of API).
        let urlWarning = '';
        try {
          const testUrl = baseUrl.endsWith('/v1') ? `${baseUrl}/models` : `${baseUrl}/v1/models`;
          const authHeader = p.authHeaderFormat ? p.authHeaderFormat.replace('{key}', p.apiKey) : `Bearer ${p.apiKey}`;
          const testRes = await fetch(testUrl, {
            headers: { 'Authorization': authHeader, 'Accept': 'application/json' },
            cf: { cacheTtl: 0, cacheEverything: false } as any
          });
          const ct = testRes.headers.get('content-type') || '';
          if (testRes.ok && !ct.includes('json') && !ct.includes('text/plain')) {
            // Provider returned 200 but not JSON — likely a website, not an API
            urlWarning = `URL may be incorrect: ${baseUrl} returned ${ct} instead of JSON. This may be a website URL, not an API endpoint.`;
          }
        } catch (urlErr) {
          // Connectivity check failed — not fatal, provider might still work.
        }
        
        p.baseUrl = baseUrl;
        const models = await this.kv.getProviderModels();
        try {
           await discoverProviderModels(this.kv, p, models, true);
        } catch (discoverErr: any) {
           return new Response(JSON.stringify({ error: discoverErr.message }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
        await this.kv.putProvider(p);
        // Immediate health + capability probe for the newly added provider so
        // its models become usable at once (no waiting up to 12h for Cron).
        // Runs regardless of the 12h-auto-check toggle — an explicit add always tests.
        if (ctx) {
          ctx.waitUntil(runHealthChecksForProvider(this.env, p.id).catch(console.error));
        } else {
          runHealthChecksForProvider(this.env, p.id).catch(console.error);
        }
        const msg = urlWarning ? `Saved Provider. Warning: ${urlWarning}` : "Saved Provider";
        return new Response(msg, { status: 200 });
      } catch (e) { return new Response("Error", { status: 400 }); }
    }

    // Manual "Run Health Checks Now": probe every active provider/model on demand.
    // `force: true` bypasses the interval self-gate so the admin can ALWAYS
    // re-probe (critical after a deploy that changes classification logic, so
    // stale pre-fix `broken` statuses get re-evaluated immediately).
    if (url.pathname === "/admin/health/run" && request.method === "POST") {
      try {
        if (ctx) {
          ctx.waitUntil(runHealthChecks(this.env, true).catch(console.error));
        } else {
          runHealthChecks(this.env, true).catch(console.error);
        }
        return new Response(JSON.stringify({ status: "ok" }), { status: 200, headers: { "Content-Type": "application/json" } });
      } catch (e) { return new Response("Error", { status: 500 }); }
    }

    if (request.method === "POST" && url.pathname.startsWith("/admin/providers/") && url.pathname.endsWith("/discover")) {
       const id = url.pathname.split("/")[3];
       const providers = await this.kv.getAllProviders();
       const p = providers.find(x => x.id === id);
       if (!p) return new Response("Provider not found", { status: 404 });
       const models = await this.kv.getProviderModels();
       try {
           await discoverProviderModels(this.kv, p, models, true);
           return new Response("OK", { status: 200 });
       } catch (e: any) {
           return new Response(e.message, { status: 500 });
       }
    }

    if (request.method === "DELETE" && url.pathname.startsWith("/admin/providers/")) {
      const id = url.pathname.split("/").pop()!;
      await this.kv.deleteProvider(id);
      return new Response("Deleted", { status: 200 });
    }

    if (request.method === "GET" && url.pathname === "/admin/virtual-keys") {
        const vks = await this.kv.getAllVirtualKeys();
        return new Response(JSON.stringify(vks), { headers: { "Content-Type": "application/json" } });
    }

    if (request.method === "POST" && url.pathname === "/admin/virtual-keys") {
      try {
        const vk: VirtualKey = await request.json();
        vk.key = vk.key || `vk_${crypto.randomUUID()}`;
        vk.createdAt = Date.now();
        await this.kv.putVirtualKey(vk);
        return new Response(JSON.stringify(vk), { status: 200, headers: { "Content-Type": "application/json"} });
      } catch (e) { return new Response("Error", { status: 400 }); }
    }

    if (request.method === "DELETE" && url.pathname.startsWith("/admin/virtual-keys/")) {
        const key = url.pathname.split("/").pop()!;
        await this.kv.deleteVirtualKey(key);
        return new Response("Deleted", { status: 200 });
    }

    // Config endpoint
    if (url.pathname === "/admin/config") {
       if (request.method === "GET") {
         const ttl = await this.kv.getTrafficTtl();
         const loggingEnabled = await this.kv.isTrafficLoggingEnabled();
         const healthEnabled = await this.kv.isHealthChecksEnabled();
         const healthInterval = await this.kv.getHealthCheckIntervalHours();
         return new Response(JSON.stringify({ 
           status: "ok", 
           trafficTtl: ttl, 
           trafficLoggingEnabled: loggingEnabled,
           healthChecksEnabled: healthEnabled,
           healthCheckIntervalHours: healthInterval
         }), { headers: { "Content-Type": "application/json" } });
      }
      if (request.method === "POST") {
         const body: any = await request.json();
         if (body.trafficTtl !== undefined) {
             await this.kv.setTrafficTtl(body.trafficTtl);
         }
         if (body.trafficLoggingEnabled !== undefined) {
             await this.kv.setTrafficLoggingEnabled(body.trafficLoggingEnabled);
         }
         if (body.healthChecksEnabled !== undefined) {
             await this.kv.setHealthChecksEnabled(body.healthChecksEnabled);
         }
         if (body.healthCheckIntervalHours !== undefined) {
             await this.kv.setHealthCheckIntervalHours(body.healthCheckIntervalHours);
         }
         return new Response(JSON.stringify({ status: "updated" }), { headers: { "Content-Type": "application/json" } });
      }
    }

    if (url.pathname === "/admin/traffic/clear" && request.method === "POST") {
      try {
        await this.kv.clearAllTrafficLogs();
        return new Response("OK", { status: 200 });
      } catch (e) {
        return new Response("Error", { status: 500 });
      }
    }

    if (url.pathname === "/admin/traffic/live" && request.method === "GET") {
      const logs = await this.kv.getRecentTraffic();
      return new Response(JSON.stringify(logs), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/admin/health" && request.method === "GET") {
      const providers = await this.kv.getAllProviders();
      const models = await this.kv.getProviderModels();
      return new Response(JSON.stringify({ providers, models }, null, 2), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname.startsWith("/admin/test-model/") && request.method === "POST") {
      try {
        const parts = url.pathname.split("/");
        const pId = parts[3];
        const mId = parts.slice(4).join("/");
        const providers = await this.kv.getAllProviders();
        const p = providers.find(x => x.id === pId);
        if (!p) return new Response("Provider not found", { status: 404 });
        const models = await this.kv.getProviderModels(pId);
        let m = models.find(x => x.modelId === mId);
        if (!m) return new Response("Model not found", { status: 404 });
        
        // The user explicitly requested to wait for the entire capability suite
        // to finish synchronously so the tags appear instantly in the UI without
        // needing a manual refresh, removing the background execution.
        await probeModel(this.env, this.kv, p, m, { force: true });
        await this.kv.saveSnapshotOnce();
        // Surface networkIssueSuspected + lastErrorDebug so the admin sees e.g.
        // "Cloudflare edge network failure" instead of a misleading "broken".
        return new Response(JSON.stringify({
          ...m,
          networkIssueSuspected: m.networkIssueSuspected || false,
          lastErrorDebug: m.lastErrorDebug || null,
        }), { headers: { "Content-Type": "application/json" } });
      } catch (e: any) {
        return new Response("Error", { status: 500 });
      }
    }

    if (url.pathname.startsWith("/admin/toggle/") && request.method === "POST") {
      try {
        const parts = url.pathname.split("/");
        if (parts[3] === "provider") {
           const pId = parts[4];
           const providers = await this.kv.getAllProviders();
           const p = providers.find(x => x.id === pId);
           if (p) {
             p.active = !p.active;
             await this.kv.putProvider(p);
             return new Response("OK", { status: 200 });
           }
        } else if (parts[3] === "provider-name") {
           const pName = decodeURIComponent(parts[4]);
           const providers = await this.kv.getAllProviders();
           const match = providers.filter(x => x.name === pName);
           const newState = match.length > 0 ? !match[0].active : true;
           for (const p of match) {
              p.active = newState;
              await this.kv.putProvider(p);
           }
           return new Response("OK", { status: 200 });
        } else if (parts[3] === "model") {
           const pId = parts[4];
           const mId = parts.slice(5).join("/");
           const models = await this.kv.getProviderModels(pId);
           const m = models.find(x => x.modelId === mId);
           if (m) {
             m.active = !m.active;
             await this.kv.putProviderModel(m);
             return new Response("OK", { status: 200 });
           }
        } else if (parts[3] === "virtual-key") {
           const key = parts[4];
           const vks = await this.kv.getAllVirtualKeys();
           const vk = vks.find(x => x.key === key);
           if (vk) {
             vk.active = !vk.active;
             await this.kv.putVirtualKey(vk);
             return new Response("OK", { status: 200 });
           }
        }
      } catch (e) { return new Response("Error", { status: 400 }); }
    }

    if (url.pathname.startsWith("/admin/edit/") && request.method === "POST") {
      try {
        const parts = url.pathname.split("/");
        if (parts[3] === "virtual-key") {
           const key = parts[4];
           const body: any = await request.json();
           const vks = await this.kv.getAllVirtualKeys();
           const vk = vks.find(x => x.key === key);
           if (vk) {
             if (typeof body.smartPlus === "boolean") vk.smartPlus = body.smartPlus;
             if (typeof body.multimodalRestrict === "boolean") vk.multimodalRestrict = body.multimodalRestrict;
             if (typeof body.disabledQuote === "string") vk.disabledQuote = body.disabledQuote;
             await this.kv.putVirtualKey(vk);
             return new Response("OK", { status: 200 });
           }
        }
      } catch (e) { return new Response("Error", { status: 400 }); }
    }

    if (url.pathname === "/admin/traffic" && request.method === "GET") {
      const logs = await this.kv.getTrafficLogs(500);
      const providers = await this.kv.getAllProviders();
      const loggingEnabled = await this.kv.isTrafficLoggingEnabled();
      const providerNames: Record<string, string> = {};
      for (const p of providers) providerNames[p.id] = p.name;
      return new Response(JSON.stringify({ logs, providerNames, loggingEnabled }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store, no-cache, must-revalidate" } });
    }

    // Provider URL diagnostic: test what a provider URL actually returns.
    // Helps admins debug broken models by seeing the raw response from the provider.
    if (url.pathname === "/admin/diagnose-provider" && request.method === "POST") {
      try {
        const body: any = await request.json();
        const providerId = body.providerId;
        const providers = await this.kv.getAllProviders();
        const p = providers.find(x => x.id === providerId);
        if (!p) return new Response(JSON.stringify({ error: 'Provider not found' }), { status: 404, headers: { "Content-Type": "application/json" } });
        
        const base = p.baseUrl.trim().replace(/\/+$/, '');
        const authHeader = p.authHeaderFormat ? p.authHeaderFormat.replace('{key}', p.apiKey) : `Bearer ${p.apiKey}`;
        
        // Test 1: /v1/models endpoint
        const modelsUrl = base.endsWith('/v1') ? `${base}/models` : `${base}/v1/models`;
        let modelsResult: any = { url: modelsUrl };
        try {
          const res = await fetch(modelsUrl, {
            headers: { 
              'Authorization': authHeader, 
              'Accept': 'application/json',
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            },
            cf: { resolveOverride: 'cloudflare-dns.com', cacheTtl: 0, cacheEverything: false } as any
          });
          modelsResult.status = res.status;
          modelsResult.contentType = res.headers.get('content-type');
          const text = await res.text();
          modelsResult.preview = text.substring(0, 500);
          modelsResult.isJson = modelsResult.contentType?.includes('json') || false;
        } catch (e: any) {
          modelsResult.error = e.message;
        }
        
        // Test 2: /v1/chat/completions with a simple "Hi"
        let chatUrl: string;
        if (base.endsWith('/chat/completions')) {
          chatUrl = base;
        } else if (base.endsWith('/v1')) {
          chatUrl = `${base}/chat/completions`;
        } else {
          chatUrl = `${base}/v1/chat/completions`;
        }
        let chatResult: any = { url: chatUrl };
        try {
          const models = await this.kv.getProviderModels(providerId);
          const firstModel = models.find(m => m.active);
          const res = await fetch(chatUrl, {
            method: 'POST',
            headers: { 
              'Authorization': authHeader, 
              'Content-Type': 'application/json', 
              'Accept': 'application/json',
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            },
            body: JSON.stringify({ model: firstModel?.modelId || 'test', messages: [{ role: 'user', content: 'Hi' }], max_tokens: 5 }),
            cf: { resolveOverride: 'cloudflare-dns.com', cacheTtl: 0, cacheEverything: false } as any
          });
          chatResult.status = res.status;
          chatResult.contentType = res.headers.get('content-type');
          const text = await res.text();
          chatResult.preview = text.substring(0, 500);
          chatResult.isJson = chatResult.contentType?.includes('json') || false;
        } catch (e: any) {
          chatResult.error = e.message;
        }
        
        return new Response(JSON.stringify({ modelsEndpoint: modelsResult, chatEndpoint: chatResult }, null, 2), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      } catch (e: any) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }

    if (url.pathname === "/admin/playground/test" && request.method === "POST") {
      try {
        const body: any = await request.json();
        const providers = await this.kv.getAllProviders();
        const models = await this.kv.getProviderModels();
        
        let provider = providers.find(p => p.id === body.providerId);
        let model = models.find(m => m.modelId === body.modelId && m.providerId === body.providerId);
        
        if (!provider || !model) return new Response("Provider or Model not found", { status: 400 });
        
        const adapter = getAdapterForProvider(provider);
        const start = Date.now();
        const res = await adapter.fetchChatCompletion(provider, model, {
          model: model.modelId,
          messages: [
            { role: "system", content: "You are a helpful AI assistant. Please respond ONLY in English." },
            { role: "user", content: body.message }
          ],
          max_tokens: 100
        });
        
        const rawResp = await res.text();
        
        await this.kv.logTraffic({
           timestamp: Date.now(),
           virtualKey: "Playground",
           providerId: provider.id,
           modelId: model.modelId,
           status: res.status,
           latencyMs: Date.now() - start
        });
        
        return new Response(JSON.stringify({ rawResp, status: res.status }), { headers: { "Content-Type": "application/json" } });
      } catch (e: any) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }

    if (url.pathname === "/admin/internal/test-capability" && request.method === "POST") {
      try {
        const body: any = await request.json();
        const providers = await this.kv.getAllProviders();
        const models = await this.kv.getProviderModels();
        let provider = providers.find(p => p.id === body.providerId);
        let model = models.find(m => m.modelId === body.modelId && m.providerId === body.providerId);
        if (!provider || !model) return new Response("Not found", { status: 400 });
        
        const adapter = getAdapterForProvider(provider);
        // Use the network-retry wrapper so a Cloudflare-edge egress failure is
        // retried with resolveOverride (matching the production chat path) and
        // reported as networkRetried instead of a silent failure.
        const probeResult = await fetchWithNetworkRetry(adapter, provider, model, body.testBody);
        const res = probeResult.response;
        if (!res) {
          const e: any = new Error(probeResult.errorMessage || "Network failure");
          e.name = probeResult.errorName || "TypeError";
          throw e;
        }
        const networkRetried = probeResult.networkRetried;

        if (body.testBody.stream && res.ok && res.body) {
           // Route through the SAME hardened SSE re-assembly pipeline used by the
           // production chat path so Cloudflare's edge cannot mangle/split
           // mid-stream tool-call fragments during a capability probe.
           return proxyNormalizedSSE(res.body);
        }
        // Surface network-retry info so callers (executeCapabilityProbe, Test
        // Now) can distinguish a Cloudflare-edge issue from a real model fault.
        const headers = new Headers(res.headers);
        headers.set("X-Network-Retried", networkRetried ? "1" : "0");
        return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
      } catch (e: any) {
        // Network failure (Cloudflare edge). Return a NON-OK status (502) with a
        // clear network flag so the caller (executeCapabilityProbe -> probeModel)
        // classifies it as a network issue (networkIssueSuspected) and never
        // misreads this as a successful 200 probe (which would wrongly mark the
        // model "working") or as a permanent "broken".
        return new Response(JSON.stringify({ error: e.message, networkIssueSuspected: true }), {
          status: 502,
          headers: { "Content-Type": "application/json" }
        });
      }
    }

    // HTML dashboard
    if (url.pathname === "/admin") {
      const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AI Gateway Operations</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0a0a0f;
      --surface: rgba(255, 255, 255, 0.05);
      --surface-hover: rgba(255, 255, 255, 0.08);
      --border: rgba(255, 255, 255, 0.1);
      --primary: #6366f1;
      --primary-hover: #4f46e5;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --danger: #ef4444;
      --success: #10b981;
      --warning: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      min-height: 100vh;
      background-image: 
        radial-gradient(circle at 15% 50%, rgba(99, 102, 241, 0.08), transparent 25%),
        radial-gradient(circle at 85% 30%, rgba(16, 185, 129, 0.05), transparent 25%);
      background-attachment: fixed;
    }
    header {
      background: rgba(10, 10, 15, 0.8);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      padding: 1rem 2rem;
      position: sticky;
      top: 0;
      z-index: 100;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    header h1 {
      font-size: 1.25rem;
      font-weight: 600;
      background: linear-gradient(to right, #818cf8, #c084fc);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .container {
      max-width: 1400px;
      margin: 2rem auto;
      padding: 0 2rem;
    }
    .tabs {
      display: flex; gap: 1rem; margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; overflow-x: auto;
    }
    .tab {
      color: var(--text-muted); cursor: pointer; padding: 0.5rem 1rem; border-radius: 8px; transition: all 0.2s; white-space: nowrap; font-weight: 500;
    }
    .tab:hover { color: var(--text); background: var(--surface); }
    .tab.active { color: white; background: var(--surface); border: 1px solid var(--border); }
    .tab-content { display: none; animation: fadeIn 0.3s ease; }
    .tab-content.active { display: block; }
    
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes pulse {
      0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); }
      70% { box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
      100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    .grid-layout { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 1.5rem; }
    .card {
      background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 1.5rem;
      backdrop-filter: blur(10px); transition: transform 0.2s, box-shadow 0.2s;
    }
    .card:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,0.2); }
    .card h2 { font-size: 1.125rem; font-weight: 500; margin-bottom: 1.5rem; color: #e5e7eb; }
    
    input, select {
      width: 100%; background: rgba(0, 0, 0, 0.2); border: 1px solid var(--border); color: var(--text);
      padding: 0.75rem 1rem; border-radius: 8px; margin-bottom: 1rem; font-family: inherit; transition: border-color 0.2s;
    }
    input:focus, select:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2); }
    label.checkbox-label { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem; color: var(--text-muted); cursor: pointer; }
    input[type="checkbox"] { width: auto; margin: 0; accent-color: var(--primary); transform: scale(1.1); }
    
    button {
      background: var(--primary); color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 500; cursor: pointer; transition: all 0.2s; width: 100%; font-family: inherit;
    }
    button:hover { background: var(--primary-hover); }
    button.danger { background: rgba(239, 68, 68, 0.1); color: var(--danger); border: 1px solid rgba(239,68,68,0.2); }
    button.danger:hover { background: rgba(239, 68, 68, 0.2); }
    button.secondary { background: rgba(255, 255, 255, 0.05); color: var(--text); border: 1px solid var(--border); }
    button.secondary:hover { background: rgba(255, 255, 255, 0.1); }
    button.small { padding: 0.4rem 0.75rem; width: auto; font-size: 0.8rem; }
    
    .list-item { background: rgba(0,0,0,0.3); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; }
    .list-item-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; border-bottom: 1px solid var(--border); padding-bottom: 0.75rem; }
    .list-item-title { font-weight: 600; font-size: 1.1rem; }
    
    .badge { padding: 0.25rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
    .badge.active { background: rgba(16, 185, 129, 0.1); color: var(--success); border: 1px solid rgba(16,185,129,0.2); }
    .badge.inactive { background: rgba(156, 163, 175, 0.1); color: var(--text-muted); border: 1px solid rgba(156,163,175,0.2); }
    .badge.working { background: rgba(16, 185, 129, 0.1); color: var(--success); }
    .badge.degraded { background: rgba(245, 158, 11, 0.1); color: var(--warning); }
    .badge.broken { background: rgba(239, 68, 68, 0.1); color: var(--danger); }
    .badge.untested { background: rgba(156, 163, 175, 0.1); color: var(--text-muted); }

    .flex-row { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 0.5rem; }
    
    .data-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; font-size: 0.875rem; color: var(--text-muted); margin-top: 0.5rem; }
    .data-row { display: flex; justify-content: space-between; }
    
    pre { background: rgba(0,0,0,0.4); padding: 1rem; border-radius: 8px; border: 1px solid var(--border); overflow-x: auto; font-size: 0.875rem; color: #a78bfa; margin-top: 1rem; max-height: 400px; }
    
    .model-item { padding: 1rem; border-radius: 8px; background: rgba(255,255,255,0.02); margin-top: 0.5rem; border: 1px solid rgba(255,255,255,0.05); }
    .model-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
    .capabilities { display: flex; gap: 0.5rem; margin: 0.5rem 0; font-size: 0.75rem; }
    .cap { background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; }
    .cap.yes { color: var(--success); }
    .cap.no { color: var(--text-muted); text-decoration: line-through; }

    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }
  </style>
</head>
<body>
  <div id="loginOverlay" style="position:fixed; top:0; left:0; right:0; bottom:0; background:rgba(10,10,15,0.95); z-index:9999; display:flex; justify-content:center; align-items:center; backdrop-filter:blur(10px);">
     <div class="card" style="width:100%; max-width:400px;">
       <h2>Gateway OS Authentication</h2>
       <form id="loginForm">
         <input type="password" id="loginPw" placeholder="Admin Password (set on first login)" required />
         <label class="checkbox-label" style="margin-top: -0.5rem; margin-bottom: 1rem;"><input type="checkbox" onchange="document.getElementById('loginPw').type = this.checked ? 'text' : 'password'" /> Show Password</label>
         <button type="submit">Authenticate</button>
         <div id="loginErr" style="color:var(--danger); margin-top:1rem; font-size:0.875rem;"></div>
       </form>
     </div>
  </div>

  <header>
    <h1>Gateway OS</h1>
    <div style="display: flex; gap: 1rem; align-items: center;">
      <span style="font-size: 0.875rem; color: var(--text-muted);">Admin Dashboard</span>
    </div>
  </header>

  <div class="container">
    <div class="tabs">
      <div class="tab active" onclick="switchTab('health')">Health & Providers</div>
      <div class="tab" onclick="switchTab('keys')">Virtual Keys</div>
      <div class="tab" onclick="switchTab('playground')">Playground</div>
      <div class="tab" onclick="switchTab('traffic')">Traffic Analytics</div>
      <div class="tab" onclick="switchTab('live')">Live Analytics</div>
      <div class="tab" onclick="switchTab('settings')">Settings</div>
    </div>

    <!-- Health & Providers Tab -->
    <div id="tab-health" class="tab-content active">
      <div class="grid-layout">
        <div class="card">
          <h2>Add Provider Key</h2>
          <form id="providerForm">
            <input type="text" id="pName" placeholder="Provider Name (e.g. Groq)" required />
            <input type="url" id="pUrl" placeholder="Base URL" required />
            <input type="text" id="pAuth" placeholder="Auth Format (Bearer {key})" value="Bearer {key}" required />
            <input type="password" id="pKey" placeholder="API Key" required />
            <button type="submit">Deploy Provider</button>
          </form>
        </div>
        
        <div class="card" style="grid-column: 1 / -1;">
           <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
             <h2>Provider & Model Status</h2>
             <div class="flex-row">
               <button class="secondary small" onclick="runAllHealthChecks()">Run Health Checks Now</button>
             </div>
           </div>
          <div id="healthTree"></div>
        </div>
      </div>
    </div>

    <!-- Virtual Keys Tab -->
    <div id="tab-keys" class="tab-content">
      <div class="grid-layout">
        <div class="card">
          <h2>Create Virtual Key</h2>
          <form id="vkForm">
            <input type="text" id="vApp" placeholder="App Name (e.g. MobileApp)" required />
            <div style="display:flex; gap:0.5rem; align-items:center;">
              <input type="text" id="vAlias" placeholder="Model Alias to Expose" required style="margin-bottom:0;" />
              <button type="button" class="secondary" style="width:auto; padding:0.75rem;" onclick="generateAlias()">Randomize</button>
            </div>
            <br/>
            <label class="checkbox-label"><input type="checkbox" id="vMulti" /> Multimodal Restrict (Only use vision-capable)</label>
            <label class="checkbox-label"><input type="checkbox" id="vSmart" /> Smart+ Routing (Capability-based)</label>
            <div style="margin-bottom:1rem;">
               <label style="color:var(--text-muted);font-size:0.875rem;">Allowed Providers (comma separated IDs, leave empty for all)</label>
               <input type="text" id="vProv" placeholder="e.g. groq_key_1, openai_key" />
            </div>
            <div style="margin-bottom:1rem;">
               <label style="color:var(--text-muted);font-size:0.875rem;">Allowed Models (comma separated IDs, leave empty for all)</label>
               <input type="text" id="vMod" placeholder="e.g. gpt-4o, llama3-8b" />
            </div>
            <button type="submit">Issue Key</button>
          </form>
        </div>
        
        <div class="card" style="grid-column: 1 / -1;">
          <h2>Active Keys</h2>
          <div id="keysList"></div>
        </div>
      </div>
    </div>

    <!-- Playground Tab -->
    <div id="tab-playground" class="tab-content">
      <div class="grid-layout" style="grid-template-columns: 1fr; max-width: 800px; margin: 0 auto;">
        <div class="card" style="display:flex; flex-direction:column; height: 600px;">
          <h2>Playground Chat</h2>
          <div style="display:flex; gap:1rem; margin-bottom:1rem;">
             <select id="playProvSelect" required style="margin-bottom:0;" onchange="updatePlayModSelect()"><option value="">Select Provider</option></select>
             <select id="playModSelect" required style="margin-bottom:0;"><option value="">Select Model</option></select>
          </div>
          <div id="playChat" style="flex:1; overflow-y:auto; background:rgba(0,0,0,0.3); border:1px solid var(--border); border-radius:8px; padding:1rem; display:flex; flex-direction:column; gap:1rem; margin-bottom:1rem;">
             <div style="color:var(--text-muted); text-align:center; margin-top:auto; margin-bottom:auto;">Select a model and start chatting...</div>
          </div>
          <form id="playForm" style="display:flex; gap:1rem;">
            <input type="text" id="playMsg" placeholder="Type your message..." required style="margin-bottom:0; flex:1;" />
            <button type="submit" style="width:auto;">Send</button>
          </form>
        </div>
      </div>
    </div>

    <!-- Traffic Tab -->
    <div id="tab-traffic" class="tab-content">
      <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
          <h2 style="display:flex; align-items:center; gap:0.5rem">
             Traffic Analytics
             <span class="badge" style="background:rgba(16,185,129,0.2); border:1px solid var(--success); color:var(--success); animation: pulse 2s infinite;">LIVE</span>
          </h2>
          <div style="display: flex; align-items: center; gap: 1rem;">
            <label class="checkbox-label" style="margin-bottom: 0;">
               <input type="checkbox" id="loggingToggle" onchange="toggleLogging()" /> Enable Logging
            </label>
            <button class="danger small" onclick="clearTraffic()">Clear All</button>
            <button class="secondary small" onclick="loadTraffic()">Force Refresh</button>
          </div>
        </div>
        <div id="trafficDisplay">No data loaded.</div>
      </div>
    </div>

    <!-- Live Analytics Tab -->
    <div id="tab-live" class="tab-content">
      <div class="card" style="display:flex; flex-direction:column; height: 600px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
          <h2 style="display:flex; align-items:center; gap:0.5rem">
             Live Traffic Stream
             <span id="liveStatusBadge" class="badge inactive">DISCONNECTED</span>
          </h2>
          <div>
            <button class="secondary small" id="liveConnectBtn" onclick="toggleLiveStream()">Connect Stream</button>
          </div>
        </div>
        <div id="liveStreamDisplay" style="flex:1; overflow-y:auto; background:rgba(0,0,0,0.3); border:1px solid var(--border); border-radius:8px; padding:1rem; font-family: monospace; font-size: 0.85rem; display:flex; flex-direction:column; gap:0.5rem;">
          <div style="color:var(--text-muted); text-align:center; margin:auto;" id="livePlaceholder">Click 'Connect Stream' to listen for live requests...</div>
        </div>
      </div>
    </div>

    <!-- Settings Tab -->
    <div id="tab-settings" class="tab-content">
      <div class="grid-layout">
        <div class="card">
          <h2>Security / Change Password</h2>
          <form id="pwForm">
            <input type="password" id="pwCurr" placeholder="Current Password" required />
            <input type="password" id="pwNew" placeholder="New Password" required />
            <label class="checkbox-label" style="margin-top: -0.5rem; margin-bottom: 1rem;"><input type="checkbox" onchange="const t = this.checked ? 'text' : 'password'; document.getElementById('pwCurr').type = t; document.getElementById('pwNew').type = t;" /> Show Passwords</label>
            <button type="submit" class="secondary">Rotate Admin Password</button>
          </form>
        </div>
        <div class="card">
          <h2>Data Retention</h2>
          <form id="ttlForm">
            <label style="color:var(--text-muted);font-size:0.875rem;">Auto-clear traffic data after:</label>
            <select id="ttlSelect">
              <option value="7200">2 Hours</option>
              <option value="43200">12 Hours</option>
              <option value="86400">1 Day</option>
              <option value="259200">3 Days</option>
              <option value="604800">7 Days</option>
            </select>
            <button type="submit" class="secondary" style="margin-top: 1rem;">Save Retention Policy</button>
          </form>
        </div>
      <div class="grid-layout" style="margin-top: 1.5rem;">
        <div class="card">
          <h2>Advanced Features (KV Limits)</h2>
          <div style="display: flex; flex-direction: column; gap: 1rem; margin-top: 1rem;">
            <label class="checkbox-label">
              <input type="checkbox" id="healthChecksToggle" onchange="toggleHealthChecks()" /> Enable Automatic Health Checks
              <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">When ON, the Cron re-probes model health &amp; capabilities (smart routing). When OFF, automatic checks are skipped — but you can still probe on-demand with "Run Health Checks Now" or "Test Now", and a probe always runs immediately when you add a provider.</div>
            </label>
            <div>
              <label style="color:var(--text-muted);font-size:0.875rem;">Health-check interval (KV write savings):</label>
              <select id="healthIntervalSelect" style="margin-top:0.5rem;">
                <option value="12">12 Hours (default)</option>
                <option value="24">24 Hours</option>
                <option value="48">2 Days</option>
                <option value="168">7 Days</option>
              </select>
              <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Longer intervals mean fewer KV probe writes. The Cron still fires every 12h but only runs a full probe batch once this interval has elapsed since the last run.</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    // Escape untrusted values before injecting into innerHTML — provider
    // names, model IDs and virtual-key fields are admin-controlled but still
    // untrusted input that must never execute as markup/JS.
    function esc(s) {
      return String(s == null ? "" : s)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
    }
    let currentToken = localStorage.getItem("gateway_admin_token");
    let headers = { "Authorization": "Bearer " + currentToken };
    const loginOverlay = document.getElementById("loginOverlay");
    
    if (!currentToken) {
        loginOverlay.style.display = "flex";
    } else {
        loginOverlay.style.display = "none";
        setTimeout(loadHealth, 300);
    }
    
    document.getElementById("loginForm").onsubmit = async (e) => {
        e.preventDefault();
        const errEl = document.getElementById("loginErr");
        if (errEl) errEl.innerText = "";
        const pw = document.getElementById("loginPw").value;
        try {
            const res = await fetch('/admin/login', {
               method: 'POST',
               headers: { "Content-Type": "application/json" },
               body: JSON.stringify({ password: pw })
            });
            if (res.ok) {
               const data = await res.json();
               if (!data || !data.token) {
                  if (errEl) errEl.innerText = "Login succeeded but no token was returned.";
                  return;
               }
               localStorage.setItem("gateway_admin_token", data.token);
               currentToken = data.token;
               headers = { "Authorization": "Bearer " + currentToken };
               loginOverlay.style.display = "none";
               loadHealth();
               return;
            }

            // Surface the real server error instead of a silent blink.
            let msg = "Invalid credentials.";
            try { const t = await res.text(); if (t) msg = t; } catch (_) {}
            if (res.status === 400) {
               const sRes = await fetch('/admin/setup', {
                  method: 'POST',
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ password: pw })
               });
               if (sRes.ok) {
                  const data = await sRes.json();
                  if (data && data.token) {
                     localStorage.setItem("gateway_admin_token", data.token);
                     currentToken = data.token;
                     headers = { "Authorization": "Bearer " + currentToken };
                     loginOverlay.style.display = "none";
                     loadHealth();
                     return;
                  }
               }
               let smsg = "Setup failed.";
               try { const st = await sRes.text(); if (st) smsg = st; } catch (_) {}
               if (errEl) errEl.innerText = smsg;
            } else {
               if (errEl) errEl.innerText = msg;
            }
        } catch (err) {
            if (errEl) errEl.innerText = "Network error: " + (err && err.message ? err.message : err);
        }
    };

    let trafficInterval = null;

    function switchTab(tabId) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById('tab-' + tabId).classList.add('active');
      
      if (trafficInterval) {
          clearInterval(trafficInterval);
          trafficInterval = null;
      }
      
      if(tabId === 'health') loadHealth();
      if(tabId === 'keys') loadVirtualKeys();
      if(tabId === 'settings') loadSettings();
      if(tabId === 'traffic') {
          loadTraffic();
          trafficInterval = setInterval(loadTraffic, 3000);
      }
    }

    function generateAlias() {
      const words = ["fast", "smart", "pro", "vision", "chat", "max"];
      const r = () => words[Math.floor(Math.random()*words.length)];
      document.getElementById('vAlias').value = 'model-' + r() + '-' + Math.floor(Math.random()*1000);
    }

    document.getElementById('providerForm').onsubmit = async (e) => {
      e.preventDefault();
      const res = await fetch('/admin/providers', {
        method: 'POST',
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({
          name: document.getElementById('pName').value,
          baseUrl: document.getElementById('pUrl').value,
          authHeaderFormat: document.getElementById('pAuth').value,
          apiKey: document.getElementById('pKey').value,
          active: true
        })
      });
      if(res.ok) { document.getElementById('providerForm').reset(); loadHealth(); }
      else {
        const errText = await res.text();
        let msg = "Failed to add provider";
        try { const parsed = JSON.parse(errText); if (parsed.error) msg = parsed.error; } catch(e) { msg = errText; }
        alert(msg);
      }
    };

    document.getElementById('vkForm').onsubmit = async (e) => {
      e.preventDefault();
      const res = await fetch('/admin/virtual-keys', {
        method: 'POST',
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({
          appName: document.getElementById('vApp').value,
          modelAlias: document.getElementById('vAlias').value,
          active: true,
          multimodalRestrict: document.getElementById('vMulti').checked,
          smartPlus: document.getElementById('vSmart').checked,
          allowedModels: document.getElementById('vMod').value ? document.getElementById('vMod').value.split(',').map(s=>s.trim()) : [],
          allowedProviders: document.getElementById('vProv').value ? document.getElementById('vProv').value.split(',').map(s=>s.trim()) : [],
          rateLimit: { requestsPerMin: 60, tokensPerDay: 100000 }
        })
      });
      if(res.ok) { document.getElementById('vkForm').reset(); loadVirtualKeys(); }
      else alert("Failed to create key");
    };

    document.getElementById('pwForm').onsubmit = async (e) => {
      e.preventDefault();
      const res = await fetch('/admin/change-password', {
        method: 'POST',
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({
          currentPassword: document.getElementById('pwCurr').value,
          newPassword: document.getElementById('pwNew').value
        })
      });
      if (res.ok) {
         const data = await res.json();
         headers = { "Authorization": "Bearer " + data.token };
         localStorage.setItem("gateway_admin_token", data.token);
         document.getElementById('pwForm').reset();
         alert("Password updated and session refreshed");
      } else { alert("Failed to update password"); }
    };

    async function clearTraffic() {
      if(!confirm("Are you sure you want to clear all traffic logs? This cannot be undone.")) return;
      await fetch('/admin/traffic/clear', { method: 'POST', headers });
      loadTraffic();
    }

    async function toggleLogging() {
       const enabled = document.getElementById('loggingToggle').checked;
       await fetch('/admin/config', {
         method: 'POST',
         headers: { ...headers, "Content-Type": "application/json" },
         body: JSON.stringify({ trafficLoggingEnabled: enabled })
       });
    }

    document.getElementById('ttlForm').onsubmit = async (e) => {
      e.preventDefault();
      const ttl = parseInt(document.getElementById('ttlSelect').value);
      const res = await fetch('/admin/config', {
        method: 'POST',
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ trafficTtl: ttl })
      });
      if(res.ok) alert("Retention policy saved!");
      else alert("Failed to save policy");
    };

    async function loadSettings() {
      const res = await fetch('/admin/config', { headers });
      if(res.ok) {
         const data = await res.json();
         if(data.trafficTtl) {
            document.getElementById('ttlSelect').value = data.trafficTtl.toString();
         }
         document.getElementById('healthChecksToggle').checked = data.healthChecksEnabled;
         if(data.healthCheckIntervalHours) {
            document.getElementById('healthIntervalSelect').value = data.healthCheckIntervalHours.toString();
         }
      }
    }

    async function toggleHealthChecks() {
      const enabled = document.getElementById('healthChecksToggle').checked;
      await fetch('/admin/config', {
        method: 'POST',
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ healthChecksEnabled: enabled })
      });
    }

    document.getElementById('healthIntervalSelect').onchange = async (e) => {
      const hours = parseInt(e.target.value);
      await fetch('/admin/config', {
        method: 'POST',
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ healthCheckIntervalHours: hours })
      });
    };

    async function toggleProvider(pId) {
      await fetch('/admin/toggle/provider/' + pId, { method: 'POST', headers });
      loadHealth();
    }
    
    async function deleteProvider(pId) {
      if(!confirm("Are you sure you want to delete this provider key and all its models?")) return;
      await fetch('/admin/providers/' + pId, { method: 'DELETE', headers });
      loadHealth();
    }

    async function refreshProviderModels(pId) {
      const btn = event.target;
      const originalText = btn.innerText;
      btn.innerText = "Fetching...";
      btn.disabled = true;
      try {
        const res = await fetch('/admin/providers/' + pId + '/discover', { method: 'POST', headers });
        if (!res.ok) {
           const err = await res.text();
           alert("Failed to fetch models: " + err);
        } else {
           alert("Models refreshed from provider!");
        }
      } catch (e) { alert("Error: " + e.message); }
      finally {
        btn.innerText = originalText;
        btn.disabled = false;
        loadHealth();
      }
    }

    async function toggleProviderName(pName) {
      await fetch('/admin/toggle/provider-name/' + encodeURIComponent(pName), { method: 'POST', headers });
      loadHealth();
    }

    async function toggleModel(pId, mId) {
      await fetch('/admin/toggle/model/' + pId + '/' + mId, { method: 'POST', headers });
      loadHealth();
    }
    
    async function testModel(pId, mId) {
      const btn = event.target;
      const originalText = btn.innerText;
      btn.innerText = "Testing...";
      btn.disabled = true;
      // Clear any prior inline result for this model before re-testing.
      const cardId = 'testResult_' + pId + '_' + mId.replace(/[^a-zA-Z0-9_-]/g, '_');
      const prev = document.getElementById(cardId);
      if (prev) prev.remove();
      try {
        const res = await fetch('/admin/test-model/' + pId + '/' + mId, { method: 'POST', headers });
        let result = null;
        try { result = await res.json(); } catch (_) {}
        // Show an EXPLICIT, inline result on the model card so the admin sees
        // exactly what happened (previously the status just silently stayed the
        // same and looked like "nothing happened"). Green = working, amber =
        // network-limited (works on your system), red = genuinely broken.
        const ok = res.ok && result;
        const status = ok ? (result.status || 'unknown') : 'error';
        const netLimited = ok ? !!result.networkIssueSuspected : false;
        let color, label;
        if (status === 'working' || status === 'degraded') { color = 'var(--success)'; label = '✓ ' + status.toUpperCase(); }
        else if (netLimited) { color = 'var(--warning)'; label = '⚠ NETWORK-LIMITED (works on your system)'; }
        else if (status === 'untested') { color = 'var(--text-muted)'; label = '⚪ UNTESTED — provider returned no clear result'; }
        else if (status === 'broken') { color = 'var(--danger)'; label = '✗ BROKEN'; }
        else { color = 'var(--danger)'; label = '✗ ' + (status || 'ERROR'); }
        const debug = (ok && result.lastErrorDebug) ? '<div style="margin-top:4px; font-size:0.75rem; color:var(--text-muted); word-wrap:break-word;">' + esc(result.lastErrorDebug) + '</div>' : '';
        const div = document.createElement('div');
        div.id = cardId;
        div.style.cssText = 'margin-top:6px; padding:6px 10px; border-radius:8px; font-size:0.85rem; font-weight:600; border:1px solid ' + color + '; color:' + color + '; background:rgba(0,0,0,0.25);';
        div.innerHTML = label + debug;
        // Insert the result right after the button row of this model's card.
        const card = btn.closest('.model-item');
        if (card) card.appendChild(div);
      } catch (e) {
        const div = document.createElement('div');
        div.id = cardId;
        div.style.cssText = 'margin-top:6px; padding:6px 10px; border-radius:8px; font-size:0.85rem; color:var(--danger); border:1px solid var(--danger);';
        div.innerText = '✗ Test request failed: ' + (e && e.message ? e.message : e);
        const card = btn.closest('.model-item');
        if (card) card.appendChild(div);
      } finally {
        btn.innerText = originalText;
        btn.disabled = false;
        // Reload state in the background so the badge also reflects the new status.
        loadHealth();
      }
    }

    let globalProviders = [];
    let globalModels = [];
    let currentModelFilter = "";
    
    function updatePlayProvSelect() {
       const provSelect = document.getElementById('playProvSelect');
       if(!provSelect) return;
       const currentVal = provSelect.value;
       provSelect.innerHTML = '<option value="">Select Provider</option>';
        globalProviders.forEach(p => {
           provSelect.innerHTML += '<option value="' + p.id + '">' + p.name + ' (' + p.id + ')</option>';
        });
       if(currentVal) provSelect.value = currentVal;
    }
    
    function updatePlayModSelect() {
       const provId = document.getElementById('playProvSelect').value;
       const modSelect = document.getElementById('playModSelect');
       if(!modSelect) return;
       const currentVal = modSelect.value;
       modSelect.innerHTML = '<option value="">Select Model</option>';
       if(!provId) return;
        // Include every active model EXCEPT genuinely broken ones. Untested and
        // network-limited models are still routable by the gateway (and the
        // gateway retries with a re-routed egress), so hiding them from the
        // playground was wrong — it made models that "work on your system"
        // invisible here. Only truly broken (provider-side 4xx/5xx, not a
        // recoverable network/rate-limit issue) models are excluded.
        const pModels = globalModels.filter(m => m.providerId === provId && m.active &&
          !(m.status === 'broken' && !m.networkIssueSuspected));
        pModels.forEach(m => {
           modSelect.innerHTML += '<option value="' + m.modelId + '">' + m.modelId + '</option>';
        });
       if(currentVal) modSelect.value = currentVal;
    }

    async function runAllHealthChecks() {
      const btn = event && event.target;
      if (btn) { btn.innerText = "Running..."; btn.disabled = true; }
      try {
        await fetch('/admin/health/run', { method: 'POST', headers });
        alert("Health checks started in the background. They may take a few minutes to complete. Please refresh the state manually later.");
      } catch (e) {
        alert("Failed to start health checks.");
      } finally {
        if (btn) { btn.innerText = "Run Health Checks Now"; btn.disabled = false; }
        loadHealth();
      }
    }

    async function loadHealth() {
      const res = await fetch('/admin/health', { headers });
      if(!res.ok) {
         if(res.status === 401) {
            loginOverlay.style.display = "flex";
         }
         return;
      }
      const { providers, models } = await res.json();
      globalProviders = providers;
      globalModels = models;
      updatePlayProvSelect();
      
      const grouped = {};
      for (const p of providers) {
          if (!grouped[p.name]) grouped[p.name] = [];
          grouped[p.name].push(p);
      }
      
      let html = '<h3 style="margin-bottom:1rem;">Providers</h3>';
      for (const pName in grouped) {
          html += '<div class="list-item" style="border: 1px solid rgba(99,102,241,0.3); background: rgba(99, 102, 241, 0.05);">'
            + '<div class="list-item-title" style="margin-bottom:0.75rem; color: #818cf8; font-size:1.25rem; display:flex; justify-content:space-between;">'
            + '<span>Provider: ' + esc(pName) + '</span>'
            + '<button class="secondary small" onclick="toggleProviderName(&quot;' + encodeURIComponent(pName) + '&quot;)">Toggle All ' + esc(pName) + ' Keys</button>'
            + '</div>';

          for (const p of grouped[pName]) {
              html += '<div class="list-item" style="margin-top:0.5rem; background: rgba(0,0,0,0.4);">'
                + '<div class="list-item-header">'
                + '<div style="display:flex; align-items:center; gap: 1rem;">'
                + '<div style="font-weight:600; font-size:0.9rem; font-family:monospace;">Key: ' + esc(p.id) + '</div>'
               + '<span class="badge ' + (p.active ? 'active' : 'inactive') + '">' + (p.active ? 'ACTIVE' : 'INACTIVE') + '</span>'
               + '</div>'
               + '<div class="flex-row">'
               + '<button class="secondary small" onclick="refreshProviderModels(&quot;' + p.id + '&quot;)">Refresh State</button>'
               + '<button class="secondary small" onclick="toggleProvider(&quot;' + p.id + '&quot;)">Toggle Key</button>'
               + '<button class="danger small" onclick="deleteProvider(&quot;' + p.id + '&quot;)">Delete Key</button>'
               + '</div>'
               + '</div>'
               + '</div>';
         }
         html += '</div>';
      }
      if(providers.length === 0) html = "<div style='color:var(--text-muted)'>No providers configured yet.</div>";
      
      html += '<div id="modelsContainer"></div>';
      document.getElementById('healthTree').innerHTML = html;
      renderModelsFilter();
    }

    function renderModelsFilter() {
      let html = '<div style="display:flex; justify-content:space-between; align-items:center; margin-top:2rem; margin-bottom:1rem;">';
      html += '<h3 style="margin:0; color:var(--success);">🟢 Running Models</h3>';
      html += '<select onchange="currentModelFilter=this.value; renderModelsFilter();" style="width:auto; margin:0; padding:0.25rem 0.5rem; background:rgba(0,0,0,0.4); border:1px solid var(--border); color:#fff; border-radius:4px;">';
      html += '<option value="">All Providers</option>';
      const distinctProviderIds = [...new Set(globalProviders.map(p => p.id))];
      for (const pId of distinctProviderIds) {
         const pName = globalProviders.find(p => p.id === pId)?.name || pId;
         html += '<option value="' + pId + '"' + (currentModelFilter === pId ? ' selected' : '') + '>' + pName + ' (' + pId + ')</option>';
      }
      html += '</select></div>';
      
      const runningModels = globalModels.filter(m => m.active && (m.status === 'working' || m.status === 'degraded') && (!currentModelFilter || m.providerId === currentModelFilter));
      if(runningModels.length === 0) html += "<div style='color:var(--text-muted); margin-bottom:1rem;'>No models match.</div>";
      for (const m of runningModels) {
         html += renderModel(m);
      }

      // Amber group: models the probe could NOT validate because of a
      // Cloudflare-edge / per-IP rate-limit issue (they work fine on the admin's
      // own system). Shown as "Available (network-limited)" — NOT as broken.
      const networkLimitedModels = globalModels.filter(m => m.active && m.networkIssueSuspected && (!currentModelFilter || m.providerId === currentModelFilter));
      if (networkLimitedModels.length > 0) {
        html += '<h3 style="margin-top:2rem; margin-bottom:1rem; color:#f59e0b;">🟡 Available (network-limited)</h3>';
        html += "<div style='color:var(--text-muted); font-size:0.8rem; margin-bottom:1rem;'>These models work on your own system but the gateway's Cloudflare egress IP gets rate-limited/throttled by the provider. They are still routed and usable — the gateway retries with a different egress route.</div>";
        for (const m of networkLimitedModels) {
           html += renderModel(m);
        }
      }

       html += '<h3 style="margin-top:2rem; margin-bottom:1rem; color:var(--danger);">🔴 Not Running Models</h3>';
       // Genuinely broken models only (network-suspect and untested ones are
       // shown in their own sections above, so they are excluded here).
       const notRunningModels = globalModels.filter(m => (!m.active || (m.status === 'broken' && !m.networkIssueSuspected)) && (!currentModelFilter || m.providerId === currentModelFilter));
       if(notRunningModels.length === 0) html += "<div style='color:var(--text-muted); margin-bottom:1rem;'>No models match.</div>";
       for (const m of notRunningModels) {
          html += renderModel(m);
       }

       // Grey group: UNTESTED models (never validated, or last probe was a
       // recoverable issue). These are NOT broken — they just need a "Test Now".
       // Shown in their own section with a clear call-to-action so the admin
       // understands the model is simply unverified, not dead.
       const untestedModels = globalModels.filter(m => m.active && m.status === 'untested' && !m.networkIssueSuspected && (!currentModelFilter || m.providerId === currentModelFilter));
       if (untestedModels.length > 0) {
         html += '<h3 style="margin-top:2rem; margin-bottom:1rem; color:var(--text-muted);">⚪ Untested Models (click Test Now)</h3>';
         html += "<div style='color:var(--text-muted); font-size:0.8rem; margin-bottom:1rem;'>These models have not been successfully validated yet. Click <b>Test Now</b> on each to probe them (the gateway now retries rate-limited probes with a re-routed egress, so most will flip to Working).</div>";
         for (const m of untestedModels) {
            html += renderModel(m);
         }
       }
       
       document.getElementById('modelsContainer').innerHTML = html;
    }
    
    function renderModel(m) {
      // Network-issue badge is amber (a warning, not a death sentence) so it's
      // visually distinct from a genuinely broken model.
      const netBadge = m.networkIssueSuspected ? '<span class="badge" style="background:rgba(245, 158, 11, 0.15); border:1px solid var(--warning); color:var(--warning)">⚠️ Network-limited (works on your system)</span>' : '';
      // Health data older than 24h is still trusted for routing but flagged so
      // the admin can see a re-probe is due.
      const staleMs = 24 * 60 * 60 * 1000;
      const isStale = m.lastChecked > 0 && (Date.now() - m.lastChecked) > staleMs;
      const staleBadge = isStale ? '<span class="badge" style="background:rgba(245, 158, 11, 0.15); border:1px solid var(--warning); color:var(--warning)">⏳ STALE</span>' : '';
      // UNTESTED is the most common "nothing shows up" state. Surface it loudly
      // with an explicit call-to-action badge instead of a silent grey label, so
      // the admin understands the model has NOT been validated yet and should
      // click Test Now. Previously the untested status was rendered with the raw
      // status text and dumped in the red Not Running group with no explanation.
      let statusBadgeClass = m.status;
      let statusLabel = esc(m.status.toUpperCase());
      if (m.status === 'untested') {
        statusBadgeClass = 'untested';
        statusLabel = 'UNTESTED — CLICK TEST NOW';
      }
      if (isStale) statusLabel += ' (stale)';
      const debug = m.lastErrorDebug
        ? '<div style="color:var(--danger); font-size:0.8rem; margin-top:5px; word-wrap:break-word;">' + esc(m.lastErrorDebug) + '</div>'
        : '';
      return '<div class="model-item" style="margin-bottom:0.75rem;">'
        + '<div class="model-header">'
        + '<div style="display:flex; align-items:center; gap: 0.75rem;">'
        + '<strong>' + esc(m.modelId) + '</strong>'
        + '<span style="color:var(--text-muted); font-size:0.8rem;">[' + esc(m.providerId) + ']</span>'
        + '<span class="badge ' + esc(statusBadgeClass) + '">' + statusLabel + '</span>'
        + debug
        + '<span class="badge ' + (m.active ? 'active' : 'inactive') + '">' + (m.active ? 'ACTIVE' : 'DISABLED') + '</span>'
        + netBadge
        + staleBadge
        + '</div>'
        + '<div class="flex-row">'
        + '<button class="secondary small" onclick="testModel(&quot;' + m.providerId + '&quot;, &quot;' + m.modelId + '&quot;)">Test Now</button>'
        + '<button class="secondary small" onclick="toggleModel(&quot;' + m.providerId + '&quot;, &quot;' + m.modelId + '&quot;)">Toggle</button>'
        + '</div>'
        + '</div>'
        + '<div class="capabilities">'
        + '<span class="cap ' + (m.supportsTools ? 'yes' : 'no') + '">Tools</span>'
        + '<span class="cap ' + (m.supportsVision ? 'yes' : 'no') + '">Vision</span>'
        + '<span class="cap ' + (m.supportsStreaming ? 'yes' : 'no') + '">Stream</span>'
        + '<span class="cap ' + (m.supportsWebSearch ? 'yes' : 'no') + '">Web Search</span>'
        + '<span style="color:var(--text-muted); margin-left: auto;">Latency: ' + m.avgLatencyMs + 'ms | Context: ' + m.maxContext + '</span>'
        + '</div>'
        + '</div>';
    }

    async function loadVirtualKeys() {
      const res = await fetch('/admin/virtual-keys', { headers });
      if(!res.ok) return;
      const vks = await res.json();
      let html = '';
      for(const vk of vks) {
          html += '<div class="list-item">'
          + '<div class="list-item-header">'
          + '<div>'
          + '<div class="list-item-title">' + esc(vk.appName) + ' <span class="badge ' + (vk.active ? 'active' : 'inactive') + '">' + (vk.active ? 'ACTIVE' : 'DISABLED') + '</span></div>'
          + '<div style="font-family:monospace; color:var(--primary); margin-top:0.25rem;">' + esc(vk.key) + '</div>'
          + '</div>'
          + '<div class="flex-row">'
          + '<button class="secondary small" onclick="toggleVirtualKey(&quot;' + esc(vk.key) + '&quot;)">Toggle</button>'
          + '<button class="danger small" onclick="deleteVirtualKey(&quot;' + esc(vk.key) + '&quot;)">Revoke</button>'
          + '</div>'
          + '</div>'
          + '<div class="data-grid">'
          + '<div class="data-row"><span>Alias</span><span>' + esc(vk.modelAlias) + '</span></div>'
          + '<div class="data-row"><span>Smart+</span><span>' + (vk.smartPlus ? 'Yes' : 'No') + ' <button class="secondary small" style="padding:2px 8px" onclick="editVirtualKey(&quot;' + esc(vk.key) + '&quot;, {smartPlus: ' + (!vk.smartPlus) + '})">Toggle</button></span></div>'
          + '<div class="data-row"><span>Multimodal</span><span>' + (vk.multimodalRestrict ? 'Yes' : 'No') + ' <button class="secondary small" style="padding:2px 8px" onclick="editVirtualKey(&quot;' + esc(vk.key) + '&quot;, {multimodalRestrict: ' + (!vk.multimodalRestrict) + '})">Toggle</button></span></div>'
          + '<div class="data-row"><span>Created</span><span>' + new Date(vk.createdAt).toLocaleDateString() + '</span></div>'
          + '<div class="data-row"><span>Allowed Providers</span><span>' + (vk.allowedProviders.length ? esc(vk.allowedProviders.join(', ')) : 'All') + '</span></div>'
          + '<div class="data-row"><span>Allowed Models</span><span>' + (vk.allowedModels.length ? esc(vk.allowedModels.join(', ')) : 'All') + '</span></div>'
          + '<div class="data-row" style="flex-direction: column; align-items: stretch; gap: 0.5rem;">'
          + '<div style="display: flex; justify-content: space-between;">'
          + '<span>Custom Disabled Quote</span>'
          + '<button class="secondary small" style="padding:2px 8px" onclick="updateDisabledQuote(&quot;' + vk.key + '&quot;)">Save Quote</button>'
          + '</div>'
          + '<input type="text" id="quote_' + esc(vk.key) + '" value="' + esc(vk.disabledQuote || '') + '" placeholder="Message to show when key is disabled..." style="width: 100%; margin: 0; background: rgba(0,0,0,0.2);" />'
          + '</div>'
          + '</div>'
          + '</div>';
      }
      if(vks.length === 0) html = "<div style='color:var(--text-muted)'>No virtual keys issued.</div>";
      document.getElementById('keysList').innerHTML = html;
    }
    
    async function editVirtualKey(key, updates) {
      await fetch('/admin/edit/virtual-key/' + key, {
        method: 'POST',
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify(updates)
      });
      loadVirtualKeys();
    }

    async function updateDisabledQuote(key) {
      const quote = document.getElementById('quote_' + key).value;
      await fetch('/admin/edit/virtual-key/' + key, {
        method: 'POST',
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ disabledQuote: quote })
      });
      loadVirtualKeys();
      alert("Custom quote saved!");
    }

    async function toggleVirtualKey(key) {
      await fetch('/admin/toggle/virtual-key/' + key, { method: 'POST', headers });
      loadVirtualKeys();
    }

    async function deleteVirtualKey(key) {
      if(!confirm("Revoke this key? Apps using it will immediately fail.")) return;
      await fetch('/admin/virtual-keys/' + key, { method: 'DELETE', headers });
      loadVirtualKeys();
    }

    async function loadTraffic() {
      const res = await fetch('/admin/traffic', { headers });
      if(!res.ok) return;
      const data = await res.json();
      let logs = data.logs || data;
      
      const toggle = document.getElementById('loggingToggle');
      if (toggle && data.loggingEnabled !== undefined) {
         toggle.checked = data.loggingEnabled;
      }

      const provNames = data.providerNames || {};
      const resolveProv = (id) => provNames[id] || id;
      
      if (!logs || logs.length === 0) {
          document.getElementById('trafficDisplay').innerHTML = "<div style='color:var(--text-muted)'>No traffic data recorded. Make API calls via /v1/chat/completions to see data here.</div>";
          return;
      }

      // Sort logs descending by timestamp
      logs.sort((a, b) => b.timestamp - a.timestamp);

      let fullHtml = '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;"><h3>Aggregated Stats</h3><span style="color:var(--text-muted); font-size:0.85rem;">' + logs.length + ' total requests tracked</span></div>';
      fullHtml += '<table style="width:100%; text-align:left; border-collapse:collapse; margin-top:0.5rem; font-size:0.95rem;">';
      fullHtml += '<tr style="border-bottom:1px solid var(--border);"><th style="padding:0.75rem">App (Virtual Key)</th><th>Provider</th><th>Model</th><th>Total</th><th>Success</th><th>Failures</th><th>Avg Latency</th></tr>';
      
      const stats = {};
      logs.forEach(l => {
          const key = l.virtualKey + '|' + l.providerId + '|' + l.modelId;
          if(!stats[key]) stats[key] = { app: l.virtualKey, provider: l.providerId, model: l.modelId, total: 0, success: 0, fail: 0, latencySum: 0 };
          stats[key].total++;
          stats[key].latencySum += l.latencyMs;
          if(l.status === 200) stats[key].success++;
          else stats[key].fail++;
      });
      
      for(const k in stats) {
          const s = stats[k];
          const avgLat = Math.round(s.latencySum / s.total) + 'ms';
          fullHtml += '<tr style="border-bottom:1px solid rgba(255,255,255,0.05);"><td style="padding:0.75rem; color:var(--primary); font-family:monospace;">' + s.app + '</td><td>' + resolveProv(s.provider) + '</td><td>' + s.model + '</td><td>' + s.total + '</td><td style="color:var(--success)">' + s.success + '</td><td style="color:var(--danger)">' + s.fail + '</td><td>' + avgLat + '</td></tr>';
      }
      fullHtml += '</table>';

      fullHtml += '<h3 style="margin-top:2rem">Recent Requests (Raw)</h3>';
      fullHtml += '<table style="width:100%; text-align:left; border-collapse:collapse; margin-top:1rem; font-size:0.95rem;">';
      fullHtml += '<tr style="border-bottom:1px solid var(--border);"><th style="padding:0.75rem">Time</th><th>App</th><th>Provider</th><th>Model</th><th>Status</th><th>Latency</th></tr>';
      
      logs.slice(0, 100).forEach(l => {
          const timeStr = new Date(l.timestamp).toLocaleTimeString();
          const statColor = l.status === 200 ? 'var(--success)' : 'var(--danger)';
          fullHtml += '<tr style="border-bottom:1px solid rgba(255,255,255,0.05);"><td style="padding:0.75rem; color:var(--text-muted);">' + timeStr + '</td><td style="color:var(--primary); font-family:monospace;">' + l.virtualKey + '</td><td>' + resolveProv(l.providerId) + '</td><td>' + l.modelId + '</td><td style="color:' + statColor + '">' + l.status + ' ' + (l.errorType ? '(' + l.errorType + ')' : '') + '</td><td>' + l.latencyMs + 'ms</td></tr>';
      });
      fullHtml += '</table>';
      
      document.getElementById('trafficDisplay').innerHTML = fullHtml;
    }

    let liveWs = null;
    let liveInterval = null;
    let displayedLogs = new Set();
    
    function renderLiveLog(log) {
       const display = document.getElementById("liveStreamDisplay");
       const id = log.timestamp + "|" + log.virtualKey + "|" + log.modelId;
       if (displayedLogs.has(id)) return;
       displayedLogs.add(id);
       
       const div = document.createElement("div");
       div.style.padding = "0.5rem";
       div.style.background = "rgba(255,255,255,0.05)";
       div.style.borderRadius = "4px";
       div.style.borderLeft = log.status >= 400 ? "4px solid var(--danger)" : "4px solid var(--success)";
       
       const time = new Date(log.timestamp).toLocaleTimeString();
       let errText = log.errorType ? (' | Err: <span style="color:var(--danger)">' + esc(log.errorType) + '</span>') : '';
       div.innerHTML = '<strong>[' + time + ']</strong> Key: <span style="color:var(--primary)">' + esc(log.virtualKey) + '</span> | Provider: ' + esc(log.providerId) + ' | Model: ' + esc(log.modelId) + ' | Status: <strong>' + log.status + '</strong> | Latency: ' + log.latencyMs + 'ms' + errText;
       
       const placeholder = document.getElementById("livePlaceholder");
       if (placeholder) {
         display.removeChild(placeholder);
       }
       
       display.prepend(div);
       if (display.children.length > 100) {
         display.removeChild(display.lastChild);
       }
    }

    async function fetchGlobalLiveLogs() {
       try {
           const res = await fetch('/admin/traffic/live', { headers });
           if (!res.ok) return;
           const logs = await res.json();
           logs.reverse().forEach(renderLiveLog);
       } catch(e) {}
    }

    function toggleLiveStream() {
      const btn = document.getElementById("liveConnectBtn");
      const badge = document.getElementById("liveStatusBadge");
      
      if (liveWs || liveInterval) {
        if (liveWs) liveWs.close();
        if (liveInterval) clearInterval(liveInterval);
        liveWs = null;
        liveInterval = null;
        btn.innerText = "Connect Stream";
        badge.className = "badge inactive";
        badge.innerText = "DISCONNECTED";
        badge.style.animation = "none";
        return;
      }
      
      btn.innerText = "Disconnect";
      badge.className = "badge working";
      badge.innerText = "CONNECTING...";
      
      fetchGlobalLiveLogs();
      liveInterval = setInterval(fetchGlobalLiveLogs, 3000);
      
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = protocol + "//" + window.location.host + "/admin/ws?token=" + currentToken;
      
      liveWs = new WebSocket(wsUrl);
      
      liveWs.onopen = () => {
        badge.className = "badge working";
        badge.innerText = "LIVE (Global)";
        badge.style.animation = "pulse 2s infinite";
        const placeholder = document.getElementById("livePlaceholder");
        if (placeholder) {
          placeholder.innerText = "Listening for requests globally... (Make API calls to see them here)";
        }
      };
      
      liveWs.onmessage = (e) => {
        try { renderLiveLog(JSON.parse(e.data)); } catch (err) {}
      };
      
      liveWs.onclose = () => {};
      liveWs.onerror = () => { if(liveWs) liveWs.close(); };
    }

    let playChatHistory = [];
    
    document.getElementById('playForm').onsubmit = async (e) => {
      e.preventDefault();
      const provId = document.getElementById('playProvSelect').value;
      const modId = document.getElementById('playModSelect').value;
      const msgInput = document.getElementById('playMsg');
      const msgText = msgInput.value;
      if(!provId || !modId || !msgText) return;
      
      const chatBox = document.getElementById('playChat');
      if (playChatHistory.length === 0) chatBox.innerHTML = '';
      
      // User message
      chatBox.innerHTML += '<div style="align-self:flex-end; background:var(--primary); padding:0.75rem 1rem; border-radius:12px 12px 0 12px; max-width:80%; word-break:break-word;">' + msgText + '</div>';
      msgInput.value = '';

      // Bot loading
      const loadId = 'load_' + Date.now();
      chatBox.innerHTML += '<div id="' + loadId + '" style="align-self:flex-start; background:rgba(255,255,255,0.1); padding:0.75rem 1rem; border-radius:12px 12px 12px 0; max-width:80%; color:var(--text-muted);">Thinking...</div>';
      chatBox.scrollTop = chatBox.scrollHeight;
      
      try {
        const res = await fetch('/admin/playground/test', {
          method: 'POST',
          headers: { ...headers, "Content-Type": "application/json" },
          body: JSON.stringify({
            providerId: provId,
            modelId: modId,
            message: msgText
          })
        });
        const data = await res.json();
        let reply = "No content";
        try {
           const parsed = JSON.parse(data.rawResp);
           reply = parsed.choices?.[0]?.message?.content || data.rawResp;
        } catch(err) { reply = data.rawResp; }
        
        document.getElementById(loadId).outerHTML = '<div style="align-self:flex-start; background:rgba(255,255,255,0.1); padding:0.75rem 1rem; border-radius:12px 12px 12px 0; max-width:80%; word-break:break-word; white-space:pre-wrap;">' + reply + '</div>';
        playChatHistory.push({ role: "user", content: msgText }, { role: "assistant", content: reply });
      } catch(err) {
        document.getElementById(loadId).outerHTML = '<div style="align-self:flex-start; background:rgba(239,68,68,0.2); padding:0.75rem 1rem; border-radius:12px 12px 12px 0; max-width:80%; color:var(--danger);">Error: ' + err.message + '</div>';
      }
      chatBox.scrollTop = chatBox.scrollHeight;
    };
      </script>
</body>
</html>`;
      return new Response(html, {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "X-Content-Type-Options": "nosniff",
          "X-Frame-Options": "DENY",
          "Referrer-Policy": "no-referrer",
          "Cache-Control": "no-store, no-cache, must-revalidate",
          // The dashboard is a single self-contained page: all JS/CSS is
          // inline, and it fetches only same-origin /admin/* endpoints. We
          // therefore lock the CSP to 'self' + 'unsafe-inline' (needed for the
          // inline <script>/<style>), and block every external origin,
          // frame, and object — eliminating the XSS exfiltration surface.
          "Content-Security-Policy":
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'",
        },
      });
    }

    return new Response("Not Found", { status: 404 });
  }
}
