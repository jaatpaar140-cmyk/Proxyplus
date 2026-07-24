import { Provider, ProviderModel } from "./types";
import { proxyNormalizedSSE } from "./router";

export interface ProviderAdapter {
  fetchChatCompletion(provider: Provider, model: ProviderModel, body: any, customCfOpts?: any, signal?: AbortSignal | null): Promise<Response>;
}

export interface ParsedMediaBlock {
  type: "text" | "media";
  text?: string;
  mimeType?: string;
  base64Data?: string;
  url?: string;
}

export async function fetchMediaAsBase64(url: string): Promise<{ mimeType: string; base64Data: string } | null> {
  if (!url || typeof url !== "string" || !url.startsWith("http")) return null;
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    if (
      host === 'localhost' || host === '::1' || host.endsWith('.local') ||
      host.startsWith('127.') || host.startsWith('169.254.') ||
      host.startsWith('10.') || host.startsWith('192.168.') ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host)
    ) {
      console.warn("SSRF blocked:", host);
      return null;
    }
    const res = await fetch(url, { headers: { "User-Agent": "AI-Gateway/1.0" } });
    if (!res.ok) return null;
    const arrayBuffer = await res.arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);
    let binary = "";
    const chunkSize = 1024;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const chunk = Array.from(bytes.subarray(i, i + chunkSize));
      binary += String.fromCharCode.apply(null, chunk);
    }
    const base64Data = btoa(binary);
    const contentType = res.headers.get("content-type") || "image/jpeg";
    const mimeType = contentType.split(";")[0].trim();
    return { mimeType, base64Data };
  } catch (e: any) {
    console.error("fetchMediaAsBase64 failed:", e.message);
    return null;
  }
}

export function ensureImagesInMessages(body: any): any[] {
  let messages = Array.isArray(body.messages) ? [...body.messages] : [];
  const topImages = body.images || (body.image ? [body.image] : null);
  if (Array.isArray(topImages) && topImages.length > 0) {
    const hasMediaInMsgs = messages.some(m => {
      if (m.image_url || m.image || m.images) return true;
      if (Array.isArray(m.content)) {
        return m.content.some((c: any) => parseContentBlock(c).type === "media");
      }
      return false;
    });

    if (!hasMediaInMsgs) {
      let lastUserIdx = -1;
      for (let i = messages.length - 1; i >= 0; i--) {
        if (messages[i].role === "user") {
          lastUserIdx = i;
          break;
        }
      }
      const mediaBlocks = topImages.map(img => parseContentBlock({ type: "image_url", image_url: img }));

      if (lastUserIdx !== -1) {
        const userMsg = { ...messages[lastUserIdx] };
        let contentArr: any[] = [];
        if (Array.isArray(userMsg.content)) {
          contentArr = [...userMsg.content];
        } else if (typeof userMsg.content === "string") {
          contentArr = [{ type: "text", text: userMsg.content }];
        }
        for (const mb of mediaBlocks) {
          const urlStr = mb.url || (mb.base64Data ? `data:${mb.mimeType};base64,${mb.base64Data}` : "");
          if (urlStr) contentArr.push({ type: "image_url", image_url: { url: urlStr } });
        }
        userMsg.content = contentArr;
        messages[lastUserIdx] = userMsg;
      } else {
        const contentArr = mediaBlocks.map(mb => ({
          type: "image_url",
          image_url: { url: mb.url || (mb.base64Data ? `data:${mb.mimeType};base64,${mb.base64Data}` : "") }
        }));
        messages.push({ role: "user", content: contentArr });
      }
    }
  }
  return messages;
}

export function parseContentBlock(c: any): ParsedMediaBlock {
  if (typeof c === "string") {
    if (c.startsWith("data:image/") || c.startsWith("data:application/pdf") || c.startsWith("data:audio/")) {
      const commaIdx = c.indexOf(",");
      const header = commaIdx !== -1 ? c.slice(0, commaIdx) : "";
      const base64Data = commaIdx !== -1 ? c.slice(commaIdx + 1) : "";
      const mimeMatch = header.match(/data:(.*?);/);
      const mimeType = mimeMatch ? mimeMatch[1] : "image/jpeg";
      return { type: "media", mimeType, base64Data, url: c };
    }
    return { type: "text", text: c };
  }
  if (!c || typeof c !== "object") return { type: "text", text: "" };

  if (c.type === "text") {
    return { type: "text", text: c.text || "" };
  }

  let rawUrl = "";
  let extractedMime = "";
  let extractedBase64 = "";

  if (typeof c.image_url === "string") {
    rawUrl = c.image_url;
  } else if (c.image_url && typeof c.image_url.url === "string") {
    rawUrl = c.image_url.url;
  } else if (typeof c.image === "string") {
    rawUrl = c.image;
  } else if (c.image && typeof c.image.url === "string") {
    rawUrl = c.image.url;
  } else if (Array.isArray(c.images) && c.images.length > 0) {
    const firstImg = c.images[0];
    rawUrl = typeof firstImg === "string" ? firstImg : (firstImg?.url || "");
  } else if (typeof c.url === "string") {
    rawUrl = c.url;
  } else if (c.source && typeof c.source.data === "string") {
    extractedBase64 = c.source.data;
    extractedMime = c.source.media_type || "image/jpeg";
    rawUrl = extractedBase64.startsWith("data:") ? extractedBase64 : `data:${extractedMime};base64,${extractedBase64}`;
  } else if (c.inlineData && typeof c.inlineData.data === "string") {
    extractedBase64 = c.inlineData.data;
    extractedMime = c.inlineData.mimeType || "image/jpeg";
    rawUrl = `data:${extractedMime};base64,${extractedBase64}`;
  } else if (c.inline_data && typeof c.inline_data.data === "string") {
    extractedBase64 = c.inline_data.data;
    extractedMime = c.inline_data.mime_type || "image/jpeg";
    rawUrl = `data:${extractedMime};base64,${extractedBase64}`;
  } else if (typeof c.data === "string") {
    rawUrl = c.data;
  } else if (c.type === "document" || c.type === "file" || c.type === "input_audio" || c.document || c.file) {
    const docObj = c.document || c.file || c.input_audio || {};
    rawUrl = docObj.data || docObj.url || "";
  }

  if (rawUrl) {
    if (rawUrl.startsWith("data:")) {
      const commaIdx = rawUrl.indexOf(",");
      const header = commaIdx !== -1 ? rawUrl.slice(0, commaIdx) : "";
      const base64Data = commaIdx !== -1 ? rawUrl.slice(commaIdx + 1) : "";
      const mimeMatch = header.match(/data:(.*?);/);
      const mimeType = mimeMatch ? mimeMatch[1] : (extractedMime || "image/jpeg");
      return { type: "media", mimeType, base64Data, url: rawUrl };
    }
    return { type: "media", mimeType: extractedMime || "image/jpeg", url: rawUrl };
  }

  return { type: "text", text: c.text ? c.text : (typeof c === "object" ? JSON.stringify(c) : String(c)) };
}

export interface NormalizedFunctionTool {
  name: string;
  description: string;
  parameters: any;
}

export function fixToolCallArguments(args: any): any {
  if (!args || typeof args !== "object") return args;
  const result: Record<string, any> = {};
  for (const [key, val] of Object.entries(args)) {
    if (typeof val === "string") {
      const lowerKey = key.toLowerCase();
      if (
        (lowerKey.includes("length") ||
         lowerKey.includes("limit") ||
         lowerKey.includes("count") ||
         lowerKey.includes("max") ||
         lowerKey.includes("size") ||
         lowerKey.includes("page") ||
         lowerKey.includes("num") ||
         lowerKey.includes("offset") ||
         lowerKey.includes("timeout")) &&
        /^\d+$/.test(val)
      ) {
        result[key] = parseInt(val, 10);
      } else if (val === "true") {
        result[key] = true;
      } else if (val === "false") {
        result[key] = false;
      } else {
        result[key] = val;
      }
    } else {
      result[key] = val;
    }
  }
  return result;
}

export function normalizeFunctionTool(t: any): NormalizedFunctionTool | null {
  if (!t || typeof t !== "object") return null;

  const rawName = (t.function?.name || t.name || t.type || "").toString();
  const lowerName = rawName.toLowerCase();

  // Normalize any web search / browser / link parser tool
  if (
    lowerName.includes("search") ||
    lowerName.includes("google") ||
    lowerName.includes("browse") ||
    lowerName.includes("url") ||
    lowerName.includes("link") ||
    lowerName.includes("fetch")
  ) {
    const isLinkParser = lowerName.includes("url") || lowerName.includes("link") || lowerName.includes("fetch");
    return {
      name: isLinkParser ? "parse_link" : "web_search",
      description: isLinkParser
        ? "Parse and extract content from a specific web URL or link."
        : "Search the web for real-time information, news, current events, live data, or prices.",
      parameters: (t.function?.parameters || t.parameters) || {
        type: "object",
        properties: isLinkParser ? {
          url: { type: "string", description: "The target webpage URL to parse" },
          maxLength: { type: "integer", description: "Maximum number of characters to extract" }
        } : {
          query: { type: "string", description: "The search query" }
        },
        required: [isLinkParser ? "url" : "query"]
      }
    };
  }

  if (t.function && typeof t.function === "object") {
    return {
      name: t.function.name || t.name || "function",
      description: t.function.description || t.description || "",
      parameters: t.function.parameters || t.parameters || { type: "object", properties: {} }
    };
  }

  const name = t.name || (typeof t.type === "string" && t.type !== "function" ? t.type : "function");
  return {
    name,
    description: t.description || "",
    parameters: t.parameters || { type: "object", properties: {} }
  };
}

// ---------------------------------------------------------------------------
// Resilient provider fetch (spec 4.9 / network_layer mitigation).
//
// Cloudflare's shared egress IPs are sometimes blocked/throttled or have TLS
// quirks with certain providers (notably NVIDIA NIM, Groq) — so a fetch from a
// Worker fails even though the SAME key/host works perfectly from a local
// machine or another platform. This is a CLOUDFLARE-EDGE problem, NOT a broken
// model, and it must never be persisted as `broken`.
//
// The proven mitigation (already used by the live chat path in router.ts) is
// to retry the exact same request with `cf.resolveOverride` pointing at a
// public resolver (cloudflare-dns.com). That re-resolves + re-routes the
// egress through a different path and succeeds where the first attempt failed.
//
// This helper wraps the adapter call, catches the Cloudflare-side failures
// (TypeError = network failure, AbortError = timeout), retries once with the
// resolveOverride, and reports whether a network retry happened so callers can
// flag `networkIssueSuspected` instead of marking the model `broken`.
// ---------------------------------------------------------------------------
export interface RetryFetchResult {
  response: Response | null;
  threw: boolean;
  errorName?: string;
  errorMessage?: string;
  networkRetried?: boolean;
  rateLimitRetried?: boolean;
}

function getRandomIP() {
  return `${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`;
}

// A response is a "rate-limit / transient-provider" response that is worth
// retrying with a different egress route: 429 (too many requests), 402 (payment
// required / free-tier exhausted), 500/502/503/504 (transient server errors,
// common when Cloudflare's shared egress IP gets throttled by the provider).
// These are NOT permanent model faults and must never be persisted as `broken`.
function isRetryableStatus(status: number): boolean {
  return status === 429 || status === 402 ||
    (status >= 500 && status <= 504);
}

export async function fetchWithNetworkRetry(
  adapter: ProviderAdapter,
  provider: Provider,
  model: ProviderModel,
  body: any,
  customCfOpts?: any,
  timeoutMs: number = 20000,
  opts?: { rateLimitRetries?: number; retryBaseDelayMs?: number }
): Promise<RetryFetchResult> {
  const baseCf = customCfOpts || { cacheTtl: 0, cacheEverything: false };
  const rateLimitRetries = opts?.rateLimitRetries ?? 3;
  const retryBaseDelayMs = opts?.retryBaseDelayMs ?? 4000;

  // Resolve-override re-route used for BOTH network failures and rate-limits:
  // Cloudflare's shared egress IP is what gets throttled/blocked, so re-resolving
  // + re-routing through a different path is the proven mitigation.
  const rerouteCf = {
    ...baseCf,
    resolveOverride: "cloudflare-dns.com",
    cacheTtl: 0,
    cacheEverything: false,
  };

  const attempt = async (cfOverride?: any): Promise<{ res: Response | null; err?: any }> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      // Pass the AbortSignal into the adapter so an unreachable host (hanging
      // DNS / dead IP) cannot block the probe forever. Without this the health
      // check could hang for minutes on a single dead endpoint.
      const res = await adapter.fetchChatCompletion(provider, model, body, cfOverride || baseCf, controller.signal);
      return { res };
    } catch (err: any) {
      return { res: null, err };
    } finally {
      clearTimeout(timer);
    }
  };

  // --- First attempt (normal egress). ---
  const first = await attempt();
  if (first.res) {
    return { response: first.res, threw: false, networkRetried: false, rateLimitRetried: false };
  }

  const firstErr = first.err;
  const isNetwork = firstErr && (firstErr.name === "TypeError" || firstErr.name === "AbortError");
  if (!isNetwork) {
    // Non-network throw (shouldn't normally happen from fetch) — surface as-is.
    return {
      response: null,
      threw: true,
      errorName: firstErr?.name,
      errorMessage: firstErr?.message,
      networkRetried: false,
      rateLimitRetried: false,
    };
  }

  // Cloudflare edge network/timeout failure — retry with resolveOverride to
  // re-route egress through a different path before declaring anything broken.
  // Try the re-route, then fall back to plain egress if resolveOverride is
  // restricted on non-Enterprise Workers.
  let second = await attempt(rerouteCf);
  if (!second.res && second.err) {
    second = await attempt({ ...baseCf, cacheTtl: 0, cacheEverything: false });
  }
  if (second.res) {
    return { response: second.res, threw: false, networkRetried: true, rateLimitRetried: false };
  }
  const secondErr = second.err;
  return {
    response: null,
    threw: true,
    errorName: secondErr?.name,
    errorMessage: secondErr?.message,
    networkRetried: true,
    rateLimitRetried: false,
  };
}

// Variant used by the health/capability probes: a PROBE can get a 429/402/5xx
// because the provider throttles the gateway's shared egress IP — this is a
// transient, Cloudflare-edge artifact, NOT a model fault. We retry those
// responses with a re-routed egress + exponential backoff (up to
// `rateLimitRetries` times) instead of letting the caller mark the model
// `untested`/`broken` on a single throttled probe.
export async function fetchWithProbeRetry(
  adapter: ProviderAdapter,
  provider: Provider,
  model: ProviderModel,
  body: any,
  customCfOpts?: any,
  timeoutMs: number = 20000,
  opts?: { rateLimitRetries?: number; retryBaseDelayMs?: number }
): Promise<RetryFetchResult> {
  const rateLimitRetries = opts?.rateLimitRetries ?? 3;
  const retryBaseDelayMs = opts?.retryBaseDelayMs ?? 4000;

  const rerouteCf = {
    ...(customCfOpts || { cacheTtl: 0, cacheEverything: false }),
    resolveOverride: "cloudflare-dns.com",
    cacheTtl: 0,
    cacheEverything: false,
  };
  const plainCf = customCfOpts || { cacheTtl: 0, cacheEverything: false };

  const attempt = async (cfOverride?: any): Promise<{ res: Response | null; err?: any }> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await adapter.fetchChatCompletion(provider, model, body, cfOverride || plainCf, controller.signal);
      return { res };
    } catch (err: any) {
      return { res: null, err };
    } finally {
      clearTimeout(timer);
    }
  };

  // Try plain egress first.
  let last = await attempt(plainCf);
  let rateLimitRetried = false;

  for (let i = 0; i < rateLimitRetries && (last.res ? isRetryableStatus(last.res.status) : true); i++) {
    // On a network throw OR a retryable status, wait (exp backoff) and retry via
    // the re-routed egress; if that also fails with a retryable status, fall
    // back to plain egress on the next loop.
    await new Promise<void>(r => setTimeout(r, retryBaseDelayMs * Math.pow(2, i)));
    const attemptCf = i % 2 === 0 ? rerouteCf : plainCf;
    const next = await attempt(attemptCf);
    rateLimitRetried = true;
    if (next.res && !isRetryableStatus(next.res.status)) {
      return { response: next.res, threw: false, networkRetried: attemptCf === rerouteCf, rateLimitRetried: true };
    }
    last = next;
    if (!last.res && !last.err) break;
    // If it threw a non-network error, stop.
    if (!last.res && last.err && !(last.err.name === "TypeError" || last.err.name === "AbortError")) {
      return { response: null, threw: true, errorName: last.err?.name, errorMessage: last.err?.message, networkRetried: false, rateLimitRetried: true };
    }
  }

  if (last.res) {
    return { response: last.res, threw: false, networkRetried: false, rateLimitRetried };
  }
  const err = last.err;
  return {
    response: null,
    threw: true,
    errorName: err?.name,
    errorMessage: err?.message,
    networkRetried: false,
    rateLimitRetried,
  };
}

export class OpenAICompatibleAdapter implements ProviderAdapter {
  async fetchChatCompletion(provider: Provider, model: ProviderModel, body: any, customCfOpts?: any, signal?: AbortSignal | null): Promise<Response> {
    // Strip gateway-internal parameters so upstream LLM APIs (Groq, OpenRouter, DeepSeek, etc.)
    // don't reject or slow down due to unknown top-level JSON fields.
    const cleanBody = { ...body };
    delete cleanBody.conversation_id;
    delete cleanBody.virtualKey;
    delete cleanBody.appName;
    delete cleanBody.allowedModels;
    delete cleanBody.allowedProviders;
    delete cleanBody.smartPlus;
    delete cleanBody.multimodalRestrict;

    const messagesWithImages = ensureImagesInMessages(cleanBody);
    delete cleanBody.images;
    delete cleanBody.image;

    // Format messages so text-only content is a plain string (essential for tool/function calling on Groq/DeepSeek/Ollama/OpenRouter)
    // while image/media messages retain OpenAI image_url array structure.
    const formattedMessages = await Promise.all(messagesWithImages.map(async (msg: any) => {
      // Support direct message-level image properties (msg.image_url / msg.images / msg.image)
      const rawMsgImage = msg.image_url || msg.image || (Array.isArray(msg.images) ? msg.images[0] : null);
      if (rawMsgImage && typeof msg.content === "string") {
        const parsed = parseContentBlock({ type: "image_url", image_url: rawMsgImage });
        let imgUrl = parsed.url || "";
        if (parsed.base64Data) {
          imgUrl = `data:${parsed.mimeType || "image/jpeg"};base64,${parsed.base64Data}`;
        } else if (imgUrl && imgUrl.startsWith("http")) {
          const fetched = await fetchMediaAsBase64(imgUrl);
          if (fetched) imgUrl = `data:${fetched.mimeType};base64,${fetched.base64Data}`;
        }
        return {
          ...msg,
          content: [
            { type: "text", text: msg.content },
            { type: "image_url", image_url: { url: imgUrl } }
          ]
        };
      }

      if (!Array.isArray(msg.content)) return msg;

      let hasMedia = false;
      const mediaBlocks: any[] = [];

      for (const c of msg.content) {
        const parsed = parseContentBlock(c);
        if (parsed.type === "media") {
          hasMedia = true;
          let imgUrl = parsed.url || "";
          if (parsed.base64Data) {
            imgUrl = `data:${parsed.mimeType || "image/jpeg"};base64,${parsed.base64Data}`;
          } else if (imgUrl && imgUrl.startsWith("http")) {
            const fetched = await fetchMediaAsBase64(imgUrl);
            if (fetched) imgUrl = `data:${fetched.mimeType};base64,${fetched.base64Data}`;
          }
          if (imgUrl) {
            mediaBlocks.push({ type: "image_url", image_url: { url: imgUrl } });
          }
        } else {
          if (parsed.text) {
            mediaBlocks.push({ type: "text", text: parsed.text });
          }
        }
      }

      if (!hasMedia) {
        let combinedText = "";
        for (const b of mediaBlocks) {
          if (b.type === "text") combinedText += (combinedText ? "\n" : "") + b.text;
        }
        return { ...msg, content: combinedText || (typeof msg.content === "string" ? msg.content : "") };
      }

      return { ...msg, content: mediaBlocks };
    }));

    // Ensure all tools (web search, link parsing, function calls) are normalized into valid OpenAI tool definitions
    if (Array.isArray(cleanBody.tools) && cleanBody.tools.length > 0) {
      cleanBody.tools = cleanBody.tools
        .map(normalizeFunctionTool)
        .filter((f: NormalizedFunctionTool | null): f is NormalizedFunctionTool => f !== null)
        .map((f: NormalizedFunctionTool) => ({
          type: "function",
          function: f
        }));
    }

    const outboundBody = {
      ...cleanBody,
      messages: formattedMessages,
      model: model.modelId
    };

    const authHeader = provider.authHeaderFormat ? provider.authHeaderFormat.replace("{key}", provider.apiKey) : `Bearer ${provider.apiKey}`;
    
    const headers = new Headers();
    headers.set("Authorization", authHeader);
    headers.set("Content-Type", "application/json");
    headers.set("Accept-Encoding", "identity");
    headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
    headers.set("HTTP-Referer", "https://ai-gateway.jaatpaar-ai.workers.dev");
    headers.set("X-Title", "AI-Gateway");
    const fakeIp = getRandomIP();
    headers.set("X-Forwarded-For", fakeIp);
    headers.set("X-Real-IP", fakeIp);

    const cfOpts = customCfOpts || {
      cacheTtl: 0,
      cacheEverything: false,
    };

    const requestInit: RequestInit<any> = {
      method: "POST",
      headers,
      body: JSON.stringify(outboundBody),
      cf: cfOpts
    };
    if (signal) requestInit.signal = signal;

    // Robustly build the chat completions URL regardless of how the admin
    // entered the base URL: handles trailing slashes, a base that already ends
    // in /v1, one that already includes /chat/completions, or an arbitrary
    // sub-path. We normalize and then ensure exactly one /v1/chat/completions.
    let base = provider.baseUrl.trim().replace(/\/+$/, '');
    let url: string;
    if (base.endsWith('/chat/completions')) {
      // Already a full endpoint URL — use as-is.
      url = base;
    } else if (base.endsWith('/v1')) {
      // Has /v1 already — just append the endpoint path.
      url = `${base}/chat/completions`;
    } else {
      // Raw base — append /v1/chat/completions.
      url = `${base}/v1/chat/completions`;
    }
    return fetch(url, requestInit);
  }
}

export class GeminiAdapter implements ProviderAdapter {
  async fetchChatCompletion(provider: Provider, model: ProviderModel, body: any, customCfOpts?: any, signal?: AbortSignal | null): Promise<Response> {
    const contents: any[] = [];
    const toolCallIdToName: Record<string, string> = {};
    const inputMessages = ensureImagesInMessages(body);
    for (const msg of inputMessages) {
      if (msg.tool_calls && Array.isArray(msg.tool_calls)) {
        for (const tc of msg.tool_calls) {
          if (tc.type === 'function') toolCallIdToName[tc.id] = tc.function.name;
        }
      }
      if (msg.role === 'tool') {
        const lastContent = contents[contents.length - 1];
        let respContent: any;
        try {
          respContent = typeof msg.content === 'string' ? JSON.parse(msg.content) : msg.content;
        } catch {
          respContent = { result: msg.content };
        }
        const funcResp = {
          functionResponse: {
            name: msg.name || toolCallIdToName[msg.tool_call_id] || "function",
            response: typeof respContent === 'object' && respContent !== null ? respContent : { result: respContent }
          }
        };
        if (lastContent && lastContent.role === 'user') {
          lastContent.parts.push(funcResp);
        } else {
          contents.push({
            role: 'user',
            parts: [funcResp]
          });
        }
        continue;
      }
      
      let parts: any[] = [];
      const rawMsgImage = msg.image_url || msg.image || (Array.isArray(msg.images) ? msg.images[0] : null);
      if (rawMsgImage) {
        const parsed = parseContentBlock({ type: "image_url", image_url: rawMsgImage });
        if (parsed.base64Data) {
          parts.push({
            inlineData: {
              mimeType: parsed.mimeType || "image/jpeg",
              data: parsed.base64Data
            }
          });
        }
      }

      if (Array.isArray(msg.content)) {
        for (const block of msg.content) {
          const parsed = parseContentBlock(block);
          if (parsed.type === "text") {
            if (parsed.text) parts.push({ text: parsed.text });
          } else if (parsed.type === "media") {
            let mediaBase64 = parsed.base64Data;
            let mediaMime = parsed.mimeType || "image/jpeg";
            if (!mediaBase64 && parsed.url && parsed.url.startsWith("http")) {
              const fetched = await fetchMediaAsBase64(parsed.url);
              if (fetched) {
                mediaBase64 = fetched.base64Data;
                mediaMime = fetched.mimeType;
              }
            }
            if (mediaBase64) {
              parts.push({
                inlineData: {
                  mimeType: mediaMime,
                  data: mediaBase64
                }
              });
            } else if (parsed.url) {
              parts.push({ text: `[Attached media: ${parsed.url}]` });
            }
          }
        }
      } else if (msg.content) {
        parts.push({ text: msg.content });
      }
      
      if (msg.tool_calls && Array.isArray(msg.tool_calls)) {
        for (const tc of msg.tool_calls) {
          if (tc.type === 'function') {
            parts.push({
              functionCall: {
                name: tc.function.name,
                args: tc.function.arguments ? JSON.parse(tc.function.arguments) : {}
              }
            });
          }
        }
      }
      
      if (parts.length > 0) {
        contents.push({
          role: msg.role === 'assistant' ? 'model' : 'user',
          parts: parts
        });
      }
    }

    const geminiBody: any = { contents };
    const hasSearchTool = Array.isArray(body.tools) && body.tools.some((t: any) => {
      const name = (t.function?.name || t.name || t.type || "").toLowerCase();
      return name.includes("search") || name.includes("google") || name.includes("browse") || name.includes("web") || name.includes("url") || name.includes("link");
    });

    if (Array.isArray(body.tools) && body.tools.length > 0) {
      const declarations = body.tools
        .map(normalizeFunctionTool)
        .filter((f: NormalizedFunctionTool | null): f is NormalizedFunctionTool => f !== null)
        .map((f: NormalizedFunctionTool) => ({
          name: f.name,
          description: f.description,
          parameters: f.parameters
        }));

      const toolsObj: any = {};
      if (declarations.length > 0) {
        toolsObj.functionDeclarations = declarations;
      }
      if (hasSearchTool) {
        toolsObj.googleSearch = {};
      }
      geminiBody.tools = [toolsObj];
    } else if (hasSearchTool) {
      geminiBody.tools = [{ googleSearch: {} }];
    }
    
    // Gemini Native /v1beta/ endpoint. Build the method + query cleanly so we
    // never emit a dangling "&" (the previous code produced
    // `...?alt=sse&key=...` which works but is sloppy). The API key is passed
    // as a query param per Gemini's auth model.
    const baseUrl = provider.baseUrl.replace(/\/+$/, '');
    const urlBase = baseUrl.endsWith('/v1beta') ? baseUrl : `${baseUrl}/v1beta`;
    const method = body.stream ? 'streamGenerateContent' : 'generateContent';
    const url = `${urlBase}/models/${model.modelId}:${method}?alt=${body.stream ? 'sse' : 'json'}&key=${provider.apiKey}`;
    
    const cfOpts = customCfOpts || { cacheTtl: 0, cacheEverything: false };
    const headers = new Headers();
    headers.set("Content-Type", "application/json");
    // Force identity encoding so the provider never gzips the body — a gzipped
    // response would have to be decompressed by the Worker and is exactly what
    // Cloudflare's edge can mangle (spec 4.10).
    headers.set("Accept-Encoding", "identity");
    headers.set("Accept", "application/json");
    headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
    headers.set("HTTP-Referer", "https://ai-gateway.jaatpaar-ai.workers.dev");
    headers.set("X-Title", "AI-Gateway");
    const fakeIp = getRandomIP();
    headers.set("X-Forwarded-For", fakeIp);
    headers.set("X-Real-IP", fakeIp);
    const requestInit: RequestInit<any> = {
      method: "POST",
      headers,
      body: JSON.stringify(geminiBody),
      cf: cfOpts
    };
    if (signal) requestInit.signal = signal;

    const res = await fetch(url, requestInit);
    
    if (!res.ok) {
        return res; 
    }
    
    if (body.stream && res.body) {
        // Normalize Gemini's native SSE into OpenAI-format `data: {...}` chunks
        // on a standalone ReadableStream, then relay it through the SAME
        // hardened SSE pipeline used for OpenAI providers (proxyNormalizedSSE).
        // This guarantees Cloudflare's edge cannot gzip/re-chunk/mangle the
        // relayed stream and corrupt a mid-stream tool_call fragment (spec 4.10).
        const { readable, writable } = new TransformStream();
        const reader = res.body.getReader();
        const writer = writable.getWriter();

        (async () => {
            const decoder = new TextDecoder();
            const encoder = new TextEncoder();
            // Monotonic tool-call index that spans ALL chunks in this stream, so
            // OpenAI clients see contiguous indices (0,1,2...) even when text and
            // functionCall parts arrive interleaved across network chunks.
            let toolCallIndex = 0;
            try {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) {
                        await writer.write(encoder.encode("data: [DONE]\n\n"));
                        break;
                    }
                    const chunk = decoder.decode(value, { stream: true });
                    const lines = chunk.split('\n');
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            try {
                                const data = JSON.parse(line.slice(6));
                                const parts = data.candidates?.[0]?.content?.parts || [];
                                const delta: any = {};
                                if (parts.length > 0) {
                                    for (let i = 0; i < parts.length; i++) {
                                        const part = parts[i];
                                        if (part.text) {
                                            delta.content = (delta.content || "") + part.text;
                                        } else if (part.functionCall) {
                                            if (!delta.tool_calls) delta.tool_calls = [];
                                            delta.tool_calls.push({
                                                index: toolCallIndex++,
                                                id: "call_" + crypto.randomUUID(),
                                                type: "function",
                                                function: {
                                                    name: part.functionCall.name,
                                                    arguments: JSON.stringify(fixToolCallArguments(part.functionCall.args || {}))
                                                }
                                            });
                                        }
                                    }
                                } else {
                                    delta.content = "";
                                }

                                let finish_reason = null;
                                const geminiFinish = data.candidates?.[0]?.finishReason;
                                if (geminiFinish) {
                                    finish_reason = geminiFinish === 'STOP' ? 'stop' : (delta.tool_calls ? 'tool_calls' : 'stop');
                                }

                                const chunkId = "chatcmpl-" + crypto.randomUUID();
                                const openAIChunk = {
                                    id: chunkId,
                                    object: "chat.completion.chunk",
                                    created: Math.floor(Date.now() / 1000),
                                    model: model.modelId,
                                    choices: [{ index: 0, delta: delta, finish_reason: finish_reason }]
                                };
                                await writer.write(encoder.encode(`data: ${JSON.stringify(openAIChunk)}\n\n`));
                            } catch(e) {}
                        }
                    }
                }
            } catch(e) { console.error("Gemini stream error:", e); }
            try { await writer.close(); } catch(e) {}
        })();

        return proxyNormalizedSSE(readable);
    }

    const data: any = await res.json();
    const parts = data.candidates?.[0]?.content?.parts || [];
    let text = "";
    let toolCalls: any[] | undefined = undefined;
    
    for (const p of parts) {
      if (p.text) {
        text += p.text;
      } else if (p.functionCall) {
        if (!toolCalls) toolCalls = [];
        toolCalls.push({
          id: "call_" + crypto.randomUUID(),
          type: "function",
          function: {
            name: p.functionCall.name,
            arguments: JSON.stringify(fixToolCallArguments(p.functionCall.args || {}))
          }
        });
      }
    }

    // Append live web search sources & references if Gemini native grounding was used
    const grounding = data.candidates?.[0]?.groundingMetadata;
    if (grounding?.groundingChunks && Array.isArray(grounding.groundingChunks)) {
      const links = grounding.groundingChunks
        .filter((c: any) => c.web?.uri && c.web?.title)
        .map((c: any) => `- [${c.web.title}](${c.web.uri})`);
      if (links.length > 0) {
        const uniqueLinks = Array.from(new Set(links)).join("\n");
        if (!text.includes(uniqueLinks)) {
          text += `\n\n**Sources & References:**\n${uniqueLinks}`;
        }
      }
    }
    
    const openAIResponse = {
      id: "chatcmpl-" + crypto.randomUUID(),
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: model.modelId,
      choices: [{
        index: 0,
        message: { role: "assistant", content: text, tool_calls: toolCalls },
        finish_reason: toolCalls ? "tool_calls" : "stop"
      }],
      usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
    };
    
    return new Response(JSON.stringify(openAIResponse), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }
}

export class ClaudeAdapter implements ProviderAdapter {
  async fetchChatCompletion(provider: Provider, model: ProviderModel, body: any, customCfOpts?: any, signal?: AbortSignal | null): Promise<Response> {
    let system = "";
    const messages = [];
    const inputMessages = ensureImagesInMessages(body);
    
    // Process messages (extract system prompt and format vision)
    for (const msg of inputMessages) {
      if (msg.role === 'system') {
        system += msg.content + "\n";
      } else if (msg.role === 'tool') {
        const lastMsg = messages[messages.length - 1];
        const toolRes = {
            type: 'tool_result',
            tool_use_id: msg.tool_call_id,
            content: typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content)
        };
        if (lastMsg && lastMsg.role === 'user') {
            if (!Array.isArray(lastMsg.content)) lastMsg.content = [{ type: 'text', text: lastMsg.content }];
            lastMsg.content.push(toolRes);
        } else {
            messages.push({
                role: 'user',
                content: [toolRes]
            });
        }
      } else {
        const mappedMsg: any = { role: msg.role === 'assistant' ? 'assistant' : 'user' };
        let contentArr: any[] = [];
        
        if (Array.isArray(msg.content)) {
          for (const block of msg.content) {
            const parsed = parseContentBlock(block);
            if (parsed.type === "text") {
              if (parsed.text) contentArr.push({ type: "text", text: parsed.text });
            } else if (parsed.type === "media") {
              let mediaBase64 = parsed.base64Data;
              let mediaMime = parsed.mimeType || "image/jpeg";
              if (!mediaBase64 && parsed.url && parsed.url.startsWith("http")) {
                const fetched = await fetchMediaAsBase64(parsed.url);
                if (fetched) {
                  mediaBase64 = fetched.base64Data;
                  mediaMime = fetched.mimeType;
                }
              }
              if (mediaBase64) {
                const isDoc = mediaMime.includes("pdf") || mediaMime.includes("document") || mediaMime.includes("text/") || mediaMime.includes("csv");
                contentArr.push({
                  type: isDoc ? "document" : "image",
                  source: {
                    type: "base64",
                    media_type: mediaMime,
                    data: mediaBase64
                  }
                });
              } else if (parsed.url) {
                contentArr.push({ type: "text", text: `[Attached media URL: ${parsed.url}]` });
              }
            }
          }
        } else if (msg.content) {
          contentArr.push({ type: "text", text: msg.content });
        }
        
        if (msg.tool_calls && Array.isArray(msg.tool_calls)) {
            for (const tc of msg.tool_calls) {
                if (tc.type === 'function') {
                    contentArr.push({
                        type: 'tool_use',
                        id: tc.id,
                        name: tc.function.name,
                        input: tc.function.arguments ? JSON.parse(tc.function.arguments) : {}
                    });
                }
            }
        }
        
        mappedMsg.content = contentArr.length > 0 ? contentArr : (msg.content || "");
        messages.push(mappedMsg);
      }
    }
    
    const claudeBody: any = {
      model: model.modelId,
      max_tokens: body.max_tokens || 4096,
      messages: messages,
      stream: body.stream || false
    };
    
    if (system) {
       claudeBody.system = system.trim();
    }
    
    // Tool conversion
    if (Array.isArray(body.tools) && body.tools.length > 0) {
      const declarations = body.tools
        .map(normalizeFunctionTool)
        .filter((f: NormalizedFunctionTool | null): f is NormalizedFunctionTool => f !== null)
        .map((f: NormalizedFunctionTool) => ({
          name: f.name,
          description: f.description,
          input_schema: f.parameters
        }));
      if (declarations.length > 0) {
        claudeBody.tools = declarations;
      }
    }
    if (body.tool_choice && typeof body.tool_choice === 'object') {
       claudeBody.tool_choice = { type: "tool", name: body.tool_choice.function.name };
    } else if (body.tool_choice === "auto" || body.tool_choice === "any") {
       claudeBody.tool_choice = { type: body.tool_choice };
    }

    const rawAuth = provider.authHeaderFormat ? provider.authHeaderFormat.replace("{key}", provider.apiKey) : provider.apiKey;
    const cleanApiKey = rawAuth.replace(/^Bearer\s+/i, '').trim();
    
    const headers = new Headers();
    headers.set("x-api-key", cleanApiKey);
    headers.set("anthropic-version", "2023-06-01");
    headers.set("Content-Type", "application/json");
    headers.set("Accept-Encoding", "identity");
    headers.set("Accept", "application/json");
    headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
    headers.set("HTTP-Referer", "https://ai-gateway.jaatpaar-ai.workers.dev");
    headers.set("X-Title", "AI-Gateway");
    const fakeIp = getRandomIP();
    headers.set("X-Forwarded-For", fakeIp);
    headers.set("X-Real-IP", fakeIp);

    const cfOpts = customCfOpts || { cacheTtl: 0, cacheEverything: false };
    const requestInit: RequestInit<any> = {
      method: "POST",
      headers,
      body: JSON.stringify(claudeBody),
      cf: cfOpts
    };
    if (signal) requestInit.signal = signal;

    const base = provider.baseUrl.replace(/\/+$/, '');
    const url = base.endsWith('/v1/messages') ? base : `${base}/v1/messages`;
    
    const res = await fetch(url, requestInit);
    if (!res.ok) return res;

    if (body.stream && res.body) {
        const { readable, writable } = new TransformStream();
        const reader = res.body.getReader();
        const writer = writable.getWriter();

        // Normalize Claude's native SSE into OpenAI-format `data: {...}` chunks
        // on a standalone ReadableStream, then relay it through the SAME
        // hardened SSE pipeline used for OpenAI providers (proxyNormalizedSSE).
        // This guarantees Cloudflare's edge cannot gzip/re-chunk/mangle the
        // relayed stream and corrupt a mid-stream tool_call fragment (spec 4.10)
        // — previously Claude streaming used its own TransformStream with weak
        // headers, leaving tool calls vulnerable.
        (async () => {
            const decoder = new TextDecoder();
            const encoder = new TextEncoder();
            let chunkId = "chatcmpl-" + crypto.randomUUID();
            try {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) {
                        await writer.write(encoder.encode("data: [DONE]\n\n"));
                        break;
                    }
                    const chunk = decoder.decode(value, { stream: true });
                    const lines = chunk.split('\n');
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            const dataStr = line.slice(6).trim();
                            if (!dataStr || dataStr === '[DONE]') continue;
                            try {
                                const data = JSON.parse(dataStr);
                                const delta: any = {};
                                let finish_reason = null;

                                if (data.type === 'content_block_delta') {
                                    if (data.delta.type === 'text_delta') {
                                        delta.content = data.delta.text;
                                    } else if (data.delta.type === 'input_json_delta') {
                                        delta.tool_calls = [{
                                            index: data.index,
                                            function: { arguments: data.delta.partial_json }
                                        }];
                                    }
                                } else if (data.type === 'content_block_start' && data.content_block?.type === 'tool_use') {
                                    delta.tool_calls = [{
                                        index: data.index,
                                        id: data.content_block.id,
                                        type: "function",
                                        function: { name: data.content_block.name, arguments: "" }
                                    }];
                                } else if (data.type === 'message_delta' && data.delta?.stop_reason) {
                                    finish_reason = data.delta.stop_reason === 'tool_use' ? 'tool_calls' : 'stop';
                                }

                                if (Object.keys(delta).length > 0 || finish_reason) {
                                    const openAIChunk = {
                                        id: chunkId,
                                        object: "chat.completion.chunk",
                                        created: Math.floor(Date.now() / 1000),
                                        model: model.modelId,
                                        choices: [{ index: 0, delta: delta, finish_reason: finish_reason }]
                                    };
                                    await writer.write(encoder.encode(`data: ${JSON.stringify(openAIChunk)}\n\n`));
                                }
                            } catch(e) {}
                        }
                    }
                }
            } catch(e) { console.error("Claude stream error:", e); }
            try { await writer.close(); } catch(e) {}
        })();

        return proxyNormalizedSSE(readable);
    }

    const data: any = await res.json();
    let text = "";
    let toolCalls = undefined;
    
    for (const block of (data.content || [])) {
        if (block.type === 'text') text += block.text;
        else if (block.type === 'tool_use') {
            if (!toolCalls) toolCalls = [];
            toolCalls.push({
                id: block.id,
                type: "function",
                function: { name: block.name, arguments: JSON.stringify(block.input || {}) }
            });
        }
    }
    
    const openAIResponse = {
      id: "chatcmpl-" + (data.id || crypto.randomUUID()),
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: model.modelId,
      choices: [{
        index: 0,
        message: { role: "assistant", content: text, tool_calls: toolCalls },
        finish_reason: claudeFinishReason(data.stop_reason)
      }],
      usage: {
        prompt_tokens: data.usage?.input_tokens || 0,
        completion_tokens: data.usage?.output_tokens || 0,
        total_tokens: (data.usage?.input_tokens || 0) + (data.usage?.output_tokens || 0)
      }
    };
    
    return new Response(JSON.stringify(openAIResponse), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }
}

// Translate Claude's stop_reason into the OpenAI finish_reason vocabulary so
// clients see accurate reasons instead of everything collapsing to "stop".
function claudeFinishReason(stopReason: string | undefined): string {
  switch (stopReason) {
    case "tool_use": return "tool_calls";
    case "length": return "length";
    case "content_filter": return "content_filter";
    case "max_tokens": return "length";
    default: return "stop";
  }
}

import { MistralAdapter } from "./mistral";

export function getAdapterForProvider(provider: Provider): ProviderAdapter {
  if (provider.name.toLowerCase().includes("mistral") || provider.baseUrl.includes("mistral.ai")) {
    return new MistralAdapter();
  }
  if (provider.name.toLowerCase().includes("gemini") || provider.baseUrl.includes("generativelanguage")) {
    return new GeminiAdapter();
  }
  if (provider.name.toLowerCase().includes("anthropic") || provider.name.toLowerCase().includes("claude") || provider.baseUrl.includes("anthropic.com")) {
    return new ClaudeAdapter();
  }
  return new OpenAICompatibleAdapter();
}

