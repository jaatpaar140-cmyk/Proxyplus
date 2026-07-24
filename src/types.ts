export interface Env {
  KV: KVNamespace;
  GATEWAY_URL?: string;
  ADMIN_PASSWORD?: string;
  ADMIN_SECRET?: string;
}

export interface Provider {
  id: string;
  name: string;
  baseUrl: string;
  authHeaderFormat: string; // e.g. "Bearer {key}"
  apiKey: string;
  active: boolean;
}

export interface ProviderModel {
  providerId: string;
  modelId: string;
  active: boolean;
  status: "untested" | "working" | "degraded" | "broken";
  discoveredAt: number;
  lastChecked: number;
  avgLatencyMs: number;
  supportsTools: boolean;
  supportsVision: boolean;
  supportsWebSearch: boolean;
  supportsStreaming: boolean;
  // Multimodal capability flags. `supportsVision` already existed; document and
  // audio are added so `multimodalRestrict` can mean "any multimodal modality"
  // (vision OR document OR audio) rather than vision-only. Populated best-effort
  // by the cron probe; routing treats them as advisory (never hard-blocks on a
  // missing flag — it tries the model and lets the provider reject).
  supportsDocument?: boolean;
  supportsAudio?: boolean;
  maxContext: number;
  networkIssueSuspected: boolean;
  lastErrorDebug?: string;
  capabilitiesProbed?: boolean;
}

export interface VirtualKey {
  key: string;
  appName: string;
  modelAlias: string;
  active: boolean;
  createdAt: number;
  allowedModels: string[];
  allowedProviders: string[];
  rateLimit: { requestsPerMin: number; tokensPerDay: number };
  multimodalRestrict: boolean;
  smartPlus: boolean;
  disabledQuote?: string;
}

export interface TrafficLog {
  timestamp: number;
  virtualKey: string;
  providerId: string;
  modelId: string;
  status: number;
  latencyMs: number;
  errorType?: "provider_error" | "rate_limited" | "timeout" | "malformed_response" | "network_layer";
}
