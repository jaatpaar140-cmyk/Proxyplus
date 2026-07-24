import { Env } from "./types";
import { GatewayRouter } from "./router";
import { AdminAPI } from "./admin";
import { runHealthChecks } from "./cron";
import { KVManager, activeSockets } from "./kv";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    if (url.pathname.endsWith("/v1/chat/completions") && request.method === "POST") {
      const router = new GatewayRouter(env);
      return router.handleChatCompletions(request, ctx);
    }
    
    if (url.pathname.endsWith("/v1/models") && request.method === "GET") {
      const authHeader = request.headers.get("Authorization") || "";
      const keyString = authHeader.replace("Bearer ", "").trim();
      const kv = new KVManager(env);
      const vk = await kv.getVirtualKey(keyString);
      if (vk && vk.active) {
        return new Response(JSON.stringify({
          object: "list",
          data: [
            { id: vk.modelAlias || "default-model", object: "model", created: Math.floor(Date.now()/1000), owned_by: "gateway" }
          ]
        }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
      }
      const message = (vk && vk.disabledQuote) ? vk.disabledQuote : "Invalid or revoked virtual key";
      return new Response(JSON.stringify({ error: { message } }), { 
        status: 401, 
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } 
      });
    }

    if (url.pathname === "/admin/ws") {
      const upgradeHeader = request.headers.get("Upgrade");
      if (upgradeHeader !== "websocket") {
        return new Response("Expected Upgrade: websocket", { status: 426 });
      }

      const token = url.searchParams.get("token");
      const kv = new KVManager(env);
      let isAuthorized = false;
      const adminAuth = await kv.getAdminAuth();
      if (env.ADMIN_SECRET && token === env.ADMIN_SECRET) {
        isAuthorized = true;
      } else if (adminAuth && token === adminAuth.secret) {
        isAuthorized = true;
      }
      
      if (!isAuthorized) {
        return new Response("Unauthorized", { status: 401 });
      }

      const webSocketPair = new WebSocketPair();
      const client = webSocketPair[0];
      const server = webSocketPair[1];
      
      server.accept();
      activeSockets.add(server);
      server.addEventListener("close", () => {
        activeSockets.delete(server);
      });
      server.addEventListener("error", () => {
        activeSockets.delete(server);
      });

      return new Response(null, {
        status: 101,
        webSocket: client,
      });
    }

    if (url.pathname.startsWith("/admin")) {
      const admin = new AdminAPI(env);
      const response = await admin.handleRequest(request, ctx);
      // Harden every admin response with baseline security headers (the HTML
      // dashboard already sets a strict CSP; this guarantees JSON endpoints
      // are also nosniff + framed-out + uncached).
      const h = new Headers(response.headers);
      if (!h.has("X-Content-Type-Options")) h.set("X-Content-Type-Options", "nosniff");
      if (!h.has("X-Frame-Options")) h.set("X-Frame-Options", "DENY");
      if (!h.has("Referrer-Policy")) h.set("Referrer-Policy", "no-referrer");
      if (!h.has("Content-Security-Policy")) {
        h.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
      }
      return new Response(response.body, { status: response.status, headers: h });
    }

    return new Response("Not Found", { status: 404 });
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    console.log("Running scheduled Cron for health checks and capabilities discovery...");
    ctx.waitUntil(runHealthChecks(env));
  }
};
