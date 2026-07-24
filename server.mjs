import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import workerModule from './dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 8787;
const HOST = '127.0.0.1';
const KV_FILE_PATH = path.join(__dirname, 'kv.json');

// Load local dev secrets from `.dev.vars` (gitignored) so the local server
// faithfully mirrors production env (admin password/secret must be present or
// admin login behaves differently than prod). Falls back to process.env.
function loadDevVars() {
  const vars = {};
  const devVarsPath = path.join(__dirname, '.dev.vars');
  if (fs.existsSync(devVarsPath)) {
    const content = fs.readFileSync(devVarsPath, 'utf8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const idx = trimmed.indexOf('=');
      if (idx === -1) continue;
      const key = trimmed.slice(0, idx).trim();
      const val = trimmed.slice(idx + 1).trim();
      vars[key] = val;
    }
  }
  return vars;
}
const devVars = loadDevVars();

// Mock KV Namespace that persists to kv.json
class LocalKV {
  constructor(filePath) {
    this.filePath = filePath;
    this.data = {};
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(this.filePath)) {
        this.data = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      }
    } catch (e) {
      console.error("Failed to load KV database:", e);
    }
  }

  save() {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf8');
    } catch (e) {
      console.error("Failed to save KV database:", e);
    }
  }

  async get(key) {
    return this.data[key] || null;
  }

  async put(key, value, options) {
    this.data[key] = value;
    this.save();
  }

  async delete(key) {
    delete this.data[key];
    this.save();
  }

  async list(options) {
    const prefix = options?.prefix || '';
    const limit = options?.limit || 1000;
    const keys = Object.keys(this.data)
      .filter(k => k.startsWith(prefix))
      .sort()
      .map(k => ({ name: k }))
      .slice(0, limit);
    return { keys };
  }
}

const kvMock = new LocalKV(KV_FILE_PATH);
const envMock = {
  KV: kvMock,
  // Mirror production secrets so local admin auth works identically to prod.
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || devVars.ADMIN_PASSWORD || "",
  ADMIN_SECRET: process.env.ADMIN_SECRET || devVars.ADMIN_SECRET || ""
};

const ctxMock = {
  waitUntil: (promise) => {
    promise.catch(err => {
      console.error("Error in asynchronous background context:", err);
    });
  }
};

const server = http.createServer(async (req, res) => {
  // Disable CORS restrictions for local dev ease
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }

  try {
    const url = new URL(req.url, `http://${HOST}:${PORT}`);
    
    // Read request body stream
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const bodyBuffer = chunks.length > 0 ? Buffer.concat(chunks) : null;

    // Build standard Web API Request
    const requestHeaders = new Headers();
    for (const [key, val] of Object.entries(req.headers)) {
      if (Array.isArray(val)) {
        for (const v of val) requestHeaders.append(key, v);
      } else if (val !== undefined) {
        requestHeaders.set(key, val);
      }
    }

    const init = {
      method: req.method,
      headers: requestHeaders
    };
    if (req.method !== 'GET' && req.method !== 'HEAD' && bodyBuffer) {
      init.body = bodyBuffer;
    }

    const webRequest = new Request(url.toString(), init);

    // Call Cloudflare Worker handler
    const worker = workerModule.default || workerModule;
    const webResponse = await worker.fetch(webRequest, envMock, ctxMock);

    // Set Response code and headers
    res.statusCode = webResponse.status;
    webResponse.headers.forEach((value, name) => {
      res.setHeader(name, value);
    });

    // Write Response body
    if (webResponse.body) {
      const reader = webResponse.body.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          res.write(value);
        }
      } catch (streamError) {
        console.error("Error during streaming response:", streamError);
      } finally {
        res.end();
      }
    } else {
      const text = await webResponse.text();
      res.end(text);
    }

  } catch (error) {
    console.error("Internal Server Error processing request:", error);
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: { message: "Internal server error", details: error.message } }));
  }
});

server.listen(PORT, HOST, () => {
  console.log(`\n\x1b[32m✨ AI Gateway Local Development Server is running!\x1b[0m`);
  console.log(`\x1b[36m👉 Dashboard:\x1b[0m http://${HOST}:${PORT}/admin`);
  console.log(`\x1b[36m👉 API Base:\x1b[0m  http://${HOST}:${PORT}/v1\n`);
  console.log(`Logs will display here in real-time...\n`);
  
  // Local development cron emulation
  const worker = workerModule.default || workerModule;
  if (worker.scheduled) {
      console.log(`\x1b[33m⏳ Emulating Cloudflare Cron Triggers locally...\x1b[0m\n`);
      setTimeout(() => worker.scheduled({}, envMock, ctxMock), 1000); // Run initially
      setInterval(() => worker.scheduled({}, envMock, ctxMock), 30000); // Then every 30s
  }
});
