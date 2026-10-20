const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawn } = require("child_process");

const pkg = require("../package.json");
const ui = require("./ui");
const chain = require("./chain");
const { loadConfig } = require("./config");
const { SESSIONS, listSessions, isSealed } = require("./session");
const { analyzeSession } = require("./verify");
const { recoverSession } = require("./recover");
const { sealSession } = require("./seal");
const { importCapture } = require("./importer");
const { tamperCapture, getFlows } = require("./tamper");

const WEB = path.join(__dirname, "..", "web");
const MAX_JSON = 64 * 1024;
const MAX_UPLOAD = 1024 * 1024 * 1024; // 1 GB

const STATIC = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/app.js": ["app.js", "text/javascript; charset=utf-8"],
  "/style.css": ["style.css", "text/css; charset=utf-8"],
};
const DOWNLOADS = new Set(["capture.pcap", "recovered.pcap", "restored.pcap"]);
const TAMPER_OPS = new Set(["delete", "connection", "modify", "insert", "swap"]);

// The page loads only its own files: no inline scripts, no inline styles, no external hosts.
const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
  "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const fail = (status, message) => Object.assign(new Error(message), { status });

function send(res, status, body, type = "application/json; charset=utf-8", extra = {}) {
  const data = typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": type,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    ...extra,
  });
  res.end(data);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_JSON) {
        reject(fail(413, "Request too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {});
      } catch {
        reject(fail(400, "Invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

function saveUpload(req, dest) {
  return new Promise((resolve, reject) => {
    const len = Number(req.headers["content-length"] || 0);
    if (!len) return reject(fail(411, "Content-Length is required"));
    if (len > MAX_UPLOAD) return reject(fail(413, "File too large (limit 1 GB)"));

    const out = fs.createWriteStream(dest);
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_UPLOAD) {
        out.destroy();
        req.destroy();
        reject(fail(413, "File too large (limit 1 GB)"));
      }
    });
    req.pipe(out);
    out.on("finish", () => resolve(size));
    out.on("error", reject);
    req.on("error", reject);
  });
}

function sessionInfo(name) {
  const dir = path.join(SESSIONS, name);
  const info = {
    name,
    sealed: isSealed(dir),
    packets: null,
    anchorId: null,
    sealedAt: null,
    captureBytes: null,
    hasRecovered: fs.existsSync(path.join(dir, "recovered.pcap")),
    hasRestored: fs.existsSync(path.join(dir, "restored.pcap")),
    source: fs.existsSync(path.join(dir, "import.json")) ? "imported" : "captured",
  };
  try { info.captureBytes = fs.statSync(path.join(dir, "capture.pcap")).size; } catch { /* missing */ }
  if (info.sealed) {
    try {
      const s = JSON.parse(fs.readFileSync(path.join(dir, "seal.json"), "utf8"));
      info.packets = s.packetCount;
      info.anchorId = s.anchorId;
      info.sealedAt = s.sealedAt;
    } catch { /* leave blanks */ }
  }
  return info;
}

// Only names of real sessions are accepted, so no path can escape ./sessions
function sessionDir(name) {
  if (typeof name !== "string" || !listSessions().includes(name)) throw fail(404, "Unknown session");
  return path.join(SESSIONS, name);
}

function listen(server, startPort) {
  return new Promise((resolve, reject) => {
    let port = startPort;
    const onError = (e) => {
      if (e.code === "EADDRINUSE" && port < startPort + 20) {
        port++;
        server.listen(port, "127.0.0.1");
      } else {
        reject(e);
      }
    };
    server.on("error", onError);
    server.once("listening", () => {
      server.off("error", onError);
      resolve(port);
    });
    server.listen(port, "127.0.0.1");
  });
}

async function startServer({ port = 8787, demo = false, open = false } = {}) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid port");

  const token = crypto.randomBytes(24).toString("hex");
  const tokenBuf = Buffer.from(token);
  let boundPort = port;

  const hostOk = (h) => h === `127.0.0.1:${boundPort}` || h === `localhost:${boundPort}`;
  const tokenOk = (t) => {
    if (typeof t !== "string") return false;
    const b = Buffer.from(t);
    return b.length === tokenBuf.length && crypto.timingSafeEqual(b, tokenBuf);
  };
  const needDemo = () => {
    if (!demo) throw fail(403, "Demo mode is off. Start the dashboard with: packhash ui --demo");
  };

  async function stateInfo() {
    const health = await chain.health();
    const cfg = loadConfig();
    const author = typeof pkg.author === "string" ? pkg.author : (pkg.author && pkg.author.name) || "";
    const out = {
      version: pkg.version,
      author,
      demo,
      health: health.state,
      rpcUrl: health.rpcUrl,
      contract: cfg ? cfg.contractAddress : null,
      anchors: null,
    };
    if (health.state === "ok") {
      try { out.anchors = (await chain.listAnchors()).length; } catch { /* leave null */ }
    }
    return out;
  }

  async function handle(req, res) {
    const url = new URL(req.url, "http://localhost");
    if (!hostOk(req.headers.host)) throw fail(403, "Unexpected Host header");

    if (req.method === "GET" && url.pathname === "/favicon.ico") {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === "GET" && STATIC[url.pathname]) {
      const [file, type] = STATIC[url.pathname];
      return send(res, 200, fs.readFileSync(path.join(WEB, file)), type, {
        "Content-Security-Policy": CSP,
      });
    }

    if (!url.pathname.startsWith("/api/")) throw fail(404, "Not found");

    // Downloads are plain links, which cannot set headers, so they may pass the token in the URL.
    const provided =
      req.headers["x-packhash-token"] ||
      (url.pathname === "/api/download" ? url.searchParams.get("token") : null);
    if (!tokenOk(provided)) throw fail(401, "Missing or wrong access token");

    if (req.method === "POST") {
      const origin = req.headers.origin;
      if (origin && origin !== `http://${req.headers.host}`) throw fail(403, "Cross-origin request refused");
    }

    switch (`${req.method} ${url.pathname}`) {
      case "GET /api/state":
        return send(res, 200, await stateInfo());

      case "GET /api/sessions":
        return send(res, 200, listSessions().reverse().map(sessionInfo));

      case "POST /api/verify": {
        const b = await readJson(req);
        return send(res, 200, await analyzeSession(sessionDir(b.session)));
      }

      case "POST /api/recover": {
        const b = await readJson(req);
        return send(res, 200, await recoverSession(sessionDir(b.session), { full: Boolean(b.full) }));
      }

      case "POST /api/seal": {
        const b = await readJson(req);
        const dir = sessionDir(b.session);
        if (isSealed(dir)) throw fail(409, "This session is already sealed.");
        return send(res, 200, await sealSession(dir));
      }

      case "POST /api/import": {
        const tmp = path.join(os.tmpdir(), `packhash-upload-${crypto.randomBytes(8).toString("hex")}.pcap`);
        try {
          await saveUpload(req, tmp);
          const r = await importCapture(tmp, {
            name: (url.searchParams.get("name") || "").slice(0, 40),
            seal: true,
            source: "uploaded via dashboard",
            originalName: (url.searchParams.get("filename") || "upload").slice(0, 120),
          });
          return send(res, 200, { dir: path.basename(r.dir), packets: r.packets, seal: r.seal });
        } finally {
          fs.rmSync(tmp, { force: true });
        }
      }

      case "GET /api/download": {
        const dir = sessionDir(url.searchParams.get("session"));
        const name = url.searchParams.get("file");
        if (!DOWNLOADS.has(name)) throw fail(404, "Unknown file");
        const file = path.join(dir, name);
        if (!fs.existsSync(file)) throw fail(404, "File not found");
        res.writeHead(200, {
          "Content-Type": "application/vnd.tcpdump.pcap",
          "Content-Length": fs.statSync(file).size,
          "Content-Disposition": `attachment; filename="${path.basename(dir)}_${name}"`,
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        });
        fs.createReadStream(file).pipe(res);
        return;
      }

      case "GET /api/flows": {
        needDemo();
        const dir = sessionDir(url.searchParams.get("session"));
        return send(res, 200, getFlows(path.join(dir, "capture.pcap")));
      }

      case "POST /api/tamper": {
        needDemo();
        const b = await readJson(req);
        const dir = sessionDir(b.session);
        if (!TAMPER_OPS.has(b.op)) throw fail(400, "Unknown tamper operation");
        const message = tamperCapture(path.join(dir, "capture.pcap"), { [b.op]: String(b.value) });
        return send(res, 200, { message });
      }
    }

    throw fail(404, "Not found");
  }

  const server = http.createServer(async (req, res) => {
    try {
      await handle(req, res);
    } catch (e) {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      send(res, e.status || 400, { error: e.message });
    }
  });

  boundPort = await listen(server, port);
  const link = `http://127.0.0.1:${boundPort}/?token=${token}`;

  console.log(`✔ Dashboard running ${ui.gray("(this computer only)")}`);
  console.log(`  ${ui.gray("Open:")} ${ui.cyan(link)}`);
  console.log(`  ${ui.gray("Mode:")} ${demo ? ui.yellow("demo (tamper tools enabled)") : "normal"}`);
  console.log(ui.gray("  Press Ctrl+C to stop."));

  if (open) {
    const child = spawn("xdg-open", [link], { stdio: "ignore", detached: true });
    child.on("error", () => console.log(ui.gray("  (could not open a browser automatically)")));
    child.unref();
  }

  process.on("SIGINT", () => {
    console.log("\nDashboard stopped.");
    process.exit(0);
  });
}

module.exports = { startServer };
