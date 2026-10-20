const fs = require("fs");
const path = require("path");

const SESSIONS = "sessions";

function listSessions() {
  if (!fs.existsSync(SESSIONS)) return [];
  return fs
    .readdirSync(SESSIONS)
    .filter((d) => fs.statSync(path.join(SESSIONS, d)).isDirectory())
    .sort();
}

// Accepts a session folder name, or "latest" (also the default)
function resolveSession(arg) {
  if (arg && fs.existsSync(arg) && fs.statSync(arg).isFile()) {
    throw new Error(`"${arg}" is a file, not a session. Import it first with: packhash import ${arg}`);
  }
  
  const all = listSessions();
  if (all.length === 0) throw new Error("No sessions found in ./sessions. Run: packhash capture");
  const name = !arg || arg === "latest" ? all[all.length - 1] : path.basename(arg);
  const dir = path.join(SESSIONS, name);
  if (!fs.existsSync(dir)) throw new Error(`Session not found: ${name}`);
  return dir;
}

function isSealed(dir) {
  return fs.existsSync(path.join(dir, "seal.json"));
}

module.exports = { SESSIONS, listSessions, resolveSession, isSealed };
