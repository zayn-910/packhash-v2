const fs = require("fs");
const path = require("path");

const DIR = ".packhash";
const FILE = path.join(DIR, "config.json");
const DEFAULT_RPC = "http://127.0.0.1:8545";

function loadConfig() {
  if (!fs.existsSync(FILE)) return null;
  return JSON.parse(fs.readFileSync(FILE, "utf8"));
}

function saveConfig(cfg) {
  fs.mkdirSync(DIR, { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(cfg, null, 2));
}

module.exports = { loadConfig, saveConfig, DEFAULT_RPC };
