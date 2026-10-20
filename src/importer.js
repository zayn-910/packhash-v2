const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { SESSIONS } = require("./session");
const { countPackets } = require("./capture");
const { sealSession } = require("./seal");
const chain = require("./chain");

function sha256File(file) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash("sha256");
    fs.createReadStream(file)
      .on("data", (c) => h.update(c))
      .on("end", () => resolve(h.digest("hex")))
      .on("error", reject);
  });
}

// Copies an outside capture into a new session and (by default) seals it.
// Shared by the CLI `import` command and the dashboard's upload.
async function importCapture(file, opts = {}) {
  const { name = "", seal = true, source, originalName } = opts;

  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
    throw new Error(`File not found: ${file}`);
  }

  // Validate before creating anything
  let n;
  try {
    n = countPackets(file);
  } catch {
    throw new Error(`${originalName || file} is not a readable capture file.`);
  }
  if (n === 0) throw new Error("The capture contains no packets.");

  // Fail fast: don't import evidence we can't seal right after.
  if (seal) await chain.connect();

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const label = name ? "_" + name.replace(/[^A-Za-z0-9_-]/g, "-") : "";
  const dir = path.join(SESSIONS, stamp + label);
  fs.mkdirSync(dir, { recursive: true });
  fs.copyFileSync(file, path.join(dir, "capture.pcap"));

  // Provenance: where the file came from and its hash at the moment of import
  fs.writeFileSync(
    path.join(dir, "import.json"),
    JSON.stringify({
      source: source || path.resolve(file),
      originalName: originalName || path.basename(file),
      fileSize: fs.statSync(file).size,
      fileSha256: await sha256File(file),
      importedAt: new Date().toISOString(),
    }, null, 2)
  );

  const sealed = seal ? await sealSession(dir) : null;
  return { dir, packets: n, seal: sealed };
}

module.exports = { importCapture };
