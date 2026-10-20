const { execSync } = require("child_process");

// Interface used by the default route, e.g. "default via 10.0.2.2 dev enp0s3"
function fromDefaultRoute() {
  try {
    const out = execSync("ip route show default", { encoding: "utf8" });
    const m = out.match(/\bdev\s+(\S+)/);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

// Fallback: first real interface listed by tshark
function fromTshark() {
  try {
    const out = execSync("tshark -D", { encoding: "utf8" });
    const names = out
      .split("\n")
      .map((l) => l.match(/^\d+\.\s+(\S+)/))
      .filter(Boolean)
      .map((m) => m[1]);
    const skip = /^(lo|any|bluetooth|nflog|nfqueue|dbus|usbmon|ciscodump|sshdump|udpdump|randpkt|wifidump|androiddump)/;
    return names.find((n) => !skip.test(n)) || null;
  } catch {
    return null;
  }
}

function detectInterface() {
  return fromDefaultRoute() || fromTshark();
}

module.exports = { detectInterface };
