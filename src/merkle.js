const crypto = require("crypto");

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

// Inner nodes use prefix 0x01 (leaves use 0x00, see packets.js)
function nodeHash(left, right) {
  return sha256(Buffer.concat([Buffer.from([0x01]), left, right]));
}

// leafHexes: array of hex strings, in packet order. Returns hex root.
function merkleRoot(leafHexes) {
  if (leafHexes.length === 0) throw new Error("Cannot build a tree with no packets");
  let level = leafHexes.map((h) => Buffer.from(h, "hex"));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return level[0].toString("hex");
}

module.exports = { sha256, merkleRoot };
