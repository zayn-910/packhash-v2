const fs = require("fs");
const path = require("path");
const { readPcap } = require("./pcap");
const { leafHash, describe } = require("./packets");
const { merkleRoot } = require("./merkle");
const { compare, recordPacket, when } = require("./verify");
const { writePcap } = require("./tamper");
const chain = require("./chain");
const { repairSeal } = require("./seal");

// Rebuilds packets and returns what it did as plain data (no printing).
async function recoverSession(dir, opts = {}) {
  const sealFile = path.join(dir, "seal.json");
  if (!fs.existsSync(sealFile) && !(await repairSeal(dir))) {
    throw new Error(`${dir} is not sealed, so there is nothing to recover from.`);
  }
  const seal = JSON.parse(fs.readFileSync(sealFile, "utf8"));

  const recFile = path.join(dir, "records.json");
  if (!fs.existsSync(recFile)) throw new Error("records.json is missing, so the original packets cannot be rebuilt.");
  const data = JSON.parse(fs.readFileSync(recFile, "utf8"));
  const orig = data.records.map(recordPacket);

  // Only trust the stored records if the blockchain vouches for them.
  const anchor = await chain.getAnchor(seal.anchorId);
  const root = "0x" + merkleRoot(orig.map(leafHash));
  if (root !== anchor.sessionRoot.toLowerCase()) {
    throw new Error("records.json does not match the anchored root (it was altered), so it cannot be trusted for recovery.");
  }

  // Full restore: rebuild the whole original capture next to the evidence.
  if (opts.full) {
    const out = path.join(dir, "restored.pcap");
    writePcap(out, { linktype: data.linktype, snaplen: data.snaplen, packets: orig });
    return { anchorId: anchor.id, mode: "full", file: out, count: orig.length, items: [], notes: [] };
  }

  // Otherwise rebuild only what is missing or changed.
  const notes = [];
  let cur = [];
  const capFile = path.join(dir, "capture.pcap");
  if (fs.existsSync(capFile)) {
    try { cur = readPcap(capFile).packets; }
    catch { notes.push("capture.pcap is unreadable; treating every packet as lost."); }
  } else {
    notes.push("capture.pcap is missing; treating every packet as lost.");
  }

  const r = compare(orig, cur);
  const lost = [
    ...r.deleted.map((x) => ({ index: x.index, p: x.p, why: "deleted" })),
    ...r.modified.map((x) => ({ index: x.index, p: x.orig, why: "original of modified packet" })),
  ].sort((a, b) => a.index - b.index);

  if (lost.length === 0) {
    return { anchorId: anchor.id, mode: "partial", file: null, count: 0, items: [], notes };
  }

  const out = path.join(dir, "recovered.pcap");
  writePcap(out, { linktype: data.linktype, snaplen: data.snaplen, packets: lost.map((l) => l.p) });

  const items = lost.map((l) => ({
    index: l.index,
    time: when(l.p),
    desc: describe(l.p.data, l.p.origLen, data.linktype),
    why: l.why,
  }));

  return { anchorId: anchor.id, mode: "partial", file: out, count: lost.length, items, notes };
}

module.exports = { recoverSession };
