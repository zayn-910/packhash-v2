const fs = require("fs");
const path = require("path");
const { readPcap } = require("./pcap");
const { toRecord, leafHash } = require("./packets");
const { merkleRoot } = require("./merkle");
const { isSealed } = require("./session");
const chain = require("./chain");

// If seal.json is missing but records.json exists, find the matching anchor on the
// chain (same Merkle root) and rebuild seal.json. Returns the seal, or null if the
// records match no anchor (altered records, or a different chain).
async function repairSeal(dir) {
  const recFile = path.join(dir, "records.json");
  if (isSealed(dir) || !fs.existsSync(recFile)) return null;

  let data;
  try { data = JSON.parse(fs.readFileSync(recFile, "utf8")); } catch { return null; }
  if (!data.records || data.records.length === 0) return null;

  const root = merkleRoot(
    data.records.map((r) =>
      leafHash({ tsSec: r.tsSec, tsUsec: r.tsUsec, origLen: r.origLen, data: Buffer.from(r.hex, "hex") })
    )
  );

  const anchors = await chain.listAnchors();
  const a = anchors.find((x) => x.sessionRoot.toLowerCase() === "0x" + root);
  if (!a) return null;

  const seal = {
    anchorId: a.id,
    txHash: null, // not recoverable from the anchor alone
    sessionRoot: root,
    chainRoot: a.chainRoot,
    packetCount: a.packetCount,
    sealedAt: new Date(a.timestamp * 1000).toISOString(),
    rebuilt: true,
  };
  fs.writeFileSync(path.join(dir, "seal.json"), JSON.stringify(seal, null, 2));
  return seal;
}

async function sealSession(dir) {
  if (isSealed(dir)) throw new Error("This session is already sealed.");

  // Records without a seal record mean the session was sealed before. Never overwrite them.
  if (fs.existsSync(path.join(dir, "records.json"))) {
    const r = await repairSeal(dir);
    if (r) {
      throw new Error(
        `This session was already sealed (anchor #${r.anchorId}). Its seal record was missing and has been rebuilt from the chain.`
      );
    }
    throw new Error(
      "This session already has records but no seal record, and the records match no anchor on this chain. " +
      "Sealing again would overwrite the original records, so it was refused. " +
      "If you are sure, delete records.json by hand first."
    );
  }

  const { linktype, snaplen, packets } = readPcap(path.join(dir, "capture.pcap"));
  if (packets.length === 0) throw new Error("The capture has no packets.");

  const records = packets.map(toRecord);
  const root = merkleRoot(records.map((r) => r.leaf));

  const { id, txHash } = await chain.seal("0x" + root, records.length);
  if (id === null) throw new Error("Sealed, but could not read the anchor id from the transaction.");
  const anchor = await chain.getAnchor(id);

  fs.writeFileSync(
    path.join(dir, "records.json"),
    JSON.stringify({ linktype, snaplen, records })
  );

  const seal = {
    anchorId: id,
    txHash,
    sessionRoot: root,
    chainRoot: anchor.chainRoot,
    packetCount: records.length,
    sealedAt: new Date(anchor.timestamp * 1000).toISOString(),
  };
  fs.writeFileSync(path.join(dir, "seal.json"), JSON.stringify(seal, null, 2));
  return seal;
}

module.exports = { sealSession, repairSeal };
