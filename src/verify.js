const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { readPcap } = require("./pcap");
const { leafHash, describe } = require("./packets");
const { merkleRoot } = require("./merkle");
const chain = require("./chain");
const { printVerify } = require("./report");
const { repairSeal } = require("./seal");

function when(p) {
  const ms = p.tsSec * 1000 + Math.floor(p.tsUsec / 1000);
  return new Date(ms).toISOString().replace("T", " ").slice(0, 23);
}

function recordPacket(r) {
  return { tsSec: r.tsSec, tsUsec: r.tsUsec, origLen: r.origLen, data: Buffer.from(r.hex, "hex") };
}

// Recompute the chained roots; return the id of the first broken anchor, or -1.
function firstBrokenAnchor(anchors) {
  let prev = Buffer.alloc(32);
  for (const a of anchors) {
    const sr = Buffer.from(a.sessionRoot.slice(2), "hex");
    const expected = crypto.createHash("sha256").update(Buffer.concat([prev, sr])).digest();
    if ("0x" + expected.toString("hex") !== a.chainRoot.toLowerCase()) return a.id;
    prev = expected;
  }
  return -1;
}

// Positions (in seq) that belong to one longest increasing subsequence.
function lisPositions(seq) {
  const tails = [], tailIdx = [], prev = new Array(seq.length).fill(-1);
  for (let k = 0; k < seq.length; k++) {
    let lo = 0, hi = tails.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (tails[mid] < seq[k]) lo = mid + 1; else hi = mid;
    }
    tails[lo] = seq[k];
    tailIdx[lo] = k;
    prev[k] = lo > 0 ? tailIdx[lo - 1] : -1;
  }
  const keep = new Set();
  let k = tails.length ? tailIdx[tails.length - 1] : -1;
  while (k !== -1) { keep.add(k); k = prev[k]; }
  return keep;
}

function compare(origPackets, curPackets) {
  const origLeaves = origPackets.map(leafHash);
  const curLeaves = curPackets.map(leafHash);

  const queues = new Map();
  origLeaves.forEach((h, i) => {
    if (!queues.has(h)) queues.set(h, []);
    queues.get(h).push(i);
  });

  const matched = new Array(origPackets.length).fill(false);
  const common = [];   // packets present in both: { cur, orig }
  const extraIdx = []; // current packets with no original counterpart

  curLeaves.forEach((h, j) => {
    const q = queues.get(h);
    if (q && q.length) {
      const i = q.shift();
      matched[i] = true;
      common.push({ cur: j, orig: i });
    } else {
      extraIdx.push(j);
    }
  });

  const missingIdx = [];
  matched.forEach((m, i) => { if (!m) missingIdx.push(i); });

  // Same timestamp but different bytes -> modified. Everything else is delete/insert.
  const extraByTs = new Map();
  for (const j of extraIdx) {
    const k = `${curPackets[j].tsSec}.${curPackets[j].tsUsec}`;
    if (!extraByTs.has(k)) extraByTs.set(k, []);
    extraByTs.get(k).push(j);
  }

  const deleted = [], modified = [], used = new Set();
  for (const i of missingIdx) {
    const o = origPackets[i];
    const list = extraByTs.get(`${o.tsSec}.${o.tsUsec}`);
    if (list && list.length) {
      const j = list.shift();
      used.add(j);
      modified.push({ index: i + 1, orig: o, cur: curPackets[j] });
    } else {
      deleted.push({ index: i + 1, p: o });
    }
  }

  const inserted = extraIdx
    .filter((j) => !used.has(j))
    .map((j) => ({ index: j + 1, p: curPackets[j] }));

  const keep = lisPositions(common.map((c) => c.orig));
  const moved = common
    .filter((_, k) => !keep.has(k))
    .map((c) => ({ origIndex: c.orig + 1, curIndex: c.cur + 1, p: curPackets[c.cur] }));

  return { deleted, modified, inserted, moved };
}

function diffBytes(a, b) {
  if (a.length !== b.length) return `length ${a.length} → ${b.length} bytes`;
  let n = 0;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) n++;
  return `${n} byte(s) differ`;
}

// Runs every check and returns the findings as plain data (no printing).
async function analyzeSession(dir) {
  const sealFile = path.join(dir, "seal.json");
  if (!fs.existsSync(sealFile)) {
    if (!(await repairSeal(dir))) {
      if (fs.existsSync(path.join(dir, "records.json"))) {
        throw new Error(`${dir} has records but no seal record, and the records match no anchor on this chain. Do not re-seal it.`);
      }
      throw new Error(`${dir} is not sealed. Run: packhash seal`);
    }
  }
  const seal = JSON.parse(fs.readFileSync(sealFile, "utf8"));

  let anchor;
  try {
    anchor = await chain.getAnchor(seal.anchorId);
  } catch (e) {
    if (/No such anchor/.test(e.message)) {
      throw new Error(`Anchor #${seal.anchorId} does not exist on this chain (a different or restarted node?).`);
    }
    throw e;
  }

  const onchainRoot = anchor.sessionRoot.toLowerCase();
  const checks = [];
  let failures = 0;

  // 1. Chained roots
  const anchors = await chain.listAnchors();
  const broken = firstBrokenAnchor(anchors);
  if (broken === -1) {
    checks.push({ name: "Chain", ok: true, text: `${anchors.length} anchor(s), chained roots consistent` });
  } else {
    checks.push({ name: "Chain", ok: false, text: `anchor #${broken} does not follow from the previous one` });
    failures++;
  }

  // 2. Reference records
  let origPackets = null;
  let linktype = 1;
  const recFile = path.join(dir, "records.json");
  if (!fs.existsSync(recFile)) {
    checks.push({ name: "Records", ok: false, text: "records.json is missing (changed packets cannot be identified)" });
    failures++;
  } else {
    try {
      const data = JSON.parse(fs.readFileSync(recFile, "utf8"));
      linktype = data.linktype;
      const packets = data.records.map(recordPacket);
      const root = packets.length ? "0x" + merkleRoot(packets.map(leafHash)) : null;
      if (root === onchainRoot) {
        checks.push({ name: "Records", ok: true, text: "records.json matches the anchored root" });
        origPackets = packets;
      } else {
        checks.push({ name: "Records", ok: false, text: "records.json does not match the anchored root (it was altered)" });
        failures++;
      }
    } catch {
      checks.push({ name: "Records", ok: false, text: "records.json is unreadable" });
      failures++;
    }
  }

  // 3. Evidence file
  const capFile = path.join(dir, "capture.pcap");
  let cur = null, problem = null;
  if (!fs.existsSync(capFile)) {
    problem = "capture.pcap is missing";
  } else {
    try { cur = readPcap(capFile); }
    catch (e) { problem = `capture.pcap cannot be read (${e.message}): corrupted or truncated`; }
  }

  let diff = null, unidentifiable = false, summary = "";

  if (problem) {
    checks.push({ name: "Evidence", ok: false, text: problem });
    failures++;
  } else {
    const curRoot = cur.packets.length ? "0x" + merkleRoot(cur.packets.map(leafHash)) : null;
    if (curRoot === onchainRoot) {
      checks.push({ name: "Evidence", ok: true, text: `all ${cur.packets.length} packets match the anchored root` });
    } else {
      checks.push({
        name: "Evidence",
        ok: false,
        text: `capture differs from the sealed version (${cur.packets.length} packets now, ${anchor.packetCount} sealed)`,
      });
      failures++;

      if (!origPackets) {
        unidentifiable = true;
      } else {
        const r = compare(origPackets, cur.packets);
        const info = (p) => ({ time: when(p), desc: describe(p.data, p.origLen, linktype) });
        diff = {
          deleted: r.deleted.map((x) => ({ index: x.index, ...info(x.p) })),
          modified: r.modified.map((x) => ({
            index: x.index, ...info(x.orig), change: diffBytes(x.orig.data, x.cur.data),
          })),
          inserted: r.inserted.map((x) => ({ index: x.index, ...info(x.p) })),
          moved: r.moved.map((x) => ({ origIndex: x.origIndex, curIndex: x.curIndex, ...info(x.p) })),
        };
        summary = `${r.deleted.length} deleted, ${r.modified.length} modified, ` +
                  `${r.inserted.length} inserted, ${r.moved.length} moved`;
      }
    }
  }

  return {
    dir,
    anchor: {
      id: anchor.id,
      packetCount: anchor.packetCount,
      sealedAt: new Date(anchor.timestamp * 1000).toISOString(),
    },
    checks,
    diff,
    unidentifiable,
    summary,
    intact: failures === 0,
    exitCode: failures === 0 ? 0 : 2,
  };
}

// Prints the findings. Returns an exit code: 0 intact, 2 tampering detected.
async function verifySession(dir) {
  const result = await analyzeSession(dir);
  printVerify(result);
  return result.exitCode;
}

module.exports = { verifySession, analyzeSession, compare, recordPacket, when };
