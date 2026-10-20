const fs = require("fs");
const { readPcap } = require("./pcap");
const { flowOf } = require("./packets");

// Writes a classic pcap file (Wireshark opens it fine).
function writePcap(file, { linktype, snaplen, packets }) {
  const hdr = Buffer.alloc(24);
  hdr.writeUInt32LE(0xa1b2c3d4, 0);
  hdr.writeUInt16LE(2, 4);
  hdr.writeUInt16LE(4, 6);
  hdr.writeInt32LE(0, 8);
  hdr.writeUInt32LE(0, 12);
  hdr.writeUInt32LE(snaplen, 16);
  hdr.writeUInt32LE(linktype, 20);

  const parts = [hdr];
  for (const p of packets) {
    const rec = Buffer.alloc(16);
    rec.writeUInt32LE(p.tsSec, 0);
    rec.writeUInt32LE(p.tsUsec, 4);
    rec.writeUInt32LE(p.data.length, 8);
    rec.writeUInt32LE(p.origLen, 12);
    parts.push(rec, p.data);
  }
  fs.writeFileSync(file, Buffer.concat(parts));
}

function parseList(s) {
  const out = new Set();
  for (const part of String(s).split(",")) {
    const m = part.trim().match(/^(\d+)(?:-(\d+))?$/);
    if (!m) throw new Error(`Bad packet list "${s}" (use e.g. 5,10-12)`);
    const a = +m[1], b = m[2] ? +m[2] : a;
    for (let i = a; i <= b; i++) out.add(i);
  }
  return out;
}

// Group packets into connections, numbered by first appearance.
function groupFlows(packets) {
  const map = new Map();
  packets.forEach((p, i) => {
    const f = flowOf(p.data);
    if (!f) return;
    let g = map.get(f.key);
    if (!g) {
      g = { key: f.key, name: "", idx: [] };
      map.set(f.key, g);
    }
    g.idx.push(i + 1);
    if (!g.name && f.name) g.name = f.name;
  });
  return [...map.values()];
}

function listFlows(file) {
  const flows = groupFlows(readPcap(file).packets);
  if (flows.length === 0) {
    console.log("No TCP/UDP connections found in this capture.");
    return;
  }
  console.log("Connections in this capture:\n");
  flows.forEach((f, i) => {
    const label = f.name ? `  (${f.name})` : "";
    console.log(`  ${String(i + 1).padStart(3)}  ${String(f.idx.length).padStart(4)} packets  ${f.key}${label}`);
  });
  console.log("\nDelete one with: packhash tamper --connection <number>");
}

function tamperCapture(file, opts) {
  const chosen = ["delete", "modify", "insert", "swap", "connection"].filter((k) => opts[k] !== undefined);
  if (chosen.length !== 1) {
    throw new Error("Choose exactly one of: --delete, --modify, --insert, --swap, --connection");
  }
  const op = chosen[0];

  const cap = readPcap(file);
  const pk = cap.packets.map((p) => ({ ...p }));
  const n = pk.length;
  const need = (i) => {
    if (!Number.isInteger(i) || i < 1 || i > n) throw new Error(`Packet ${i} is out of range (1-${n})`);
    return i;
  };

  let msg;
  if (op === "delete") {
    const del = parseList(opts.delete);
    del.forEach(need);
    if (del.size >= n) throw new Error("That would delete every packet");
    cap.packets = pk.filter((_, i) => !del.has(i + 1));
    msg = `deleted ${del.size} packet(s): ${opts.delete}`;
  } else if (op === "connection") {
    const flows = groupFlows(pk);
    const num = parseInt(opts.connection, 10);
    const f = flows[num - 1];
    if (!f) throw new Error(`No connection #${opts.connection}. List them with: packhash tamper --flows`);
    const del = new Set(f.idx);
    if (del.size >= n) throw new Error("That would delete every packet");
    cap.packets = pk.filter((_, i) => !del.has(i + 1));
    msg = `deleted the entire connection #${num}, ${del.size} packets: ${f.key}${f.name ? ` (${f.name})` : ""}`;
  } else if (op === "modify") {
    const i = need(parseInt(opts.modify, 10));
    const d = Buffer.from(pk[i - 1].data);
    d[d.length - 1] ^= 0xff;
    pk[i - 1].data = d;
    cap.packets = pk;
    msg = `changed one byte in packet ${i}`;
  } else if (op === "insert") {
    const i = need(parseInt(opts.insert, 10));
    const src = pk[i - 1];
    const d = Buffer.from(src.data);
    d[d.length - 1] ^= 0xff;
    let tsSec = src.tsSec, tsUsec = src.tsUsec + 1;
    if (tsUsec >= 1000000) { tsSec += 1; tsUsec = 0; }
    pk.splice(i, 0, { tsSec, tsUsec, origLen: src.origLen, data: d });
    cap.packets = pk;
    msg = `inserted a forged packet after packet ${i}`;
  } else {
    const parts = String(opts.swap).split(",");
    if (parts.length !== 2) throw new Error("--swap needs two packet numbers, e.g. --swap 5,6");
    const [a, b] = parts.map((x) => need(parseInt(x, 10)));
    if (a === b) throw new Error("Pick two different packets to swap");
    [pk[a - 1], pk[b - 1]] = [pk[b - 1], pk[a - 1]];
    cap.packets = pk;
    msg = `swapped packets ${a} and ${b}`;
  }

  writePcap(file, cap);
  return msg;
}

function getFlows(file) {
  return groupFlows(readPcap(file).packets).map((f, i) => ({
    n: i + 1,
    packets: f.idx.length,
    key: f.key,
    name: f.name,
  }));
}

module.exports = { tamperCapture, writePcap, listFlows, getFlows };
