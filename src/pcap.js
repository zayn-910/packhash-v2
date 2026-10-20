const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

// tshark writes pcapng by default and editcap keeps the input format.
// Converting to classic pcap first gives one simple format to parse.
function toClassicPcap(file) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "packhash-"));
  const out = path.join(tmp, "classic.pcap");
  try {
    execFileSync("editcap", ["-F", "pcap", file, out], { stdio: ["ignore", "ignore", "pipe"] });
    return fs.readFileSync(out);
  } catch (e) {
    const msg = e.stderr ? e.stderr.toString().trim() : e.message;
    throw new Error(`Could not read ${file}: ${msg}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function parsePcap(buf) {
  const magic = buf.readUInt32LE(0);
  let le, nano;
  if (magic === 0xa1b2c3d4) { le = true; nano = false; }
  else if (magic === 0xd4c3b2a1) { le = false; nano = false; }
  else if (magic === 0xa1b23c4d) { le = true; nano = true; }
  else if (magic === 0x4d3cb2a1) { le = false; nano = true; }
  else throw new Error("Not a valid pcap file");

  const u32 = (o) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  const snaplen = u32(16);
  const linktype = u32(20);

  const packets = [];
  let off = 24;
  while (off + 16 <= buf.length) {
    const tsSec = u32(off);
    const tsFrac = u32(off + 4);
    const inclLen = u32(off + 8);
    const origLen = u32(off + 12);
    off += 16;
    if (off + inclLen > buf.length) throw new Error("Capture file is truncated");
    packets.push({
      tsSec,
      tsUsec: nano ? Math.floor(tsFrac / 1000) : tsFrac,
      origLen,
      data: buf.subarray(off, off + inclLen),
    });
    off += inclLen;
  }
  return { linktype, snaplen, packets };
}

function readPcap(file) {
  return parsePcap(toClassicPcap(file));
}

module.exports = { readPcap };
