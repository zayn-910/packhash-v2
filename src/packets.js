const { sha256 } = require("./merkle");

// Leaf hash covers timestamp, original length and the raw bytes.
// It deliberately excludes the packet's position in the file: positions shift
// when packets are deleted, which caused false alarms in the v1 project.
// (Do not change this function: it must stay identical to what was sealed.)
function leafHash(p) {
  const head = Buffer.alloc(13);
  head.writeUInt8(0x00, 0); // leaf prefix
  head.writeUInt32BE(p.tsSec, 1);
  head.writeUInt32BE(p.tsUsec, 5);
  head.writeUInt32BE(p.origLen, 9);
  return sha256(Buffer.concat([head, p.data])).toString("hex");
}

function toRecord(p, i) {
  return {
    index: i + 1, // display only, not part of the hash
    tsSec: p.tsSec,
    tsUsec: p.tsUsec,
    origLen: p.origLen,
    hex: p.data.toString("hex"),
    leaf: leafHash(p),
  };
}

function ip6(b) {
  const g = [];
  for (let i = 0; i < 16; i += 2) g.push(b.readUInt16BE(i).toString(16));
  return g.join(":");
}

function dnsName(b, off) {
  const labels = [];
  while (off < b.length) {
    const len = b[off];
    if (len === 0) break;
    if (len > 63 || off + 1 + len > b.length) return null;
    labels.push(b.toString("latin1", off + 1, off + 1 + len));
    off += 1 + len;
  }
  return labels.length ? labels.join(".") : null;
}

// One-line human summary of a packet (Ethernet captures only).
function describe(buf, origLen, linktype) {
  const size = `${origLen} bytes`;
  if (linktype !== 1 || buf.length < 34) return size;

  const ethType = buf.readUInt16BE(12);
  let src, dst, proto, l4;
  if (ethType === 0x0800) {
    proto = buf[23];
    src = Array.from(buf.subarray(26, 30)).join(".");
    dst = Array.from(buf.subarray(30, 34)).join(".");
    l4 = 14 + (buf[14] & 0x0f) * 4;
  } else if (ethType === 0x86dd && buf.length >= 54) {
    proto = buf[20];
    src = ip6(buf.subarray(22, 38));
    dst = ip6(buf.subarray(38, 54));
    l4 = 54;
  } else {
    return size;
  }

  const names = { 1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6" };
  const pname = names[proto] || `proto ${proto}`;
  let from = src, to = dst, extra = "";

  if ((proto === 6 || proto === 17) && buf.length >= l4 + 4) {
    const sp = buf.readUInt16BE(l4);
    const dp = buf.readUInt16BE(l4 + 2);
    from = `${src}:${sp}`;
    to = `${dst}:${dp}`;
    if (proto === 17 && (sp === 53 || dp === 53) && buf.length >= l4 + 8 + 13) {
      const dns = l4 + 8;
      if (buf.readUInt16BE(dns + 4) >= 1) {
        const q = dnsName(buf, dns + 12);
        if (q) extra = `  DNS ${buf[dns + 2] & 0x80 ? "response" : "query"} ${q}`;
      }
    }
  }
  return `${from} → ${to}  ${pname}  ${size}${extra}`;
}

// SNI (server name) from a TLS Client Hello, or null.
function sniOf(buf, off) {
  try {
    if (buf[off] !== 0x16 || buf[off + 5] !== 0x01) return null; // handshake / ClientHello
    let p = off + 5 + 4 + 2 + 32;                                // skip headers, version, random
    p += 1 + buf[p];                                             // session id
    p += 2 + buf.readUInt16BE(p);                                // cipher suites
    p += 1 + buf[p];                                             // compression
    const end = p + 2 + buf.readUInt16BE(p);
    p += 2;
    while (p + 4 <= end) {
      const type = buf.readUInt16BE(p);
      const len = buf.readUInt16BE(p + 2);
      if (type === 0) {
        const nlen = buf.readUInt16BE(p + 7);
        return buf.toString("latin1", p + 9, p + 9 + nlen);
      }
      p += 4 + len;
    }
  } catch { /* not a Client Hello */ }
  return null;
}

// Connection identity of a packet: { key, name } or null (Ethernet captures only).
function flowOf(buf) {
  if (buf.length < 34) return null;
  const ethType = buf.readUInt16BE(12);
  let src, dst, proto, l4;
  if (ethType === 0x0800) {
    proto = buf[23];
    src = Array.from(buf.subarray(26, 30)).join(".");
    dst = Array.from(buf.subarray(30, 34)).join(".");
    l4 = 14 + (buf[14] & 0x0f) * 4;
  } else if (ethType === 0x86dd && buf.length >= 54) {
    proto = buf[20];
    src = ip6(buf.subarray(22, 38));
    dst = ip6(buf.subarray(38, 54));
    l4 = 54;
  } else {
    return null;
  }
  if ((proto !== 6 && proto !== 17) || buf.length < l4 + 8) return null;

  const sp = buf.readUInt16BE(l4);
  const dp = buf.readUInt16BE(l4 + 2);
  const a = `${src}:${sp}`, b = `${dst}:${dp}`;
  const [x, y] = a < b ? [a, b] : [b, a];
  const key = `${proto === 6 ? "TCP" : "UDP"} ${x} <-> ${y}`;

  let name = "";
  if (proto === 17 && (sp === 53 || dp === 53) && buf.length >= l4 + 8 + 13) {
    const dns = l4 + 8;
    if (buf.readUInt16BE(dns + 4) >= 1) name = dnsName(buf, dns + 12) || "";
  } else if (proto === 6 && buf.length > l4 + 12) {
    const payload = l4 + (buf[l4 + 12] >> 4) * 4;
    if (payload + 44 < buf.length) name = sniOf(buf, payload) || "";
  }
  return { key, name };
}

module.exports = { leafHash, toRecord, describe, flowOf };
