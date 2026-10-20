#!/usr/bin/env node
// Red-team test suite: attacks a sealed capture in many ways and checks that
// packhash detects each one (and recovers what it should).
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const { writePcap, tamperCapture } = require("../src/tamper");
const { sealSession } = require("../src/seal");
const { verifySession } = require("../src/verify");
const { recoverSession } = require("../src/recover");
const { readPcap } = require("../src/pcap");
const { leafHash, toRecord } = require("../src/packets");
const { merkleRoot } = require("../src/merkle");
const chain = require("../src/chain");
const { loadConfig, saveConfig, DEFAULT_RPC } = require("../src/config");

// ---------------------------------------------------------------- packets

const CL_MAC = Buffer.from("080027b63b0b", "hex");
const GW_MAC = Buffer.from("525400123500", "hex");
const CLIENT = [10, 0, 2, 15];

const eth = (out, ip) =>
  Buffer.concat([out ? GW_MAC : CL_MAC, out ? CL_MAC : GW_MAC, Buffer.from([0x08, 0x00]), ip]);

function ipv4(proto, src, dst, l4) {
  const h = Buffer.alloc(20);
  h[0] = 0x45;
  h.writeUInt16BE(20 + l4.length, 2);
  h.writeUInt16BE(0x1234, 4);
  h[8] = 64;
  h[9] = proto;
  Buffer.from(src).copy(h, 12);
  Buffer.from(dst).copy(h, 16);
  return Buffer.concat([h, l4]);
}

function tcp(sport, dport, seq, ack, flags, data) {
  const h = Buffer.alloc(20);
  h.writeUInt16BE(sport, 0);
  h.writeUInt16BE(dport, 2);
  h.writeUInt32BE(seq >>> 0, 4);
  h.writeUInt32BE(ack >>> 0, 8);
  h[12] = 0x50;
  h[13] = flags;
  h.writeUInt16BE(64240, 14);
  return Buffer.concat([h, data]);
}

function udp(sport, dport, data) {
  const h = Buffer.alloc(8);
  h.writeUInt16BE(sport, 0);
  h.writeUInt16BE(dport, 2);
  h.writeUInt16BE(8 + data.length, 4);
  return Buffer.concat([h, data]);
}

function dnsMsg(id, name, response) {
  const labels = name.split(".").map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
  const question = Buffer.concat([...labels, Buffer.from([0, 0, 1, 0, 1])]);
  const h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0);
  h.writeUInt16BE(response ? 0x8180 : 0x0100, 2);
  h.writeUInt16BE(1, 4);
  if (response) h.writeUInt16BE(1, 6);
  const answer = response
    ? Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34])
    : Buffer.alloc(0);
  return Buffer.concat([h, question, answer]);
}

// Deterministic application-data-looking bytes
function payload(len, seed) {
  const b = Buffer.alloc(len);
  for (let k = 0; k < len; k++) b[k] = (seed * 31 + k * 7) & 0xff;
  b[0] = 0x17; b[1] = 0x03; b[2] = 0x03;
  return b;
}

// Two DNS lookups and two TCP connections, interleaved like real traffic.
// Connections are numbered by first appearance: dns1=1, c1=2, dns2=3, c2=4.
function buildCapture() {
  const S1 = [93, 184, 216, 34];
  const S2 = [151, 101, 1, 69];
  const DNS = [192, 168, 31, 1];
  const none = Buffer.alloc(0);

  const steps = [
    ["dns1", true,  ipv4(17, CLIENT, DNS, udp(40001, 53, dnsMsg(0x1a01, "example.org", false)))],
    ["dns1", false, ipv4(17, DNS, CLIENT, udp(53, 40001, dnsMsg(0x1a01, "example.org", true)))],
    ["c1",   true,  ipv4(6, CLIENT, S1, tcp(50001, 443, 1000, 0, 0x02, none))],
    ["c1",   false, ipv4(6, S1, CLIENT, tcp(443, 50001, 5000, 1001, 0x12, none))],
    ["c1",   true,  ipv4(6, CLIENT, S1, tcp(50001, 443, 1001, 5001, 0x10, none))],
    ["dns2", true,  ipv4(17, CLIENT, DNS, udp(40002, 53, dnsMsg(0x1a02, "example.net", false)))],
    ["c1",   true,  ipv4(6, CLIENT, S1, tcp(50001, 443, 1001, 5001, 0x18, payload(517, 1)))],
    ["dns2", false, ipv4(17, DNS, CLIENT, udp(53, 40002, dnsMsg(0x1a02, "example.net", true)))],
    ["c2",   true,  ipv4(6, CLIENT, S2, tcp(50002, 443, 2000, 0, 0x02, none))],
    ["c1",   false, ipv4(6, S1, CLIENT, tcp(443, 50001, 5001, 1518, 0x18, payload(1200, 2)))],
    ["c2",   false, ipv4(6, S2, CLIENT, tcp(443, 50002, 7000, 2001, 0x12, none))],
    ["c2",   true,  ipv4(6, CLIENT, S2, tcp(50002, 443, 2001, 7001, 0x10, none))],
    ["c2",   true,  ipv4(6, CLIENT, S2, tcp(50002, 443, 2001, 7001, 0x18, payload(480, 3)))],
    ["c1",   true,  ipv4(6, CLIENT, S1, tcp(50001, 443, 1518, 6201, 0x10, none))],
    ["c2",   false, ipv4(6, S2, CLIENT, tcp(443, 50002, 7001, 2481, 0x18, payload(900, 4)))],
    ["c1",   true,  ipv4(6, CLIENT, S1, tcp(50001, 443, 1518, 6201, 0x11, none))],
    ["c2",   true,  ipv4(6, CLIENT, S2, tcp(50002, 443, 2481, 7901, 0x10, none))],
    ["c1",   false, ipv4(6, S1, CLIENT, tcp(443, 50001, 6201, 1519, 0x11, none))],
    ["c2",   false, ipv4(6, S2, CLIENT, tcp(443, 50002, 7901, 2481, 0x18, payload(300, 5)))],
    ["c2",   true,  ipv4(6, CLIENT, S2, tcp(50002, 443, 2481, 8201, 0x11, none))],
    ["c2",   false, ipv4(6, S2, CLIENT, tcp(443, 50002, 8201, 2482, 0x11, none))],
    ["c1",   true,  ipv4(6, CLIENT, S1, tcp(50001, 443, 1519, 6202, 0x10, none))],
  ];

  const BASE = 1760000000;
  const packets = steps.map(([, out, ip], i) => {
    const data = eth(out, ip);
    const us = (i + 1) * 40000;
    return { tsSec: BASE + Math.floor(us / 1e6), tsUsec: us % 1e6, origLen: data.length, data };
  });
  return { packets, tags: steps.map((s) => s[0]) };
}

// ---------------------------------------------------------------- helpers

async function quiet(fn) {
  const real = console.log;
  let log = "";
  console.log = (...a) => { log += a.join(" ") + "\n"; };
  try {
    return { value: await fn(), log };
  } finally {
    console.log = real;
  }
}

async function check(dir) {
  const { value: code, log } = await quiet(() => verifySession(dir));
  const m = log.match(/TAMPERING DETECTED: (\d+) deleted, (\d+) modified, (\d+) inserted, (\d+) moved/);
  const counts = m ? { deleted: +m[1], modified: +m[2], inserted: +m[3], moved: +m[4] } : null;
  return { code, counts, log };
}

function summarize(r) {
  if (r.code === 0) return "intact";
  if (r.code !== 2) return `error (exit ${r.code})`;
  if (!r.counts) return "tampering detected";
  const parts = Object.entries(r.counts).filter(([, v]) => v > 0).map(([k, v]) => `${v} ${k}`);
  return parts.length ? parts.join(", ") : "tampering detected";
}

const cap = (d) => path.join(d, "capture.pcap");
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

const only = (o) => (r) =>
  r.code === 2 && r.counts &&
  ["deleted", "modified", "inserted", "moved"].every((k) => r.counts[k] === (o[k] || 0));

const detected = (r) => r.code === 2;

function editRecords(dir) {
  const f = path.join(dir, "records.json");
  const j = JSON.parse(fs.readFileSync(f, "utf8"));
  j.records[0].tsSec += 1;
  fs.writeFileSync(f, JSON.stringify(j));
}

function detect(name, expected, attack, pred) {
  return {
    name,
    expected,
    run: async (dir) => {
      await attack(dir);
      const r = await check(dir);
      return { ok: !!pred(r), got: summarize(r), log: r.log };
    },
  };
}

// ---------------------------------------------------------------- main

async function main() {
  try {
    execFileSync("editcap", ["-h"], { stdio: "ignore" });
  } catch {
    throw new Error("editcap not found. Install Wireshark: sudo apt install wireshark");
  }

  const startDir = process.cwd();
  const rpcUrl = (loadConfig() || {}).rpcUrl || DEFAULT_RPC;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "packhash-test-"));
  process.chdir(tmp);

  try {
    // A fresh contract of our own: the user's real anchors stay untouched.
    const address = await chain.deploy(rpcUrl);
    saveConfig({ rpcUrl, contractAddress: address });

    const { packets, tags } = buildCapture();
    const N = packets.length;
    const idx = (tag) => tags.map((t, i) => (t === tag ? i + 1 : 0)).filter(Boolean);
    const baseLeaves = packets.map(leafHash);

    const base = path.join(tmp, "base");
    fs.mkdirSync(base);
    writePcap(cap(base), { linktype: 1, snaplen: 65535, packets });
    const seal = await sealSession(base);

    console.log("packhash red-team suite");
    console.log(`Test contract ${address}, ${N} packets, 2 DNS lookups + 2 TCP connections\n`);

    const nC1 = idx("c1").length;
    const nDns1 = idx("dns1").length;

    const scenarios = [
      detect("Control: untouched evidence", "intact", () => {}, (r) => r.code === 0),

      detect("Delete 1 packet", "1 deleted",
        (d) => tamperCapture(cap(d), { delete: "10" }), only({ deleted: 1 })),
      detect("Delete 3 scattered packets", "3 deleted",
        (d) => tamperCapture(cap(d), { delete: "4,9,14" }), only({ deleted: 3 })),
      detect("Delete first and last packet", "2 deleted",
        (d) => tamperCapture(cap(d), { delete: `1,${N}` }), only({ deleted: 2 })),
      detect("Delete one whole TCP connection", `${nC1} deleted`,
        (d) => tamperCapture(cap(d), { connection: "2" }), only({ deleted: nC1 })),
      detect("Delete a connection and its DNS lookup", `${nC1 + nDns1} deleted`,
        (d) => {
          tamperCapture(cap(d), { connection: "2" });
          tamperCapture(cap(d), { connection: "1" });
        }, only({ deleted: nC1 + nDns1 })),

      detect("Modify 1 byte inside a packet", "1 modified",
        (d) => tamperCapture(cap(d), { modify: "5" }), only({ modified: 1 })),
      detect("Insert a forged packet", "1 inserted",
        (d) => tamperCapture(cap(d), { insert: "6" }), only({ inserted: 1 })),
      detect("Swap two neighbouring packets", "1 moved",
        (d) => tamperCapture(cap(d), { swap: "7,8" }), only({ moved: 1 })),
      detect("Swap two distant packets", "2 moved",
        (d) => tamperCapture(cap(d), { swap: "3,17" }),
        (r) => r.code === 2 && r.counts && r.counts.moved >= 1 &&
               r.counts.deleted === 0 && r.counts.modified === 0 && r.counts.inserted === 0),
      detect("Combined: delete + modify + insert", "1 del, 1 mod, 1 ins",
        (d) => {
          tamperCapture(cap(d), { delete: "3" });
          tamperCapture(cap(d), { modify: "10" });
          tamperCapture(cap(d), { insert: "15" });
        }, only({ deleted: 1, modified: 1, inserted: 1 })),

      detect("Truncate the capture file mid-packet", "detected",
        (d) => {
          const b = fs.readFileSync(cap(d));
          fs.writeFileSync(cap(d), b.subarray(0, b.length - 30));
        }, detected),
      detect("Delete capture.pcap entirely", "detected",
        (d) => fs.rmSync(cap(d)), detected),
      detect("Replace evidence with an empty capture", "detected",
        (d) => writePcap(cap(d), { linktype: 1, snaplen: 65535, packets: [] }), detected),

      detect("Attack the records: edit records.json", "records rejected",
        (d) => editRecords(d),
        (r) => r.code === 2 && r.log.includes("does not match the anchored root")),
      detect("Delete packets AND rewrite records to match", "records rejected",
        (d) => {
          tamperCapture(cap(d), { delete: "10-12" });
          const c = readPcap(cap(d));
          fs.writeFileSync(
            path.join(d, "records.json"),
            JSON.stringify({ linktype: c.linktype, snaplen: c.snaplen, records: c.packets.map(toRecord) })
          );
        },
        (r) => r.code === 2 && r.log.includes("does not match the anchored root")),
      detect("Re-seal forged copy as a new anchor", "3 deleted",
        async (d) => {
          tamperCapture(cap(d), { delete: "10-12" });
          const forged = d + "-forged";
          fs.mkdirSync(forged);
          fs.copyFileSync(cap(d), cap(forged));
          await sealSession(forged); // insider with the owner key seals the forged file
        }, only({ deleted: 3 })),

      {
        name: "Recover 3 deleted packets",
        expected: "exact originals",
        run: async (d) => {
          tamperCapture(cap(d), { delete: "4,9,14" });
          await quiet(() => recoverSession(d, {}));
          const got = readPcap(path.join(d, "recovered.pcap")).packets.map(leafHash).sort();
          const want = [4, 9, 14].map((i) => baseLeaves[i - 1]).sort();
          return { ok: same(got, want), got: `${got.length} packet(s) recovered` };
        },
      },
      {
        name: "Recover a whole deleted connection",
        expected: "exact originals",
        run: async (d) => {
          tamperCapture(cap(d), { connection: "2" });
          await quiet(() => recoverSession(d, {}));
          const got = readPcap(path.join(d, "recovered.pcap")).packets.map(leafHash).sort();
          const want = idx("c1").map((i) => baseLeaves[i - 1]).sort();
          return { ok: same(got, want), got: `${got.length} packet(s) recovered` };
        },
      },
      {
        name: "Rebuild original after capture.pcap is deleted",
        expected: "root matches chain",
        run: async (d) => {
          fs.rmSync(cap(d));
          await quiet(() => recoverSession(d, { full: true }));
          const pk = readPcap(path.join(d, "restored.pcap")).packets;
          const root = merkleRoot(pk.map(leafHash));
          return { ok: root === seal.sessionRoot, got: `${pk.length} packets rebuilt` };
        },
      },
      {
        name: "Refuse recovery from altered records",
        expected: "refused",
        run: async (d) => {
          editRecords(d);
          try {
            await quiet(() => recoverSession(d, {}));
            return { ok: false, got: "recovered from forged records" };
          } catch (e) {
            return { ok: /does not match the anchored root/.test(e.message), got: "refused" };
          }
        },
      },
    ];

    const W = 50;
    console.log(`      ${"Attack".padEnd(W)} ${"Expected".padEnd(21)} Detected as`);
    console.log(`      ${"-".repeat(W)} ${"-".repeat(21)} ${"-".repeat(20)}`);

    let passed = 0;
    const failures = [];
    for (let i = 0; i < scenarios.length; i++) {
      const s = scenarios[i];
      const work = path.join(tmp, `case-${i}`);
      fs.cpSync(base, work, { recursive: true });

      let res;
      try {
        res = await s.run(work);
      } catch (e) {
        res = { ok: false, got: `crashed: ${e.message}` };
      }
      if (res.ok) passed++;
      else failures.push({ s, res });

      console.log(
        `  ${res.ok ? "✔" : "✘"}  ${String(i + 1).padStart(2)}  ` +
        `${s.name.padEnd(W - 4).slice(0, W - 4)} ${s.expected.padEnd(21)} ${res.got}`
      );
    }

    for (const f of failures) {
      console.log(`\n--- FAILED: ${f.s.name} ---`);
      if (f.res.log) console.log(f.res.log);
    }

    console.log(`\n${passed}/${scenarios.length} passed`);
    return failures.length;
  } finally {
    process.chdir(startDir);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

main()
  .then((failed) => process.exit(failed ? 1 : 0))
  .catch((e) => {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  });
