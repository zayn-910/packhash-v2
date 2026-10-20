const MAX_LINES = 20;

function printList(title, items, line) {
  if (items.length === 0) return;
  console.log(`\n  ${title} (${items.length}):`);
  items.slice(0, MAX_LINES).forEach((it) => console.log(`    ${line(it)}`));
  if (items.length > MAX_LINES) console.log(`    ... and ${items.length - MAX_LINES} more`);
}

function printVerify(r) {
  console.log(`Verifying ${r.dir}`);
  console.log(`Anchor #${r.anchor.id}: ${r.anchor.packetCount} packets, sealed ${r.anchor.sealedAt}\n`);

  for (const c of r.checks) {
    console.log(`  ${c.ok ? "✔" : "✘"} ${c.name.padEnd(11)} ${c.text}`);
  }

  if (r.unidentifiable) {
    console.log("\n  The stored records are unreliable, so the changed packets cannot be identified.");
  }

  if (r.diff) {
    printList("Deleted", r.diff.deleted, (x) => `#${x.index}  ${x.time}  ${x.desc}`);
    printList("Modified", r.diff.modified, (x) => `#${x.index}  ${x.time}  ${x.desc}\n         ${x.change}`);
    printList("Inserted", r.diff.inserted, (x) => `at position ${x.index}  ${x.time}  ${x.desc}`);
    printList("Moved", r.diff.moved, (x) =>
      `was #${x.origIndex}, now at position ${x.curIndex}  ${x.time}  ${x.desc}`);
  }

  console.log();
  if (r.intact) {
    console.log("RESULT: INTACT. Nothing has been altered since sealing.");
  } else {
    console.log(`RESULT: TAMPERING DETECTED${r.summary ? ": " + r.summary : ""}`);
  }
}

function printRecover(r) {
  console.log(`Records verified against anchor #${r.anchorId}.`);

  if (r.mode === "full") {
    console.log(`Rebuilt all ${r.count} original packets: ${r.file}`);
    return;
  }

  r.notes.forEach((n) => console.log(n));

  if (r.count === 0) {
    console.log("Nothing to recover: no packets are missing or changed.");
    return;
  }

  console.log(`\nRecovered ${r.count} packet(s):`);
  for (const l of r.items.slice(0, MAX_LINES)) {
    console.log(`  #${l.index}  ${l.time}  ${l.desc}  [${l.why}]`);
  }
  if (r.count > MAX_LINES) console.log(`  ... and ${r.count - MAX_LINES} more`);
  console.log(`\nSaved to ${r.file}`);
  console.log("Open it with Wireshark, or: tshark -r " + r.file);
}

module.exports = { printVerify, printRecover };
