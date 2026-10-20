# packhash

Tamper-evident packet captures, anchored on a blockchain.

Network captures (`.pcap`) are often the evidence after a security incident. Anyone with
write access to the stored file can quietly delete the packets that matter, and the file
still looks complete. `packhash` seals a capture on a blockchain when it is taken, so any
later deletion, modification, insertion or reordering is detected, the exact packets are
identified, and deleted packets can be rebuilt.

It can be used three ways: as plain commands, through an interactive terminal menu, or
through a local web dashboard.

## How it works

1. **Capture.** `tshark` records live traffic into `sessions/<timestamp>/capture.pcap`.
   Existing captures (for example saved from Wireshark) can be imported instead.
2. **Hash.** Every packet gets a SHA-256 leaf hash over its timestamp, original length and
   raw bytes. A packet's position in the file is not part of the hash, so deleting a
   packet does not change the hash of the packets after it.
3. **Merkle root.** All leaf hashes are combined into one Merkle root. Leaves and inner
   nodes use different prefixes, and left/right order matters, so swapping two packets
   changes the root.
4. **Anchor.** The root is stored by a Solidity smart contract. The contract is
   append-only and has no function to edit or delete an anchor. Each anchor also stores a
   chained root, `sha256(previous chained root + session root)`, so the history cannot be
   quietly rewritten.
5. **Keep a reference.** The raw bytes of every packet are saved in `records.json`.
6. **Verify.** The current capture is re-hashed and compared with the on-chain root. If it
   differs, the stored records (themselves checked against the on-chain root) are used to
   report exactly which packets were deleted, modified, inserted or moved.
7. **Recover.** Deleted packets, and the originals of modified ones, are rebuilt from the
   verified records into a pcap you can open in Wireshark.

Only 32 bytes per session go on-chain, so the cost stays constant however large the
capture is.

## Requirements

- Linux (tested on Ubuntu)
- Node.js (LTS)
- Wireshark (provides `tshark` and `editcap`)

```bash
sudo apt update
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt install -y nodejs wireshark
sudo usermod -aG wireshark $USER    # then log out and back in
```

When the Wireshark installer asks whether non-superusers may capture packets, choose Yes.

## Install

```bash
git clone https://github.com/zayn-910/packhash-v2.git
cd packhash-v2
npm install
npx hardhat compile
sudo npm link          # makes the `packhash` command available
```

## Quick start

Start a local blockchain in its own terminal and leave it running. It prints test private
keys, which are public defaults with no value, but keep that terminal off screen when
recording or sharing:

```bash
npx hardhat node
```

Then, in another terminal, run `packhash`. In a terminal this opens the interactive menu,
which deploys the contract on first run and offers everything else:

```bash
packhash
```

Or use the commands directly:

```bash
packhash init          # deploy the contract (once per node start)
packhash capture       # capture until Ctrl+C, then seal automatically
packhash verify        # check the latest session
```

Restarting the local node wipes the chain. Run `packhash init` (or just open the menu)
again afterwards. Sessions sealed on the old chain can no longer be verified.

## Three ways to use it

### 1. Commands

| Command | What it does |
|---|---|
| `packhash init` | Deploy the contract and save the configuration. `--rpc <url>` sets the node URL, `--force` redeploys. |
| `packhash capture` | Capture packets and seal them. Runs until Ctrl+C. |
| `packhash import <file>` | Copy an existing capture (.pcap / .pcapng) into a new session and seal it. |
| `packhash seal [session]` | Seal a capture already in `sessions/` (default: latest). |
| `packhash verify [session]` | Check a session against the chain. `--all` checks every sealed session, `--json` prints the result as data. |
| `packhash recover [session]` | Rebuild deleted or modified packets as `recovered.pcap`. `--full` rebuilds the whole original as `restored.pcap`. |
| `packhash status` | Show configuration, on-chain anchors and local sessions. |
| `packhash menu` | Open the interactive menu. |
| `packhash ui` | Open the web dashboard. |
| `packhash tamper [session]` | Demo/testing helper that attacks a capture. See below. |

`capture` options:

| Option | Meaning |
|---|---|
| `-i, --interface <name>` | Network interface. Auto-detected from the default route if omitted. |
| `-c, --count <n>` | Stop after n packets. |
| `-d, --duration <seconds>` | Stop after n seconds. |
| `-f, --filter <expr>` | Capture filter, e.g. `"tcp port 443"`. |
| `--no-seal` | Capture only; seal later with `packhash seal`. |

`import` options: `-n, --name <label>` adds a label to the session folder, `--no-seal`
imports without sealing. The original file is copied, never modified, and `import.json`
in the session records where it came from and its SHA-256 at the moment of import.

Run `packhash --help` for the full reference. A session argument is a folder name under
`sessions/`, or `latest`.

**Exit codes.** `verify` returns `0` when the evidence is intact, `1` on an error and `2`
when tampering is detected, so it can be used in scripts.

### 2. Interactive menu

Running `packhash` with no arguments in a terminal opens a menu: capture, import a file,
browse sessions, verify everything, show status. Pick a session to verify, recover or
rebuild it. The menu checks the node and the contract each time it is shown, and deploys
the contract on the first run. If the contract has disappeared (the node was restarted) it
explains what that means and asks before deploying a new one.

When the output is piped or not a terminal, `packhash` prints the help text instead.

### 3. Web dashboard

```bash
packhash ui              # then open the printed link in a browser on the same machine
packhash ui --demo       # also enables the tamper tools
packhash ui --port 9000  # choose a port (default 8787)
packhash ui --open       # try to open a browser automatically
```

The dashboard has a sessions table with sealed and missing-capture badges, a verify view
with the three checks and the deleted, modified, inserted and moved packets, buttons to
recover or rebuild a capture and download the result, and an upload form that imports and
seals a capture. In demo mode there is also a panel that tampers with a capture so you can
verify it straight away.

Capturing and initializing the chain are deliberately not in the dashboard. Use the menu or
the commands for those.

**Dashboard security.** The dashboard reads and handles evidence, so:
- It listens on `127.0.0.1` only, never on other network interfaces.
- A random access token is generated every time it starts. The link contains it, and every
  API call must send it, so another web page open in your browser cannot call the dashboard.
- Requests with an unexpected `Host` or `Origin` are refused.
- The page uses a strict Content Security Policy and never inserts captured data as HTML,
  because values such as DNS names come from traffic an attacker can influence.
- Session names and file names are checked against a whitelist, so nothing outside
  `sessions/` can be reached.
- The tamper tools exist only with `--demo`.

## Verification output

```
Verifying sessions/2026-10-17T12-08-40-868Z
Anchor #0: 897 packets, sealed 2026-10-17T12:08:58.000Z

  ✔ Chain      1 anchor(s), chained roots consistent
  ✔ Records    records.json matches the anchored root
  ✘ Evidence   capture differs from the sealed version (894 packets now, 897 sealed)

  Deleted (3):
    #10  2026-10-17 12:08:44.120  10.0.2.15:50592 → 142.251.156.4:443  TCP  54 bytes
    ...

RESULT: TAMPERING DETECTED: 3 deleted, 0 modified, 0 inserted, 0 moved
```

The three checks:
- **Chain.** The chained roots across all anchors are consistent.
- **Records.** The root rebuilt from `records.json` matches the one on-chain, so the
  stored reference data can be trusted.
- **Evidence.** The root rebuilt from the current `capture.pcap` matches the one on-chain.

Detection needs only the capture and the chain. The records are used to say *which* packets
changed and to rebuild them.

## The `tamper` helper

`tamper` exists only to demonstrate and test detection. It is not part of the forensic
workflow and must never be pointed at real evidence. It alters a session's capture in place:

```bash
packhash tamper --delete 10-12      # delete packets
packhash tamper --flows             # list the connections in the capture
packhash tamper --connection 3      # delete every packet of one connection
packhash tamper --modify 5          # change one byte inside a packet
packhash tamper --insert 5          # insert a forged packet
packhash tamper --swap 5,6          # swap two packets
```

Deleting a whole connection is the interesting case. Wireshark's own "previous segment not
captured" warnings only appear when part of a TCP connection is missing. Remove every
packet of a connection and Wireshark shows nothing unusual. `packhash` still finds it.

## Red-team test suite

```bash
npm test
```

The suite builds a synthetic capture (two DNS lookups and two TCP connections), seals it on
its own fresh contract, and runs 21 scenarios against it: single, scattered and
whole-connection deletions, a connection plus its DNS lookup, modification, insertion,
reordering, combined attacks, truncated and deleted capture files, attacks on
`records.json`, a re-sealed forgery, and recovery checks. It needs the local node running
and leaves your own sessions and anchors untouched.

## Safeguards around sealing

- A session that is already sealed cannot be sealed again.
- If `seal.json` is deleted, `verify` and `recover` rebuild it by finding the anchor on the
  chain whose root matches the stored records.
- A session that has `records.json` but no seal record cannot be re-sealed, because that
  would overwrite the original records with possibly tampered data.

## Limitations

- **Tampering before sealing is not detected.** The seal captures the file as it is when
  sealing runs. Sealing automatically at the end of `capture` keeps that window short, but
  it is not zero. For imported files the window is whatever happened to the file before
  the import.
- **`records.json` is verified but not protected from deletion.** A forged or edited copy is
  rejected, because its root no longer matches the chain. But if an attacker deletes it,
  tampering is still detected while the original packets can no longer be identified or
  rebuilt. A blockchain proves integrity, not availability. Keep an extra copy of
  `records.json` somewhere the attacker cannot reach, such as removable media or another
  machine.
- **The contract owner can seal anything.** Someone holding the owner key could seal a forged
  capture as a new anchor. The original anchor still exposes the change, and the extra
  anchor shows up in `packhash status`, but anchors should be reviewed.
- **The chained roots show history is consistent, not that it is complete.** The contract
  computes them itself. Publishing the latest chained root somewhere independent would let
  you later prove that no earlier anchor was altered or dropped.
- **The blockchain is a local simulation.** Hardhat runs one in-memory node, so there is no
  real decentralization, and restarting it erases everything. Pointing `--rpc` at a
  persistent or consortium chain is the natural next step.
- **HTTPS payloads are encrypted.** Recovered packets are bit-for-bit identical to the
  originals, but encrypted traffic stays encrypted. DNS and plain HTTP remain readable.
- **Readable packet summaries need Ethernet captures.** Other link types (such as Wi-Fi
  monitor mode) still seal, verify and recover correctly, but the summaries show only sizes
  and `tamper --connection` finds no connections.
- **`sessions/` contains raw traffic.** It is gitignored. Do not commit or share it.

## Project layout

```
bin/packhash.js            command-line entry point
src/ui.js                  banner and colors
src/menu.js                interactive menu
src/server.js              web dashboard server
web/                       dashboard page (index.html, app.js, style.css)
src/capture.js             runs tshark
src/interface.js           network interface auto-detection
src/importer.js            imports an outside capture into a session
src/pcap.js                pcap reader
src/packets.js             leaf hashing, packet descriptions, connection detection
src/merkle.js              Merkle tree
src/chain.js               contract deployment and calls, health check
src/config.js              saved configuration
src/session.js             finding sessions
src/seal.js                sealing, and rebuilding a missing seal record
src/verify.js              detects deleted, modified, inserted and moved packets
src/recover.js             rebuilds packets from verified records
src/report.js              prints verify and recover results
src/tamper.js              attack helper
contracts/PacketRegistry.sol   append-only registry with chained roots
test/redteam.js            red-team test suite
```

## Future work

- Seal during capture (streaming), to shrink the capture-to-seal window.
- Redundant, optionally encrypted copies of the records, with Merkle inclusion proofs so
  any copy can be checked against the chain.
- Hourly and daily rollups for long-running capture.
- Merkle proofs for showing that a single packet belongs to a session.
- Verification reports as JSON or HTML files.
- A continuous watch mode that verifies as soon as a capture file changes.
- Persisting chain state across node restarts, or a persistent multi-node chain.

## License

MIT
