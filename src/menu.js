const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const ui = require("./ui");
const chain = require("./chain");
const { loadConfig } = require("./config");
const { SESSIONS, listSessions, isSealed } = require("./session");

const BIN = path.join(__dirname, "..", "bin", "packhash.js");

// Runs a real packhash command with the terminal attached, so output is identical
// to typing it. Ctrl+C is left to the child (e.g. to stop a capture), not the menu.
function runCli(args) {
  return new Promise((resolve) => {
    const ignore = () => {};
    process.on("SIGINT", ignore);
    const done = (code) => {
      process.off("SIGINT", ignore);
      resolve(code);
    };
    const child = spawn(process.execPath, [BIN, ...args], { stdio: "inherit" });
    child.on("error", () => done(1));
    child.on("close", (code) => done(code));
  });
}

function sessionInfo(name) {
  const dir = path.join(SESSIONS, name);
  const info = { name, sealed: isSealed(dir), packets: null, anchor: null };
  if (info.sealed) {
    try {
      const s = JSON.parse(fs.readFileSync(path.join(dir, "seal.json"), "utf8"));
      info.packets = s.packetCount;
      info.anchor = s.anchorId;
    } catch { /* leave blanks */ }
  }
  return info;
}

function sessionLabel(i) {
  const state = i.sealed
    ? ui.green(`sealed #${i.anchor ?? "?"}`)
    : ui.yellow("not sealed");
  const count = i.packets != null ? ui.gray(`${i.packets} packets`) : "";
  return `${i.name}  ${state}  ${count}`;
}

function cleanPath(p) {
  let s = p.trim().replace(/^['"]|['"]$/g, ""); // drag-and-drop adds quotes
  if (s === "~") s = os.homedir();
  else if (s.startsWith("~/")) s = path.join(os.homedir(), s.slice(2));
  return s;
}

const isPositiveInt = (v) => (/^\d+$/.test(v.trim()) && +v > 0) || "Enter a whole number above 0";

async function start() {
  const p = await import("@inquirer/prompts");

  const pause = () => p.input({ message: ui.gray("Press Enter to return to the menu") });

  async function act(args) {
    console.log("");
    await runCli(args);
    console.log("");
    await pause();
  }

  // Makes sure a node is reachable and a live contract exists, fixing what it can.
  async function ensureReady() {
    for (;;) {
      const h = await chain.health();
      if (h.state === "ok") return true;

      if (h.state === "no-node") {
        console.log(ui.yellow(`\nNo blockchain node found at ${h.rpcUrl}.`));
        console.log(`Start one in another terminal:  ${ui.cyan("npx hardhat node")}\n`);
        const a = await p.select({
          message: "What now?",
          choices: [
            { name: "I started it, check again", value: "retry" },
            { name: "Quit", value: "quit" },
          ],
        });
        if (a === "quit") return false;
        continue;
      }

      if (h.state === "no-config") {
        console.log(ui.gray("\nFirst run: deploying the contract..."));
      } else {
        console.log(ui.yellow("\nThe contract is gone from this chain (the node was restarted)."));
        console.log(ui.gray("Sessions sealed on the old chain can no longer be verified."));
        const ok = await p.confirm({ message: "Deploy a new contract now?", default: true });
        if (!ok) {
          console.log(ui.gray("Run `packhash init` whenever you are ready."));
          return false;
        }
      }

      const code = await runCli(["init"]);
      if (code !== 0) {
        await pause();
        return false;
      }
      console.log("");
    }
  }

  async function statusLine() {
    try {
      const addr = loadConfig().contractAddress;
      const n = (await chain.listAnchors()).length;
      return ui.gray(`Chain connected · contract ${addr.slice(0, 8)}…${addr.slice(-4)} · ${n} anchor(s)`);
    } catch {
      return "";
    }
  }

  async function captureFlow() {
    const mode = await p.select({
      message: "Capture until...",
      choices: [
        { name: "I press Ctrl+C", value: "manual" },
        { name: "A set number of seconds", value: "time" },
        { name: "A set number of packets", value: "count" },
        { name: "Back", value: "back" },
      ],
    });
    if (mode === "back") return;
    const args = ["capture"];
    if (mode === "time") {
      const n = await p.input({ message: "Seconds:", validate: isPositiveInt });
      args.push("-d", n.trim());
    } else if (mode === "count") {
      const n = await p.input({ message: "Packets:", validate: isPositiveInt });
      args.push("-c", n.trim());
    }
    console.log(ui.gray("\nBrowse a few sites while it captures."));
    await act(args);
  }

  async function importFlow() {
    const file = await p.input({
      message: "Path of the capture file (.pcap / .pcapng):",
      validate: (v) => {
        const f = cleanPath(v);
        return (f && fs.existsSync(f) && fs.statSync(f).isFile()) || "File not found";
      },
    });
    const label = await p.input({ message: "Label for the session (optional):" });
    const args = ["import", cleanPath(file)];
    if (label.trim()) args.push("-n", label.trim());
    await act(args);
  }

  async function tamperFlow(name) {
    console.log(ui.yellow("\nDemo helper: this permanently alters the capture file in this session."));
    const ok = await p.confirm({ message: "Continue?", default: false });
    if (!ok) return;

    const kind = await p.select({
      message: "Attack:",
      choices: [
        { name: "Delete packets", value: "delete" },
        { name: "Delete a whole connection", value: "connection" },
        { name: "Modify a packet", value: "modify" },
        { name: "Insert a forged packet", value: "insert" },
        { name: "Swap two packets", value: "swap" },
        { name: "Back", value: "back" },
      ],
    });
    if (kind === "back") return;

    const args = ["tamper", name];
    if (kind === "delete") {
      const v = await p.input({
        message: "Packets to delete (e.g. 5,10-12):",
        validate: (x) => /^[\d,\-\s]+$/.test(x) && x.trim() !== "" || "Use numbers, commas and ranges",
      });
      args.push("--delete", v.replace(/\s/g, ""));
    } else if (kind === "connection") {
      console.log("");
      await runCli(["tamper", name, "--flows"]);
      console.log("");
      const v = await p.input({ message: "Connection number:", validate: isPositiveInt });
      args.push("--connection", v.trim());
    } else if (kind === "modify" || kind === "insert") {
      const v = await p.input({
        message: kind === "modify" ? "Packet to modify:" : "Insert a forged packet after packet:",
        validate: isPositiveInt,
      });
      args.push(`--${kind}`, v.trim());
    } else {
      const v = await p.input({
        message: "Two packets to swap (e.g. 5,6):",
        validate: (x) => /^\d+\s*,\s*\d+$/.test(x) || "Format: 5,6",
      });
      args.push("--swap", v.replace(/\s/g, ""));
    }
    await act(args);
  }

  async function sessionMenu(name) {
    for (;;) {
      const info = sessionInfo(name);
      console.log(`\n${ui.bold("Session:")} ${sessionLabel(info)}`);
      const choices = [];
      if (info.sealed) {
        choices.push(
          { name: "Verify against the blockchain", value: "verify" },
          { name: "Recover deleted or modified packets", value: "recover" },
          { name: "Rebuild the full original capture", value: "full" }
        );
      } else {
        choices.push({ name: "Seal on-chain", value: "seal" });
      }
      choices.push(
        { name: ui.gray("Demo: tamper with this capture"), value: "tamper" },
        { name: "Back to sessions", value: "back" }
      );

      const a = await p.select({ message: "What now?", choices });
      if (a === "back") return;
      if (a === "verify") await act(["verify", name]);
      else if (a === "recover") await act(["recover", name]);
      else if (a === "full") await act(["recover", name, "--full"]);
      else if (a === "seal") await act(["seal", name]);
      else if (a === "tamper") await tamperFlow(name);
    }
  }

  async function browseFlow() {
    for (;;) {
      const names = listSessions().reverse(); // newest first
      if (names.length === 0) {
        console.log(ui.yellow("\nNo sessions yet. Capture or import something first.\n"));
        return;
      }
      const choice = await p.select({
        message: "Sessions (newest first):",
        pageSize: 12,
        choices: [
          ...names.map((n) => ({ name: sessionLabel(sessionInfo(n)), value: n })),
          { name: "Back", value: "__back" },
        ],
      });
      if (choice === "__back") return;
      await sessionMenu(choice);
    }
  }

  console.log(ui.banner());

  try {
    for (;;) {
      if (!(await ensureReady())) break;
      const line = await statusLine();
      if (line) console.log(line);

      const choice = await p.select({
        message: "What do you want to do?",
        choices: [
          { name: "Capture traffic", value: "capture" },
          { name: "Import a capture file", value: "import" },
          { name: "Browse sessions", value: "browse" },
          { name: "Verify all sessions", value: "verifyall" },
          { name: "Status", value: "status" },
          { name: "Quit", value: "quit" },
        ],
      });
      if (choice === "quit") break;
      if (choice === "capture") await captureFlow();
      else if (choice === "import") await importFlow();
      else if (choice === "browse") await browseFlow();
      else if (choice === "verifyall") await act(["verify", "--all"]);
      else if (choice === "status") await act(["status"]);
    }
  } catch (e) {
    if (!(e && e.name === "ExitPromptError")) throw e; // Ctrl+C at a prompt is a normal exit
  }
  console.log(ui.gray("Bye."));
}

module.exports = { start };
