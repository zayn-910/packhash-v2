#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Command } = require("commander");
const { detectInterface } = require("../src/interface");
const { runCapture, countPackets } = require("../src/capture");
const { loadConfig, saveConfig, DEFAULT_RPC } = require("../src/config");
const { SESSIONS, listSessions, resolveSession, isSealed } = require("../src/session");
const { sealSession } = require("../src/seal");
const { verifySession, analyzeSession } = require("../src/verify");
const { tamperCapture, listFlows } = require("../src/tamper");
const { recoverSession } = require("../src/recover");
const { printRecover } = require("../src/report");
const chain = require("../src/chain");
const ui = require("../src/ui");
const { importCapture } = require("../src/importer");

ui.installColorizer();

// Wraps a command so errors print cleanly. A command may return an exit code.
function run(fn) {
  return async (...args) => {
    try {
      const code = await fn(...args);
      process.exit(typeof code === "number" ? code : 0);
    } catch (e) {
      console.error(`${ui.bold(ui.red("Error:"))} ${e.message}`);
      process.exit(1);
    }
  };
}

function printSeal(seal) {
  console.log(`✔ Sealed as anchor #${seal.anchorId} (${seal.packetCount} packets)`);
  console.log(`  ${ui.gray("Merkle root:")} 0x${seal.sessionRoot}`);
  console.log(`  ${ui.gray("Tx hash:    ")} ${seal.txHash}`);
}

const program = new Command();

program
  .name("packhash")
  .description("Tamper-evident packet captures, anchored on a blockchain")
  .version("0.1.0");

program.addHelpText("before", () => ui.banner());

program
  .command("menu")
  .description("open the interactive menu")
  .action(run(async () => {
    await require("../src/menu").start();
  }));

program
  .command("init")
  .description("deploy the contract and save the configuration")
  .option("--rpc <url>", "blockchain node URL")
  .option("--force", "deploy a new contract even if the current one works")
  .action(run(async (opts) => {
    const existing = loadConfig();
    const rpcUrl = opts.rpc || (existing && existing.rpcUrl) || DEFAULT_RPC;

    if (existing && !opts.force) {
      try {
        await chain.connect();
        console.log("✔ Already initialized and the contract is live.");
        console.log(`  ${ui.gray("Contract:")} ${existing.contractAddress}`);
        return;
      } catch (e) {
        console.log(ui.yellow("Previous contract not found on this chain. Deploying a new one."));
        console.log(ui.gray("Note: sessions sealed on the old chain can no longer be verified.\n"));
      }
    }

    console.log(`Deploying PacketRegistry to ${rpcUrl} ...`);
    const address = await chain.deploy(rpcUrl);
    saveConfig({ rpcUrl, contractAddress: address });
    console.log(`✔ Deployed at ${address}`);
    console.log(ui.gray("  Saved to .packhash/config.json"));
  }));

program
  .command("capture")
  .description("capture packets and seal them on-chain (runs until Ctrl+C unless limited)")
  .option("-i, --interface <name>", "network interface (default: auto-detect)")
  .option("-c, --count <n>", "stop after N packets")
  .option("-d, --duration <seconds>", "stop after N seconds")
  .option("-f, --filter <expr>", 'capture filter, e.g. "tcp port 443"')
  .option("--no-seal", "capture only; seal later with: packhash seal")
  .action(run(async (opts) => {
    const iface = opts.interface || detectInterface();
    if (!iface) {
      throw new Error("Could not auto-detect a network interface. Use -i <name> (list them with: tshark -D)");
    }

    // Fail fast: don't capture evidence we can't seal right after.
    if (opts.seal) await chain.connect();

    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const dir = path.join(SESSIONS, stamp);
    fs.mkdirSync(dir, { recursive: true });
    const outFile = path.join(dir, "capture.pcap");

    console.log(`${ui.gray("Interface:")} ${ui.cyan(iface)} ${ui.gray(opts.interface ? "(manual)" : "(auto-detected)")}`);
    console.log(
      opts.count || opts.duration
        ? "Capturing until the limit is reached (or Ctrl+C)..."
        : "Capturing until you press Ctrl+C..."
    );

    await runCapture({
      iface,
      count: opts.count,
      duration: opts.duration,
      filter: opts.filter,
      outFile,
    });

    const n = countPackets(outFile);
    console.log(`\nSaved ${ui.bold(n)} packets to ${outFile}`);
    if (n === 0) {
      fs.rmSync(dir, { recursive: true, force: true });
      throw new Error("No packets were captured (was there any traffic? browse a site while capturing).");
    }

    if (opts.seal) {
      printSeal(await sealSession(dir));
    } else {
      console.log(ui.yellow("Not sealed. Seal it with: packhash seal"));
    }
  }));

program
    .command("import <file>")
    .description("copy an existing capture (e.g. saved from Wireshark) into a new session and seal it")
    .option("-n, --name <label>", "add a label to the session folder name")
    .option("--no-seal", "import only; seal later with: packhash seal")
    .action(run(async (file, opts) => {
      const r = await importCapture(file, { name: opts.name, seal: opts.seal });
      console.log(`Imported ${ui.bold(r.packets)} packets from ${file}`);
      console.log(`${ui.gray("Session:")} ${r.dir}`);
      if (r.seal) printSeal(r.seal);
      else console.log(ui.yellow("Not sealed. Seal it with: packhash seal"));
    }));

program
  .command("seal [session]")
  .description('seal a capture already in ./sessions (default: "latest"); use import for outside files')
  .action(run(async (session) => {
    const dir = resolveSession(session);
    console.log(`Sealing ${dir} ...`);
    printSeal(await sealSession(dir));
  }));

program
  .command("verify [session]")
  .description('check a session against the chain (default: "latest")')
  .option("--all", "verify every sealed session")
  .option("--json", "print the result as JSON (one session)")
  .action(run(async (session, opts) => {
    if (opts.json) {
      if (opts.all) throw new Error("--json works on one session, not with --all");
      const result = await analyzeSession(resolveSession(session));
      console.log(JSON.stringify(result, null, 2));
      return result.exitCode;
    }
    if (opts.all) {
      let code = 0;
      for (const s of listSessions()) {
        const dir = path.join(SESSIONS, s);
        if (!isSealed(dir)) {
          console.log(ui.yellow(`Skipping ${dir} (not sealed)\n`));
          continue;
        }
        try {
          code = Math.max(code, await verifySession(dir));
        } catch (e) {
          console.log(`${ui.bold(ui.red("Error:"))} ${e.message}`);
          code = Math.max(code, 1);
        }
        console.log("");
      }
      return code;
    }
    return await verifySession(resolveSession(session));
  }));

  
program
  .command("tamper [session]")
  .description("demo/testing helper: alter a session's capture.pcap in place")
  .option("--delete <list>", "delete packets, e.g. 5,10-12")
  .option("--connection <n>", "delete every packet of connection n (see --flows)")
  .option("--flows", "list the connections in the capture")
  .option("--modify <n>", "change one byte inside packet n")
  .option("--insert <n>", "insert a forged packet after packet n")
  .option("--swap <a,b>", "swap the positions of two packets")
  .action(run(async (session, opts) => {
    const dir = resolveSession(session);
    const file = path.join(dir, "capture.pcap");
    if (opts.flows) {
      listFlows(file);
      return;
    }
    console.log(`${dir}: ${ui.yellow(tamperCapture(file, opts))}`);
  }));

program
  .command("recover [session]")
  .description('rebuild deleted packets from the verified records (default: "latest")')
  .option("--full", "rebuild the entire original capture as restored.pcap")
  .action(run(async (session, opts) => {
    printRecover(await recoverSession(resolveSession(session), opts));
  }));

program
  .command("ui")
  .description("open the web dashboard (this computer only)")
  .option("-p, --port <n>", "port to listen on", "8787")
  .option("--demo", "enable the tamper tools in the dashboard")
  .option("--open", "try to open the dashboard in your browser")
  .action(async (opts) => {
    try {
      await require("../src/server").startServer({
        port: Number(opts.port),
        demo: Boolean(opts.demo),
        open: Boolean(opts.open),
      });
    } catch (e) {
      console.error(`${ui.bold(ui.red("Error:"))} ${e.message}`);
      process.exit(1);
    }
  });

program
  .command("status")
  .description("show configuration, on-chain anchors and local sessions")
  .action(run(async () => {
    const cfg = loadConfig();
    if (!cfg) {
      console.log(ui.yellow("Not initialized. Run: packhash init"));
      return;
    }
    console.log(`${ui.gray("RPC:     ")} ${cfg.rpcUrl}`);
    console.log(`${ui.gray("Contract:")} ${cfg.contractAddress}`);

    const anchors = await chain.listAnchors();
    console.log(`\n${ui.bold("Anchors on-chain:")} ${anchors.length}`);
    for (const a of anchors) {
      const when = new Date(a.timestamp * 1000).toISOString();
      console.log(`  ${ui.cyan("#" + a.id)}  ${a.packetCount} packets  ${ui.gray(when)}  root ${a.sessionRoot.slice(0, 14)}...`);
    }

    const local = listSessions();
    console.log(`\n${ui.bold("Local sessions:")} ${local.length}`);
    for (const s of local) {
      const tag = isSealed(path.join(SESSIONS, s)) ? ui.green("[sealed]") : ui.yellow("[not sealed]");
      console.log(`  ${s}  ${tag}`);
    }
  }));

// Full option reference after the command list
program.addHelpText("after", () => {
  const out = ["", ui.bold("Command details:")];
  for (const cmd of program.commands) {
    if (cmd.name() === "help") continue;
    const args = cmd.registeredArguments
      .map((a) => (a.required ? `<${a.name()}>` : `[${a.name()}]`))
      .join(" ");
    out.push("", `  ${ui.cyan("packhash " + cmd.name() + (args ? " " + args : ""))}`);
    out.push(`      ${cmd.description()}`);
    for (const o of cmd.options) {
      out.push(`        ${o.flags.padEnd(26)} ${ui.gray(o.description)}`);
    }
  }
  out.push(
    "",
    ui.bold("Typical workflow:"),
    "  packhash init                     deploy the contract (once per node start)",
    "  packhash capture                  capture until Ctrl+C, then seal automatically",
    "  packhash verify                   check the latest session",
    "  packhash recover                  rebuild anything that was deleted or changed",
    "",
    ui.bold("Exit codes (verify):") + " 0 intact, 1 error, 2 tampering detected",
    ""
  );
  return out.join("\n");
});

// `packhash` with no arguments: interactive menu in a terminal, help text otherwise
if (process.argv.length <= 2) {
  if (process.stdin.isTTY && process.stdout.isTTY) {
    require("../src/menu")
      .start()
      .then(() => process.exit(0))
      .catch((e) => {
        console.error(`${ui.bold(ui.red("Error:"))} ${e.message}`);
        process.exit(1);
      });
  } else {
    program.outputHelp();
    process.exit(0);
  }
} else {
  program.parse();
}
