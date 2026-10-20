const { spawn, execSync } = require("child_process");

function runCapture({ iface, count, duration, filter, outFile }) {
  return new Promise((resolve, reject) => {
    const args = ["-i", iface, "-w", outFile];
    if (count) args.push("-c", String(count));
    if (duration) args.push("-a", `duration:${duration}`);
    if (filter) args.push("-f", filter);

    const proc = spawn("tshark", args, { stdio: ["ignore", "inherit", "inherit"] });

    // Ctrl+C is already delivered to tshark by the terminal, which makes it
    // stop cleanly and finish the file. We just keep this process alive until
    // tshark exits, so we can report the result.
    const ignore = () => {};
    process.on("SIGINT", ignore);

    proc.on("error", reject);
    proc.on("close", () => {
      process.off("SIGINT", ignore);
      resolve();
    });
  });
}

function countPackets(file) {
  const out = execSync(`tshark -r "${file}" -T fields -e frame.number`, {
    encoding: "utf8",
    maxBuffer: 1 << 28,
  });
  return out.trim() === "" ? 0 : out.trim().split("\n").length;
}

module.exports = { runCapture, countPackets };
