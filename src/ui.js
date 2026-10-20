const pkg = require("../package.json");

// Colors only when writing to a real terminal; off when piped or NO_COLOR is set.
function enabled() {
  return Boolean(process.stdout.isTTY) && !process.env.NO_COLOR && process.env.TERM !== "dumb";
}

const paint = (code) => (s) => (enabled() ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const bold = paint("1");
const dim = paint("2");
const red = paint("31");
const green = paint("32");
const yellow = paint("33");
const cyan = paint("36");
const gray = paint("90");

const LOGO = [
  "██████╗  █████╗  ██████╗██╗  ██╗██╗  ██╗ █████╗ ███████╗██╗  ██╗",
  "██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██║  ██║██╔══██╗██╔════╝██║  ██║",
  "██████╔╝███████║██║     █████╔╝ ███████║███████║███████╗███████║",
  "██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══██║██╔══██║╚════██║██╔══██║",
  "██║     ██║  ██║╚██████╗██║  ██╗██║  ██║██║  ██║███████║██║  ██║",
  "╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝",
];
const SHADES = [51, 45, 39, 33, 27, 21]; // cyan fading to blue

function author() {
  const a = pkg.author;
  return (typeof a === "string" ? a : a && a.name) || "unknown";
}

function banner() {
  const rows = LOGO.map((row, i) =>
    "  " + (enabled() ? `\x1b[38;5;${SHADES[i]}m${row}\x1b[0m` : row)
  );
  return [
    "",
    ...rows,
    "",
    "  " + bold("Tamper-evident packet captures, anchored on a blockchain"),
    "  " + gray(`v${pkg.version}  ·  developed by ${author()}`),
    "",
  ].join("\n");
}

// Colors the status marks and result lines that the library code prints.
function decorate(line) {
  if (!enabled()) return line;
  if (/^RESULT: INTACT/.test(line)) return bold(green(line));
  if (/^RESULT: TAMPERING DETECTED/.test(line)) return bold(red(line));
  if (/^\s+(Deleted|Modified|Inserted|Moved) \(\d+\):$/.test(line)) return bold(yellow(line));
  return line.replace(/✔/g, green("✔")).replace(/✘/g, red("✘"));
}

function installColorizer() {
  if (!enabled()) return;
  const original = console.log.bind(console);
  console.log = (...args) =>
    original(...args.map((a) => (typeof a === "string" ? decorate(a) : a)));
}

module.exports = { banner, installColorizer, bold, dim, red, green, yellow, cyan, gray };
