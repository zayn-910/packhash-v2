const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");
const { loadConfig, DEFAULT_RPC } = require("./config");

const ARTIFACT = path.join(
  __dirname, "..", "artifacts", "contracts",
  "PacketRegistry.sol", "PacketRegistry.json"
);

function loadArtifact() {
  if (!fs.existsSync(ARTIFACT)) {
    throw new Error("Contract not compiled yet. Run: npx hardhat compile");
  }
  return JSON.parse(fs.readFileSync(ARTIFACT, "utf8"));
}

// Quick reachability check, so we fail with a clear message instead of
// ethers retrying silently in the background.
async function ping(rpcUrl) {
  try {
    const res = await fetch(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
      signal: AbortSignal.timeout(3000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

async function getProvider(rpcUrl) {
  if (!(await ping(rpcUrl))) {
    throw new Error(
      `Cannot reach a blockchain node at ${rpcUrl}. Start one with: npx hardhat node`
    );
  }
  return new ethers.JsonRpcProvider(rpcUrl);
}

async function deploy(rpcUrl) {
  const artifact = loadArtifact();
  const provider = await getProvider(rpcUrl);
  const signer = await provider.getSigner(0);
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, signer);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  return await contract.getAddress();
}

async function connect() {
  const cfg = loadConfig();
  if (!cfg) throw new Error("Not initialized. Run: packhash init");

  const artifact = loadArtifact();
  const provider = await getProvider(cfg.rpcUrl);

  const code = await provider.getCode(cfg.contractAddress);
  if (code === "0x") {
    throw new Error(
      "The contract no longer exists on this chain (the local node was restarted). " +
      "Run: packhash init"
    );
  }

  const signer = await provider.getSigner(0);
  return new ethers.Contract(cfg.contractAddress, artifact.abi, signer);
}

async function seal(sessionRootHex, packetCount) {
  const contract = await connect();
  const tx = await contract.seal(sessionRootHex, packetCount);
  const receipt = await tx.wait();

  let id = null;
  for (const log of receipt.logs) {
    try {
      const parsed = contract.interface.parseLog(log);
      if (parsed && parsed.name === "Sealed") id = Number(parsed.args.id);
    } catch { /* not our event */ }
  }
  return { id, txHash: tx.hash };
}

async function listAnchors() {
  const contract = await connect();
  const n = Number(await contract.anchorCount());
  const anchors = [];
  for (let i = 0; i < n; i++) {
    const a = await contract.getAnchor(i);
    anchors.push({
      id: i,
      sessionRoot: a.sessionRoot,
      chainRoot: a.chainRoot,
      packetCount: Number(a.packetCount),
      timestamp: Number(a.timestamp),
    });
  }
  return anchors;
}

async function getAnchor(id) {
  const contract = await connect();
  const a = await contract.getAnchor(id);
  return {
    id,
    sessionRoot: a.sessionRoot,
    chainRoot: a.chainRoot,
    packetCount: Number(a.packetCount),
    timestamp: Number(a.timestamp),
  };
}

// Non-throwing health check, used by the menu to decide what needs fixing.
async function health() {
  const cfg = loadConfig();
  const rpcUrl = cfg ? cfg.rpcUrl : DEFAULT_RPC;
  if (!(await ping(rpcUrl))) return { state: "no-node", rpcUrl };
  if (!cfg) return { state: "no-config", rpcUrl };
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const code = await provider.getCode(cfg.contractAddress);
  if (code === "0x") return { state: "no-contract", rpcUrl };
  return { state: "ok", rpcUrl };
}

module.exports = { deploy, connect, seal, listAnchors, getAnchor, health };
