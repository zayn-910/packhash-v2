(() => {
  "use strict";

  const token = new URLSearchParams(location.search).get("token");
  const $ = (id) => document.getElementById(id);

  let state = null;
  let sessions = [];
  let selected = null;
  let busy = false;

  // Everything shown here comes from captures and files, which an attacker can influence
  // (DNS names, for example), so this page never uses innerHTML.
  function el(tag, props, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v == null || v === false) continue;
      if (k === "class") n.className = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      n.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return n;
  }

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      ...opts,
      headers: { "X-Packhash-Token": token, ...(opts.headers || {}) },
    });
    let data = null;
    try { data = await res.json(); } catch { /* not JSON */ }
    if (!res.ok) throw new Error((data && data.error) || `Request failed (${res.status})`);
    return data;
  }
  const post = (path, body) =>
    api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

  const fmtBytes = (n) => {
    if (n == null) return "missing";
    const u = ["B", "KB", "MB", "GB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${i > 0 && n < 10 ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
  };
  const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString() : "");
  const short = (a) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : "");
  const current = () => sessions.find((s) => s.name === selected);

  function notice(text, kind) {
    const n = $("notice");
    n.className = `notice ${kind || "info"}`;
    n.textContent = text;
  }
  const clearNotice = () => { $("notice").className = "notice hidden"; };

  // ---------- header / state ----------
  async function loadState() {
    state = await api("/api/state");
    $("version").textContent = `v${state.version}`;
    $("demo").classList.toggle("hidden", !state.demo);
    $("footer").textContent = `packhash v${state.version}${state.author ? " · developed by " + state.author : ""}`;

    const pill = $("chain");
    pill.className = "pill";
    if (state.health === "ok") {
      pill.classList.add("ok");
      pill.textContent = `Chain connected · contract ${short(state.contract)} · ${state.anchors ?? 0} anchor(s)`;
      clearNotice();
    } else if (state.health === "no-node") {
      pill.classList.add("bad");
      pill.textContent = "No blockchain node";
      notice("Start a node with “npx hardhat node”, then press Refresh.", "warn");
    } else {
      pill.classList.add("bad");
      pill.textContent = "Contract not deployed";
      notice("Run “packhash init” (or open the packhash menu) to deploy the contract, then press Refresh.", "warn");
    }
  }

  // ---------- sessions table ----------
  async function loadSessions() {
    sessions = await api("/api/sessions");
    if (selected && !current()) selected = null;
    renderSessions();
    if (selected) renderButtons();
    else $("detail").classList.add("hidden");
  }

  function renderSessions() {
    const box = $("sessions");
    box.replaceChildren();
    if (!sessions.length) {
      box.append(el("p", { class: "muted pad" }, "No sessions yet. Capture traffic with packhash, or import a capture file."));
      return;
    }
    box.append(
      el("div", { class: "scroll" },
        el("table", { class: "table" },
          el("thead", null, el("tr", null, ["Session", "Status", "Packets", "Sealed", "Capture file"].map((h) => el("th", null, h)))),
          el("tbody", null, sessions.map((s) =>
            el("tr", { class: s.name === selected ? "row sel" : "row", onclick: () => select(s.name) },
              el("td", { class: "mono wrap" }, s.name),
              el("td", null, s.sealed
                ? el("span", { class: "badge ok" }, `sealed #${s.anchorId}`)
                : el("span", { class: "badge warn" }, "not sealed")),
              el("td", null, s.packets ?? "—"),
              el("td", null, s.sealed ? fmtDate(s.sealedAt) : "—"),
              el("td", null, s.captureBytes == null
                ? el("span", { class: "badge bad" }, "missing")
                : fmtBytes(s.captureBytes))))))));
  }

  function select(name) {
    selected = name;
    renderSessions();
    renderDetail();
  }

  // ---------- session detail ----------
  function renderDetail() {
    const s = current();
    const box = $("detail");
    if (!s) { box.classList.add("hidden"); return; }
    box.classList.remove("hidden");
    box.replaceChildren(
      el("div", { class: "card-head" },
        el("h2", { class: "mono wrap" }, s.name),
        el("div", { class: "actions", id: "buttons" })),
      el("div", { id: "tamper" }),
      el("div", { id: "result" }));
    renderButtons();
    renderTamper();
  }

  function dl(file, label, s) {
    const q = new URLSearchParams({ session: s.name, file, token });
    return el("a", { class: "btn ghost", href: `/api/download?${q}` }, label);
  }

  function renderButtons() {
    const s = current();
    const box = $("buttons");
    if (!s || !box) return;
    const items = [
      s.sealed
        ? el("button", { class: "btn primary", onclick: doVerify }, "Verify")
        : el("button", { class: "btn primary", onclick: doSeal }, "Seal on-chain"),
      s.sealed ? el("button", { class: "btn", onclick: () => doRecover(false) }, "Recover packets") : null,
      s.sealed ? el("button", { class: "btn", onclick: () => doRecover(true) }, "Rebuild full capture") : null,
      s.captureBytes != null ? dl("capture.pcap", "Download capture", s) : null,
      s.hasRecovered ? dl("recovered.pcap", "Download recovered", s) : null,
      s.hasRestored ? dl("restored.pcap", "Download restored", s) : null,
    ].filter(Boolean);
    box.replaceChildren(...items);
  }
  
  async function run(fn) {
    if (busy) return;
    busy = true;
    document.querySelectorAll("#buttons button").forEach((b) => { b.disabled = true; });
    const out = $("result");
    out.replaceChildren(el("p", { class: "muted pad" }, "Working…"));
    try {
      await fn(out);
    } catch (e) {
      out.replaceChildren(el("div", { class: "banner bad" }, e.message));
    } finally {
      busy = false;
      document.querySelectorAll("#buttons button").forEach((b) => { b.disabled = false; });
    }
  }

  // ---------- result rendering ----------
  function table(heads, rows, limit = 500) {
    return el("div", { class: "scroll" },
      el("table", { class: "table mono" },
        el("thead", null, el("tr", null, heads.map((h) => el("th", null, h)))),
        el("tbody", null, rows.slice(0, limit).map((r) => el("tr", null, r.map((c) => el("td", null, c)))))),
      rows.length > limit ? el("p", { class: "muted" }, `…and ${rows.length - limit} more`) : null);
  }

  function group(title, items, heads, row) {
    if (!items.length) return null;
    return el("div", { class: "group" }, el("h3", null, `${title} (${items.length})`), table(heads, items.map(row)));
  }

  function renderVerify(r) {
    const d = r.diff;
    return el("div", null,
      el("div", { class: `banner ${r.intact ? "ok" : "bad"}` },
        r.intact
          ? "INTACT. Nothing has been altered since sealing."
          : `TAMPERING DETECTED${r.summary ? ": " + r.summary : ""}`),
      el("p", { class: "muted" }, `Anchor #${r.anchor.id} · ${r.anchor.packetCount} packets · sealed ${fmtDate(r.anchor.sealedAt)}`),
      el("ul", { class: "checks" }, r.checks.map((c) =>
        el("li", { class: c.ok ? "ok" : "bad" },
          el("span", { class: "mark" }, c.ok ? "✔" : "✘"), el("strong", null, c.name), " ", c.text))),
      r.unidentifiable
        ? el("p", { class: "muted" }, "The stored records are unreliable, so the changed packets cannot be identified.")
        : null,
      d && group("Deleted", d.deleted, ["#", "Time", "Packet"], (x) => [x.index, x.time, x.desc]),
      d && group("Modified", d.modified, ["#", "Time", "Packet", "Change"], (x) => [x.index, x.time, x.desc, x.change]),
      d && group("Inserted", d.inserted, ["Position", "Time", "Packet"], (x) => [x.index, x.time, x.desc]),
      d && group("Moved", d.moved, ["Was", "Now", "Time", "Packet"], (x) => [x.origIndex, x.curIndex, x.time, x.desc]));
  }

  function renderRecover(r) {
    const notes = r.notes.map((n) => el("p", { class: "muted" }, n));
    if (r.mode === "full") {
      return el("div", null,
        el("div", { class: "banner ok" }, `Rebuilt all ${r.count} original packets as restored.pcap.`),
        el("p", { class: "muted" }, `Records verified against anchor #${r.anchorId}. Use “Download restored” above.`));
    }
    if (r.count === 0) {
      return el("div", null,
        el("div", { class: "banner ok" }, "Nothing to recover: no packets are missing or changed."), notes);
    }
    return el("div", null,
      el("div", { class: "banner ok" }, `Recovered ${r.count} packet(s) as recovered.pcap.`),
      el("p", { class: "muted" }, `Records verified against anchor #${r.anchorId}. Use “Download recovered” above.`),
      notes,
      table(["#", "Time", "Packet", "Why"], r.items.map((x) => [x.index, x.time, x.desc, x.why])));
  }

  // ---------- actions ----------
  const doVerify = () => run(async (out) => {
    out.replaceChildren(renderVerify(await post("/api/verify", { session: selected })));
  });

  const doRecover = (full) => run(async (out) => {
    const r = await post("/api/recover", { session: selected, full });
    await loadSessions(); // refreshes the download buttons
    out.replaceChildren(renderRecover(r));
  });

  const doSeal = () => run(async () => {
    const r = await post("/api/seal", { session: selected });
    await loadSessions();
    await loadState();
    renderDetail();
    $("result").replaceChildren(
      el("div", { class: "banner ok" }, `Sealed as anchor #${r.anchorId} (${r.packetCount} packets).`),
      el("p", { class: "muted mono wrap" }, `Merkle root: 0x${r.sessionRoot}`),
      el("p", { class: "muted mono wrap" }, `Tx hash: ${r.txHash}`));
  });

  // ---------- demo: tamper panel ----------
  const KINDS = {
    delete: { label: "Delete packets", hint: "e.g. 5,10-12" },
    connection: { label: "Delete a whole connection", hint: "" },
    modify: { label: "Modify one packet", hint: "packet number" },
    insert: { label: "Insert a forged packet", hint: "insert after packet number" },
    swap: { label: "Swap two packets", hint: "e.g. 5,6" },
  };

  function renderTamper() {
    const box = $("tamper");
    box.replaceChildren();
    if (!state || !state.demo) return;

    const op = el("select", null, Object.entries(KINDS).map(([k, v]) => el("option", { value: k }, v.label)));
    const val = el("input", { type: "text", placeholder: KINDS.delete.hint });
    const flows = el("select", { class: "hidden" });
    const status = el("span", { class: "muted" });

    op.addEventListener("change", async () => {
      const k = op.value;
      val.classList.toggle("hidden", k === "connection");
      flows.classList.toggle("hidden", k !== "connection");
      val.placeholder = KINDS[k].hint;
      status.textContent = "";
      if (k !== "connection") return;
      try {
        const list = await api(`/api/flows?session=${encodeURIComponent(selected)}`);
        flows.replaceChildren(...(list.length
          ? list.map((f) => el("option", { value: f.n }, `#${f.n} · ${f.packets} packets · ${f.key}${f.name ? " (" + f.name + ")" : ""}`))
          : [el("option", { value: "" }, "No connections found")]));
      } catch (e) {
        status.textContent = e.message;
      }
    });

    const apply = el("button", {
      class: "btn",
      onclick: () => {
        const k = op.value;
        const v = k === "connection" ? flows.value : val.value.trim();
        if (!v) { status.textContent = "Enter a value first."; return; }
        if (!confirm(`This permanently alters capture.pcap in this session.\n\n${KINDS[k].label}: ${v}\n\nContinue?`)) return;
        status.textContent = "";
        run(async (out) => {
          const r = await post("/api/tamper", { session: selected, op: k, value: v });
          await loadSessions();
          out.replaceChildren(
            el("div", { class: "banner warn" }, r.message),
            el("p", { class: "muted" }, "The capture has been altered. Press Verify to see whether packhash notices."));
        });
      },
    }, "Apply");

    box.append(el("div", { class: "panel" },
      el("h3", null, "Demo: tamper with this capture"),
      el("div", { class: "form" }, op, val, flows, apply, status)));
  }

  // ---------- import ----------
  $("file").addEventListener("change", async (ev) => {
    const f = ev.target.files[0];
    ev.target.value = "";
    if (!f || busy) return;
    busy = true;
    notice(`Importing ${f.name} (${fmtBytes(f.size)}). It is sealed on-chain after the upload…`, "info");
    try {
      const q = new URLSearchParams({ name: f.name.replace(/\.[^.]+$/, ""), filename: f.name });
      const r = await api(`/api/import?${q}`, {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body: f,
      });
      await loadSessions();
      await loadState();
      select(r.dir);
      notice(`Imported ${r.packets} packets and sealed them as anchor #${r.seal.anchorId}.`, "ok");
    } catch (e) {
      notice(e.message, "bad");
    } finally {
      busy = false;
    }
  });

  $("refresh").addEventListener("click", async () => {
    try { await loadState(); await loadSessions(); } catch (e) { notice(e.message, "bad"); }
  });

  (async () => {
    if (!token) {
      notice("Open the link printed by “packhash ui”. It contains the access token.", "warn");
      return;
    }
    try { await loadState(); await loadSessions(); } catch (e) { notice(e.message, "bad"); }
  })();
})();
