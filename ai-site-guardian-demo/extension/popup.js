const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const LABEL = { auto_fix: "Safe to auto-fix", require_approval: "Needs your approval", notify_only: "Urgent: alert only" };
let audit = null, tab = null;

// Runs inside the page being inspected (read-only: it only reads the DOM and timings).
function pageScan() {
  const q = s => [...document.querySelectorAll(s)];
  const gen = document.querySelector('meta[name=generator]')?.content || "";
  const urls = q("script[src],link[href],img[src]").map(e => e.src || e.href);
  const plugins = {};
  urls.forEach(u => { const m = u.match(/\/wp-content\/plugins\/([^/]+)\//); if (!m) return;
    const v = (u.match(/[?&]ver=([\d.]+)/) || [])[1]; if (!(m[1] in plugins) || v) plugins[m[1]] = v || plugins[m[1]] || null; });
  const th = urls.map(u => u.match(/\/wp-content\/themes\/([^/]+)\//)).find(Boolean);
  const nav = performance.getEntriesByType("navigation")[0], res = performance.getEntriesByType("resource"), imgs = q("img");
  return { isWP: /wordpress/i.test(gen) || urls.some(u => /wp-content|wp-includes/.test(u)),
    core: (gen.match(/WordPress\s+([\d.]+)/i) || [])[1] || null,
    plugins: Object.entries(plugins).map(([slug, ver]) => ({ slug, ver })), theme: th ? th[1] : null,
    perf: { load: nav ? Math.round(nav.loadEventEnd) : null, transferKB: Math.round(res.reduce((a, r) => a + (r.transferSize || 0), 0) / 1024),
            images: imgs.length, noAlt: imgs.filter(i => !i.hasAttribute("alt")).length, http: urls.filter(u => u.startsWith("http://")).length } };
}

async function api() { return (($("#api").value || "").trim() || "http://localhost:8000").replace(/\/$/, ""); }

async function run() {
  $("#list").innerHTML = ""; $("#agent").hidden = true; $("#score").textContent = "--"; $("#ring").style.setProperty("--p", 0);
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !/^https?:/.test(tab.url)) { $("#host").textContent = "Open a website first"; $("#list").innerHTML = '<div class="err">This page type cannot be scanned. Open a normal http or https website.</div>'; return; }
  $("#host").textContent = new URL(tab.url).host; $("#tags").innerHTML = '<span class="tag">Scanning…</span>';
  try {
    const [{ result: scan }] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: pageScan });
    const headers = {}; try { const r = await fetch(tab.url, { cache: "no-store" }); r.headers.forEach((v, k) => headers[k] = v); } catch {}
    const res = await fetch(await api() + "/api/ext/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: tab.url, wp: scan, headers, perf: scan.perf }) });
    audit = await res.json(); show(audit, scan);
  } catch (e) {
    $("#tags").innerHTML = ""; $("#list").innerHTML = '<div class="err"><b>Backend not reachable.</b><br>Start it with <code>uvicorn main:app --port 8000</code> or set the Render URL below.</div>';
  }
}

function show(a, scan) {
  const c = a.score >= 80 ? "var(--teal)" : a.score >= 55 ? "var(--amber)" : "var(--red)";
  $("#ring").style.setProperty("--c", c); requestAnimationFrame(() => $("#ring").style.setProperty("--p", a.score)); $("#score").textContent = a.score;
  $("#tags").innerHTML = [a.wordpress ? "WordPress" : "Not WordPress", scan.core && "Core " + scan.core, scan.theme && "Theme " + scan.theme,
    scan.plugins.length && scan.plugins.length + " plugins"].filter(Boolean).map(t => `<span class="tag">${esc(t)}</span>`).join("");
  $("#mode").textContent = a.ai_source === "claude" ? "Claude live" : "Built-in AI"; $("#mode").className = "mode " + (a.ai_source === "claude" ? "live" : "");
  $("#agent").hidden = false; $("#agent").innerHTML = `<small>Agent summary</small><br>${esc(a.summary)}`;
  const order = { high: 0, medium: 1, low: 2 };
  $("#list").innerHTML = a.findings.length ? a.findings.sort((x, y) => order[x.level] - order[y.level]).map(f =>
    `<details class="${f.level}"><summary><span>${esc(f.title)}</span><span class="pill ${f.level}">${f.level}</span></summary>
     <div class="body"><b>${LABEL[f.action]}</b> (rule: ${esc(f.rule)})<br>${esc(f.detail)}<br><br><b>Plan:</b> ${esc(f.plan)}</div></details>`).join("")
    : '<div class="err" style="background:#1fb5a322">No issues found on this page.</div>';
}

async function ask() {
  const q = $("#q").value.trim(); if (!q || !audit) return; $("#answer").hidden = false; $("#answer").textContent = "Thinking…";
  try { const r = await fetch(await api() + "/api/agent/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question: q, audit }) });
    $("#answer").textContent = (await r.json()).answer; } catch { $("#answer").textContent = "Backend not reachable."; }
}

chrome.storage.local.get("api").then(v => { $("#api").value = v.api || "http://localhost:8000"; run(); });
$("#api").onchange = () => chrome.storage.local.set({ api: $("#api").value });
$("#rescan").onclick = run; $("#send").onclick = ask; $("#q").onkeydown = e => e.key === "Enter" && ask();
