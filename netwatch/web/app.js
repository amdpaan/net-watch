// net-watch dashboard. Plain JS, no build step. Everything that came from the network (hostnames, vendors)
// goes into the page with textContent only, never as HTML.
"use strict";

const ICONS = {
  phone: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/></svg>',
  laptop: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4.5" y="5" width="15" height="10" rx="1.5"/><path d="M2.5 19h19"/></svg>',
  tv: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="4.5" width="19" height="12.5" rx="2"/><path d="M8 20.5h8"/></svg>',
  router: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M10.5 16.5h.01M17 13V9"/><path d="M13.5 6.5a5 5 0 0 1 7 0"/></svg>',
  other: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="6" width="12" height="12" rx="2"/><path d="M10 2.5V6M14 2.5V6M10 18v3.5M14 18v3.5M2.5 10H6M2.5 14H6M18 10h3.5M18 14h3.5"/></svg>',
};
const TYPE_NAMES = { phone: "Phone", laptop: "Laptop", tv: "TV", router: "Router", other: "Other" };
const SUN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
const MOON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/></svg>';

const $ = (id) => document.getElementById(id);
const state = { data: null, filter: "all", query: "", sort: "status", dir: 1, open: null, timer: null };

// ---------- helpers
function el(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v);
  }
  for (const c of children) if (c !== null && c !== undefined) node.append(c);
  return node;
}

function icon(type, big) {
  const span = el("span", { class: "dev-icon" + (big ? " big" : ""), "aria-hidden": "true" });
  span.innerHTML = ICONS[type] || ICONS.other; // constant markup above, never data
  return span;
}

function ago(seconds) {
  seconds = Math.max(0, Math.round(seconds));
  if (seconds < 60) return "just now";
  const units = [["d", 86400], ["h", 3600], ["min", 60]];
  for (const [u, s] of units) if (seconds >= s) return Math.floor(seconds / s) + " " + u;
  return seconds + " s";
}

function dateTime(ts) {
  return new Date(ts * 1000).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
}

function day(ts) {
  return new Date(ts * 1000).toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

function ipKey(ip) {
  return (ip || "").split(".").reduce((n, p) => n * 256 + (+p || 0), 0);
}

async function api(path, body) {
  const opts = body === undefined ? {} :
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

// ---------- theme
function storedTheme() {
  try { return localStorage.getItem("netwatch-theme"); } catch (e) { return null; }
}

function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
  const dark = theme ? theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  $("theme-btn").innerHTML = dark ? SUN : MOON;
}

function toggleTheme() {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  try { localStorage.setItem("netwatch-theme", next); } catch (e) { /* private mode: just this visit */ }
  applyTheme(next);
}

// ---------- rendering
function statusText(d) {
  if (d.online) return "Online";
  return "Offline for " + ago(d.offline_for);
}

function matches(d) {
  if (state.filter === "online" && !d.online) return false;
  if (state.filter === "unknown" && d.label) return false;
  if (state.filter === "known" && !d.label) return false;
  if (!state.query) return true;
  const q = state.query.toLowerCase();
  return [d.name, d.ip, d.vendor, d.mac, d.hostname, d.label].some((v) => v && v.toLowerCase().includes(q));
}

function compare(a, b) {
  const key = state.sort;
  let r;
  if (key === "ip") r = ipKey(a.ip) - ipKey(b.ip);
  else if (key === "first_seen") r = a.first_seen - b.first_seen;
  else if (key === "status") r = (b.online - a.online) || (a.offline_for || 0) - (b.offline_for || 0) || ipKey(a.ip) - ipKey(b.ip);
  else r = String(a[key] || "").localeCompare(String(b[key] || ""), undefined, { sensitivity: "base" });
  return r * state.dir;
}

function renderRow(d) {
  const tags = [];
  if (d.new) tags.push(el("span", { class: "tag new", text: "New" }));
  if (d.is_self) tags.push(el("span", { class: "tag", text: "This Mac" }));
  if (d.is_gateway) tags.push(el("span", { class: "tag", text: "Router" }));
  const sub = d.label && d.hostname && d.hostname !== d.label ? d.hostname : d.mac;
  return el("tr", { class: d.online ? "online" : "", tabindex: "0", "data-mac": d.mac,
                    onclick: () => openSheet(d.mac),
                    onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openSheet(d.mac); } } },
    el("td", { class: "c-icon" }, icon(d.type)),
    el("td", { class: "c-name" }, el("div", { class: "name" }, el("span", { text: d.name }), ...tags),
       el("div", { class: "mac", text: sub })),
    el("td", { class: "c-ip mono", text: d.ip || "–" }),
    el("td", { class: "c-vendor" + (d.private_mac || d.vendor === "Unknown vendor" ? " muted" : ""), text: d.vendor }),
    el("td", { class: "c-status" }, el("span", { class: "status" + (d.online ? "" : " off") },
       el("span", { class: "dot" + (d.online ? " on" : "") }), statusText(d))),
    el("td", { class: "c-first muted", text: dateTime(d.first_seen) }),
  );
}

function renderTable() {
  const rows = state.data.devices.filter(matches).sort(compare);
  $("rows").replaceChildren(...rows.map(renderRow));
  const empty = $("empty");
  empty.hidden = rows.length > 0;
  if (!state.data.devices.length) empty.textContent = "No devices yet. The first scan saves what's on your network now.";
  else empty.textContent = "No devices match.";
  document.querySelectorAll(".devices th[data-sort]").forEach((th) => {
    th.setAttribute("aria-sort", th.dataset.sort === state.sort ? (state.dir > 0 ? "ascending" : "descending") : "none");
  });
}

function renderStatus() {
  const { status, last_scan: scan, now, home_subnet: subnet } = state.data;
  const parts = [];
  if (subnet) parts.push(subnet);
  if (status.scanning) parts.push("scanning…");
  else if (scan) parts.push("last scan " + (now - scan.ts < 60 ? "just now" : ago(now - scan.ts) + " ago"));
  $("subtitle").textContent = parts.join(" · ") || "No home network saved yet";

  const btn = $("scan-btn");
  btn.disabled = status.scanning;
  btn.textContent = status.scanning ? "Scanning…" : "Scan now";

  const notice = $("status-notice");
  const show = ["away", "not_set", "refused", "offline", "permission", "error"].includes(status.state);
  notice.hidden = !show;
  if (show) {
    let msg = status.message;
    if (status.state === "not_set") msg = "No home network saved yet. Run `netwatch home` in Terminal at home to confirm it.";
    if (status.state === "away") msg = status.message + " Showing what was saved at home.";
    notice.textContent = msg;
    notice.className = "notice" + (["permission", "error"].includes(status.state) ? " warn" : "");
  }
}

function renderBanner() {
  const items = state.data.new;
  const banner = $("banner");
  banner.hidden = items.length === 0;
  if (!items.length) return;
  $("banner-title").textContent = items.length === 1 ? "A new device joined your network" : items.length + " new devices joined your network";
  $("banner-list").replaceChildren(...items.slice(0, 5).map((d) => el("li", {},
    el("button", { type: "button", text: d.name, onclick: () => openSheet(d.mac) }),
    el("span", { class: "meta", text: "  " + [d.ip, d.vendor, ago(state.data.now - d.first_seen) + " ago"].filter(Boolean).join(" · ") }),
  )));
}

function render() {
  const c = state.data.counts;
  $("c-online").textContent = c.online;
  $("c-known").textContent = c.known;
  $("c-unknown").textContent = c.unknown;
  renderStatus();
  renderBanner();
  renderTable();
}

// ---------- data
async function refresh() {
  clearTimeout(state.timer);
  try {
    state.data = await api("/api/devices");
    render();
  } catch (e) {
    const notice = $("status-notice");
    notice.hidden = false;
    notice.className = "notice warn";
    notice.textContent = "Can't reach net-watch (" + e.message + "). Is `netwatch serve` still running?";
  }
  const scanning = state.data && state.data.status.scanning;
  state.timer = setTimeout(refresh, scanning ? 2000 : 20000);
}

async function scanNow() {
  $("scan-btn").disabled = true;
  try { await api("/api/scan", {}); } catch (e) { alert("Couldn't start a scan: " + e.message); }
  setTimeout(refresh, 300);
}

// ---------- detail sheet
function deviceByMac(mac) {
  return state.data.devices.find((d) => d.mac === mac);
}

function fact(dl, label, value, mono) {
  if (value === null || value === undefined || value === "") return;
  dl.append(el("dt", { text: label }), el("dd", { class: mono ? "mono" : "", text: value }));
}

function openSheet(mac) {
  const d = deviceByMac(mac);
  if (!d) return;
  state.open = mac;
  $("sheet-icon").replaceWith(Object.assign(icon(d.type, true), { id: "sheet-icon" }));
  $("sheet-title").textContent = d.name;
  $("sheet-sub").textContent = statusText(d) + (d.ip ? " · " + d.ip : "");
  $("f-label").value = d.label || "";
  $("f-label").placeholder = d.hostname || "e.g. Living room TV";

  const types = $("f-types");
  types.replaceChildren();
  for (const t of state.data.types) {
    const id = "type-" + t;
    const input = el("input", { type: "radio", name: "type", id, value: t });
    input.checked = d.type === t;
    const label = el("label", { for: id }, icon(t).firstChild.cloneNode(true), el("span", { text: TYPE_NAMES[t] || t }));
    types.append(input, label);
  }

  const facts = $("facts");
  facts.replaceChildren();
  fact(facts, "MAC", d.mac + (d.private_mac ? "  (private, randomized)" : ""), true);
  fact(facts, "Vendor", d.vendor);
  fact(facts, "Hostname", d.hostname);
  fact(facts, "Last IP", d.ip, true);
  fact(facts, "First seen", dateTime(d.first_seen));
  fact(facts, "Last seen", d.online ? "Now" : dateTime(d.last_seen) + " (" + ago(d.offline_for) + " ago)");
  if (!d.type_set) fact(facts, "Type", (TYPE_NAMES[d.type] || d.type) + " (guessed)");

  $("forget-btn").hidden = d.is_self || d.is_gateway;
  if (window.loadTimeline) window.loadTimeline(d);
  $("sheet").returnValue = "";
  $("sheet").showModal();
}

async function saveSheet() {
  const mac = state.open;
  const checked = document.querySelector('#f-types input:checked');
  const d = deviceByMac(mac);
  const body = { label: $("f-label").value.trim() };
  if (checked && (d.type_set || checked.value !== d.type)) body.type = checked.value;
  try {
    await api("/api/devices/" + mac, body);
  } catch (e) {
    alert("Couldn't save: " + e.message);
  }
  refresh();
}

async function forgetDevice() {
  const d = deviceByMac(state.open);
  if (!d || !confirm("Forget " + d.name + "? Its history is deleted, and it will count as new if it comes back.")) return;
  try {
    await api("/api/devices/" + d.mac + "/forget", {});
  } catch (e) {
    alert("Couldn't forget it: " + e.message);
  }
  $("sheet").close();
  refresh();
}

// ---------- wiring
function setFilter(filter) {
  state.filter = filter;
  document.querySelectorAll(".chip").forEach((c) => c.classList.toggle("on", c.dataset.filter === filter));
  renderTable();
}

document.addEventListener("DOMContentLoaded", () => {
  applyTheme(storedTheme());
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => applyTheme(storedTheme()));
  $("theme-btn").addEventListener("click", toggleTheme);
  $("scan-btn").addEventListener("click", scanNow);
  $("dismiss-btn").addEventListener("click", async () => { await api("/api/dismiss", {}).catch(() => {}); refresh(); });
  document.querySelectorAll(".chip").forEach((c) => c.addEventListener("click", () => setFilter(c.dataset.filter)));
  document.querySelectorAll(".card").forEach((c) => c.addEventListener("click", () => setFilter(c.dataset.filter)));
  $("search").addEventListener("input", (e) => { state.query = e.target.value.trim(); renderTable(); });
  document.querySelectorAll(".devices th[data-sort]").forEach((th) => th.addEventListener("click", () => {
    if (state.sort === th.dataset.sort) state.dir *= -1;
    else { state.sort = th.dataset.sort; state.dir = 1; }
    renderTable();
  }));
  $("sheet").addEventListener("close", () => {
    if ($("sheet").returnValue === "save") saveSheet();
    state.open = null;
  });
  document.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => $("sheet").close("cancel")));
  $("forget-btn").addEventListener("click", forgetDevice);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
  refresh();
});
