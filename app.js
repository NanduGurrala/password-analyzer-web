"use strict";

/* PassGuard UI. The engine (analysis, generator, hashing) lives in engine.js. */

const $ = (sel, root = document) => root.querySelector(sel);

function el(tag, cls, text) { // text is always inserted as textContent, never HTML
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
function setBanner(node, kind, text) { node.className = "banner " + kind; node.textContent = text; node.hidden = false; }
const hasWebCrypto = () => !!(window.crypto && window.crypto.subtle);
const WEBCRYPTO_MESSAGE = "Hashing needs the Web Crypto API, which browsers only enable on HTTPS or localhost. " +
  "Open the hosted link, or run: python -m http.server";

async function copyText(text, button) {
  try { await navigator.clipboard.writeText(text); button.textContent = "Copied"; }
  catch (e) { button.textContent = "Press Ctrl+C"; }
  setTimeout(() => { button.textContent = "Copy"; }, 1500);
}
function codeBox(text) {
  const box = el("div", "codebox"), btn = el("button", "copy", "Copy");
  btn.type = "button";
  btn.addEventListener("click", () => copyText(text, btn));
  box.append(el("code", "", text), btn);
  return box;
}

/* ---------- dark / light theme ---------- */
function setTheme(t) {
  document.documentElement.dataset.theme = t;
  $("#theme-btn").textContent = t === "dark" ? "☀️ Light" : "🌙 Dark";
  try { localStorage.setItem("pg-theme", t); } catch (e) { /* storage may be blocked */ }
}
function initTheme() {
  let t = "dark";
  try { t = localStorage.getItem("pg-theme") || "dark"; } catch (e) { /* ignore */ }
  setTheme(t);
  $("#theme-btn").addEventListener("click", () =>
    setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
}

/* ---------- page switching ---------- */
const VIEWS = ["home", "check", "generate", "hash", "verify", "lab", "learn"];
const started = {};
const starters = {};

function route() {
  let name = location.hash.replace("#/", "");
  if (!VIEWS.includes(name)) name = "home";
  VIEWS.forEach((v) => { $("#view-" + v).hidden = v !== name; });
  document.querySelectorAll(".links a").forEach((a) => {
    if (a.getAttribute("href") === "#/" + name) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  window.scrollTo(0, 0);
  if (!started[name] && starters[name]) { started[name] = true; starters[name](); }
}

/* ---------- check my password ---------- */
function renderAnalysis(a) {
  const filled = a.length > 0;
  $("#meter-fill").style.width = a.score + "%";
  $("#meter-fill").style.backgroundColor = a.colour;
  $("#meter").setAttribute("aria-valuenow", String(a.score));
  $("#meter-label").textContent = a.label;
  $("#meter-label").style.color = filled ? a.colour : "";
  $("#meter-score").textContent = filled ? a.score + " / 100" : "";
  $("#plain").textContent = filled
    ? (a.crack[2].time === "instantly"
        ? "A hacker with a powerful computer could crack this instantly. " + a.note
        : "A hacker with a powerful computer could crack this in about " + a.crack[2].time + ". " + a.note)
    : "Type a password above, or tap one of the examples.";

  $("#stat-length").textContent = String(a.length);
  $("#stat-pool").textContent = String(a.pool);
  $("#stat-raw").textContent = a.rawEntropy.toFixed(1);
  $("#stat-eff").textContent = a.entropy.toFixed(1);

  document.querySelectorAll("#checklist li").forEach((li) => {
    const ok = filled && a.checks[li.dataset.check];
    li.classList.toggle("ok", !!ok);
    li.classList.toggle("bad", filled && !ok);
  });

  const crack = $("#crack-list");
  crack.replaceChildren();
  a.crack.forEach((c) => {
    const row = el("div", "crack"), left = el("div");
    left.append(el("div", "n", c.name), el("div", "r", c.rate));
    row.append(left, el("div", "t", c.time));
    crack.append(row);
  });

  const f = $("#findings"); f.replaceChildren();
  if (!a.findings.length) f.append(el("p", "muted", "Type something to see what we find."));
  a.findings.forEach((x) => f.append(el("div", "finding " + x.level, x.text)));
  const t = $("#tips"); t.replaceChildren();
  if (!a.suggestions.length) t.append(el("p", "muted", "Tips appear as you type."));
  a.suggestions.forEach((x) => t.append(el("div", "tip", x)));
}

starters.check = () => {
  const input = $("#pw-input");
  const refresh = () => renderAnalysis(analyze(input.value));
  input.addEventListener("input", () => { $("#example-note").hidden = true; refresh(); });
  input.value = "summer2024"; // example so the page is never empty
  document.querySelectorAll(".chip[data-ex]").forEach((b) =>
    b.addEventListener("click", () => { input.value = b.dataset.ex; $("#example-note").hidden = true; refresh(); }));
  $("#pw-toggle").addEventListener("click", (e) => {
    const showing = input.type === "text";
    input.type = showing ? "password" : "text";
    e.currentTarget.textContent = showing ? "Show" : "Hide";
  });
  refresh();
  input.focus(); input.select();
};

/* ---------- create a strong password ---------- */
starters.generate = () => {
  const make = () => {
    const pw = generatePassword(Number($("#gen-length").value), $("#gen-symbols").checked);
    const a = analyze(pw);
    $("#gen-out").textContent = pw;
    $("#gen-label").textContent = a.label;
    $("#gen-label").style.color = a.colour;
    $("#gen-bits").textContent = a.entropy.toFixed(0) + " bits of entropy";
    $("#gen-fill").style.width = a.score + "%";
    $("#gen-fill").style.backgroundColor = a.colour;
  };
  $("#gen-length").addEventListener("input", (e) => { $("#gen-length-out").textContent = e.target.value; make(); });
  $("#gen-symbols").addEventListener("change", make);
  $("#gen-btn").addEventListener("click", make);
  $("#gen-copy").addEventListener("click", (e) => copyText($("#gen-out").textContent, e.currentTarget));
  make();
};

/* ---------- make a hash ---------- */
starters.hash = () => {
  const algo = $("#h-algo"), err = $("#h-error");
  algo.addEventListener("change", () => { $("#h-iter-wrap").hidden = algo.value !== "PBKDF2"; run(); });
  $("#h-iter").addEventListener("change", run);

  async function run() {
    err.hidden = true;
    const text = $("#h-input").value;
    if (!text) return setBanner(err, "warn", "Type some text to hash.");
    if (!hasWebCrypto()) return setBanner(err, "warn", WEBCRYPTO_MESSAGE);
    const btn = $("#h-btn");
    btn.disabled = true; btn.textContent = "Working...";
    try {
      const r = await hashText(algo.value, text, Number($("#h-iter").value));
      $("#h-title").textContent = r.info.label;
      $("#h-badge").className = "badge " + r.info.badge;
      $("#h-badge").textContent = r.info.verdict;
      $("#h-hash").textContent = r.display;
      $("#h-salt-row").hidden = r.saltHex === null;
      if (r.saltHex) $("#h-salt").textContent = r.saltHex;
      $("#h-meta").textContent = `${r.info.bits}-bit result, made in ${r.ms < 1 ? r.ms.toFixed(3) : r.ms.toFixed(1)} ms.`;
      $("#h-note").textContent = r.info.note;
      $("#h-out").hidden = false;
    } catch (e) {
      setBanner(err, "warn", "Hashing failed: " + e.message);
    } finally {
      btn.disabled = false; btn.textContent = "Make hash";
    }
  }
  $("#h-btn").addEventListener("click", run);
  $("#h-input").addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
  $("#h-copy").addEventListener("click", (e) => copyText($("#h-hash").textContent, e.currentTarget));
  run(); // shows a result straight away
};

/* ---------- verify a hash ---------- */
// Pre-computed samples: the checker works with no setup at all.
const SAMPLES = [
  { name: "SHA-256", pw: "Sunshine#42", hint: "The right password is Sunshine#42. Change one letter to see it fail.",
    hash: "40bfd06a1ec1d4a8a0590e395d47ee6b214c378dc5f0f49a56a01b1e13b54cdf" },
  { name: "MD5 (weak)", pw: "letmein", hint: "MD5 is broken. This one is a very common password, so it falls instantly.",
    hash: "0d107d09f5bbe40cade3de5c71e9e9b7" },
  { name: "PBKDF2 (salted, slow)", pw: "Blue!Tiger88", hint: "A proper password hash with salt. The right password is Blue!Tiger88.",
    hash: "pbkdf2_sha256$100000$a1b2c3d4e5f60718293a4b5c6d7e8f90$5d65d6a8b3af1a88ed7472e27b2daa8fefa8ace38a54ef7c84f14f8829e1884b" },
];

starters.verify = () => {
  const out = $("#v-out");
  async function check() {
    const stored = $("#v-hash").value, pw = $("#v-pw").value;
    if (!stored.trim() || !pw) return setBanner(out, "warn", "Fill in both boxes, or pick a sample.");
    if (!hasWebCrypto()) return setBanner(out, "warn", WEBCRYPTO_MESSAGE);
    try {
      const r = await verifyHash(pw, stored);
      if (r.match) setBanner(out, "ok", `✔ Match. This password is correct (${r.label}).`);
      else setBanner(out, "bad", `✘ No match. This password does not fit this ${r.label} hash.`);
    } catch (e) { setBanner(out, "warn", e.message); }
  }
  const pick = (s) => {
    $("#v-hash").value = s.hash; $("#v-pw").value = s.pw; $("#v-hint").textContent = s.hint; check();
  };
  SAMPLES.forEach((s) => {
    const b = el("button", "chip", s.name); b.type = "button";
    b.addEventListener("click", () => pick(s));
    $("#samples").append(b);
  });
  $("#v-btn").addEventListener("click", check);
  $("#v-pw").addEventListener("input", check);
  pick(SAMPLES[0]);
};

/* ---------- demo lab ---------- */
starters.lab = () => {
  async function salting() {
    if (!hasWebCrypto()) return;
    const data = encoder.encode("hunter2");
    const plain = [await digestHex("SHA-256", data), await digestHex("SHA-256", data)];
    const salted = [];
    for (let i = 0; i < 2; i++) {
      const salt = randomBytes(16);
      salted.push("sha256$" + toHex(salt) + "$" + await digestHex("SHA-256", concatBytes(salt, data)));
    }
    const fill = (sel, list) => { const h = $(sel); h.replaceChildren(); list.forEach((x) => h.append(codeBox(x))); };
    fill("#salt-plain", plain); fill("#salt-salted", salted);
  }
  $("#salt-btn").addEventListener("click", salting);
  salting();

  let timer = null;
  async function avalanche() {
    if (!hasWebCrypto()) { $("#av-stat").textContent = WEBCRYPTO_MESSAGE; return; }
    const a = $("#av-a").value, b = $("#av-b").value;
    const ha = await digestHex("SHA-256", encoder.encode(a)), hb = await digestHex("SHA-256", encoder.encode(b));
    const paint = (sel, mine, other) => {
      const h = $(sel); h.replaceChildren();
      for (let i = 0; i < mine.length; i++) h.append(el("span", mine[i] === other[i] ? "" : "diff", mine[i]));
    };
    paint("#av-ha", ha, hb); paint("#av-hb", hb, ha);
    const bits = bitDifference(ha, hb);
    $("#av-stat").textContent = a === b
      ? "Same input, same hash: 0 of 256 bits differ."
      : `${bits} of 256 bits changed (${((bits / 256) * 100).toFixed(0)}%). Highlighted characters are different.`;
  }
  const later = () => { clearTimeout(timer); timer = setTimeout(avalanche, 120); };
  $("#av-a").addEventListener("input", later);
  $("#av-b").addEventListener("input", later);
  avalanche();

  $("#speed-btn").addEventListener("click", async (e) => {
    if (!hasWebCrypto()) return;
    const btn = e.currentTarget;
    btn.disabled = true; btn.textContent = "Racing...";
    try {
      const data = encoder.encode("benchmark-password"), runs = 3000;
      let t0 = performance.now();
      for (let i = 0; i < runs; i++) await crypto.subtle.digest("SHA-256", data);
      const fast = runs / ((performance.now() - t0) / 1000);
      t0 = performance.now();
      await pbkdf2Hex("benchmark-password", randomBytes(16), 600000);
      const slow = 1000 / (performance.now() - t0);
      $("#speed-sha").textContent = Math.round(fast).toLocaleString("en-US");
      $("#speed-pbkdf2").textContent = slow.toFixed(1);
      $("#speed-ratio").textContent = Math.round(fast / slow).toLocaleString("en-US") + "x";
      $("#speed-note").textContent = "Every guess now costs the hacker that much more work, so a password that fell in seconds now holds out for days.";
      $("#speed-note").hidden = false; $("#speed-out").hidden = false;
    } finally { btn.disabled = false; btn.textContent = "Run again"; }
  });
};

/* ---------- start ---------- */
initTheme();
window.addEventListener("hashchange", route);
route();
