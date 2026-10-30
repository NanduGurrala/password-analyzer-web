"use strict";

/* ==========================================================================
   Password Strength Analyzer & Secure Hashing Tool
   Runs 100% in the browser. No network requests, no storage.

   1. Data and constants
   2. Strength analysis engine (entropy, patterns, dictionary, crack time)
   3. Secure random password generator
   4. Hashing engine (Web Crypto API + a small MD5 for comparison)
   5. User interface wiring
   ========================================================================== */


/* ==========================================================================
   1. DATA AND CONSTANTS
   ========================================================================== */

// Most common leaked passwords, roughly most popular first. Position = rank.
const COMMON = ("123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon 123123 baseball " +
  "abc123 football monkey letmein shadow master 666666 qwertyuiop 123321 1234567890 superman 654321 1qaz2wsx " +
  "7777777 121212 000000 qazwsx 123qwe killer trustno1 jordan jennifer zxcvbnm asdfgh hunter buster soccer " +
  "harley batman andrew tigger sunshine iloveyou 2000 charlie robert thomas hockey ranger daniel starwars " +
  "112233 george computer michelle jessica pepper 1111 zxcvbn 555555 11111111 131313 freedom 777777 pass " +
  "maggie 159753 aaaaaa ginger princess joshua cheese amanda summer love ashley nicole chelsea biteme " +
  "matthew access yankees 987654321 dallas austin thunder taylor matrix monitor montana moon welcome admin " +
  "admin123 password1 password123 password12 passw0rd p@ssw0rd p@ssword qwerty123 qwerty1 qwerty12 letmein1 " +
  "welcome1 welcome123 login root toor guest test test123 testing changeme default secret secret123 " +
  "letmein123 iloveyou1 abcd1234 abc12345 abcdef abcdefg abcdefgh 1q2w3e 1q2w3e4r 1q2w3e4r5t zaq12wsx " +
  "qweasd qweasdzxc asdfghjkl asdf1234 asdfasdf zxcv1234 qazwsxedc 1qazxsw2 q1w2e3r4 qwe123 qwerty1234 " +
  "11111 22222 33333 44444 66666 88888 99999 123123123 12341234 11223344 1234abcd 12344321 123454321 " +
  "1357924680 0987654321 0123456789 147258369 159357 951753 741852963 963852741 654123 789456 789456123 " +
  "987654 112358 abc abcabc aaaaaaaa 00000000 1111111111 passwords password01 pass123 pass1234 pa55word " +
  "pa$$word p455w0rd iloveu love123 lover loveme lovely sweetheart babygirl angel angel123 princess1 " +
  "flower butterfly cookie chocolate banana orange apple lemon cherry rainbow purple pink blue green red " +
  "black white yellow silver golden diamond tiger lion eagle wolf bear panda monkey123 dragon123 ninja " +
  "pirate wizard samurai spiderman superman1 batman1 ironman naruto pokemon pikachu mario zelda minecraft " +
  "fortnite hogwarts liverpool arsenal barcelona ronaldo messi cricket sachin india india123 password@123 " +
  "admin@123 welcome@123 pass@123 abc@123 test@123 india@123 qwerty@123 hello hello123 helloworld whatever " +
  "google facebook instagram microsoft windows ubuntu android iphone samsung laptop private security " +
  "passcode mypassword username student teacher school college university").split(" ");

const RANK = new Map();
COMMON.forEach((word, i) => { if (!RANK.has(word)) RANK.set(word, i + 1); });

const SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; // the 32 ASCII punctuation characters
const KEYBOARD_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"];
const LEET = { "@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t" };

const LEVELS = [ // [upper bound of effective entropy, label, colour]
  [28, "Very weak", "#D92D20"],
  [36, "Weak", "#F0641E"],
  [60, "Fair", "#E8A600"],
  [80, "Strong", "#2FA84F"],
  [Infinity, "Very strong", "#0E8A5F"],
];

const SUMMARY = {
  "Very weak": "Cracked almost instantly. Do not use this password.",
  "Weak": "Easy to guess with common tools and wordlists.",
  "Fair": "Resists casual guessing, but not a determined attacker.",
  "Strong": "Hard to crack with today's hardware.",
  "Very strong": "Practically impossible to crack by guessing.",
};

const SCENARIOS = [
  { name: "Online login form", rate: 100, text: "100 guesses per second" },
  { name: "Offline, slow hash (bcrypt, Argon2)", rate: 1e4, text: "10,000 guesses per second" },
  { name: "Offline, fast hash (MD5, SHA-256 on GPUs)", rate: 1e11, text: "100 billion guesses per second" },
];


/* ==========================================================================
   2. STRENGTH ANALYSIS ENGINE
   --------------------------------------------------------------------------
   Step 1  pool size       lowercase 26, uppercase 26, digits 10, symbols 32, other 32
   Step 2  raw entropy     length x log2(pool)
   Step 3  patterns        sequences, keyboard walks, repeats and years each count as ~1 character
   Step 4  dictionary      common passwords / leetspeak / common word + digits cap the entropy
   Step 5  label and score from effective entropy
   Step 6  crack time      half the search space / guesses per second
   ========================================================================== */

function poolSize(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  for (const c of pw) { if (SYMBOLS.includes(c)) { pool += SYMBOLS.length; break; } }
  for (const c of pw) {
    if (!/[A-Za-z0-9]/.test(c) && !SYMBOLS.includes(c)) { pool += 32; break; } // spaces, accents, emoji
  }
  return pool;
}

function calcEntropy(length, pool) {
  if (length <= 0 || pool <= 1) return 0;
  return length * Math.log2(pool);
}

// Runs such as "abc", "4567", "cba". Returns [{start, end, text}] with end exclusive.
function findSequences(pw, minLen = 3) {
  const s = pw.toLowerCase();
  const found = [];
  let i = 0;
  while (i < s.length - 1) {
    const step = s.charCodeAt(i + 1) - s.charCodeAt(i);
    if ((step === 1 || step === -1) && /[a-z0-9]/.test(s[i]) && /[a-z0-9]/.test(s[i + 1])) {
      let j = i + 1;
      while (j + 1 < s.length && /[a-z0-9]/.test(s[j + 1]) &&
             s.charCodeAt(j + 1) - s.charCodeAt(j) === step) j++;
      if (j - i + 1 >= minLen) found.push({ start: i, end: j + 1, text: pw.slice(i, j + 1) });
      i = j;
    } else {
      i++;
    }
  }
  return found;
}

// Neighbouring keys on one QWERTY row, forwards or backwards: "qwerty", "asdf", "poiuy".
function findKeyboardWalks(pw, minLen = 4) {
  const s = pw.toLowerCase();
  const found = [];
  for (const row of KEYBOARD_ROWS) {
    for (const r of [row, [...row].reverse().join("")]) {
      let i = 0;
      while (i <= s.length - minLen) {
        if (r.includes(s.slice(i, i + minLen))) {
          let len = minLen;
          while (i + len < s.length && r.includes(s.slice(i, i + len + 1))) len++;
          found.push({ start: i, end: i + len, text: pw.slice(i, i + len) });
          i += len;
        } else {
          i++;
        }
      }
    }
  }
  return found;
}

// "aaa", "abab", "abcabc": repeated characters or repeated chunks.
function findRepeats(pw) {
  const found = [];
  for (const m of pw.matchAll(/(.)\1{2,}/g)) {
    found.push({ start: m.index, end: m.index + m[0].length, text: m[0] });
  }
  for (const m of pw.matchAll(/(.{2,4}?)\1+/g)) {
    if (m[0].length >= 4) found.push({ start: m.index, end: m.index + m[0].length, text: m[0] });
  }
  return found;
}

// Four-digit years 1900-2099 that form a whole run of digits.
function findYears(pw) {
  const found = [];
  for (const m of pw.matchAll(/\d+/g)) {
    if (m[0].length === 4 && /^(19|20)/.test(m[0])) {
      found.push({ start: m.index, end: m.index + 4, text: m[0] });
    }
  }
  return found;
}

function mergeSpans(spans) {
  const sorted = spans.map((s) => [s.start, s.end]).sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const [start, end] of sorted) {
    const last = merged[merged.length - 1];
    if (last && start <= last[1]) last[1] = Math.max(last[1], end);
    else merged.push([start, end]);
  }
  return merged;
}

const deleet = (s) => s.replace(/[@4310$5!7]/g, (c) => LEET[c]);

// Is the password dictionary based? Returns { kind, cap } (cap = maximum entropy in bits).
function dictionaryCheck(pw) {
  const lower = pw.toLowerCase();
  if (RANK.has(lower)) return { kind: "common", cap: Math.max(1, Math.log2(RANK.get(lower))) };

  const plain = deleet(lower);
  if (RANK.has(plain)) return { kind: "leet", cap: Math.log2(RANK.get(plain)) + 3 };

  const stem = lower.replace(/[\d\W_]+$/, ""); // a common word followed by digits or symbols
  if (stem.length >= 3 && stem !== lower) {
    for (const candidate of [stem, deleet(stem)]) {
      if (RANK.has(candidate)) {
        return { kind: "suffix", cap: Math.log2(RANK.get(candidate)) + (lower.length - stem.length) * 3.5 };
      }
    }
  }
  return { kind: null, cap: null };
}

function formatDuration(sec) {
  if (sec < 1) return "instantly";
  const units = [["second", 60], ["minute", 60], ["hour", 24], ["day", 365], ["year", 1000]];
  let v = sec;
  for (const [name, size] of units) {
    if (v < size) {
      const n = Math.floor(v);
      return n + " " + name + (n === 1 ? "" : "s");
    }
    v /= size;
  }
  const years = v * 1000; // v is now in thousands of years
  if (!isFinite(years) || years >= 1e15) return "more than a quadrillion years";
  for (const [name, size] of [["trillion", 1e12], ["billion", 1e9], ["million", 1e6], ["thousand", 1e3]]) {
    if (years >= size) return Math.round(years / size).toLocaleString("en-US") + " " + name + " years";
  }
  return Math.round(years).toLocaleString("en-US") + " years";
}

function crackTimes(entropy) {
  const guesses = Math.pow(2, Math.max(entropy - 1, 0)); // average case: half the search space
  return SCENARIOS.map((s) => ({ name: s.name, rate: s.text, time: formatDuration(guesses / s.rate) }));
}

function emptyAnalysis() {
  return {
    length: 0, pool: 0, rawEntropy: 0, entropy: 0, score: 0, label: "No password yet",
    colour: "#98A2B3", note: "Type a password above. Your analysis appears here instantly.",
    checks: {}, findings: [], suggestions: [], crack: crackTimes(0).map((c) => ({ ...c, time: "-" })),
  };
}

function analyze(password) {
  if (!password) return emptyAnalysis();

  const length = Array.from(password).length; // counts emoji as one character
  const a = emptyAnalysis();
  a.length = length;
  a.pool = poolSize(password);
  a.rawEntropy = calcEntropy(length, a.pool);

  // Patterns: each predictable run counts as about one character of entropy.
  const seqs = findSequences(password);
  const walks = findKeyboardWalks(password);
  const reps = findRepeats(password);
  const years = findYears(password);
  const merged = mergeSpans([...seqs, ...walks, ...reps, ...years]);
  const covered = merged.reduce((sum, [s, e]) => sum + (e - s), 0);
  const effectiveLength = Math.max(1, length - covered + merged.length);
  let entropy = calcEntropy(effectiveLength, a.pool);

  // Dictionary weakness caps the entropy at a very low value.
  const dict = dictionaryCheck(password);
  if (dict.cap !== null) entropy = Math.min(entropy, dict.cap);
  a.entropy = Math.round(entropy * 10) / 10;

  // Label and score.
  for (const [bound, label, colour] of LEVELS) {
    if (a.entropy < bound) { a.label = label; a.colour = colour; break; }
  }
  a.score = Math.max(1, Math.min(100, Math.round((a.entropy / 90) * 100)));
  if (length < 8 && a.label !== "Very weak" && a.label !== "Weak") {
    a.label = "Weak"; a.colour = LEVELS[1][2]; a.score = Math.min(a.score, 35);
  }
  a.note = SUMMARY[a.label];
  a.crack = crackTimes(a.entropy);

  // Requirement checklist.
  const hasPattern = seqs.length + walks.length + reps.length + years.length > 0;
  a.checks = {
    len12: length >= 12,
    lower: /[a-z]/.test(password),
    upper: /[A-Z]/.test(password),
    digit: /[0-9]/.test(password),
    symbol: /[^A-Za-z0-9]/.test(password),
    notCommon: dict.kind === null,
    noPattern: !hasPattern,
  };

  // Findings.
  const add = (level, text) => a.findings.push({ level, text });
  if (length >= 16) add("good", `Length is ${length} characters - excellent.`);
  else if (length >= 12) add("good", `Length is ${length} characters - good.`);
  else if (length >= 8) add("warn", `Length is ${length} characters - acceptable, but longer is better.`);
  else add("bad", `Only ${length} characters - too short.`);

  const classes = [a.checks.lower, a.checks.upper, a.checks.digit, a.checks.symbol].filter(Boolean).length;
  if (classes === 4) {
    add("good", "Uses lowercase, uppercase, digits and symbols.");
  } else {
    const missing = [["lowercase", a.checks.lower], ["uppercase", a.checks.upper],
                     ["digits", a.checks.digit], ["symbols", a.checks.symbol]]
      .filter(([, ok]) => !ok).map(([n]) => n);
    add("warn", "Missing character types: " + missing.join(", ") + ".");
  }

  if (dict.kind === "common") add("bad", "This is one of the most commonly used passwords.");
  else if (dict.kind === "leet") add("bad", "A common password with letter-to-symbol swaps (like a to @). Attackers try these automatically.");
  else if (dict.kind === "suffix") add("bad", "A common word with digits or symbols added at the end.");
  else add("good", "Not found in the common-password list.");

  seqs.forEach((p) => add("bad", `Sequence detected: '${p.text}'.`));
  walks.forEach((p) => add("bad", `Keyboard pattern detected: '${p.text}'.`));
  [...new Set(reps.map((p) => p.text))].forEach((t) => add("warn", `Repeated characters or chunks: '${t}'.`));
  years.forEach((p) => add("warn", `Looks like a year: '${p.text}'. Years are easy to guess.`));

  // Suggestions.
  const tip = (t) => a.suggestions.push(t);
  if (length < 12) tip("Make it at least 12 characters. Each extra character multiplies the work for an attacker.");
  if (classes < 3) tip("Mix in other character types, or switch to a long passphrase of several unrelated words.");
  if (dict.kind) tip("Avoid dictionary words and predictable substitutions. Pick something unrelated to you.");
  if (seqs.length || walks.length || reps.length) tip("Remove sequences, keyboard runs and repetition. Attackers try these early.");
  if (years.length) tip("Do not use birth years or other dates.");
  if (!a.suggestions.length) tip("This is a solid password. Store it in a password manager and never reuse it.");

  return a;
}


/* ==========================================================================
   3. SECURE RANDOM GENERATOR
   ========================================================================== */

// Unbiased random integer in [0, max) using rejection sampling.
function randomInt(max) {
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
  return buf[0] % max;
}

function generatePassword(length = 16, useSymbols = true) {
  length = Math.max(8, Math.min(64, length));
  const groups = ["abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789"];
  if (useSymbols) groups.push(SYMBOLS);
  const all = groups.join("");
  const chars = groups.map((g) => g[randomInt(g.length)]); // at least one from every group
  while (chars.length < length) chars.push(all[randomInt(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) { // Fisher-Yates shuffle
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}


/* ==========================================================================
   4. HASHING ENGINE
   ========================================================================== */

const encoder = new TextEncoder();

const toHex = (bytes) => Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");

function fromHex(hex) {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) throw new Error("Invalid hex value.");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// Constant-time style comparison: always inspects every character.
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// MD5 (RFC 1321). Not available in Web Crypto because it is broken. Included only to compare.
function md5Hex(bytes) {
  const s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
             5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
             4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
             6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0);
  const len = bytes.length;
  const total = (((len + 8) >>> 6) + 1) << 6;
  const buf = new Uint8Array(total);
  buf.set(bytes);
  buf[len] = 0x80;
  const view = new DataView(buf.buffer);
  view.setUint32(total - 8, (len << 3) >>> 0, true);
  view.setUint32(total - 4, Math.floor(len / 0x20000000), true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Uint32Array(16);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = view.getUint32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + ((F << s[i]) | (F >>> (32 - s[i])))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16);
  const outView = new DataView(out.buffer);
  [a0, b0, c0, d0].forEach((w, i) => outView.setUint32(i * 4, w, true));
  return toHex(out);
}

// Plain digest: MD5 (own code) or SHA-1/256/384/512 (Web Crypto).
async function digestHex(algo, bytes) {
  if (algo === "MD5") return md5Hex(bytes);
  return toHex(await crypto.subtle.digest(algo, bytes));
}

// PBKDF2-HMAC-SHA256 through Web Crypto. Returns a 256-bit key as hex.
async function pbkdf2Hex(password, saltBytes, iterations) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations }, key, 256);
  return toHex(bits);
}

const ALGO_INFO = {
  "MD5": { label: "MD5", bits: 128, badge: "red", verdict: "Broken",
    note: "Collisions can be created in seconds and billions of guesses per second are possible. Never use it for passwords." },
  "SHA-1": { label: "SHA-1", bits: 160, badge: "red", verdict: "Deprecated",
    note: "A practical collision was demonstrated in 2017 (SHAttered). Avoid it for anything security related." },
  "SHA-256": { label: "SHA-256", bits: 256, badge: "amber", verdict: "Good hash, wrong tool",
    note: "Excellent for file integrity and signatures, but too fast for passwords, and equal inputs always give equal hashes." },
  "SHA-384": { label: "SHA-384", bits: 384, badge: "amber", verdict: "Good hash, wrong tool",
    note: "Part of the SHA-2 family. Strong, but still far too fast for storing passwords." },
  "SHA-512": { label: "SHA-512", bits: 512, badge: "amber", verdict: "Good hash, wrong tool",
    note: "Part of the SHA-2 family. Strong, but still far too fast for storing passwords." },
  "SALTED": { label: "SHA-256 + random salt", bits: 256, badge: "orange", verdict: "Better, still fast",
    note: "The random salt defeats rainbow tables and hides duplicate passwords, but every guess is still cheap to compute." },
  "PBKDF2": { label: "PBKDF2-SHA256", bits: 256, badge: "green", verdict: "Suitable for passwords",
    note: "Salted and deliberately slow. The iteration count is the work factor. Prefer Argon2id or bcrypt on a server." },
};

// Hash text with the chosen mode. Returns the value to display plus metadata.
async function hashText(mode, text, iterations = 600000) {
  const data = encoder.encode(text);
  const t0 = performance.now();
  let display, saltHex = null;

  if (mode === "SALTED") {
    const salt = randomBytes(16);
    saltHex = toHex(salt);
    display = "sha256$" + saltHex + "$" + await digestHex("SHA-256", concatBytes(salt, data));
  } else if (mode === "PBKDF2") {
    const salt = randomBytes(16);
    saltHex = toHex(salt);
    display = "pbkdf2_sha256$" + iterations + "$" + saltHex + "$" + await pbkdf2Hex(text, salt, iterations);
  } else {
    display = await digestHex(mode, data);
  }
  return { display, saltHex, ms: performance.now() - t0, info: ALGO_INFO[mode] };
}

// Check a password against a stored hash string. Returns { match, label } or throws on bad input.
async function verifyHash(password, stored) {
  stored = stored.trim();
  const parts = stored.split("$");
  const data = encoder.encode(password);

  if (parts[0] === "pbkdf2_sha256" && parts.length === 4) {
    const iterations = Number(parts[1]);
    if (!Number.isInteger(iterations) || iterations < 1 || iterations > 2000000) {
      throw new Error("Iteration count must be between 1 and 2,000,000.");
    }
    const computed = await pbkdf2Hex(password, fromHex(parts[2]), iterations);
    return { match: safeEqual(computed, parts[3].toLowerCase()), label: "PBKDF2-SHA256" };
  }
  if (parts[0] === "sha256" && parts.length === 3) {
    const computed = await digestHex("SHA-256", concatBytes(fromHex(parts[1]), data));
    return { match: safeEqual(computed, parts[2].toLowerCase()), label: "SHA-256 + salt" };
  }
  const byLength = { 32: "MD5", 40: "SHA-1", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512" };
  if (/^[0-9a-f]+$/i.test(stored) && byLength[stored.length]) {
    const algo = byLength[stored.length];
    const computed = await digestHex(algo, data);
    return { match: safeEqual(computed, stored.toLowerCase()), label: algo };
  }
  throw new Error("Unrecognised hash format.");
}

// Number of differing bits between two equal-length hex strings.
function bitDifference(hexA, hexB) {
  let bits = 0;
  for (let i = 0; i < hexA.length; i++) {
    let x = parseInt(hexA[i], 16) ^ parseInt(hexB[i], 16);
    while (x) { bits += x & 1; x >>= 1; }
  }
  return bits;
}

