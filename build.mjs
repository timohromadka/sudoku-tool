// Encrypts src/index.html with a passcode -> docs/index.html (the only file published).
// Usage: node build.mjs <passcode>
import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

const pass = process.argv[2];
if (!pass) { console.error("usage: node build.mjs <passcode>"); process.exit(1); }
const ITER = 600000;
const enc = new TextEncoder();
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" },
  base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(readFileSync("src/index.html", "utf8"))));
const b64 = (u) => Buffer.from(u).toString("base64");
const payload = JSON.stringify({ salt: b64(salt), iv: b64(iv), ct: b64(ct), iter: ITER });

writeFileSync("docs/index.html", `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Sudoku</title>
<style>
  body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px system-ui,sans-serif;background:#f4f1ea;color:#222}
  form{display:flex;flex-direction:column;gap:12px;width:min(300px,85vw)}
  input[type=password]{font-size:18px;padding:12px;border:1px solid #bbb;border-radius:8px}
  button{font-size:17px;padding:12px;border:0;border-radius:8px;background:#222;color:#fff}
  label{font-size:14px;display:flex;gap:8px;align-items:center}
  #err{color:#b00020;min-height:1.2em;font-size:14px}
  @media (prefers-color-scheme:dark){body{background:#1b1b1b;color:#eee}input[type=password]{background:#2a2a2a;color:#eee;border-color:#555}button{background:#eee;color:#111}}
</style></head><body>
<form id="f">
  <h2 style="margin:0">Sudoku</h2>
  <input id="p" type="password" placeholder="Passcode" autocomplete="current-password" autofocus>
  <label><input id="r" type="checkbox" checked> Remember on this device</label>
  <button>Open</button>
  <div id="err"></div>
</form>
<script>
const P = ${payload};
const d = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function unlock(pass) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: d(P.salt), iterations: P.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: d(P.iv) }, key, d(P.ct));
  return new TextDecoder().decode(pt);
}
function show(html) { document.open(); document.write(html); document.close(); }
const KEY = "sudoku-pass";
const saved = localStorage.getItem(KEY);
if (saved) unlock(saved).then(show).catch(() => localStorage.removeItem(KEY));
document.getElementById("f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pass = document.getElementById("p").value, err = document.getElementById("err");
  err.textContent = "Checking…";
  try {
    const html = await unlock(pass);
    if (document.getElementById("r").checked) localStorage.setItem(KEY, pass);
    show(html);
  } catch { err.textContent = "Wrong passcode"; }
});
</script></body></html>
`);
console.log("wrote docs/index.html");
