#!/usr/bin/env python3
"""Encrypt the private hub into a password-gated static page.

Usage:
    python3 encrypt.py PASSWORD [INPUT_HTML] [OUTPUT_HTML]

Defaults:
    INPUT_HTML  = "../../content/hub/index.html"
    OUTPUT_HTML = "index.html"

Cryptography:
    - PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP 2023 recommendation)
    - 16-byte random salt + 12-byte random nonce per encryption
    - AES-256-GCM authenticated encryption

The output is a single self-contained HTML page with a minimal, deliberately neutral (no campaign name leaks)
password form, embedded ciphertext (base64), and inline JavaScript that decrypts
in-browser via the Web Crypto API. Once the password is correct, the decrypted
hub HTML replaces the gate page via document.write().

The password lives OUTSIDE the repo (share via Signal/iMessage/in person) and is
never committed. To rotate it, re-run with the new password and re-publish.

Pattern: .claude/concepts/surface-modes.md (mode: encrypted), adopted from
dramafree/public/crm. README.md in this folder has the rotation runbook.
"""

import base64, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def encrypt(password: str, plaintext: bytes) -> dict:
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    key = kdf.derive(password.encode("utf-8"))
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return {
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ciphertext).decode(),
        "iter": 600_000,
    }


GATE_HTML = """<!DOCTYPE html>
<html lang="sr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>Zaštićeno</title>
<style>
:root{--bg:#f6f4ef;--card:#fff;--ink:#1d1d1f;--muted:#5d5d63;--rule:#e2ded5;--accent:#1d1d1f;--err:#c8102e}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1c1c1f;--ink:#ececef;--muted:#a0a0a8;--rule:#2e2e33;--accent:#ececef;--err:#ff4d5e}}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;color:var(--ink);background:var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.gate{max-width:400px;width:100%;background:var(--card);border:1px solid var(--rule);border-radius:12px;padding:32px 28px}
.gate h1{margin:0 0 6px;font-size:18px;font-weight:600}
.gate .sub{margin:0 0 24px;font-size:13px;color:var(--muted);line-height:1.5}
.gate form{display:flex;flex-direction:column;gap:10px}
.gate input{padding:10px 12px;font-size:16px;border:1px solid var(--rule);border-radius:6px;background:var(--bg);font-family:inherit;color:var(--ink)}
.gate input:focus{outline:none;border-color:var(--accent)}
.gate button{padding:10px 14px;font-size:14px;font-weight:600;border:1px solid var(--accent);background:var(--accent);color:var(--card);border-radius:6px;cursor:pointer;font-family:inherit}
.gate button:disabled{opacity:.6;cursor:wait}
.gate .err{margin-top:10px;font-size:13px;color:var(--err);min-height:18px}
</style>
</head>
<body>
<div class="gate">
  <h1>Zaštićena stranica</h1>
  <p class="sub">Sadržaj je šifrovan. Unesite lozinku koju ste dobili od tima.</p>
  <form id="f">
    <input type="password" id="pw" autocomplete="current-password" placeholder="Lozinka" required autofocus />
    <button type="submit" id="b">Otključaj</button>
  </form>
  <div class="err" id="e"></div>
</div>
<script>
const PAYLOAD = __PAYLOAD__;
function b64(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
async function decrypt(pw){
  const enc=new TextEncoder();
  const km=await crypto.subtle.importKey("raw",enc.encode(pw),"PBKDF2",false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey(
    {name:"PBKDF2",salt:b64(PAYLOAD.salt),iterations:PAYLOAD.iter,hash:"SHA-256"},
    km,{name:"AES-GCM",length:256},false,["decrypt"]
  );
  const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:b64(PAYLOAD.iv)},key,b64(PAYLOAD.ct));
  return new TextDecoder().decode(pt);
}
document.getElementById("f").addEventListener("submit",async e=>{
  e.preventDefault();
  const b=document.getElementById("b");
  const er=document.getElementById("e");
  er.textContent="";
  b.disabled=true;b.textContent="Otključavam…";
  try{
    const html=await decrypt(document.getElementById("pw").value);
    document.open();document.write(html);document.close();
  }catch(err){
    er.textContent="Pogrešna lozinka.";
    b.disabled=false;b.textContent="Otključaj";
  }
});
</script>
</body>
</html>
"""


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 encrypt.py PASSWORD [INPUT_HTML] [OUTPUT_HTML]", file=sys.stderr)
        sys.exit(1)
    password = sys.argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    inp = sys.argv[2] if len(sys.argv) > 2 else os.path.join(here, "..", "..", "content", "hub", "index.html")
    out = sys.argv[3] if len(sys.argv) > 3 else os.path.join(here, "index.html")

    with open(inp, "rb") as f:
        plaintext = f.read()

    payload = encrypt(password, plaintext)
    html = GATE_HTML.replace("__PAYLOAD__", json.dumps(payload))
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Encrypted {len(plaintext):,} bytes -> {len(html):,} byte gate page")
    print(f"  input:  {inp}")
    print(f"  output: {out}")
    print(f"  iter:   {payload['iter']:,}")


if __name__ == "__main__":
    main()
