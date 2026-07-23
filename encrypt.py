import os, sys, zlib, pathlib, hashlib, json, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OUT = pathlib.Path(sys.argv[1]); PWD = sys.argv[2]
# argv[3] opcional: PNG del logo → se embebe como data URI (gate autocontenido)
LOGO = ''
if len(sys.argv) > 3 and sys.argv[3]:
    LOGO = 'data:image/png;base64,' + base64.b64encode(pathlib.Path(sys.argv[3]).read_bytes()).decode()
data = (OUT/'deck-bundle.html').read_bytes()
comp = zlib.compress(data, 9)                       # deflate (DecompressionStream lo lee)

salt = os.urandom(16); iv = os.urandom(12)
ITER = 1_000_000
key  = hashlib.pbkdf2_hmac('sha256', PWD.encode(), salt, ITER, 32)
ct   = AESGCM(key).encrypt(iv, comp, None)

(OUT/'payload.bin').write_bytes(salt + iv + ct)     # el server solo guarda esto
print(f'payload.bin : {len(salt+iv+ct)/1e6:.2f} MB (cifrado · AES-256-GCM · PBKDF2 {ITER:,} iter)')

logo_tag = f'<img class="logo" src="{LOGO}" alt="Link FieldIQ" width="72" height="72">' if LOGO else ''
shell = '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>FieldIQ — Microinteractions</title><style>
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{background:#0C0C0C;color:#fff;display:grid;place-items:center;
  font-family:'Inter Tight',-apple-system,system-ui,sans-serif}
.b{width:340px;text-align:center}
.logo{width:72px;height:72px;border-radius:16px;margin:0 auto 18px;display:block}
h1{font-size:19px;font-weight:600;margin:0 0 6px;letter-spacing:-.01em}
p{font-size:13px;color:#8b8b8b;margin:0 0 22px;line-height:1.5}
input{width:100%;padding:13px 15px;border-radius:10px;border:1px solid #2a2a2a;
  background:#151515;color:#fff;font:inherit;font-size:15px;text-align:center;letter-spacing:.06em}
input:focus{outline:2px solid #68BE65;outline-offset:2px;border-color:transparent}
button{width:100%;margin-top:10px;padding:13px;border:0;border-radius:10px;background:#fff;
  color:#0C0C0C;font:inherit;font-size:15px;font-weight:600;cursor:pointer}
button:disabled{opacity:.5;cursor:default}
.m{margin-top:14px;font-size:12.5px;min-height:18px;color:#8b8b8b}
.m.err{color:#F0857D}
</style></head><body>
<div class="b">
  ''' + logo_tag + '''
  <h1>Link FieldIQ &middot; Microinteractions</h1>
  <p>Protected content. Enter the password to view it.</p>
  <form id="f"><input id="p" type="password" autocomplete="current-password" autofocus>
  <button id="go">Open</button></form>
  <div class="m" id="m"></div>
</div>
<script>
const $=i=>document.getElementById(i), m=$('m');
function say(t,e){ m.textContent=t; m.className='m'+(e?' err':''); }
$('f').addEventListener('submit', async ev=>{
  ev.preventDefault(); $('go').disabled=true; say('Decrypting\u2026');
  try{
    const buf = new Uint8Array(await (await fetch('payload.bin')).arrayBuffer());
    const salt=buf.slice(0,16), iv=buf.slice(16,28), ct=buf.slice(28);
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode($('p').value),
                   'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      {name:'PBKDF2', salt, iterations:1000000, hash:'SHA-256'},
      base, {name:'AES-GCM', length:256}, false, ['decrypt']);
    // si la clave es incorrecta, GCM falla la autenticaci&oacute;n y tira acá
    const plain = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
    const ds = new DecompressionStream('deflate');
    const html = await new Response(new Blob([plain]).stream().pipeThrough(ds)).text();
    document.open(); document.write(html); document.close();
  }catch(err){
    say('Incorrect password.', true); $('go').disabled=false; $('p').select();
  }
});
</script></body></html>'''
(OUT/'index.html').write_text(shell)
print(f'index.html  : {len(shell)/1024:.1f} KB (shell)')
