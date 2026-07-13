package main

import (
	"net/http"
	"net/url"
)

// decryptedAssetURL builds a browser-openable link to the /view page. The
// ciphertext URL and the decryption key travel in the URL *fragment* (after
// #), which browsers never send to the server — so opening the link decrypts
// the image entirely client-side and pintr never sees the key.
func decryptedAssetURL(publicURL, ciphertextURL, keyB64 string) string {
	return publicURL + "/view#u=" + url.QueryEscape(ciphertextURL) + "&k=" + url.QueryEscape(keyB64)
}

func handleView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(viewerHTML))
}

// The page reads u (ciphertext URL) and k (base64 AES-256-GCM key) from the
// fragment, fetches the ciphertext, and decrypts it with WebCrypto. The blob
// layout is nonce(12) || ciphertext(+tag), matching assetStore.putEncrypted.
const viewerHTML = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>pintr asset</title>
<style>
html,body{margin:0;height:100%;background:#0f0f10}
body{display:grid;place-items:center}
img{max-width:100vw;max-height:100vh;object-fit:contain}
#msg{color:#e7e7e7;font-family:system-ui,sans-serif;padding:2rem;text-align:center}
.err{color:#f87171}
</style></head><body>
<div id="msg">decrypting…</div>
<script>
(async () => {
  const msg = document.getElementById('msg');
  try {
    const p = new URLSearchParams(location.hash.slice(1));
    const u = p.get('u'), k = p.get('k');
    if (!u || !k) throw new Error('link is missing the image url or key');
    const raw = Uint8Array.from(atob(k), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey('raw', raw, {name:'AES-GCM'}, false, ['decrypt']);
    const resp = await fetch(u);
    if (!resp.ok) throw new Error('could not download the image ('+resp.status+')');
    const blob = new Uint8Array(await resp.arrayBuffer());
    const iv = blob.slice(0, 12), data = blob.slice(12);
    const plain = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, data);
    const img = new Image();
    img.onload = () => msg.replaceWith(img);
    img.src = URL.createObjectURL(new Blob([plain], {type:'image/png'}));
  } catch (e) {
    msg.className = 'err';
    msg.textContent = 'could not show this image: ' + e.message;
  }
})();
</script>
</body></html>`
