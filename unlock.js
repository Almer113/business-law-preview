// Lock screen for the temporary GitHub Pages preview of the Grok Business Law study app. It is NOT part of the
// app: build-site.mjs publishes it as unlock.js, the only readable script in the preview.
//
// 1. Asks for the passphrase and rebuilds the key from it (PBKDF2-SHA-256, the same settings as the build).
// 2. Decrypts the app's stylesheet and script (AES-256-GCM, gzip inside), and answers the app's requests for
//    its legal-source files (…/sources/<file>.json) from …/d/<scrambled name>.bin the same way.
// 3. Starts the app as a guest (there are no accounts in the preview), with a Lock button to forget the key.

const BASE = new URL('./', import.meta.url).href // https://almer113.github.io/business-law-preview/
const KEY_STORE = 'blp-key'
const CHECK_TEXT = 'business-law-preview-ok'
const subtle = crypto.subtle

const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
const toB64 = (u) => btoa(String.fromCharCode(...u))
const hex = (b) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('')
const normalize = (p) => p.normalize('NFC').trim().replace(/\s+/g, ' ').toLowerCase() // same as build-site.mjs

async function derive(pass, lock) {
  const base = await subtle.importKey('raw', new TextEncoder().encode(normalize(pass)), 'PBKDF2', false, ['deriveBits'])
  const bits = await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: fromB64(lock.salt), iterations: lock.iter }, base, 512)
  return new Uint8Array(bits)
}

async function isRight(raw, lock) {
  try {
    const aes = await subtle.importKey('raw', raw.slice(0, 32), 'AES-GCM', false, ['decrypt'])
    const buf = fromB64(lock.check)
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, aes, buf.slice(12))
    return new TextDecoder().decode(plain) === CHECK_TEXT
  } catch {
    return false
  }
}

function storedKey() {
  try {
    const v = localStorage.getItem(KEY_STORE) || sessionStorage.getItem(KEY_STORE)
    return v ? fromB64(v) : null
  } catch {
    return null
  }
}
function saveKey(raw, remember) {
  try {
    ;(remember ? localStorage : sessionStorage).setItem(KEY_STORE, toB64(raw))
  } catch { /* private window: this visit only */ }
}
function forgetKey() {
  try {
    localStorage.removeItem(KEY_STORE)
    sessionStorage.removeItem(KEY_STORE)
  } catch { /* nothing stored */ }
}

/** Fetch and decrypt one of the encrypted files by its original name ("app.js", "sources/uu-5-1999.json"). */
async function decryptor(raw) {
  const aes = await subtle.importKey('raw', raw.slice(0, 32), 'AES-GCM', false, ['decrypt'])
  const mac = await subtle.importKey('raw', raw.slice(32, 64), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const realFetch = window.fetch.bind(window)
  return async function open(rel, init) {
    const name = hex(await subtle.sign('HMAC', mac, new TextEncoder().encode(rel))).slice(0, 32)
    const r = await realFetch(new URL(`d/${name}.bin`, BASE), init)
    if (!r.ok) return { status: r.status }
    const buf = await r.arrayBuffer()
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, aes, buf.slice(12))
    return { status: 200, body: new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip')) }
  }
}

/** The app fetches …/sources/<file>.json: answer those requests with the decrypted files. */
function installFetch(open) {
  const realFetch = window.fetch.bind(window)
  const dataPath = new URL('sources/', BASE).pathname
  window.fetch = async (input, init) => {
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const url = new URL(href, location.href)
    if (url.origin !== location.origin || !url.pathname.startsWith(dataPath)) return realFetch(input, init)
    const rel = 'sources/' + decodeURIComponent(url.pathname.slice(dataPath.length))
    try {
      const f = await open(rel, { signal: init?.signal })
      if (f.status !== 200) return new Response('not found', { status: f.status })
      return new Response(f.body, { status: 200, headers: { 'content-type': 'application/json; charset=utf-8' } })
    } catch (e) {
      if (e?.name === 'AbortError') throw e
      return new Response('cannot decrypt', { status: 500 })
    }
  }
}

const CSS = `
.blp{position:fixed;inset:0;display:grid;place-items:center;padding:16px;background:#f8fafc;color:#0f172a;font:15px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;z-index:100}
.blp form{width:min(380px,100%);background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:24px;box-shadow:0 2px 12px rgba(15,23,42,.06)}
.blp .mark{width:38px;height:38px;border-radius:10px;background:#4f46e5;color:#fff;display:grid;place-items:center;font-weight:800;font-size:.85rem;margin-bottom:10px}
.blp h1{font-size:1.25rem;margin:0 0 2px}.blp p{margin:0 0 16px;color:#64748b;font-size:.9rem}
.blp input[type=password]{width:100%;box-sizing:border-box;font:inherit;padding:10px 12px;border:1px solid #94a3b8;border-radius:8px;margin:4px 0 10px}
.blp label{font-size:.88rem}.blp .row{display:flex;gap:8px;align-items:center;margin-bottom:14px}
.blp button{width:100%;font:inherit;font-weight:600;padding:10px;border:0;border-radius:8px;background:#4f46e5;color:#fff;cursor:pointer}
.blp button:disabled{opacity:.6;cursor:default}.blp .err{color:#b91c1c;font-size:.88rem;min-height:1.3em;margin:8px 0 0}
@media (prefers-color-scheme:dark){.blp{background:#020617;color:#e2e8f0}.blp form{background:#0f172a;border-color:#1e293b}
.blp p{color:#94a3b8}.blp input[type=password]{background:#020617;color:#e2e8f0;border-color:#475569}.blp button{background:#818cf8;color:#0b1020}.blp .err{color:#fca5a5}}
.blp-lock{position:fixed;right:10px;bottom:10px;z-index:60;font:12px system-ui,sans-serif;padding:3px 10px;border-radius:12px;border:1px solid #94a3b8;background:rgba(255,255,255,.88);color:#334155;cursor:pointer;opacity:.75}
.blp-lock:hover{opacity:1}
@media (max-width:1023px){.blp-lock{bottom:76px}}
@media (prefers-color-scheme:dark){.blp-lock{background:rgba(15,23,42,.88);color:#cbd5e1;border-color:#475569}}
`

function ask(lock) {
  return new Promise((resolve) => {
    const box = document.createElement('div')
    box.className = 'blp'
    box.innerHTML = `<form autocomplete="off">
      <div class="mark" aria-hidden="true">BL</div>
      <h1>Business Law: course preview</h1>
      <p>A preview for a small test group. Enter the passphrase you were given.</p>
      <label for="blp-pass">Passphrase</label>
      <input id="blp-pass" type="password" autocomplete="current-password" required autofocus>
      <div class="row"><input id="blp-remember" type="checkbox" checked><label for="blp-remember">Remember on this device</label></div>
      <button type="submit">Unlock</button>
      <p class="err" role="alert"></p>
    </form>`
    document.body.appendChild(box)
    const form = box.querySelector('form')
    const input = box.querySelector('#blp-pass')
    const remember = box.querySelector('#blp-remember')
    const button = box.querySelector('button')
    const err = box.querySelector('.err')
    input.focus()
    form.addEventListener('submit', async (e) => {
      e.preventDefault()
      button.disabled = true
      button.textContent = 'Unlocking…'
      err.textContent = ''
      const raw = await derive(input.value, lock)
      if (await isRight(raw, lock)) {
        saveKey(raw, remember.checked)
        box.remove()
        resolve(raw)
      } else {
        button.disabled = false
        button.textContent = 'Unlock'
        err.textContent = 'That passphrase is not right. Check it and try again.'
        input.select()
      }
    })
  })
}

function lockButton() {
  const b = document.createElement('button')
  b.className = 'blp-lock'
  b.textContent = 'Lock'
  b.title = 'Forget the passphrase on this device'
  b.addEventListener('click', () => {
    forgetKey()
    location.reload()
  })
  document.body.appendChild(b)
}

function fail(message) {
  const box = document.createElement('div')
  box.className = 'blp'
  box.innerHTML = '<form><h1>The preview couldn’t start</h1><p></p></form>'
  box.querySelector('p').textContent = message
  document.body.appendChild(box)
}

async function start() {
  const style = document.createElement('style')
  style.textContent = CSS
  document.head.appendChild(style)
  if (!window.crypto?.subtle || !window.DecompressionStream) return fail('This browser is too old for the preview. Use a current Chrome, Edge, Firefox or Safari.')
  let lock
  try {
    lock = await fetch(new URL('lock.json', BASE), { cache: 'no-cache' }).then((r) => r.json())
  } catch {
    return fail('Check your connection and reload the page.')
  }
  let raw = storedKey()
  if (raw && !(await isRight(raw, lock))) {
    forgetKey() // the passphrase was changed since this device remembered it
    raw = null
  }
  if (!raw) raw = await ask(lock)

  const open = await decryptor(raw)
  const text = async (rel) => {
    const f = await open(rel, { cache: 'no-cache' })
    if (f.status !== 200) throw new Error(`${rel}: ${f.status}`)
    return new Response(f.body).text()
  }
  try {
    const [css, js] = await Promise.all([text('app.css'), text('app.js')])
    const appStyle = document.createElement('style')
    appStyle.textContent = css
    document.head.appendChild(appStyle)
    installFetch(open)
    // No accounts in the preview: start as a guest (progress is saved in this browser).
    try {
      if (!localStorage.getItem('gbl-auth')) localStorage.setItem('gbl-auth', JSON.stringify({ mode: 'guest' }))
    } catch { /* private window */ }
    document.title = 'Business Law (preview)'
    lockButton()
    await import(URL.createObjectURL(new Blob([js], { type: 'text/javascript' })))
  } catch (e) {
    fail(`The app could not be loaded (${e?.message ?? e}). Reload the page; if it keeps happening, tell the person who sent you the link.`)
  }
}

start()
