/*
 * SPID — Universal Switchboard Portal
 * portail.js — §1 CRYPTO + §2 ACCESS DISCOVERY + §3 UI WIRING
 *
 * Same-origin as the Passport PWA — reads the SAME IndexedDB vault.
 * Crypto primitives identical to passport.crypto.js. WebCrypto only.
 *
 * The switchboard host is derived from the membership credential's
 * issuer did:web (your passport talks to YOUR vine). DEFAULT_HOST is
 * only the fallback for bare passports (no vine credential yet) —
 * the network's welcome door.
 *
 * ES2017 target. Forbidden: ?. ?? 0n 600_000 catch{} {...obj}
 */

// ═════════════════════════════════════════════════════════════════════════
// SECTION 1 — CRYPTO (identical to passport.crypto.js primitives)
// ═════════════════════════════════════════════════════════════════════════

var DEFAULT_HOST = 'https://mdusl.sovereign-passport.id'
var DEFAULT_VINE_DID = 'did:web:mdusl.sovereign-passport.id'
var PBKDF2_ITER = 600000

function toB64url(b) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(b)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function fromB64url(s) {
  var p = s.replace(/-/g, '+').replace(/_/g, '/')
    .padEnd(s.length + (4 - s.length % 4) % 4, '=')
  return Uint8Array.from(atob(p), function(c) { return c.charCodeAt(0) })
}
function enc(s) { return new TextEncoder().encode(s) }
function dec(b) { return new TextDecoder().decode(b) }

// ── IndexedDB — same store as the Passport PWA ───────────────────────────
var DB_NAME = 'passport', STORE = 'vault'

function openDB() {
  return new Promise(function(res, rej) {
    var r = indexedDB.open(DB_NAME, 1)
    r.onupgradeneeded = function(e) {
      if (!e.target.result.objectStoreNames.contains(STORE)) {
        e.target.result.createObjectStore(STORE, { keyPath: 'key' })
      }
    }
    r.onsuccess = function(e) { res(e.target.result) }
    r.onerror   = function(e) { rej(e.target.error) }
  })
}

function loadStoredVault() {
  return openDB().then(function(db) {
    return new Promise(function(res, rej) {
      var tx = db.transaction(STORE, 'readonly')
      var r  = tx.objectStore(STORE).get('current')
      r.onsuccess = function(e) {
        res(e.target.result !== undefined ? e.target.result : null)
      }
      r.onerror = function(e) { rej(e.target.error) }
    })
  })
}

// ── Vault unlock — PBKDF2 + AES-256-GCM ──────────────────────────────────
function deriveVaultKey(password, saltB64) {
  var salt = fromB64url(saltB64)
  return crypto.subtle.importKey('raw', enc(password), 'PBKDF2', false, ['deriveKey'])
    .then(function(km) {
      return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
        km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
      )
    })
}

function decryptVault(vaultKey, ivB64, ciphertextB64) {
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64url(ivB64) },
    vaultKey, fromB64url(ciphertextB64)
  ).then(function(buf) { return dec(new Uint8Array(buf)) })
}

function unlockVault(password, salt, iv, ciphertext) {
  return deriveVaultKey(password, salt).then(function(vk) {
    return decryptVault(vk, iv, ciphertext)
      .catch(function(err) {
        var e = new Error('WRONG_PASSWORD')
        e.code = 'WRONG_PASSWORD'
        throw e
      })
      .then(function(pt) {
        return { vault: JSON.parse(pt), vaultKey: vk }
      })
  })
}

// ── Ed25519 signing (identical to src/crypto/vault.js) ───────────────────
function importPrivateKey(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign'])
}

function edSign(privateKey, dataStr) {
  return crypto.subtle.sign('Ed25519', privateKey, enc(dataStr))
    .then(function(buf) { return toB64url(buf) })
}

// ── Build a Verifiable Presentation (identical to credentials.js) ────────
function encodeJSON(obj) { return toB64url(enc(JSON.stringify(obj))) }
function uuid() { return crypto.randomUUID() }
function nowIso() { return new Date().toISOString() }

function buildPresentation(opts) {
  var credential        = opts.credential
  var revealKeys        = opts.revealKeys
  var holderDid         = opts.holderDid
  var holderPrivateKey  = opts.holderPrivateKey
  var verifierDid       = opts.verifierDid
  var nonce             = opts.nonce

  var chosenDisclosures = (credential.disclosures || []).filter(function(d) {
    return revealKeys.indexOf(d.key) !== -1
  })

  var jwtPart = credential.sd_jwt.split('~')[0]
  var presentedSdJwt = [jwtPart].concat(chosenDisclosures.map(function(d) {
    return d.disclosure
  })).join('~')

  var proofPayload = {
    iss:   holderDid,
    aud:   verifierDid || null,
    nonce: nonce || null,
    iat:   nowIso(),
    vp:    presentedSdJwt,
  }

  var proofB64 = encodeJSON(proofPayload)

  return edSign(holderPrivateKey, proofB64).then(function(proofSig) {
    return {
      id:               uuid(),
      type:             'VerifiablePresentation',
      holder_did:       holderDid,
      credential_id:    credential.id,
      credential_type:  credential.type,
      presented_at:     nowIso(),
      verifier_did:     verifierDid || null,
      nonce:            nonce || null,
      sd_jwt:           presentedSdJwt,
      holder_proof: {
        payload:     proofPayload,
        payload_b64: proofB64,
        signature:   proofSig,
      },
      revealed_claims: chosenDisclosures.map(function(d) {
        return { key: d.key, value: d.value }
      }),
    }
  })
}

// ═════════════════════════════════════════════════════════════════════════
// SECTION 2 — ACCESS DISCOVERY
// ═════════════════════════════════════════════════════════════════════════

// Derive the switchboard host from the credential issuer's did:web.
// did:web:mdusl.sovereign-passport.id → https://mdusl.sovereign-passport.id
// Bare passports (no credential) fall back to the network welcome door.
function switchboardHostFor(credential) {
  if (credential && credential.issuer_did &&
      credential.issuer_did.indexOf('did:web:') === 0) {
    var domain = credential.issuer_did.slice('did:web:'.length)
    // did:web path segments use ':' — convert to '/' (rare, but spec-legal)
    domain = domain.split(':').join('/')
    return 'https://' + domain
  }
  return DEFAULT_HOST
}

function requestAccess(unlockedVault) {
  var credential = (unlockedVault.credentials || []).filter(function(c) {
    return c.type === 'MembershipCredential' && !c.revoked
  })[0]

  var holderDid = unlockedVault.identity.id
  var host      = switchboardHostFor(credential)

  return importPrivateKey(unlockedVault.keys.privateKey).then(function(privateKey) {
    return fetch(host + '/api/switch/nonce')
      .then(function(nonceResp) {
        if (!nonceResp.ok) throw new Error('Could not reach the switchboard for a nonce.')
        return nonceResp.json()
      })
      .then(function(nonceData) {
        var nonce = nonceData.nonce

        var bodyPromise
        if (credential) {
          bodyPromise = buildPresentation({
            credential:       credential,
            revealKeys:       [],
            holderDid:        holderDid,
            holderPrivateKey: privateKey,
            verifierDid:      credential.issuer_did || DEFAULT_VINE_DID,
            nonce:            nonce,
          }).then(function(presentation) {
            return { did: holderDid, presentation: presentation, nonce: nonce,
                     service: 'spid', action: 'access', data: {} }
          })
        } else {
          bodyPromise = Promise.resolve(
            { service: 'spid', action: 'access', data: {} }
          )
        }

        return bodyPromise
      })
      .then(function(body) {
        return fetch(host + '/api/switch', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify(body),
        })
      })
  })
}

// ═════════════════════════════════════════════════════════════════════════
// SECTION 3 — UI WIRING
// ═════════════════════════════════════════════════════════════════════════

var didDisplay     = document.getElementById('didDisplay')
var unlockField    = document.getElementById('unlockField')
var pwInput        = document.getElementById('pwInput')
var unlockBtn      = document.getElementById('unlockBtn')
var unlockBtnLabel = document.getElementById('unlockBtnLabel')
var doorsDivider   = document.getElementById('doorsDivider')
var doorsField     = document.getElementById('doorsField')
var doorsList      = document.getElementById('doorsList')
var msgBox         = document.getElementById('msgBox')

var _storedPayload = null
var _unlockedVault = null

function showMsg(kind, text) {
  msgBox.className = 'msg show ' + kind
  msgBox.textContent = text
}
function clearMsg() {
  msgBox.className = 'msg'
  msgBox.textContent = ''
}

function showDoors(level, services) {
  doorsDivider.style.display = 'flex'
  doorsField.style.display   = 'block'
  doorsList.innerHTML        = ''

  if (!services || services.length === 0) {
    var empty = document.createElement('div')
    empty.className = 'door-empty'
    empty.textContent = 'No doors open for this passport yet. Ask your vine for an invitation.'
    doorsList.appendChild(empty)
    return
  }

  services.forEach(function(svc) {
    var a = document.createElement('a')
    a.className   = 'door-link'
    a.href        = svc.url
    a.textContent = svc.label
    doorsList.appendChild(a)
  })
}

// ── Step 1 — detect a stored passport on this device ─────────────────────
loadStoredVault()
  .catch(function(err) { return null })
  .then(function(payload) {
    _storedPayload = payload

    if (!_storedPayload || !_storedPayload.did) {
      didDisplay.textContent = 'No Passport found on this device'
      didDisplay.classList.add('empty')
      showMsg('info', 'Open your Passport first to create or restore your sovereign identity, then come back here.')
      return
    }

    didDisplay.textContent = _storedPayload.did
    didDisplay.classList.remove('empty')

    unlockField.style.display = 'block'
    pwInput.focus()
  })

// ── Step 2 — unlock, then the vine answers with YOUR doors ───────────────
unlockBtn.addEventListener('click', function() {
  clearMsg()
  var password = pwInput.value
  if (!password) {
    showMsg('error', 'Enter your vault password.')
    return
  }

  unlockBtn.disabled = true
  unlockBtnLabel.innerHTML = '<span class="spinner"></span>'

  unlockVault(password, _storedPayload.salt, _storedPayload.iv, _storedPayload.ciphertext)
    .then(function(result) {
      _unlockedVault = result.vault
      unlockField.style.display = 'none'
      showMsg('info', 'Passport unlocked. Asking your vine…')
      return requestAccess(_unlockedVault)
    })
    .then(function(resp) {
      if (!resp) return
      return resp.text().then(function(responseText) {
        var parsed = null
        try { parsed = JSON.parse(responseText) } catch (err) { parsed = null }

        if (!resp.ok) {
          var reason = (parsed && (parsed.message || parsed.error)) || ('HTTP ' + resp.status)
          showMsg('error', 'Access denied: ' + reason)
          return
        }

        clearMsg()
        showDoors(parsed.level, parsed.services)
      })
    })
    .catch(function(e) {
      if (e.code === 'WRONG_PASSWORD') {
        showMsg('error', 'Wrong password. Try again.')
        unlockField.style.display = 'block'
      } else {
        showMsg('error', 'Request failed: ' + e.message)
      }
    })
    .then(function() {
      unlockBtn.disabled = false
      unlockBtnLabel.textContent = 'Unlock →'
    })
})

pwInput.addEventListener('keydown', function(e) {
  if (e.key === 'Enter') unlockBtn.click()
})

// ═════════════════════════════════════════════════════════════════════════
// SECTION 4 — SERVICES SHELL (tabs, #service fragment, ?embed=1)
//
// Only the `embed` flag and the `service` fragment are read from the URL.
// No secret, DID or authorization is ever accepted from the URL.
// ═════════════════════════════════════════════════════════════════════════

var SERVICES = ['assist', 'billboard', 'calendar', 'messages']
var DEFAULT_SERVICE = 'assist'

var tabButtons = Array.prototype.slice.call(document.querySelectorAll('.tab'))
var servicePanels = {}
SERVICES.forEach(function(name) {
  servicePanels[name] = document.getElementById('panel-' + name)
})

function normalizeService(value) {
  return SERVICES.indexOf(value) !== -1 ? value : DEFAULT_SERVICE
}

function activateService(name) {
  var target = normalizeService(name)

  tabButtons.forEach(function(btn) {
    var selected = btn.getAttribute('data-service') === target
    btn.setAttribute('aria-selected', selected ? 'true' : 'false')
    btn.tabIndex = selected ? 0 : -1
  })

  SERVICES.forEach(function(n) {
    var panel = servicePanels[n]
    if (!panel) return
    if (n === target) panel.removeAttribute('hidden')
    else panel.setAttribute('hidden', '')
  })
}

function serviceFromHash() {
  var h = location.hash || ''
  if (h.charAt(0) === '#') h = h.slice(1)
  try {
    return new URLSearchParams(h).get('service')
  } catch (err) {
    return null
  }
}

function updateHash(name) {
  var target = normalizeService(name)
  var next = '#service=' + target
  if (location.hash !== next) location.hash = next
}

// Tab clicks — update the fragment without reloading the page.
tabButtons.forEach(function(btn) {
  btn.addEventListener('click', function() {
    updateHash(btn.getAttribute('data-service'))
  })
})

// Keyboard navigation — ARIA tabs pattern, automatic activation.
function onTabKeydown(e) {
  var idx = tabButtons.indexOf(e.currentTarget)
  if (idx === -1) return
  var next = null
  if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (idx + 1) % tabButtons.length
  else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = (idx - 1 + tabButtons.length) % tabButtons.length
  else if (e.key === 'Home') next = 0
  else if (e.key === 'End') next = tabButtons.length - 1
  if (next === null) return
  e.preventDefault()
  tabButtons[next].focus()
  updateHash(tabButtons[next].getAttribute('data-service'))
}
tabButtons.forEach(function(btn) {
  btn.addEventListener('keydown', onTabKeydown)
})

window.addEventListener('hashchange', function() {
  activateService(serviceFromHash())
})

// Embed mode — ?embed=1 makes the page transparent for the MduSL host UI.
try {
  if (new URLSearchParams(location.search).get('embed') === '1') {
    document.documentElement.classList.add('embed')
  }
} catch (err) {}

// Fragment absent or invalid → Assist.
activateService(serviceFromHash())
