/*
 * SPID — Universal Switchboard Portal
 * portail.js — §1 CRYPTO + §2 SWITCHBOARD REQUEST + §3 UI WIRING
 *
 * Same-origin as the Passport PWA (deploy under the same GitHub Pages
 * repo, e.g. sovereign-passport.github.io/portail/) so it reads the SAME
 * IndexedDB vault — no separate login, no duplicated identity.
 *
 * Crypto primitives below mirror passport.crypto.js / src/crypto/vault.js /
 * src/credentials/credentials.js, kept byte-for-byte identical so
 * signatures and presentations verify correctly against the vine
 * switchboard (mdusl spid-js). Zero external libraries. WebCrypto only.
 *
 * ES2017 target — same discipline as the rest of the passport source.
 * Forbidden: ?. ?? 0n 600_000 catch{} {...obj}
 */

// ═════════════════════════════════════════════════════════════════════════
// SECTION 1 — CRYPTO (identical to passport.crypto.js primitives)
// ═════════════════════════════════════════════════════════════════════════

var SWITCHBOARD_HOST = 'https://mdusl.sovereign-passport.id'
var VINE_DID          = 'did:web:mdusl.sovereign-passport.id'
var PBKDF2_ITER        = 600000

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
// SECTION 2 — SWITCHBOARD REQUEST
// ═════════════════════════════════════════════════════════════════════════

function requestSwitch(unlockedVault, service) {
  var credential = (unlockedVault.credentials || []).filter(function(c) {
    return c.type === 'MembershipCredential' && c.issuer_did === VINE_DID && !c.revoked
  })[0]

  var holderDid = unlockedVault.identity.id

  return importPrivateKey(unlockedVault.keys.privateKey).then(function(privateKey) {
    return fetch(SWITCHBOARD_HOST + '/api/switch/nonce')
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
            verifierDid:      VINE_DID,
            nonce:            nonce,
          }).then(function(presentation) {
            return { did: holderDid, presentation: presentation, nonce: nonce, service: service, action: 'ui', data: {} }
          })
        } else {
          bodyPromise = Promise.resolve(
            { did: holderDid, service: service, action: 'ui', data: {} }
          )
        }

        return bodyPromise
      })
      .then(function(body) {
        return fetch(SWITCHBOARD_HOST + '/api/switch', {
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
var svcDivider     = document.getElementById('svcDivider')
var svcField       = document.getElementById('svcField')
var svcSelect      = document.getElementById('svcSelect')
var enterBtn       = document.getElementById('enterBtn')
var enterBtnLabel  = document.getElementById('enterBtnLabel')
var msgBox         = document.getElementById('msgBox')
var resultBox      = document.getElementById('resultBox')

var _storedPayload = null   // { did, salt, iv, ciphertext, created_at, updated_at }
var _unlockedVault  = null  // decrypted vault object, after successful unlock

function showMsg(kind, text) {
  msgBox.className = 'msg show ' + kind
  msgBox.textContent = text
}
function clearMsg() {
  msgBox.className = 'msg'
  msgBox.textContent = ''
}
function showResult(text) {
  resultBox.className = 'result-box show'
  resultBox.textContent = text
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

// ── Step 2 — unlock the vault (same PBKDF2/AES-GCM as the Passport) ──────
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
      svcDivider.style.display  = 'flex'
      svcField.style.display    = 'block'
      enterBtn.style.display    = 'flex'
      showMsg('success', 'Passport unlocked. Choose a service.')
    })
    .catch(function(e) {
      if (e.code === 'WRONG_PASSWORD') {
        showMsg('error', 'Wrong password. Try again.')
      } else {
        showMsg('error', 'Could not unlock this passport: ' + e.message)
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

// ── Step 3 — find the MduSL membership credential, sign, submit ──────────
enterBtn.addEventListener('click', function() {
  clearMsg()
  resultBox.className = 'result-box'

  if (!_unlockedVault) {
    showMsg('error', 'Unlock your passport first.')
    return
  }

  var service = svcSelect.value

  enterBtn.disabled = true
  enterBtnLabel.innerHTML = '<span class="spinner"></span>'

  requestSwitch(_unlockedVault, service)
    .then(function(switchResp) {
      return switchResp.text().then(function(responseText) {
        var parsed = null
        try { parsed = JSON.parse(responseText) } catch (err) { parsed = null }

        if (!switchResp.ok) {
          var reason = (parsed && (parsed.message || parsed.error)) || ('HTTP ' + switchResp.status)
          showMsg('error', 'Access denied: ' + reason)
          if (parsed) showResult(JSON.stringify(parsed, null, 2))
          return
        }

        showMsg('success', 'Connected to ' + service + '.')
        showResult(parsed ? JSON.stringify(parsed, null, 2) : responseText)
      })
    })
    .catch(function(e) {
      showMsg('error', 'Request failed: ' + e.message)
    })
    .then(function() {
      enterBtn.disabled = false
      enterBtnLabel.textContent = 'Enter'
    })
})
