/*
 * SPID — Universal Switchboard Portal
 * portail.js — §1 CRYPTO + §2 ACCESS DISCOVERY + §3 UI WIRING
 *
 * Same-origin as the Passport PWA — reads the SAME IndexedDB vault.
 * Crypto primitives identical to passport.crypto.js. WebCrypto only.
 *
 * The switchboard host is derived from the membership credential's
 * issuer did:web (your passport talks to YOUR vine). SPID_BOOTSTRAP_HOST
 * is the SPID/Switchboard entry point for bare passports and for owned
 * Clusters — it is NOT a relation with any Vine and is NEVER written into
 * vine_endpoint or Cluster metadata.
 *
 * ES2017 target. Forbidden: ?. ?? 0n 600_000 catch{} {...obj}
 */

// ═════════════════════════════════════════════════════════════════════════
// SECTION 1 — CRYPTO (identical to passport.crypto.js primitives)
// ═════════════════════════════════════════════════════════════════════════

// SPID/Switchboard entry point (alpha node). NOT a relation with a Vine;
// never persisted into vine_endpoint, ClusterVineRelation or Cluster metadata.
var SPID_BOOTSTRAP_HOST = 'https://mdusl.sovereign-passport.id'
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

// ── Ed25519 verify — used to check a SELF-ISSUED ownership proof ─────────
// (the public key is recovered from the vault's own private JWK).
function importPublicFromPrivate(jwk) {
  return crypto.subtle.importKey('jwk',
    { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, { name: 'Ed25519' }, false, ['verify'])
}

function edVerify(publicKey, dataStr, sigB64) {
  return crypto.subtle.verify('Ed25519', publicKey, fromB64url(sigB64), enc(dataStr))
    .catch(function() { return false })
}

// ── Re-encrypt + persist the SAME vault store the Passport uses ──────────
function encryptVault(vaultKey, plaintext) {
  var iv = crypto.getRandomValues(new Uint8Array(12))
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, vaultKey, enc(plaintext))
    .then(function(buf) { return { iv: toB64url(iv), ciphertext: toB64url(new Uint8Array(buf)) } })
}

function persistVault(record) {
  return openDB().then(function(db) {
    return new Promise(function(res, rej) {
      var tx = db.transaction(STORE, 'readwrite')
      tx.objectStore(STORE).put(record)
      tx.oncomplete = function() { res() }
      tx.onerror    = function(e) { rej(e.target.error) }
    })
  })
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
  return SPID_BOOTSTRAP_HOST
}

function accessScopeFor(credential) {
  if (!credential) return null
  if (credential.scope === 'cluster' && credential.cluster_id) {
    return { type: 'cluster', id: credential.cluster_id }
  }
  if (credential.scope === 'vignard' && credential.vignard_id) {
    return { type: 'vignard', id: credential.vignard_id }
  }
  if (credential.vine_id) return { type: 'vine', id: credential.vine_id }
  if (credential.node_id) return { type: 'vine', id: credential.node_id }
  return null
}

/** Literal local/private host only. A public DNS name is left to the browser. */
function isLocalTarget(host) {
  try {
    var h = new URL(host).hostname.toLowerCase().replace(/^\[|\]$/g, '')
    if (h === 'localhost' || h === '127.0.0.1' || h === '::1') return true
    if (h.length > 6 && h.slice(-6) === '.local') return true
    if (/^10\./.test(h) || /^192\.168\./.test(h)) return true
    if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(h)) return true
    if (h.indexOf(':') !== -1 &&
        (h.indexOf('fe80:') === 0 || /^f[cd][0-9a-f]{2}:/.test(h))) return true
  } catch (e) {}
  return false
}

/**
 * CORS options for the Switchboard. The LNA hint is only sent for literal
 * local targets, or when the user explicitly retries through the LNA button.
 * A public hostname may resolve locally (LAN) or publicly (5G): let the
 * browser decide in that case.
 */
function switchFetchOptions(host, forceLocal) {
  var opts = { mode: 'cors', credentials: 'omit', cache: 'no-store' }
  if (forceLocal || isLocalTarget(host)) opts.targetAddressSpace = 'local'
  return opts
}

/** TypeError/Failed-to-fetch is the portable signal for a possible LNA block. */
function isLnaLikely(err) {
  if (!err) return false
  if (typeof navigator !== 'undefined' && navigator.onLine === false) return false
  var msg = String(err.message || err)
  return err.name === 'TypeError' ||
    /failed to fetch|networkerror|load failed|local network|private network/i.test(msg)
}

function requestAccess(unlockedVault, options) {
  var forceLocal = !!(options && options.forceLocal)
  var credential = (unlockedVault.credentials || []).filter(function(c) {
    return c.type === 'MembershipCredential' && !c.revoked
  })[0]

  var holderDid = unlockedVault.identity.id
  var host      = switchboardHostFor(credential)
  var scope      = accessScopeFor(credential)

  return importPrivateKey(unlockedVault.keys.privateKey).then(function(privateKey) {
    return fetch(host + '/api/switch/nonce', switchFetchOptions(host, forceLocal))
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
            var body = { did: holderDid, presentation: presentation, nonce: nonce,
                         service: 'spid', action: 'access', data: {} }
            if (scope) { body.scope_type = scope.type; body.scope_id = scope.id }
            return body
          })
        } else if (holderDid) {
          // Bare Passport: the DID signs the nonce itself and asks for its
          // OWN scope. No credential, no Vine, same DID + proof + scope flow.
          bodyPromise = edSign(privateKey, nonce).then(function(signature) {
            return {
              did: holderDid, nonce: nonce,
              self_proof: { nonce: nonce, signature: signature },
              scope_type: 'did', scope_id: holderDid,
              service: 'spid', action: 'access', data: {},
            }
          })
        } else {
          bodyPromise = Promise.resolve(
            { service: 'spid', action: 'access', data: {} }
          )
        }

        return bodyPromise
      })
      .then(function(body) {
        var opts = switchFetchOptions(host, forceLocal)
        opts.method = 'POST'
        opts.headers = { 'Content-Type': 'application/json' }
        opts.body = JSON.stringify(body)
        return fetch(host + '/api/switch', opts)
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
var _lnaPending    = false
// Contextual rights confirmed by the Switchboard for the current access.
var _accessRights  = null
// Derived AES-GCM vault key — held ONLY in memory to re-decrypt the latest
// IndexedDB payload on a soft refresh. Never persisted anywhere.
var _vaultKey      = null

function showMsg(kind, text) {
  msgBox.className = 'msg show ' + kind
  msgBox.textContent = text
}
function clearMsg() {
  msgBox.className = 'msg'
  msgBox.textContent = ''
}

// The Switchboard returns contextual rights, not a service catalog.
// Assist owns the catalog; this hidden block only keeps the confirmed scope
// visible for debugging without presenting a second source of truth.
function showDoors(rights) {
  doorsDivider.style.display = 'none'
  doorsField.style.display   = 'none'
  doorsList.innerHTML        = ''
  if (!rights || rights.relation === 'guest') return
  var note = document.createElement('div')
  note.className = 'door-empty'
  note.textContent = (rights.scope ? rights.scope.type + ': ' + rights.scope.id : '') +
                     ' — ' + rights.relation
  doorsList.appendChild(note)
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

function handleAccessResponse(resp) {
  if (!resp) return Promise.resolve(false)
  return resp.text().then(function(responseText) {
    var parsed = null
    try { parsed = JSON.parse(responseText) } catch (err) { parsed = null }
    if (!resp.ok) {
      _accessRights = null
      assistSetReady(false)
      var reason = (parsed && (parsed.message || parsed.error)) || ('HTTP ' + resp.status)
      showMsg('error', 'Access denied: ' + reason)
      return false
    }
    clearMsg()
    _accessRights = parsed.rights || null
    assistSetReady(_rightsAllowAssist(_accessRights))
    showDoors(_accessRights)
    return true
  })
}

function afterAccess() {
  return bbPullAndImport().then(function() {
    updateBillboardComposer()
    assistInit()
    calendarReset()
    msUpdateDot()
  })
}

function showLnaGate() {
  _lnaPending = true
  var el = document.getElementById('lnaField')
  if (el) el.style.display = 'block'
}

function hideLnaGate() {
  _lnaPending = false
  var el = document.getElementById('lnaField')
  if (el) el.style.display = 'none'
}

/**
 * Discover the DID rights. Assist is already visible; protected actions stay
 * disabled until this succeeds. The LNA gate is only a fallback after a
 * network/LNA failure, never a prerequisite for showing Assist.
 */
function connectSwitchboard(forceLocal) {
  if (!_unlockedVault) return Promise.resolve(false)
  assistSetStatus('Connexion au Switchboard…', true)
  return requestAccess(_unlockedVault, { forceLocal: !!forceLocal })
    .then(function(resp) { return handleAccessResponse(resp) })
    .then(function(ok) {
      if (!ok) { assistSetStatus(''); return false }
      hideLnaGate()
      assistSetStatus('')
      return afterAccess().then(function() { return true }).catch(function(err) {
        console.warn('[Access] refresh after access failed:', err)
        return true
      })
    })
    .catch(function(err) {
      _accessRights = null
      assistSetReady(false)
      assistSetStatus('')
      if (isLnaLikely(err)) {
        showLnaGate()
        showMsg('info', 'Connexion locale requise. Autorisez l’accès au serveur SPID.')
      } else {
        showMsg('error', 'Connexion au Switchboard échouée : ' +
          (err && err.message ? err.message : err))
      }
      return false
    })
}

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
      _vaultKey      = result.vaultKey
      try {
        var vlang = _unlockedVault.prefs && _unlockedVault.prefs.lang
        var llang = null
        try { llang = localStorage.getItem('spidLang') } catch (e) {}
        if (!llang && vlang) spidAdoptLang(vlang)          // fresh device → vault wins
        else if (llang && llang !== vlang) spidPersistLang(llang)  // local (recent) wins
      } catch (e) {}
      updateBillboardComposer()
      unlockField.style.display = 'none'
      hideLnaGate()
      _accessRights = null
      // The conversation is visible immediately after unlock; only protected
      // actions wait for the Switchboard's contextual rights.
      assistInit()
      assistSetReady(false)
      connectSwitchboard(false)
      return null
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

var lnaAllowBtn = document.getElementById('lnaAllowBtn')
if (lnaAllowBtn) lnaAllowBtn.addEventListener('click', function() {
  if (!_unlockedVault || !_vaultKey) return
  hideLnaGate()
  connectSwitchboard(true)
})

pwInput.addEventListener('keydown', function(e) {
  if (e.key === 'Enter') unlockBtn.click()
})

// ═════════════════════════════════════════════════════════════════════════
// SECTION 5 — BILLBOARD (Cluster selected from the unlocked Passport vault)
//
// Clusters come ONLY from canonical cluster_id (UUID) sources; Vines,
// Vignards and legacy memberships are ignored. The Switchboard host is the
// Cluster's own stored endpoint for JOINED Clusters, and the SPID/Switchboard
// entry point (SPID_BOOTSTRAP_HOST) for OWNED Clusters — never a Vine relation.
// Reading and creating both require the unlocked Passport (Ed25519 key).
// ═════════════════════════════════════════════════════════════════════════

var bbClusterSelect  = document.getElementById('bbClusterSelect')
var bbClusterField   = document.getElementById('bbClusterField')
var bbNoCluster      = document.getElementById('bbNoCluster')
var bbRefreshBtn     = document.getElementById('bbRefreshBtn')
var bbNewBtn         = document.getElementById('bbNewBtn')
var bbCreateHint     = document.getElementById('bbCreateHint')
var bbStatus         = document.getElementById('bbStatus')
var bbList           = document.getElementById('bbList')
var bbChecklistDivider = document.getElementById('bbChecklistDivider')
var bbChecklists     = document.getElementById('bbChecklists')
var bbForm           = document.getElementById('bbForm')
var bbTitle          = document.getElementById('bbTitle')
var bbBody           = document.getElementById('bbBody')
var bbExpires        = document.getElementById('bbExpires')
var bbTitleCount     = document.getElementById('bbTitleCount')
var bbBodyCount      = document.getElementById('bbBodyCount')
var bbFormError      = document.getElementById('bbFormError')
var bbReviewBtn      = document.getElementById('bbReviewBtn')
var bbCancelBtn      = document.getElementById('bbCancelBtn')
var bbConfirm        = document.getElementById('bbConfirm')
var bbConfirmCluster = document.getElementById('bbConfirmCluster')
var bbConfirmType    = document.getElementById('bbConfirmType')
var bbConfirmWarn    = document.getElementById('bbConfirmWarn')
var bbFormMode       = document.getElementById('bbFormMode')
var bbConfirmTitle   = document.getElementById('bbConfirmTitle')
var bbConfirmBody    = document.getElementById('bbConfirmBody')
var bbConfirmExp     = document.getElementById('bbConfirmExp')
var bbConfirmExpRow  = document.getElementById('bbConfirmExpRow')
var bbConfirmError   = document.getElementById('bbConfirmError')
var bbBackBtn        = document.getElementById('bbBackBtn')
var bbSignBtn        = document.getElementById('bbSignBtn')

// Signed credential reused byte-for-byte across retries in one attempt.
var _bbPending = null
// Cluster the confirmation card was built for (guards a post-confirmation change).
var _bbConfirmClusterId = null
// Current composer intent: { action:'create'|'update'|'archive', post }.
var _bbMode = null
// Current Cluster options (canonical UUID only).
var _bbClusters = []

var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** Normalize an endpoint to a scheme+host origin, or null. No name→id mapping. */
function bbEndpointHost(raw) {
  if (!raw) return null
  var s = String(raw).trim()
  if (!s) return null
  if (!/^https?:\/\//i.test(s)) {
    var local = /^localhost(:\d+)?(\/|$)/i.test(s) ||
                /^127\.0\.0\.1(:\d+)?(\/|$)/i.test(s) ||
                /^\[::1\](:\d+)?(\/|$)/i.test(s)
    s = (local ? 'http://' : 'https://') + s
  }
  try {
    var u = new URL(s)
    return u.protocol + '//' + u.host
  } catch (e) { return null }
}

/**
 * Find the EXACT ownership proof for a Cluster in the vault — never rebuilt,
 * never modified: a ClusterOwnerCredential, or a legacy FounderCredential
 * (Cluster) matching the same cluster_id and signed by the vault DID.
 * @returns {Object|null}
 */
function ownerProofFor(vault, clusterId, did) {
  if (!vault || !clusterId || !did) return null
  var creds = vault.credentials || []
  for (var i = 0; i < creds.length; i++) {
    var c = creds[i]
    if (c.type === 'ClusterOwnerCredential') {
      if (c.cluster_id === clusterId && c.owner_did === did) return c
    } else if (c.type === 'FounderCredential') {
      var cid    = c.cluster_id || (c.claims && c.claims.cluster_id)
      var signer = c.issuer_did
      var isClusterFounder = !!(c.claims && c.claims.role === 'founder' && c.cluster_id)
      if (isClusterFounder && cid === clusterId && signer === did && c.issuer_did === c.subject) return c
    }
  }
  return null
}

/**
 * Build the Cluster list from canonical sources, merged ONLY by cluster_id
 * (UUID). Ignores Vines/Vignards, legacy memberships without cluster_id,
 * Clusters without a usable endpoint, and revoked/removed memberships.
 * The displayed label is dynamic: "<cluster name> — <vine name>" when the
 * vine name is found by endpoint match, else "<cluster name> — My Cluster".
 */
function buildClusterOptions(vault) {
  var byId = {}

  // Vine name by endpoint — dynamic, matched from vine credentials only.
  var vineByHost = {}
  var creds = (vault && vault.credentials) || []
  creds.forEach(function(c) {
    if (c.type !== 'MembershipCredential') return
    if (c.scope === 'cluster' || c.scope === 'vignard') return
    if (c.revoked) return
    var host = bbEndpointHost(c.offer_endpoint || c.vine_endpoint)
    if (host && c.node_name && !vineByHost[host]) vineByHost[host] = c.node_name
  })

  function add(clusterId, name, endpoint, status, credentialId, allowNoEndpoint, owned) {
    if (!clusterId || !UUID_RE.test(clusterId)) return        // canonical UUID only
    if (status === 'revoked' || status === 'removed') return
    var host = bbEndpointHost(endpoint)
    var cur = byId[clusterId]
    if (cur) {
      // Enrich an existing Cluster (name / credential / endpoint).
      if (!cur.name && name) cur.name = name
      if (!cur.credential_id && credentialId) cur.credential_id = credentialId
      if (!cur.endpoint && host) cur.endpoint = host
      if (owned) cur.owned = true
      return
    }
    if (!host && !allowNoEndpoint) return                     // joined Cluster without endpoint → ignore
    byId[clusterId] = {
      cluster_id: clusterId, name: name || null, endpoint: host || null,
      status: status || 'unknown', credential_id: credentialId || null,
      owned: !!owned,
    }
  }

  ;(vault.ownClusters || []).forEach(function(c) {
    add(c.id, c.name || c.cluster_name, c.vine_endpoint, c.status || 'active', null, true, true)
  })
  ;(vault.memberships || []).forEach(function(m) {
    add(m.cluster_id, m.node_name || m.cluster_name, m.vine_endpoint, m.status, null, false, false)
  })
  creds.forEach(function(c) {
    if (c.type === 'MembershipCredential' && c.scope === 'cluster') {
      add(c.cluster_id, c.cluster_name, c.vine_endpoint, c.status, c.id, false, false)
    }
  })

  var vaultDid = (vault && vault.identity && vault.identity.id) || null
  var out = []
  Object.keys(byId).forEach(function(k) {
    var o = byId[k]
    var vineName = vineByHost[o.endpoint] || null
    var clusterName = o.name || o.cluster_id
    o.label = clusterName + ' — ' + (vineName || 'My Cluster')
    // Owned Clusters carry their exact owner proof (used for the owner sync).
    if (o.owned) o.ownerProof = ownerProofFor(vault, o.cluster_id, vaultDid)
    out.push(o)
  })
  return out
}

function bbSelectedCluster() {
  var id = bbClusterSelect.value
  for (var i = 0; i < _bbClusters.length; i++) {
    if (_bbClusters[i].cluster_id === id) return _bbClusters[i]
  }
  return null
}

/** Rebuild the <select> from _bbClusters, preserving the current selection. */
function bbRenderClusterSelect(preferredId) {
  var keep = bbClusterSelect.value
  bbClusterSelect.innerHTML = ''
  _bbClusters.forEach(function(c) {
    var opt = document.createElement('option')
    opt.value = c.cluster_id
    opt.textContent = c.label
    bbClusterSelect.appendChild(opt)
  })
  // Non-level (public) announcements — always offered in the same select.
  var pub = document.createElement('option')
  pub.value = '__public__'
  pub.textContent = '— Public — réseau entier —'
  bbClusterSelect.appendChild(pub)
  // The Vine is a community feed: public announcements belong there too.
  var vine = document.createElement('option')
  vine.value = '__vine__'
  vine.textContent = '— Vine — annonces de la communauté —'
  bbClusterSelect.appendChild(vine)
  // URL preference is UI-only: select it ONLY if it is a real UUID present here.
  var want = (typeof preferredId === 'string' && UUID_RE.test(preferredId)) ? preferredId : null
  var hasWant = false
  for (var w = 0; w < _bbClusters.length; w++) {
    if (_bbClusters[w].cluster_id === want) { hasWant = true; break }
  }
  if (hasWant) { bbClusterSelect.value = want; return }
  if (keep === '__public__' || keep === '__vine__') { bbClusterSelect.value = keep; return }
  var found = false
  for (var i = 0; i < _bbClusters.length; i++) {
    if (_bbClusters[i].cluster_id === keep) { found = true; break }
  }
  if (found) bbClusterSelect.value = keep
  else if (_bbClusters.length) bbClusterSelect.value = _bbClusters[0].cluster_id
  else bbClusterSelect.value = '__public__'
}

/** One POST to a Cluster's Switchboard. Host is the Cluster endpoint only. */
function bbSwitch(host, body) {
  return fetch(host + '/api/switch', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  })
}

function bbShortDid(did) {
  if (!did) return '—'
  return did.length > 24 ? did.slice(0, 16) + '…' + did.slice(-6) : did
}

function bbShowStatus(text) {
  bbStatus.textContent = text
  bbStatus.style.display = 'block'
}
function bbHideStatus() {
  bbStatus.style.display = 'none'
  bbStatus.textContent = ''
}

function renderBillboardPosts(posts) {
  bbList.innerHTML = ''
  if (!posts || posts.length === 0) {
    var empty = document.createElement('p')
    empty.className = 'bb-empty'
    empty.textContent = 'No announcements yet.'
    bbList.appendChild(empty)
    return
  }
  posts.forEach(function(p) {
    var card = document.createElement('article')
    card.className = 'bb-post'

    var h = document.createElement('h3')
    h.className = 'bb-post-title'
    h.textContent = p.title || ''
    card.appendChild(h)

    var b = document.createElement('p')
    b.className = 'bb-post-body'
    b.textContent = p.body || ''
    card.appendChild(b)

    var meta = document.createElement('div')
    meta.className = 'bb-post-meta'
    var by = document.createElement('span')
    by.textContent = p.author_handle || 'Sans pseudo'
    meta.appendChild(by)
    var copy = document.createElement('button')
    copy.type = 'button'
    copy.className = 'btn btn-ghost'
    copy.style.cssText = 'width:auto;margin:0;padding:2px 7px;font-size:11px;'
    copy.textContent = '⧉'
    copy.title = 'Copier la DID de l’auteur'
    copy.setAttribute('aria-label', 'Copier la DID de l’auteur')
    copy.addEventListener('click', function () {
      try {
        navigator.clipboard.writeText(p.author_did)
        bbShowStatus('DID copiée ✓')
        setTimeout(bbHideStatus, 1500)
      } catch (e) { bbShowStatus('Copie impossible.') }
    })
    meta.appendChild(copy)
    if (p.expires_at) {
      var exp = document.createElement('span')
      exp.textContent = 'expires ' + new Date(p.expires_at).toLocaleString()
      meta.appendChild(exp)
    }
    card.appendChild(meta)

    // Edit / Archive — author of the post only (see bbCanEditPost).
    if (bbCanEditPost(p)) {
      var actions = document.createElement('div')
      actions.className = 'bb-post-actions'

      var editBtn = document.createElement('button')
      editBtn.type = 'button'
      editBtn.className = 'btn btn-ghost'
      editBtn.textContent = 'Edit'
      editBtn.addEventListener('click', function() { bbStartEdit(p) })
      actions.appendChild(editBtn)

      var archBtn = document.createElement('button')
      archBtn.type = 'button'
      archBtn.className = 'btn btn-ghost'
      archBtn.textContent = 'Archive'
      archBtn.addEventListener('click', function() { bbStartArchive(p) })
      actions.appendChild(archBtn)

      card.appendChild(actions)
    }

    bbList.appendChild(card)
  })
}

/** A Cluster with no stored endpoint has no Switchboard — never invent one. */
function bbRenderDisconnected() {
  bbHideStatus()
  bbList.innerHTML = ''
  var p = document.createElement('p')
  p.className = 'bb-empty'
  p.textContent = 'Cluster services are not connected yet.'
  bbList.appendChild(p)
}

/**
 * Push the COMPLETE owned set (self-issued proofs) so the Switchboard can
 * mirror its projection: a Cluster ABSENT from the set is removed from it
 * (revoked if not attached to a Vine, held pending if it is). Best-effort —
 * a reconciliation failure never blocks the pull.
 * @param {string} host
 * @param {string} did
 */
function bbOwnerReconcile(host, did) {
  if (!_unlockedVault || !_vaultKey) return Promise.resolve()
  var proofs = buildClusterOptions(_unlockedVault)
    .filter(function(c) { return c.owned && c.ownerProof })
    .map(function(c) { return c.ownerProof })

  return fetch(host + '/api/switch/nonce')
    .then(function(r) { if (!r.ok) throw new Error('nonce'); return r.json() })
    .then(function(nd) {
      var nonce = nd.nonce, issued_at = nowIso()
      var base = { type: 'PassportSyncRequest', did: did, nonce: nonce, issued_at: issued_at,
                   proofs: proofs, pending: [], complete: true }
      return importPrivateKey(_unlockedVault.keys.privateKey)
        .then(function(pk) { return edSign(pk, JSON.stringify(base)) })
        .then(function(sig) {
          var sync = { type: base.type, did: base.did, nonce: base.nonce, issued_at: base.issued_at,
                       proofs: base.proofs, pending: base.pending, complete: base.complete, signature: sig }
          return bbSwitch(host, { service: 'spid', action: 'sync', did: did, nonce: nonce, data: { sync: sync } })
        })
    })
}

/**
 * Pull the Switchboard's view for THIS DID (owned + joined) and adopt into the
 * vault ONLY the ownership proofs that are SELF-ISSUED by this DID and whose
 * signature verifies against the vault's own key. Joined clusters are recorded
 * as memberships. The Passport stays the source: the Switchboard never imposes
 * a cluster the DID did not sign for itself.
 */
function bbPullAndImport() {
  if (!_unlockedVault || !_vaultKey) return Promise.resolve({ changed: false })
  var did  = _unlockedVault.identity.id
  var host = SPID_BOOTSTRAP_HOST
  // Best-effort FIRST: push the COMPLETE owned set so the Switchboard can
  // reconcile its projection (a Cluster absent from it is removed). Never
  // blocks the pull — the pull still works if this fails.
  return bbOwnerReconcile(host, did).catch(function() {})
    .then(function() { return fetch(host + '/api/switch/nonce') })
    .then(function(r) { if (!r.ok) throw new Error('nonce'); return r.json() })
    .then(function(nd) {
      var nonce = nd.nonce, issued_at = nowIso()
      var base = { type: 'PassportSyncRequest', did: did, nonce: nonce, issued_at: issued_at, proofs: [], pending: [] }
      return importPrivateKey(_unlockedVault.keys.privateKey)
        .then(function(pk) { return edSign(pk, JSON.stringify(base)) })
        .then(function(sig) {
          var sync = { type: base.type, did: base.did, nonce: base.nonce, issued_at: base.issued_at,
                       proofs: base.proofs, pending: base.pending, signature: sig }
          return bbSwitch(host, { service: 'spid', action: 'sync', did: did, nonce: nonce, data: { sync: sync } })
        })
    })
    .then(function(resp) {
      return resp.json().then(function(d) {
        if (!resp.ok || !d || d.ok !== true) throw new Error((d && (d.error || d.message)) || ('HTTP ' + resp.status))
        return d
      })
    })
    .then(function(view) {
      return importPublicFromPrivate(_unlockedVault.keys.privateKey).then(function(pub) {
        return _adoptView(view, did, pub)
      })
    })
    .catch(function() { return { changed: false } })
}

/** Adopt a Switchboard view into the vault (owned proofs + joined memberships). */
function _adoptView(view, did, pub) {
  var vault   = _unlockedVault
  var changed = false
  var chain   = Promise.resolve()

  // ── owned clusters: self-issued proof only, verified with our own key ──
  var ownIds = {}
  ;(vault.ownClusters || []).forEach(function(c) { ownIds[c.id] = true })
  ;(view.owned_clusters || []).forEach(function(o) {
    if (!o.proof || o.proof.owner_did !== did || !o.proof.signature) return
    if (o.status === 'revoked') {
      // Confirmed deletion → drop it locally (ownClusters + ownership credential).
      if (vault.ownClusters) {
        var n = vault.ownClusters.length
        vault.ownClusters = vault.ownClusters.filter(function(c) { return c.id !== o.cluster_id })
        if (vault.ownClusters.length !== n) changed = true
      }
      if (vault.credentials) {
        var m = vault.credentials.length
        vault.credentials = vault.credentials.filter(function(c) {
          return !(c.cluster_id === o.cluster_id &&
                   (c.type === 'FounderCredential' || c.type === 'ClusterOwnerCredential'))
        })
        if (vault.credentials.length !== m) changed = true
      }
      return
    }
    chain = chain.then(function() {
      return edVerify(pub, o.proof.signed_payload, o.proof.signature).then(function(ok) {
        if (!ok) return
        if (!ownIds[o.cluster_id]) {
          if (!vault.ownClusters) vault.ownClusters = []
          vault.ownClusters.push({
            id: o.cluster_id, name: o.name || o.cluster_id, description: o.description || '',
            founder_did: did, vine_endpoint: null, vignard_did: null, members: [],
            status: 'active', created_at: nowIso(),
          })
          ownIds[o.cluster_id] = true; changed = true
        }
        if (!vault.credentials) vault.credentials = []
        var has = vault.credentials.some(function(c) {
          return c.cluster_id === o.cluster_id &&
            (c.type === 'FounderCredential' || c.type === 'ClusterOwnerCredential')
        })
        if (!has) {
          var claims = null
          try { claims = JSON.parse(o.proof.signed_payload) } catch (e) { claims = null }
          var cred
          if (o.proof.credential_type === 'FounderCredential') {
            cred = { id: 'founder:' + o.cluster_id, type: 'FounderCredential', cluster_id: o.cluster_id,
                     cluster_name: o.name, issuer_did: did, subject: did, issued_at: nowIso(),
                     claims: claims, signature: o.proof.signature }
          } else {
            cred = Object.assign({ signature: o.proof.signature }, claims || {
              type: 'ClusterOwnerCredential', cluster_id: o.cluster_id, owner_did: did,
            })
          }
          vault.credentials.push(cred); changed = true
        }
      })
    })
  })

  // ── joined clusters: participant view (memberships) ──
  var joined = view.joined_clusters || []
  // A Cluster the DID OWNS is never recorded as "joined": owning already
  // implies membership, and it must not be listed twice in the Passport.
  var viewOwned = {}
  ;(view.owned_clusters || []).forEach(function(o) { viewOwned[o.cluster_id] = true })

  // Prune stale membership entries that are in fact owned (or revoked upstream).
  if (vault.memberships && vault.memberships.length) {
    var bLen = vault.memberships.length
    vault.memberships = vault.memberships.filter(function(m) {
      return !(m.cluster_id && (ownIds[m.cluster_id] || viewOwned[m.cluster_id]))
    })
    if (vault.memberships.length !== bLen) changed = true
  }

  if (joined.length) {
    if (!vault.memberships) vault.memberships = []
    var memIds = {}
    vault.memberships.forEach(function(m) { if (m.cluster_id) memIds[m.cluster_id] = true })
    joined.forEach(function(j) {
      if (j.status === 'revoked') return   // revoked cluster: never adopt
      if (ownIds[j.cluster_id] || viewOwned[j.cluster_id]) return   // owned → never "joined"
      if (j.cluster_id && !memIds[j.cluster_id]) {
        vault.memberships.push({
          cluster_id: j.cluster_id, node_name: j.name || null, cluster_name: j.name || null,
          status: j.member_status || 'unknown', vine_endpoint: null,
        })
        memIds[j.cluster_id] = true; changed = true
      }
    })
  }

  return chain.then(function() {
    if (!changed) return { changed: false }
    // SAFETY: the Passport and the Portal SHARE this vault record. Never write
    // back a record without the PBKDF2 salt/key — the Passport would then be
    // unable to derive the key and would report "Wrong password" forever.
    if (!_storedPayload || !_storedPayload.salt || !_storedPayload.key) {
      return { changed: false, error: 'NO_BASE_PAYLOAD' }
    }
    var next = Object.assign({}, _storedPayload, { did: did })
    return encryptVault(_vaultKey, JSON.stringify(vault)).then(function(r) {
      next.iv = r.iv; next.ciphertext = r.ciphertext
      return persistVault(next).then(function() { _storedPayload = next; return { changed: true } })
    })
  })
}

/**
 * Present the Cluster's EXACT owner proof to the SPID/Switchboard entry point
 * and sync ONLY this Cluster. The proof is sent byte-for-byte as stored in the
 * vault — never rebuilt, never modified. No vault and no private key are ever
 * sent: only the public proof, the DID, the nonce and the signature.
 */
function bbOwnerSync(cluster) {
  var did   = _unlockedVault.identity.id
  var proof = cluster.ownerProof
  if (!proof) return Promise.reject(new Error('No owner proof found for this Cluster.'))

  var host = SPID_BOOTSTRAP_HOST
  return fetch(host + '/api/switch/nonce')
    .then(function(resp) {
      if (!resp.ok) throw new Error('Could not reach the Switchboard for a nonce.')
      return resp.json()
    })
    .then(function(nd) {
      var nonce = nd && nd.nonce
      if (!nonce) throw new Error('Switchboard returned no nonce.')
      var issued_at = nowIso()
      // Sign exactly {type,did,nonce,issued_at,proofs,pending}.
      var base = { type: 'PassportSyncRequest', did: did, nonce: nonce, issued_at: issued_at, proofs: [proof], pending: [] }
      return importPrivateKey(_unlockedVault.keys.privateKey)
        .then(function(privateKey) { return edSign(privateKey, JSON.stringify(base)) })
        .then(function(signature) {
          var sync = {
            type: base.type, did: base.did, nonce: base.nonce, issued_at: base.issued_at,
            proofs: base.proofs, pending: base.pending, signature: signature,
          }
          return bbSwitch(host, { service: 'spid', action: 'sync', did: did, nonce: nonce, data: { sync: sync } })
        })
    })
    .then(function(resp) {
      return resp.text().then(function(t) {
        var data = null
        try { data = JSON.parse(t) } catch (e) { data = null }
        if (!resp.ok || !data || data.ok !== true) {
          var msg = (data && (data.message || data.error)) || ('HTTP ' + resp.status)
          throw new Error(msg)
        }
        return data
      })
    })
    .catch(function(e) { throw new Error('Owner sync failed: ' + e.message) })
}

function bbHideChecklists() {
  if (bbChecklistDivider) bbChecklistDivider.style.display = 'none'
  if (bbChecklists) bbChecklists.innerHTML = ''
}

function bbRenderChecklists(lists, cluster, host) {
  if (!bbChecklists) return
  bbChecklists.innerHTML = ''
  if (!lists || lists.length === 0) {
    var empty = document.createElement('p')
    empty.className = 'bb-empty'
    empty.textContent = 'Aucune checklist pour ce Cluster.'
    bbChecklists.appendChild(empty)
    return
  }
  lists.forEach(function (list) {
    var card = document.createElement('div')
    card.className = 'bb-post'
    var title = document.createElement('div')
    title.className = 'bb-title'
    title.textContent = list.title || 'Checklist'
    card.appendChild(title)
    var items = list.items || []
    if (items.length === 0) {
      var none = document.createElement('p')
      none.className = 'bb-note'
      none.textContent = 'Aucun item.'
      card.appendChild(none)
    }
    items.forEach(function (item) {
      var row = document.createElement('label')
      row.className = 'bb-row'
      row.style.cursor = 'pointer'
      var cb = document.createElement('input')
      cb.type = 'checkbox'
      cb.checked = !!item.done
      cb.addEventListener('change', function () {
        bbToggleChecklistItem(item, cb.checked, cluster, host)
      })
      var label = document.createElement('span')
      label.textContent = item.label || ''
      row.appendChild(cb)
      row.appendChild(label)
      card.appendChild(row)
    })
    bbChecklists.appendChild(card)
  })
}

/** Read the checklists of the selected Cluster through the Switchboard. */
function bbLoadChecklists(cluster, host) {
  if (!bbChecklists) return Promise.resolve()
  if (!cluster || !host || !_unlockedVault) {
    bbHideChecklists()
    return Promise.resolve()
  }
  if (bbChecklistDivider) bbChecklistDivider.style.display = 'flex'
  bbChecklists.innerHTML = ''
  var loading = document.createElement('p')
  loading.className = 'bb-empty'
  loading.textContent = 'Loading checklists…'
  bbChecklists.appendChild(loading)
  return _selfSignedBody('billboard', 'checklist/list', {},
      { type: 'cluster', id: cluster.cluster_id }, host)
    .then(function (resp) {
      return resp.text().then(function (t) {
        var d = null
        try { d = JSON.parse(t) } catch (e) { d = null }
        if (!resp.ok || !d || !Array.isArray(d.checklists)) {
          throw new Error((d && (d.message || d.error)) || ('HTTP ' + resp.status))
        }
        bbRenderChecklists(d.checklists, cluster, host)
      })
    })
    .catch(function (e) {
      bbChecklists.innerHTML = ''
      var err = document.createElement('p')
      err.className = 'bb-empty'
      err.textContent = 'Checklists indisponibles : ' + ((e && e.message) || e)
      bbChecklists.appendChild(err)
    })
}

function bbToggleChecklistItem(item, done, cluster, host) {
  return _selfSignedBody('billboard', 'checklist/toggle',
      { item_id: item.id, done: !!done },
      { type: 'cluster', id: cluster.cluster_id }, host)
    .then(function (resp) {
      return resp.text().then(function (t) {
        var d = null
        try { d = JSON.parse(t) } catch (e) { d = null }
        if (!resp.ok) {
          throw new Error((d && (d.message || d.error)) || ('HTTP ' + resp.status))
        }
        return bbLoadChecklists(cluster, host)
      })
    })
    .catch(function (e) {
      bbShowStatus('Checklist : ' + ((e && e.message) || e))
    })
}

/** Public (non-level) announcements — read-only, no scope. */
function loadPublicBillboard() {
  if (!_unlockedVault) return Promise.resolve()
  bbHideChecklists()
  bbNewBtn.style.display = 'none'
  bbHideForm()
  bbConfirm.style.display = 'none'
  bbHideStatus()
  bbList.innerHTML = ''
  var loading = document.createElement('p')
  loading.className = 'bb-empty'
  loading.textContent = 'Loading…'
  bbList.appendChild(loading)
  return bbSwitch(SPID_BOOTSTRAP_HOST, { service: 'billboard', action: 'public' })
    .then(function (resp) { return resp.text().then(function (t) {
      var data = null; try { data = JSON.parse(t) } catch (e) { data = null }
      if (!resp.ok || !data || !Array.isArray(data.posts)) {
        throw new Error((data && (data.message || data.error)) || ('HTTP ' + resp.status))
      }
      renderBillboardPosts(data.posts)
    })})
    .catch(function (e) {
      bbList.innerHTML = ''
      var err = document.createElement('p')
      err.className = 'bb-empty'
      err.textContent = 'Could not load public announcements: ' + ((e && e.message) || e)
      bbList.appendChild(err)
    })
}

/** Read the selected Cluster: DID-signed proof + Switchboard cluster/list. */
function loadClusterBillboard() {
  if (bbClusterSelect.value === '__public__') return loadPublicBillboard()
  // A Vine feed is the community view of network-wide announcements.
  if (bbClusterSelect.value === '__vine__') return loadPublicBillboard()
  var cluster = bbSelectedCluster()
  if (!_unlockedVault || !cluster) return Promise.resolve()

  // Owned Clusters use the SPID/Switchboard entry point (never a Vine
  // relation). Joined Clusters keep their own verified endpoint.
  var isOwned = !!cluster.owned
  var host    = isOwned ? SPID_BOOTSTRAP_HOST : cluster.endpoint

  if (!isOwned && !cluster.endpoint) {
    // Joined Cluster with no endpoint → no Switchboard at all.
    bbNewBtn.style.display = 'none'
    bbHideForm()
    bbConfirm.style.display = 'none'
    bbHideChecklists()
    bbRenderDisconnected()
    return Promise.resolve()
  }

  // Checklists are a Cluster-scoped service; load them alongside posts.
  bbLoadChecklists(cluster, host)

  // Diagnostics — surfaced in the error message so a phone failure can be read.
  var diag = { host: host, status: null, sync: null }

  bbNewBtn.style.display = 'inline-block'
  bbHideStatus()
  bbList.innerHTML = ''
  var loading = document.createElement('p')
  loading.className = 'bb-empty'
  loading.textContent = 'Loading…'
  bbList.appendChild(loading)

  // Owned Cluster: present its exact owner proof to the Switchboard FIRST.
  // Best-effort: reading announcements must never be blocked by a failed sync
  // — but its error is kept for the diagnostics below.
  var prep
  if (isOwned && cluster.ownerProof) {
    prep = bbOwnerSync(cluster).catch(function(e) { diag.sync = (e && e.message) || String(e) })
  } else {
    if (isOwned) diag.sync = 'no owner proof in this vault'
    prep = Promise.resolve()
  }

  return prep.then(function() {
    var did = _unlockedVault.identity.id
    var timestamp = Date.now()
    var proof = { action: 'billboard_cluster_list', did: did, cluster_id: cluster.cluster_id, timestamp: timestamp }
    return importPrivateKey(_unlockedVault.keys.privateKey)
      .then(function(privateKey) { return edSign(privateKey, JSON.stringify(proof)) })
      .then(function(signature) {
        return fetch(host + '/api/switch/nonce').then(function (r) { return r.json() }).then(function (nd) {
          return bbSwitch(host, {
            service: 'billboard', action: 'cluster/list', nonce: nd && nd.nonce,
            data: { did: did, cluster_id: cluster.cluster_id, timestamp: timestamp, signature: signature },
          })
        })
      })
  })
  .then(function(resp) {
    return resp.text().then(function(t) {
      var data = null
      try { data = JSON.parse(t) } catch (e) { data = null }
      return { ok: resp.ok, status: resp.status, data: data }
    })
  })
  .then(function(r) {
    diag.status = r.status
    if (!r.ok || !r.data || !Array.isArray(r.data.posts)) {
      var msg = (r.data && (r.data.message || r.data.error)) || ('HTTP ' + r.status)
      throw new Error(msg)
    }
    renderBillboardPosts(r.data.posts)
  })
  .catch(function(e) {
    bbList.innerHTML = ''
    var err = document.createElement('pre')
    err.className = 'bb-empty'
    err.style.whiteSpace = 'pre-wrap'
    err.style.wordBreak = 'break-word'
    var lines = 'Could not load announcements: ' + ((e && e.message) || e)
    lines += '\n→ ' + diag.host
    lines += (diag.status == null)
      ? '   — no response (network / DNS / CORS)'
      : '   (HTTP ' + diag.status + ')'
    if (diag.sync) lines += '\n→ owner sync: ' + diag.sync
    err.textContent = lines
    bbList.appendChild(err)
    var retry = document.createElement('button')
    retry.type = 'button'
    retry.className = 'btn btn-ghost'
    retry.textContent = 'Retry'
    retry.addEventListener('click', loadClusterBillboard)   // retry → fresh nonce
    bbList.appendChild(retry)
  })
}

function bbUpdateCounts() {
  bbTitleCount.textContent = (bbTitle.value ? bbTitle.value.length : 0) + ' / 160'
  bbBodyCount.textContent  = (bbBody.value  ? bbBody.value.length  : 0) + ' / 5000'
}

/**
 * Edit/Archive authority. Author-only for now: buildClusterOptions() does not
 * expose a reliable "approved issuer of this Cluster" flag for the vault DID,
 * so issuer rights are NOT inferred here (never invented, never from a label
 * or the URL). Reported as an open gap.
 */
function bbCanEditPost(post) {
  if (!_unlockedVault || !post || !post.post_id || !post.author_did) return false
  return post.author_did === _unlockedVault.identity.id
}

/** ISO date → value for <input type="datetime-local"> (local time). */
function bbToLocalInput(iso) {
  if (!iso) return ''
  var d = new Date(iso)
  if (isNaN(d.getTime())) return ''
  var p = function(n) { return (n < 10 ? '0' : '') + n }
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
    'T' + p(d.getHours()) + ':' + p(d.getMinutes())
}

function bbHideForm() {
  bbForm.style.display = 'none'
  bbFormError.style.display = 'none'
  bbFormError.textContent = ''
  bbFormMode.style.display = 'none'
  _bbPending = null           // Cancel/close invalidates any memoized credential
  _bbConfirmClusterId = null
  _bbMode = null
}

/** New post (create) — fresh, empty composer. */
function bbShowForm() {
  bbConfirm.style.display = 'none'
  bbConfirmError.style.display = 'none'
  bbForm.style.display = 'block'
  bbFormMode.style.display = 'none'
  bbTitle.value = ''
  bbBody.value = ''
  bbExpires.value = ''
  _bbPending = null
  _bbMode = { action: 'create', post: null }
  bbUpdateCounts()
  bbTitle.focus()
}

/** Edit an existing post — prefilled composer, same scope/cluster/post/actor. */
function bbStartEdit(post) {
  if (!_unlockedVault || !bbCanEditPost(post)) return
  bbForm.style.display = 'block'
  bbConfirm.style.display = 'none'
  bbConfirmError.style.display = 'none'
  bbFormError.style.display = 'none'
  bbFormMode.textContent = 'Editing your announcement (v' + post.version + ')'
  bbFormMode.style.display = 'block'
  bbTitle.value = post.title || ''
  bbBody.value  = post.body || ''
  bbExpires.value = bbToLocalInput(post.expires_at)
  _bbPending = null
  _bbMode = { action: 'update', post: post }
  bbUpdateCounts()
  bbTitle.focus()
}

/** Archive — explicit confirmation; content stays byte-identical. */
function bbStartArchive(post) {
  if (!_unlockedVault || !bbCanEditPost(post)) return
  var cluster = bbSelectedCluster()
  bbForm.style.display = 'none'
  bbFormError.style.display = 'none'
  _bbPending = null
  _bbMode = { action: 'archive', post: post }
  _bbConfirmClusterId = cluster ? cluster.cluster_id : null
  _bbShowConfirm(cluster, post.title, post.body, post.expires_at, 'archive')
}

function bbShowFormError(msg) {
  bbFormError.textContent = msg
  bbFormError.className = 'msg show error'
  bbFormError.style.display = 'block'
}

/** Local validation. Bounds on the exact values; trim only checks emptiness. */
function bbValidate() {
  var title = bbTitle.value
  var body  = bbBody.value
  if (title.trim().length === 0)   return 'Title is required.'
  if (title.length > 160)          return 'Title must be 160 characters or fewer.'
  if (body.trim().length === 0)    return 'Message is required.'
  if (body.length > 5000)          return 'Message must be 5000 characters or fewer.'
  if (bbExpires.value) {
    var ms = Date.parse(bbExpires.value)
    if (!isFinite(ms))   return 'Invalid expiration date.'
    if (ms <= Date.now()) return 'Expiration must be in the future.'
  }
  return null
}

function bbReview() {
  var mode = _bbMode || { action: 'create', post: null }
  var err = bbValidate()
  if (err) { bbShowFormError(err); return }
  var cluster = bbSelectedCluster()
  if (!cluster) { bbShowFormError('No Cluster selected.'); return }
  _bbPending = null   // a new confirmation → a fresh id/signature
  _bbConfirmClusterId = cluster.cluster_id
  var expIso = bbExpires.value ? new Date(Date.parse(bbExpires.value)).toISOString() : null
  bbFormError.style.display = 'none'
  _bbShowConfirm(cluster, bbTitle.value, bbBody.value, expIso, mode.action)
}

/** Populate + show the confirmation card for the given action. */
function _bbShowConfirm(cluster, title, body, expIso, action) {
  var isUpdate  = action === 'update'
  var isArchive = action === 'archive'
  bbConfirmType.textContent = isArchive ? 'Confirm archive'
                            : isUpdate  ? 'Confirm update'
                            :             'Confirm announcement'
  bbConfirmCluster.textContent = cluster ? cluster.label : '—'
  bbConfirmTitle.textContent = title
  bbConfirmBody.textContent  = body
  if (expIso) {
    bbConfirmExpRow.style.display = 'flex'
    bbConfirmExp.textContent = new Date(expIso).toLocaleString()
  } else {
    bbConfirmExpRow.style.display = 'none'
  }
  if (isArchive) {
    bbConfirmWarn.textContent = 'This archives the announcement and cannot be undone.'
    bbConfirmWarn.style.display = 'block'
  } else {
    bbConfirmWarn.style.display = 'none'
    bbConfirmWarn.textContent = ''
  }
  bbSignBtn.textContent = isArchive ? 'Sign & archive'
                        : isUpdate  ? 'Sign & update'
                        :             'Sign & publish'
  bbConfirmError.style.display = 'none'
  bbForm.style.display = 'none'
  bbConfirm.style.display = 'block'
}

/**
 * Build + sign the EXACT backend contract, key order:
 *   id, type, action, actor_did, post_id, scope, cluster_id, version,
 *   title, body, expires_at, issued_at  →  signature appended last.
 */
function bbBuildCredential(cluster) {
  var mode   = _bbMode || { action: 'create', post: null }
  var action = mode.action
  var post   = mode.post
  var title, body, expIso, postId, version

  if (action === 'archive' && post) {
    // Archive keeps the current content byte-identical.
    title   = post.title
    body    = post.body
    expIso  = post.expires_at || null
    postId  = post.post_id
    version = post.version + 1
  } else if (action === 'update' && post) {
    title   = bbTitle.value
    body    = bbBody.value
    expIso  = bbExpires.value ? new Date(Date.parse(bbExpires.value)).toISOString() : null
    postId  = post.post_id
    version = post.version + 1
  } else {
    title   = bbTitle.value
    body    = bbBody.value
    expIso  = bbExpires.value ? new Date(Date.parse(bbExpires.value)).toISOString() : null
    postId  = uuid()
    version = 1
  }

  var payload = {
    id:         uuid(),
    type:       'BillboardAction',
    action:     action,
    actor_did:  _unlockedVault.identity.id,
    post_id:    postId,
    scope:      'cluster',
    cluster_id: cluster.cluster_id,
    version:    version,
    title:      title,
    body:       body,
    expires_at: expIso,
    issued_at:  nowIso(),
  }
  return importPrivateKey(_unlockedVault.keys.privateKey).then(function(privateKey) {
    return edSign(privateKey, JSON.stringify(payload))
  }).then(function(sig) {
    payload.signature = sig
    return payload
  })
}

function bbPublish() {
  if (!_unlockedVault) { updateBillboardComposer(); return }
  if (bbSignBtn.disabled) return

  var cluster = bbSelectedCluster()
  // Refuse if the Cluster changed after the confirmation was shown.
  if (!cluster || !_bbConfirmClusterId || cluster.cluster_id !== _bbConfirmClusterId) {
    bbConfirmError.textContent = 'The selected Cluster changed — review again before signing.'
    bbConfirmError.className = 'msg show error'
    bbConfirmError.style.display = 'block'
    return
  }
  var mode   = _bbMode || { action: 'create', post: null }
  var action = mode.action
  if ((action === 'update' || action === 'archive') && (!mode.post || !mode.post.post_id)) {
    bbConfirmError.textContent = 'Nothing to sign — review again.'
    bbConfirmError.className = 'msg show error'
    bbConfirmError.style.display = 'block'
    return
  }
  var label = action === 'archive' ? 'Sign & archive'
            : action === 'update'  ? 'Sign & update'
            :                        'Sign & publish'

  bbSignBtn.disabled = true
  bbSignBtn.textContent = 'Signing…'
  bbConfirmError.style.display = 'none'

  var build = _bbPending ? Promise.resolve(_bbPending) : bbBuildCredential(cluster)

  build.then(function(cred) {
    _bbPending = cred   // same id/signature reused on retry
    return bbSwitch(cluster.endpoint, { service: 'billboard', action: 'action', data: cred })
  }).then(function(resp) {
    return resp.text().then(function(t) {
      var data = null
      try { data = JSON.parse(t) } catch (e) { data = null }
      return { ok: resp.ok, status: resp.status, data: data }
    })
  }).then(function(r) {
    if (!r.ok || !r.data || r.data.success !== true) {
      var msg = (r.data && (r.data.message || r.data.error)) || ('HTTP ' + r.status)
      throw new Error(msg)
    }
    _bbPending = null
    bbConfirm.style.display = 'none'
    bbHideForm()
    bbTitle.value = ''
    bbBody.value = ''
    bbExpires.value = ''
    bbUpdateCounts()
    // Show the success message after the list reload (which clears status).
    return loadClusterBillboard().then(function() {
      bbShowStatus(action === 'archive' ? 'Announcement archived.'
                 : action === 'update'  ? 'Announcement updated.'
                 :                        'Announcement published.')
    })
  }).catch(function(e) {
    if ((e.message || '').indexOf('STALE_VERSION') > -1) {
      // The post moved on — reload the list and ask to review again.
      _bbPending = null
      bbConfirm.style.display = 'none'
      bbHideForm()
      return loadClusterBillboard().then(function() {
        bbShowStatus('This post changed. Review it again.')
      })
    }
    // Failure keeps the form values and the signed credential (same-id retry).
    bbConfirmError.textContent = 'Could not ' +
      (action === 'archive' ? 'archive' : action === 'update' ? 'update' : 'publish') +
      ': ' + e.message
    bbConfirmError.className = 'msg show error'
    bbConfirmError.style.display = 'block'
  }).then(function() {
    bbSignBtn.disabled = false
    bbSignBtn.textContent = label
  })
}

/** Rebuild the Cluster selector + gating. Called on unlock and tab activation. */
function updateBillboardComposer() {
  var unlocked = !!_unlockedVault
  bbConfirm.style.display = 'none'
  bbHideForm()
  bbHideStatus()
  bbList.innerHTML = ''

  if (!unlocked) {
    _bbClusters = []
    bbClusterField.style.display = 'none'
    bbNoCluster.style.display = 'none'
    bbCreateHint.textContent = 'Open your Passport to publish'
    bbCreateHint.style.display = 'block'
    bbNewBtn.style.display = 'none'
    bbRenderClusterSelect()
    return
  }

  _bbClusters = buildClusterOptions(_unlockedVault)
  bbClusterField.style.display = 'block'
  bbRenderClusterSelect(clusterFromHash())

  if (_bbClusters.length === 0) {
    bbNoCluster.style.display = 'block'
    bbCreateHint.style.display = 'none'
    bbNewBtn.style.display = 'none'
    loadClusterBillboard()   // no Cluster → offer the non-level (public) feed
    return
  }
  bbNoCluster.style.display = 'none'
  bbCreateHint.style.display = 'none'
  loadClusterBillboard()   // sets New post per the selected Cluster's endpoint
}

/**
 * Re-read the LATEST encrypted vault from IndexedDB and re-decrypt it with the
 * unlock key held ONLY in memory. The vault key and the plaintext are never
 * persisted. On any failure the current in-memory vault is kept unchanged.
 * @returns {Promise<void>} resolves once _unlockedVault may have been refreshed
 */
function reloadVaultFromStorage() {
  if (!_vaultKey) return Promise.resolve()
  return loadStoredVault()
    .catch(function() { return null })
    .then(function(payload) {
      if (!payload || !payload.iv || !payload.ciphertext) return
      return decryptVault(_vaultKey, payload.iv, payload.ciphertext)
        .then(function(pt) {
          // Replace only AFTER a successful decrypt.
          _unlockedVault = JSON.parse(pt)
          _storedPayload = payload
        })
        .catch(function() { /* keep the current in-memory vault */ })
    })
}

/**
 * Soft refresh — re-reads the latest vault from IndexedDB (re-decrypted with the
 * in-memory key), rebuilds the Clusters and their metadata, then re-runs
 * owner sync → cluster/list. Never reloads the page, never locks the Passport,
 * never persists the password, the private key or the decrypted vault.
 */
function bbSoftRefresh() {
  // No unlocked vault → keep the normal Unlock screen untouched.
  if (!_unlockedVault) { updateBillboardComposer(); return }

  if (bbRefreshBtn.disabled) return            // one refresh at a time
  bbRefreshBtn.disabled = true

  // Preserve the selected cluster_id across the rebuild.
  var selectedId = bbClusterSelect.value || null
  if (!selectedId) { var cur = bbSelectedCluster(); selectedId = cur ? cur.cluster_id : null }

  reloadVaultFromStorage()
    .then(function() { return bbPullAndImport() })
    .then(function() {
      // Rebuild Clusters + metadata from the (refreshed) Passport state.
      _bbClusters = buildClusterOptions(_unlockedVault)
      bbClusterField.style.display = 'block'
      bbRenderClusterSelect(selectedId)

      if (_bbClusters.length === 0) {
        bbNoCluster.style.display = 'block'
        bbCreateHint.style.display = 'none'
        bbNewBtn.style.display = 'none'
        return
      }
      bbNoCluster.style.display = 'none'
      bbCreateHint.style.display = 'none'

      // owner sync → cluster/list. On network error the list shows a Retry and
      // the Passport stays unlocked.
      return loadClusterBillboard()
    })
    .then(function() {
      bbRefreshBtn.disabled = false
    }, function() {
      bbRefreshBtn.disabled = false
    })
}

bbRefreshBtn.addEventListener('click', bbSoftRefresh)
bbNewBtn.addEventListener('click', bbShowForm)
bbCancelBtn.addEventListener('click', bbHideForm)
bbReviewBtn.addEventListener('click', bbReview)
bbBackBtn.addEventListener('click', function() {
  var mode = _bbMode || { action: 'create', post: null }
  _bbPending = null
  if (mode.action === 'archive') {
    // Archive has no editable form — return to the list.
    bbConfirm.style.display = 'none'
    bbHideForm()
    return
  }
  bbConfirm.style.display = 'none'
  bbForm.style.display = 'block'
})
bbSignBtn.addEventListener('click', bbPublish)
bbClusterSelect.addEventListener('change', function() {
  // A Cluster change invalidates any memoized/confirmed credential and mode.
  bbConfirm.style.display = 'none'
  bbHideForm()
  bbHideStatus()
  loadClusterBillboard()
})
bbTitle.addEventListener('input', function() { bbUpdateCounts(); _bbPending = null })
bbBody.addEventListener('input',  function() { bbUpdateCounts(); _bbPending = null })
bbExpires.addEventListener('input', function() { _bbPending = null })

updateBillboardComposer()


// ═════════════════════════════════════════════════════════════════════════
// SECTION 4 — SERVICES SHELL (tabs, #service fragment, ?embed=1)
//
// Only the `embed` flag and the `service` fragment are read from the URL.
// No secret, DID or authorization is ever accepted from the URL.
// ═════════════════════════════════════════════════════════════════════════

var SERVICES = ['assist', 'billboard', 'calendar', 'messages', 'relations']
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

  if (target === 'billboard') {
    updateBillboardComposer()
  }
  if (target === 'calendar') {
    calendarInit()
  }
  if (target === 'messages') {
    msInit()
  }
  if (target === 'relations') {
    relInit()
  }
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

// UI-only Cluster preference from the URL — never an authorization.
function clusterFromHash() {
  var h = location.hash || ''
  if (h.charAt(0) === '#') h = h.slice(1)
  try {
    return new URLSearchParams(h).get('cluster')
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

// ═════════════════════════════════════════════════════════════════════════
// SECTION 6 — ASSIST (chat + voice)
//
// Text -> Switchboard 'assist/plan' (planner, no execution) -> clarification
// or confirmation -> on confirm, the Passport signs EACH action through the
// Switchboard (calendar/messages/finance/checklist). Nothing runs server-side.
// ═════════════════════════════════════════════════════════════════════════

// UI language: localStorage override → browser preference → EN (default).
var _LANGS = ['fr', 'en', 'es']
function _uiLang() {
  try {
    var saved = localStorage.getItem('spidLang')
    if (saved && _LANGS.indexOf(saved) !== -1) return saved
  } catch (e) {}
  var langs = navigator.languages || [navigator.language || '']
  for (var i = 0; i < langs.length; i++) {
    var l = String(langs[i] || '').slice(0, 2).toLowerCase()
    if (_LANGS.indexOf(l) !== -1) return l
  }
  return 'en'
}

// Spoken language for STT: the EXPLICIT choice only, else FR.
// Never the display default — a wrong model transcribes as hallucinated words.
function _voiceLang() {
  try {
    var s = localStorage.getItem('spidLang')
    if (s && _LANGS.indexOf(s) !== -1) return s
  } catch (e) {}
  return 'fr'
}

// Durable mirror of the language choice inside the DID's vault (best effort).
function spidPersistLang(l) {
  if (!_unlockedVault || !_vaultKey || !_storedPayload) return null
  _unlockedVault.prefs = _unlockedVault.prefs || {}
  _unlockedVault.prefs.lang = l
  return encryptVault(_vaultKey, JSON.stringify(_unlockedVault)).then(function (e) {
    return persistVault({
      key: 'current', salt: _storedPayload.salt, iv: e.iv, ciphertext: e.ciphertext,
      did: _unlockedVault.identity.id, created_at: _storedPayload.created_at, updated_at: nowIso(),
    })
  }).catch(function () {})
}

var assistDivider = document.getElementById('assistDivider')
var assistField   = document.getElementById('assistField')
var assistInput   = document.getElementById('assistInput')
var assistSendBtn = document.getElementById('assistSendBtn')
var assistRecBtn  = document.getElementById('assistRecBtn')
var assistRecLabel = document.getElementById('assistRecLabel')
var assistStatus  = document.getElementById('assistStatus')
var assistLog     = document.getElementById('assistLog')
var assistPlanBox = document.getElementById('assistPlanBox')

var _assistDraft   = ''    // original request, kept across a clarification
var _assistPending = null  // plan awaiting confirmation
var _assistPlanScope = null // scope used by the current plan
var _assistPlanHost  = null // Switchboard host used by the current plan

/** Only these contextual relations can use the Assist planner. */
function _rightsAllowAssist(rights) {
  return !!(rights && ['self', 'member', 'admin'].indexOf(rights.relation) !== -1)
}

function assistInit() {
  // A partial/cached first load may call this before the section-6 refs ran.
  if (!assistDivider) assistDivider = document.getElementById('assistDivider')
  if (!assistField) assistField = document.getElementById('assistField')
  if (!assistDivider || !assistField) return
  assistDivider.style.display = 'flex'
  assistField.style.display   = 'block'
  assistSetReady(_rightsAllowAssist(_accessRights))
}

function assistLine(text) {
  if (!assistLog) return
  var p = document.createElement('div')
  p.className = 'bb-note'
  p.textContent = text
  assistLog.appendChild(p)
}
function assistSetStatus(text, loading) {
  if (!assistStatus) return
  if (!text) {
    assistStatus.style.display = 'none'
    assistStatus.textContent = ''
    assistStatus.classList.remove('loading')
    return
  }
  assistStatus.textContent = text
  assistStatus.style.display = 'block'
  assistStatus.classList.toggle('loading', !!loading)
}

// Busy = a plan/execution is in flight: block duplicate submits, show a spinner.
// Access-ready = the Switchboard confirmed contextual rights for Assist.
var _assistBusy = false
var _assistAccessReady = false

function _assistSyncButtons() {
  if (assistSendBtn) assistSendBtn.disabled = _assistBusy || !_assistAccessReady
  if (assistRecBtn)  assistRecBtn.disabled  = _assistBusy || !_assistAccessReady
}

function assistSetReady(ready) {
  _assistAccessReady = !!ready
  _assistSyncButtons()
}

function assistSetBusy(on) {
  _assistBusy = !!on
  _assistSyncButtons()
  if (!_assistBusy) assistSetStatus('')
}

function _assistCredential() {
  var creds = (_unlockedVault && _unlockedVault.credentials) || []
  return creds.filter(function (c) {
    return c.type === 'MembershipCredential' && !c.revoked
  })[0] || null
}
function _assistCluster() {
  return (_bbClusters && _bbClusters.length) ? _bbClusters[0] : null
}
function _assistHost() {
  // Same Switchboard as the access discovery: derived from the credential's
  // issuer, never from an unrelated Cluster selection.
  return switchboardHostFor(_assistCredential())
}
function _assistScope() {
  // Same scope as the access discovery (confirmed by the Switchboard).
  if (_accessRights && _accessRights.scope) return _accessRights.scope
  // Fallbacks are only for a Passport whose credential does not carry a
  // scope (legacy/owned only); the Switchboard still verifies the relation.
  var scoped = accessScopeFor(_assistCredential())
  if (scoped) return scoped
  var did = _holderDid()
  if (did) return { type: 'did', id: did }
  var cl = _assistCluster()
  return cl ? { type: 'cluster', id: cl.cluster_id } : null
}

/**
 * If the request names one of the DID's Clusters, use that Cluster scope.
 * The Switchboard remains the authority: it verifies the relation for this
 * exact scope, so naming a Cluster never grants rights in another one.
 */
function _assistSelectedTarget() {
  if (!_unlockedVault) return null
  var c = bbSelectedCluster && bbSelectedCluster()
  if (!c || !c.cluster_id) return null
  return {
    scope: { type: 'cluster', id: c.cluster_id },
    host: c.endpoint || null,
  }
}

function _assistTargetForText(text) {
  if (!_unlockedVault) return null
  var n = _assistNorm(text)
  if (!n) return null
  var clusters = (_bbClusters && _bbClusters.length)
    ? _bbClusters
    : buildClusterOptions(_unlockedVault)
  var best = null
  ;(clusters || []).forEach(function (c) {
    if (!c || !c.cluster_id) return
    var name = _assistNorm(c.name || c.label || '')
    if (name.length < 3) return
    var id = _assistNorm(c.cluster_id)
    var score = 0
    var exact = false
    if (n.indexOf(name) !== -1) {
      score = name.length
      exact = true
    } else if (id && n.indexOf(id) !== -1) {
      score = 1000
      exact = true
    } else {
      // Match distinctive words: "Mandalin" selects
      // "Sailing-Mexico.com : Mandalin Holbox" without requiring the full name.
      name.split(' ').forEach(function (word) {
        if (word.length >= 4 && n.indexOf(word) !== -1) score += word.length
      })
    }
    if (!score) return
    if (!best || score > best.score || (score === best.score && exact && !best.exact)) {
      best = { cluster: c, score: score, exact: exact }
    }
  })
  if (!best) return null
  var c = best.cluster
  return {
    scope: { type: 'cluster', id: c.cluster_id },
    host: c.endpoint || null,
  }
}

/** Sign one Switchboard request with the unlocked Passport (presentation). */
function _assistSignedBody(service, action, data, scope, hostOverride) {
  var host = hostOverride || _assistHost()
  var cred = _assistCredential()
  var sc   = scope || _assistScope()
  return fetch(host + '/api/switch/nonce')
    .then(function (r) { if (!r.ok) throw new Error('nonce'); return r.json() })
    .then(function (n) {
      var body = { service: service, action: action, data: data || {} }
      if (sc) { body.scope_type = sc.type; body.scope_id = sc.id }
      if (!_unlockedVault) return body
      return importPrivateKey(_unlockedVault.keys.privateKey).then(function (pk) {
        if (!cred) {
          // Bare Passport: sign the nonce with its own key (self-proof).
          return edSign(pk, n.nonce).then(function (signature) {
            body.did = _unlockedVault.identity.id
            body.nonce = n.nonce
            body.self_proof = { nonce: n.nonce, signature: signature }
            return body
          })
        }
        return buildPresentation({
          credential: cred, revealKeys: [],
          holderDid: _unlockedVault.identity.id, holderPrivateKey: pk,
          verifierDid: cred.issuer_did || DEFAULT_VINE_DID, nonce: n.nonce,
        }).then(function (pres) {
          body.did = _unlockedVault.identity.id
          body.presentation = pres
          body.nonce = n.nonce
          return body
        })
      })
    })
    .then(function (body) { return bbSwitch(host, body) })
}

function assistRenderPlan(plan) {
  assistPlanBox.innerHTML = ''
  assistPlanBox.style.display = 'block'

  var head = document.createElement('p'); head.className = 'cred-type'
  head.textContent = 'Plan proposé (' + (plan.status || '?') + ')'
  assistPlanBox.appendChild(head)

  // Capabilities come from Assist's own catalog, already filtered by the
  // contextual rights confirmed by the Switchboard.
  var caps = plan.capabilities || []
  if (caps.length) {
    var capLine = document.createElement('p'); capLine.className = 'bb-note'
    capLine.textContent = 'Services disponibles : ' + caps.map(function (c) {
      return (c.label || c.service) + ' (' + (c.actions || []).join(', ') + ')'
    }).join(' · ')
    assistPlanBox.appendChild(capLine)
  }

  if (plan.summary) assistLine(plan.summary)
  if (plan.question) {
    var q = document.createElement('p'); q.className = 'bb-note'
    q.textContent = '❓ ' + plan.question
    assistPlanBox.appendChild(q)
    return
  }

  var actions = plan.actions || []
  actions.forEach(function (a) {
    var row = document.createElement('div'); row.className = 'bb-confirm-row'
    row.innerHTML = '<span>' + (a.service || '?') + '</span><strong>' + (a.action || '') + '</strong>'
    assistPlanBox.appendChild(row)
  })

  if (plan.status === 'needs_confirmation' && actions.length) {
    _assistPending = plan
    var ok = document.createElement('button')
    ok.className = 'btn btn-gold'; ok.type = 'button'
    ok.textContent = 'Confirmer et exécuter'
    ok.style.marginTop = '12px'
    ok.addEventListener('click', function () {
      if (_assistBusy) return
      ok.disabled = true
      ok.textContent = 'Exécution…'
      assistConfirm(plan)
    })
    assistPlanBox.appendChild(ok)
  }
}

function _assistReadChecklists(scope, host) {
  return _selfSignedBody('billboard', 'checklist/list', {}, scope, host)
    .then(function (resp) {
      return resp.text().then(function (t) {
        var d = null
        try { d = JSON.parse(t) } catch (e) { d = null }
        if (!resp.ok || !d || !Array.isArray(d.checklists)) {
          throw new Error((d && (d.message || d.error)) || ('HTTP ' + resp.status))
        }
        return d.checklists
      })
    })
}

function _assistFindChecklist(lists, ref) {
  var nref = _assistNorm(ref)
  if (!nref) return lists.length === 1 ? lists[0] : null
  for (var i = 0; i < lists.length; i++) {
    var nt = _assistNorm(lists[i].title)
    if (nt.indexOf(nref) !== -1 || nref.indexOf(nt) !== -1) return lists[i]
  }
  return lists.length === 1 ? lists[0] : null
}

function assistChecklistUpdate(a, scope, host) {
  var d = a.data || {}
  var ref = String(d.ref || '').trim()
  if (!ref) return Promise.reject(new Error('checklist cible manquante'))
  return _assistReadChecklists(scope, host).then(function (lists) {
    var found = _assistFindChecklist(lists, ref)
    if (!found) throw new Error('checklist introuvable (ref: "' + ref + '")')
    var body = { id: found.id }
    if (d.new_title) body.title = d.new_title
    if (Array.isArray(d.items)) {
      body.items = d.items.map(function (it) {
        return typeof it === 'string' ? { label: it } : it
      })
    }
    if (d.replace_items === true) body.replace_items = true
    if (Array.isArray(d.remove_item_ids)) body.remove_item_ids = d.remove_item_ids
    if (!body.title && !body.items && !body.remove_item_ids) {
      throw new Error('aucune modification de checklist')
    }
    return _assistSignedBody('billboard', 'checklist/update', body, scope, host)
      .then(function (resp) {
        return resp.text().then(function (t) {
          var r = null
          try { r = JSON.parse(t) } catch (e) { r = null }
          if (!resp.ok) {
            throw new Error((r && (r.message || r.error)) || ('HTTP ' + resp.status))
          }
          var selected = bbSelectedCluster && bbSelectedCluster()
          if (selected && selected.cluster_id === scope.id) {
            bbLoadChecklists({ cluster_id: scope.id }, host || _assistHost())
          }
          return r
        })
      })
  })
}

function assistConfirm(plan) {
  if (!_assistAccessReady) {
    assistLine('Droits non confirmés pour Assist — action non exécutée.')
    return
  }
  var actions = plan.actions || []
  if (!actions.length) return
  assistSetBusy(true)
  assistSetStatus('Exécution signée…', true)
  assistPlanBox.style.display = 'none'
  var sc = _assistPlanScope || _assistScope()
  var planHost = _assistPlanHost || null
  var chain = Promise.resolve()
  var results = []
  var touchedCalendar = false
  var touchedChecklist = false
  actions.forEach(function (a) {
    chain = chain.then(function () {
      if (a.service === 'billboard' && a.action === 'checklist/update') {
        touchedChecklist = true
        return assistChecklistUpdate(a, sc, planHost)
          .then(function () { results.push('billboard/checklist/update → OK') })
          .catch(function (e) { results.push('billboard/checklist/update → erreur (' + e.message + ')') })
      }
      if (a.service === 'billboard' && a.action.indexOf('checklist/') === 0) {
        touchedChecklist = true
      }
      if (a.service === 'billboard' && a.action === 'action') {
        // Edit / repost a Billboard post — resolved + signed here (no bypass).
        return assistBillboardPostOp(a)
          .then(function () { results.push('billboard/action (' + ((a.data || {}).op || '?') + ') → OK') })
          .catch(function (e) { results.push('billboard/action → erreur (' + e.message + ')') })
      }
      if (a.service === 'calendar' && a.action === 'update') {
        // Move / edit a calendar entry — resolved + signed here (no bypass).
        touchedCalendar = true
        return assistCalendarUpdate(a)
          .then(function () { results.push('calendar/update → OK') })
          .catch(function (e) { results.push('calendar/update → erreur (' + e.message + ')') })
      }
      // Calendar entries belong to the DID itself (personal scope 'did').
      var isCal = (a.service === 'calendar')
      if (isCal) touchedCalendar = true
      var asc   = isCal ? _calScope() : sc
      var host  = isCal ? SPID_BOOTSTRAP_HOST : planHost
      return _assistSignedBody(a.service, a.action, a.data || {}, asc, host)
        .then(function (resp) { return resp.text().then(function (t) {
          var d = null; try { d = JSON.parse(t) } catch (e) { d = null }
          var label = resp.ok ? 'OK'
            : ('REFUSÉ (' + ((d && (d.error || d.detail || d.reason)) || resp.status) + ')')
          results.push(a.service + '/' + a.action + ' → ' + label)
        })})
        .catch(function (e) {
          results.push(a.service + '/' + a.action + ' → erreur (' + e.message + ')')
        })
    })
  })
  chain.then(function () {
    assistSetBusy(false)
    assistLine('Résultat : ' + results.join(' ; '))
    // A signed calendar write invalidates the cached view.
    if (touchedCalendar) {
      calendarReset()
      if (servicePanels.calendar && !servicePanels.calendar.hasAttribute('hidden')) calendarInit()
    }
    if (touchedChecklist && sc && sc.type === 'cluster') {
      var selected = bbSelectedCluster && bbSelectedCluster()
      if (selected && selected.cluster_id === sc.id) {
        bbLoadChecklists({ cluster_id: sc.id }, planHost || _assistHost())
      }
    }
  })
}

// ── Billboard post operations (edit / repost-public) ─────────────────────
// Option A : rien ne contourne le Switchboard. Le Passport (cette page) émet
// une LECTURE SB en arrière-plan pour résoudre la cible, puis SIGNE l'action SB.

/** One signed cluster read (no bypass) — returns the posts, or []. */
function assistClusterPosts(cluster, host) {
  var did = _unlockedVault.identity.id
  var timestamp = Date.now()
  var proof = { action: 'billboard_cluster_list', did: did, cluster_id: cluster.cluster_id, timestamp: timestamp }
  // Owned clusters must present their exact owner proof first (as the view does).
  var prep = (cluster.owned && cluster.ownerProof)
    ? bbOwnerSync(cluster).catch(function () {}) : Promise.resolve()
  return prep
    .then(function () { return importPrivateKey(_unlockedVault.keys.privateKey) })
    .then(function (pk) { return edSign(pk, JSON.stringify(proof)) })
    .then(function (signature) {
      return fetch(host + '/api/switch/nonce').then(function (r) { return r.json() }).then(function (nd) {
        return bbSwitch(host, {
          service: 'billboard', action: 'cluster/list', nonce: nd && nd.nonce,
          data: { did: did, cluster_id: cluster.cluster_id, timestamp: timestamp, signature: signature },
        })
      })
    })
    .then(function (resp) { return resp.text().then(function (t) {
      var d = null; try { d = JSON.parse(t) } catch (e) { d = null }
      return (d && d.posts) || []
    })})
    .catch(function () { return [] })
}

/** Background SB reads: public feed + every Cluster the DID belongs to. */
function assistReadAllPosts() {
  var jobs = []
  jobs.push(bbSwitch(SPID_BOOTSTRAP_HOST, { service: 'billboard', action: 'public' })
    .then(function (resp) { return resp.text() })
    .then(function (t) { var d = null; try { d = JSON.parse(t) } catch (e) { d = null }; return (d && d.posts) || [] })
    .catch(function () { return [] }))
  buildClusterOptions(_unlockedVault).forEach(function (c) {
    var host = c.owned ? SPID_BOOTSTRAP_HOST : c.endpoint
    if (host) jobs.push(assistClusterPosts(c, host))
  })
  return Promise.all(jobs).then(function (lists) {
    var out = []
    lists.forEach(function (l) { (l || []).forEach(function (p) { out.push(p) }) })
    return out
  })
}

/** Accent/case-insensitive normal form for title matching. */
function _assistNorm(s) {
  return String(s || '').toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9 ]+/g, ' ').replace(/\s+/g, ' ').trim()
}

/** Find the post whose title best matches `ref` (accent-insensitive, word-wise). */
function _assistMatchPost(posts, ref) {
  var nref = _assistNorm(ref)
  if (!nref) return posts[0] || null
  var rwords = nref.split(' ')
  for (var i = 0; i < posts.length; i++) {
    var nt = _assistNorm(posts[i].title)
    if (nt.indexOf(nref) !== -1) return posts[i]
    var all = true
    for (var j = 0; j < rwords.length; j++) { if (nt.indexOf(rwords[j]) === -1) { all = false; break } }
    if (all) return posts[i]
  }
  return null
}

/** Sign + send one BillboardAction through the Switchboard. */
function assistSendBillboardAction(payload) {
  return importPrivateKey(_unlockedVault.keys.privateKey)
    .then(function (pk) { return edSign(pk, JSON.stringify(payload)) })
    .then(function (sig) {
      payload.signature = sig
      return bbSwitch(SPID_BOOTSTRAP_HOST, { service: 'billboard', action: 'action', data: payload })
    })
    .then(function (resp) { return resp.text().then(function (t) {
      var r = null; try { r = JSON.parse(t) } catch (e) { r = null }
      if (!resp.ok) throw new Error((r && (r.error || r.message)) || ('HTTP ' + resp.status))
      return r || {}
    })})
}

/** Background SB reads of the DID's calendar: personal + each Cluster. */
function assistReadAllCalendar() {
  if (!_unlockedVault) return Promise.resolve([])
  var jobs = _calScopes().map(function (sc) {
    return _selfSignedBody('calendar', 'list', {}, { type: sc.type, id: sc.id }, sc.host)
      .then(function (resp) { return resp.text().then(function (t) {
        var d = null; try { d = JSON.parse(t) } catch (e) { d = null }
        return ((d && d.events) || []).map(function (e) {
          e._scopeType = sc.type; e._scopeId = sc.id; e._host = sc.host
          return e
        })
      })})
      .catch(function () { return [] })
  })
  return Promise.all(jobs).then(function (lists) {
    var out = []
    lists.forEach(function (l) { l.forEach(function (e) { out.push(e) }) })
    return out
  })
}

/** Resolve the calendar entry by title, then sign + send calendar/update. */
function assistCalendarUpdate(a) {
  if (!_unlockedVault) return Promise.reject(new Error('passport verrouillé'))
  var d   = a.data || {}
  var ref = String(d.ref || '').trim()
  return assistReadAllCalendar().then(function (events) {
    var nref = _assistNorm(ref)
    var found = null
    for (var i = 0; i < events.length; i++) {
      var t = _assistNorm(events[i].title)
      if (!nref || t.indexOf(nref) !== -1) { found = events[i]; break }
    }
    if (!found) {
      var ts = events.map(function (e) { return e.title }).slice(0, 6).join(' | ')
      throw new Error('entrée introuvable (ref: "' + ref + '", ' + events.length +
                      ' lue(s)' + (ts ? ' : ' + ts : '') + ')')
    }
    var body = { id: found.id }
    if (d.title)    body.title     = d.title
    if (d.starts_at) {
      // Date-only change keeps the original time of day.
      var sv = d.starts_at
      if (sv.indexOf('T') === -1 && found.starts_at && found.starts_at.indexOf('T') !== -1) {
        sv = sv + found.starts_at.slice(found.starts_at.indexOf('T'))
      }
      body.starts_at = sv
    }
    if (d.ends_at)  body.ends_at   = d.ends_at
    if (d.location) body.data      = { location: d.location }
    return _selfSignedBody('calendar', 'update', body,
        { type: found._scopeType, id: found._scopeId }, found._host)
      .then(function (resp) { return resp.text().then(function (t) {
        var r = null; try { r = JSON.parse(t) } catch (e) { r = null }
        if (!resp.ok) throw new Error((r && (r.error || r.message)) || ('HTTP ' + resp.status))
        return true
      })})
  })
}

/** Resolve the target post, then sign + send the Switchboard action. */
function assistBillboardPostOp(a) {
  if (!_unlockedVault) return Promise.reject(new Error('passport verrouillé'))
  var d   = a.data || {}
  var op  = d.op
  var ref = String(d.ref || '').trim()
  return assistReadAllPosts().then(function (posts) {
    var found = _assistMatchPost(posts, ref)
    if (!found) {
      var titles = posts.map(function (p) { return p.title }).slice(0, 6).join(' | ')
      throw new Error('annonce introuvable (ref: "' + ref + '", ' + posts.length +
                      ' annonce(s) lue(s)' + (titles ? ' : ' + titles : '') + ')')
    }
    var scope     = found.scope === 'public' ? 'public' : 'cluster'
    var clusterId = scope === 'cluster' ? found.cluster_id : null

    if (op === 'update') {
      var newTitle = d.title || found.title
      if (newTitle && newTitle.charAt(0) !== '[') newTitle = '[révisé] ' + newTitle
      return assistSendBillboardAction({
        id: uuid(), type: 'BillboardAction', action: 'update',
        actor_did: _unlockedVault.identity.id, post_id: found.post_id,
        scope: scope, cluster_id: clusterId, version: (found.version || 1) + 1,
        title: newTitle, body: d.body || found.body,
        expires_at: found.expires_at || null, issued_at: nowIso(),
      })
    }

    // repost-public: create the public version, then archive the original
    // (we keep a single active version) once the new one is confirmed active.
    return assistSendBillboardAction({
      id: uuid(), type: 'BillboardAction', action: 'create',
      actor_did: _unlockedVault.identity.id, post_id: uuid(),
      scope: 'public', cluster_id: null, version: 1,
      title: found.title, body: found.body, expires_at: null, issued_at: nowIso(),
    }).then(function (r) {
      var np = r && r.post
      if (np && np.status && np.status !== 'active') return r
      return assistSendBillboardAction({
        id: uuid(), type: 'BillboardAction', action: 'archive',
        actor_did: _unlockedVault.identity.id, post_id: found.post_id,
        scope: scope, cluster_id: clusterId, version: (found.version || 1) + 1,
        title: found.title, body: found.body,
        expires_at: found.expires_at || null, issued_at: nowIso(),
      }).catch(function () {}).then(function () { return r })
    })
  })
}

function assistSubmit(text) {
  if (!text || _assistBusy || !_assistAccessReady) return
  var target = _assistTargetForText(text) || _assistSelectedTarget()
  var scope = target ? target.scope : _assistScope()
  var host = target ? target.host : null
  _assistPlanScope = scope
  _assistPlanHost = host
  assistSetBusy(true)
  assistSetStatus('Planification…', true)
  var contextPromise = Promise.resolve(null)
  if (target && /check\s*-?\s*list|checklist|lista\s+de\s+verificaci|lista\s+de\s+tareas|task\s+list/i.test(text)) {
    contextPromise = _assistReadChecklists(scope, host)
      .then(function (lists) { return { checklists: lists } })
      .catch(function () { return null })
  }
  contextPromise.then(function (context) {
    return _assistSignedBody('assist', 'plan',
      { text: text, scope: scope, lang: _uiLang(), context: context }, scope, host)
  })
    .then(function (resp) { return resp.text().then(function (t) {
      var d = null; try { d = JSON.parse(t) } catch (e) { d = null }
      assistSetBusy(false)
      if (!resp.ok) {
        assistSetStatus('')
        assistLine('Erreur : ' + ((d && (d.detail || d.error)) || resp.status))
        return
      }
      if (d && d.status === 'not_possible') {
        assistSetStatus('')
        assistLine('Assist : ' + (d.message || "Cette demande n'est pas possible."))
        _assistDraft = ''
        return
      }
      if (d && d.status === 'needs_clarification' && d.question) {
        assistSetStatus('')
        assistLine('Orbit : ' + d.question)
        _assistDraft = text  // keep context; the next message is appended
        return
      }
      _assistDraft = ''
      assistSetStatus('')
      assistRenderPlan(d || {})
    })})
    .catch(function (e) { assistSetBusy(false); assistLine('Erreur : ' + e.message) })
}

function assistSend() {
  if (_assistBusy) return
  if (!_assistAccessReady) {
    assistLine('Droits non confirmés pour Assist — attendez la connexion au Switchboard.')
    return
  }
  var text = (assistInput.value || '').trim()
  if (!text) return
  assistInput.value = ''
  assistLine('Vous : ' + text)
  assistSubmit(_assistDraft ? (_assistDraft + ' ' + text) : text)
}

assistSendBtn.addEventListener('click', assistSend)
assistInput.addEventListener('keydown', function (e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); assistSend() }
})

// ── Voice: choose a mic, record, transcribe via the Switchboard ──────────
var _assistRecorder = null
var _assistChunks   = []
var _assistRecTimer = null
var _assistMime     = ''
var _assistMicId    = (window.localStorage && localStorage.getItem('assistMicId')) || ''
var _assistMeterRAF = null
var _assistMaxPeak  = 0
var ASSIST_MAX_REC_MS = 30000

/** Container hint for the STT worker (the bytes stay authoritative). */
function _assistAudioFormat(mime) {
  var m = String(mime || '').toLowerCase()
  if (m.indexOf('mp4') !== -1 || m.indexOf('aac') !== -1) return 'mp4'
  if (m.indexOf('ogg') !== -1) return 'ogg'
  if (m.indexOf('wav') !== -1) return 'wav'
  if (m.indexOf('matroska') !== -1) return 'matroska'
  return 'webm'
}

function _assistMicConstraints() {
  var c = { echoCancellation: true, noiseSuppression: true, autoGainControl: true }
  if (_assistMicId) c.deviceId = { exact: _assistMicId }
  return { audio: c }
}

function assistLoadMics() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return
  navigator.mediaDevices.enumerateDevices().then(function (devs) {
    var mics = devs.filter(function (d) { return d.kind === 'audioinput' })
    var sel = document.getElementById('assistMicSel')
    var row = document.getElementById('assistMicRow')
    if (!sel || !row) return
    if (mics.length && mics.every(function (m) { return !m.label })) {
      // Labels require a one-time permission grant.
      navigator.mediaDevices.getUserMedia({ audio: true }).then(function (s) {
        s.getTracks().forEach(function (t) { t.stop() })
        assistLoadMics()
      }).catch(function () {})
      return
    }
    row.style.display = mics.length > 1 ? 'flex' : 'none'
    sel.innerHTML = ''
    mics.forEach(function (m, i) {
      var o = document.createElement('option')
      o.value = m.deviceId
      o.textContent = m.label || ('Micro ' + (i + 1))
      if (m.deviceId === _assistMicId) o.selected = true
      sel.appendChild(o)
    })
    if (!_assistMicId && mics.length) { _assistMicId = mics[0].deviceId; sel.value = _assistMicId }
  }).catch(function () {})
}

function _assistStopMeter() {
  if (_assistMeterRAF) { cancelAnimationFrame(_assistMeterRAF); _assistMeterRAF = null }
  var m = document.getElementById('assistMeter'); if (m) m.style.display = 'none'
}

function assistRecordToggle() {
  if (_assistBusy) return
  if (!_assistAccessReady) {
    assistLine('Droits non confirmés pour Assist — attendez la connexion au Switchboard.')
    return
  }
  if (_assistRecorder) { _assistRecorder.stop(); return }
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    assistLine('Enregistrement non supporté par ce navigateur.')
    return
  }
  navigator.mediaDevices.getUserMedia(_assistMicConstraints()).then(function (stream) {
    _assistChunks = []
    _assistMaxPeak = 0
    var actx = null
    try {
      var AC = window.AudioContext || window.webkitAudioContext
      actx = new AC()
      var an = actx.createAnalyser(); an.fftSize = 1024
      actx.createMediaStreamSource(stream).connect(an)
      var buf = new Uint8Array(an.fftSize)
      var wrap = document.getElementById('assistMeter')
      var fill = document.getElementById('assistMeterFill')
      if (wrap) wrap.style.display = 'block'
      var tick = function () {
        an.getByteTimeDomainData(buf)
        var peak = 0
        for (var i = 0; i < buf.length; i++) { var v = Math.abs(buf[i] - 128); if (v > peak) peak = v }
        if (peak > _assistMaxPeak) _assistMaxPeak = peak
        if (fill) fill.style.width = Math.min(100, peak * 100 / 128) + '%'
        _assistMeterRAF = requestAnimationFrame(tick)
      }
      tick()
    } catch (e) { actx = null }

    _assistRecorder = new MediaRecorder(stream)
    _assistMime = _assistRecorder.mimeType || 'audio/webm'
    _assistRecorder.addEventListener('dataavailable', function (e) {
      if (e.data && e.data.size) _assistChunks.push(e.data)
    })
    _assistRecorder.addEventListener('stop', function () {
      if (_assistRecTimer) { clearTimeout(_assistRecTimer); _assistRecTimer = null }
      stream.getTracks().forEach(function (t) { t.stop() })
      if (actx) { try { actx.close() } catch (e) {} }
      _assistStopMeter()
      _assistRecorder = null
      assistRecLabel.textContent = window.spidT ? spidT('assist.record') : 'Enregistrer'
      var blob = new Blob(_assistChunks, { type: _assistMime })
      if (!blob.size) { assistLine('Rien enregistré.'); return }
      if (_assistMaxPeak < 3) {
        assistLine('Micro silencieux : aucun son capté. Choisis une autre entrée dans la liste « Micros » et vérifie qu’elle n’est pas muette.')
        return
      }
      assistSetStatus('Transcription…')
      var reader = new FileReader()
      reader.onload = function () {
        var b64 = String(reader.result).split(',')[1] || ''
        _assistSignedBody('assist', 'transcribe', {
          audio_b64: b64,
          format: _assistAudioFormat(_assistMime),
          lang: _voiceLang(),
        })
          .then(function (resp) { return resp.text().then(function (t) {
            var d = null; try { d = JSON.parse(t) } catch (e) { d = null }
            assistSetStatus('')
            if (!resp.ok || !d || !d.text) {
              var why = (d && (d.detail || d.error)) ||
                        (resp.ok ? 'Aucune parole reconnue.' : ('HTTP ' + resp.status))
              assistLine('Transcription indisponible : ' + why)
              return
            }
            assistInput.value = d.text
            assistInput.focus()
            assistLine('Vous (voix) : ' + d.text)
            assistSetStatus('Transcription prête — vérifie puis « Envoyer ».')
          })})
          .catch(function (e) { assistSetStatus(''); assistLine('Erreur transcription : ' + (e && e.message ? e.message : e)) })
      }
      reader.readAsDataURL(blob)
    })
    _assistRecorder.start()
    if (_assistRecTimer) clearTimeout(_assistRecTimer)
    _assistRecTimer = setTimeout(function () {
      if (!_assistRecorder) return
      assistSetStatus('Durée maximale atteinte (30 s)…')
      _assistRecorder.stop()
    }, ASSIST_MAX_REC_MS)
    assistRecLabel.textContent = window.spidT ? spidT('assist.stop') : 'Arrêter'
    assistSetStatus('Enregistrement… (cliquez Stop)')
    assistLoadMics()
  }).catch(function (e) {
    assistLine('Micro indisponible : ' + (e && e.message ? e.message : e))
  })
}
assistRecBtn.addEventListener('click', assistRecordToggle)

;(function () {
  var sel = document.getElementById('assistMicSel')
  if (sel) sel.addEventListener('change', function () {
    _assistMicId = sel.value
    try { localStorage.setItem('assistMicId', _assistMicId) } catch (e) {}
    assistLine('Micro sélectionné.')
  })
  var rf = document.getElementById('assistMicRefresh')
  if (rf) rf.addEventListener('click', function () { assistLoadMics() })
})()

// ═════════════════════════════════════════════════════════════════════════
// SECTION 7 — CALENDAR (agenda)
//
// The DID is the key: the view merges everything the DID holds a key to —
// its OWN calendar (scope 'did' → level 'grape', its personal one) plus each
// Cluster it belongs to (scope 'cluster'). One signed 'calendar/list' per
// scope, merged here. Read-only — events are created through Assist.
// ═════════════════════════════════════════════════════════════════════════

var calMonthEl  = document.getElementById('calMonth')
var calStripEl  = document.getElementById('calStrip')
var calListEl   = document.getElementById('calList')
var calPrevBtn  = document.getElementById('calPrev')
var calNextBtn  = document.getElementById('calNext')
var calTodayBtn = document.getElementById('calToday')

var CAL_PALETTE = ['#e8c877', '#6da3e0', '#b18ad6', '#6fbf73', '#d9a441', '#c94961', '#8d939c']
var _calAnchor  = null   // Date pinned to the 1st of the displayed month
var _calSel     = null   // selected day, 'YYYY-MM-DD'
var _calEvents  = []     // merged events, each tagged with _scope
var _calLoaded  = false
var _calLoading = false

function _holderDid() {
  return (_unlockedVault && _unlockedVault.identity && _unlockedVault.identity.id) || null
}

function _calScope() {
  var did = _holderDid()
  return did ? { type: 'did', id: did } : null
}

/** Every scope the DID holds a key to: its own (did) + each Cluster. */
function _calScopes() {
  var out = []
  var did = _holderDid()
  if (did) {
    out.push({ type: 'did', id: did, host: SPID_BOOTSTRAP_HOST, label: 'Personnel', color: CAL_PALETTE[0] })
  }
  var clusters = buildClusterOptions(_unlockedVault)
  for (var i = 0; i < clusters.length; i++) {
    var c = clusters[i]
    // Owned clusters live on the home Vine (same rule as the Billboard view);
    // joined clusters keep their own endpoint.
    var host = c.owned ? SPID_BOOTSTRAP_HOST : c.endpoint
    if (!host) continue
    out.push({
      type: 'cluster', id: c.cluster_id, host: host,
      label: c.name || c.cluster_id,
      color: CAL_PALETTE[1 + (Math.abs(_calHash(c.cluster_id)) % (CAL_PALETTE.length - 1))],
    })
  }
  return out
}

function _calHash(s) {
  var h = 0
  s = String(s)
  for (var i = 0; i < s.length; i++) { h = ((h << 5) - h + s.charCodeAt(i)) | 0 }
  return h
}

/** Cluster/scope shown small under the title, abbreviated to 3 words. */
function _shortScope(label) {
  var w = String(label || '').trim().split(/\s+/)
  return w.slice(0, 3).join(' ') || '—'
}

function _pad2(n) { return (n < 10 ? '0' : '') + n }
function _dayKey(iso) { return String(iso || '').slice(0, 10) }
function _todayKey() {
  var d = new Date()
  return d.getFullYear() + '-' + _pad2(d.getMonth() + 1) + '-' + _pad2(d.getDate())
}
function _hhmm(iso) {
  var m = String(iso || '').match(/T(\d{2}):(\d{2})/)
  return m ? (m[1] + ':' + m[2]) : ''
}

function calendarReset() {
  _calLoaded = false
  _calEvents = []
  _calAnchor = null
  _calSel = null
}

function calendarInit() {
  if (!calMonthEl) return
  if (!_calAnchor) {
    var n = new Date()
    _calAnchor = new Date(n.getFullYear(), n.getMonth(), 1)
    _calSel    = _todayKey()
  }
  if (_calLoaded || _calLoading) { calendarRender(); return }
  calendarLoad()
}

function calendarLoad() {
  if (!_unlockedVault) { calendarEmpty('Ouvrez votre passport pour voir votre calendrier.'); return }
  var scopes = _calScopes()
  if (!scopes.length) { _calLoaded = true; calendarEmpty('Aucun calendrier accessible.'); return }

  _calLoading = true
  calendarEmpty('Chargement…')
  var calls = scopes.map(function (sc) {
    return _selfSignedBody('calendar', 'list', {}, { type: sc.type, id: sc.id }, sc.host)
      .then(function (resp) { return resp.text().then(function (t) {
        var d = null; try { d = JSON.parse(t) } catch (e) { d = null }
        return { scope: sc, ok: resp.ok, status: resp.status, data: d }
      })})
      .catch(function (e) {
        return { scope: sc, ok: false, status: 0, data: null, err: (e && e.message) || String(e) }
      })
  })

  Promise.all(calls).then(function (rs) {
    _calLoading = false
    _calLoaded  = true
    var merged = [], oks = 0
    rs.forEach(function (r) {
      if (r.ok && r.data && Array.isArray(r.data.events)) {
        oks++
        r.data.events.forEach(function (e) {
          merged.push({ id: e.id, title: e.title, starts_at: e.starts_at, ends_at: e.ends_at, _scope: r.scope })
        })
      }
    })
    _calEvents = merged
    if (!oks && rs.length) {
      calendarEmpty('Calendrier indisponible (aucune portée n\'a répondu).')
      calendarRetry()
      return
    }
    calendarRender()
  })
}

function calendarEmpty(text) {
  calListEl.innerHTML = ''
  var p = document.createElement('p')
  p.className = 'agenda-empty'
  p.textContent = text
  calListEl.appendChild(p)
}

function calendarRetry() {
  var b = document.createElement('button')
  b.type = 'button'
  b.className = 'btn btn-ghost'
  b.textContent = 'Retry'
  b.style.marginTop = '10px'
  b.addEventListener('click', function () { _calLoaded = false; calendarLoad() })
  calListEl.appendChild(b)
}

function calendarRender() {
  if (!calMonthEl) return
  var y = _calAnchor.getFullYear(), m = _calAnchor.getMonth()
  var label = _calAnchor.toLocaleDateString(_calLocale(), { month: 'long', year: 'numeric' })
  calMonthEl.textContent = label.charAt(0).toUpperCase() + label.slice(1)

  // Group by day.
  var byDay = {}
  _calEvents.forEach(function (e) {
    var k = _dayKey(e.starts_at)
    if (!k) return
    ;(byDay[k] = byDay[k] || []).push(e)
  })
  Object.keys(byDay).forEach(function (k) {
    byDay[k].sort(function (a, b) { return String(a.starts_at).localeCompare(String(b.starts_at)) })
  })

  var today = _todayKey()
  var days  = new Date(y, m + 1, 0).getDate()

  // ── Day strip (whole displayed month) ──
  calStripEl.innerHTML = ''
  var selBtn = null
  for (var i = 1; i <= days; i++) {
    var dk = y + '-' + _pad2(m + 1) + '-' + _pad2(i)
    var btn = document.createElement('button')
    btn.type = 'button'
    btn.className = 'agenda-day'
    if (dk === today) btn.classList.add('is-today')
    if (dk === _calSel) { btn.classList.add('is-sel'); selBtn = btn }

    var dw = document.createElement('span'); dw.className = 'agenda-dow'
    dw.textContent = new Intl.DateTimeFormat(_calLocale(), { weekday: 'short' }).format(new Date(y, m, i))
    var num = document.createElement('span'); num.className = 'agenda-num'
    num.textContent = String(i)
    var dots = document.createElement('span'); dots.className = 'agenda-dots'

    var evs = byDay[dk] || [], seen = {}, uniq = []
    for (var j = 0; j < evs.length; j++) {
      var sid = evs[j]._scope ? evs[j]._scope.id : '_'
      if (seen[sid]) continue
      seen[sid] = 1
      uniq.push(evs[j]._scope)
      if (uniq.length >= 4) break
    }
    uniq.forEach(function (sc) {
      var dot = document.createElement('span'); dot.className = 'agenda-dot'
      dot.style.background = (sc && sc.color) || CAL_PALETTE[6]
      if (sc && sc.label) dot.title = _shortScope(sc.label)
      dots.appendChild(dot)
    })

    btn.appendChild(dw); btn.appendChild(num); btn.appendChild(dots)
    ;(function (key) { btn.addEventListener('click', function () { calendarSelectDay(key) }) })(dk)
    calStripEl.appendChild(btn)
  }
  if (selBtn) { try { selBtn.scrollIntoView({ inline: 'center', block: 'nearest' }) } catch (e) {} }

  // ── Continuous list, grouped by day (all days shown above) ──
  calListEl.innerHTML = ''
  var any = false
  for (var d = 1; d <= days; d++) {
    var key = y + '-' + _pad2(m + 1) + '-' + _pad2(d)
    var list = byDay[key] || []
    if (!list.length) continue
    any = true
    var head = document.createElement('div')
    head.className = 'agenda-day-head' + (key === today ? ' is-today' : '')
    head.id = 'calday-' + key
    head.textContent = _dayLabel(y, m, d)
    calListEl.appendChild(head)
    list.forEach(function (e) { calListEl.appendChild(calendarItem(e)) })
  }
  if (!any) calendarEmpty('Aucune entrée dans ce mois.')
}

function _calLocale() {
  var l = _uiLang();
  return l === 'fr' ? 'fr-CA' : l === 'es' ? 'es-ES' : 'en-CA';
}

function _dayLabel(y, m, d) {
  return new Intl.DateTimeFormat(_calLocale(), {
    weekday: 'short', day: 'numeric', month: 'short'
  }).format(new Date(y, m, d));
}

function calendarItem(e) {
  var row = document.createElement('div'); row.className = 'agenda-item'
  var bar = document.createElement('span'); bar.className = 'agenda-bar'
  bar.style.background = (e._scope && e._scope.color) || CAL_PALETTE[6]
  var body = document.createElement('div'); body.className = 'agenda-body'
  var line = document.createElement('div'); line.className = 'agenda-line'
  var t = document.createElement('span'); t.className = 'agenda-time'; t.textContent = _hhmm(e.starts_at)
  var ti = document.createElement('span'); ti.className = 'agenda-title'
  ti.textContent = e.title || (window.spidT ? spidT('calendar.no_title') : '(sans titre)')
  line.appendChild(t); line.appendChild(ti)
  var sc = document.createElement('span'); sc.className = 'agenda-scope'
  sc.textContent = _shortScope(e._scope && e._scope.label)
  body.appendChild(line); body.appendChild(sc)
  row.appendChild(bar); row.appendChild(body)
  return row
}

function calendarSelectDay(key) {
  _calSel = key
  calendarRender()
  var head = document.getElementById('calday-' + key)
  if (head) { try { head.scrollIntoView({ block: 'nearest' }) } catch (e) {} }
}

function calendarShiftMonth(delta) {
  if (!_calAnchor) return
  _calAnchor = new Date(_calAnchor.getFullYear(), _calAnchor.getMonth() + delta, 1)
  calendarRender()
}

function calendarTodayGo() {
  var n = new Date()
  _calAnchor = new Date(n.getFullYear(), n.getMonth(), 1)
  _calSel    = _todayKey()
  calendarRender()
}

if (calPrevBtn)  calPrevBtn.addEventListener('click', function () { calendarShiftMonth(-1) })
if (calNextBtn)  calNextBtn.addEventListener('click', function () { calendarShiftMonth(1) })
if (calTodayBtn) calTodayBtn.addEventListener('click', calendarTodayGo)

// The initial activateService() ran before these DOM refs existed — if the page
// opened straight on the Calendar tab, render it now.
if (servicePanels.calendar && !servicePanels.calendar.hasAttribute('hidden')) calendarInit()

// ═════════════════════════════════════════════════════════════════════════
// SECTION 8 — MESSAGES (DID-centric)
//
// The DID is the address (`to_did`). Immutable blobs — no drafts, no edit.
// The Portail reads/composes; the body stays readable here (E2E is a next step).
// ═════════════════════════════════════════════════════════════════════════

var msStatus = document.getElementById('msStatus')
var msList   = document.getElementById('msList')
var msTo     = document.getElementById('msTo')
var msToSel  = document.getElementById('msToSel')
var msBody   = document.getElementById('msBody')
var msSendBtn = document.getElementById('msSendBtn')
var msDot    = document.getElementById('msgDot')
var _msBox    = 'inbox'
var _msLoaded = false

function _msScope() { var d = _holderDid(); return d ? { type: 'did', id: d } : null }

function msSetStatus(text, loading) {
  if (!msStatus) return
  if (!text) { msStatus.style.display = 'none'; msStatus.textContent = ''; msStatus.classList.remove('loading'); return }
  msStatus.textContent = text
  msStatus.style.display = 'block'
  msStatus.classList.toggle('loading', !!loading)
}
function msNote(text) {
  msList.innerHTML = ''
  var p = document.createElement('p'); p.className = 'bb-empty'; p.textContent = text
  msList.appendChild(p)
}

function msInit() { if (!_msLoaded) msLoad(); msUpdateDot(); msLoadContacts() }

function msPickerSummary() {
  var summary = document.getElementById('msPickerSummary')
  if (!summary || !msToSel) return
  var n = msToSel.querySelectorAll('input[type="checkbox"]:checked:not(.ms-picker-all-box)').length
  summary.textContent = n
    ? n + ' destinataire' + (n > 1 ? 's' : '') + ' sélectionné' + (n > 1 ? 's' : '')
    : 'Les communautés disponibles'
}

// Recipient list: DIDs reachable by shared membership + the home Vine.
function msLoadContacts() {
  if (!msToSel || !_unlockedVault) return
  _selfSignedBody('messages', 'contacts', {}, _msScope(), SPID_BOOTSTRAP_HOST)
    .then(function (resp) { return resp.text() }).then(function (t) {
      var d = null; try { d = JSON.parse(t) } catch (e) { d = null }
      var groups = (d && d.groups) || []
      var list = (d && d.contacts) || []
      msToSel.innerHTML = ''
      var summary = document.getElementById('msPickerSummary')
      if (summary) {
        summary.textContent = groups.length
          ? 'Les communautés disponibles'
          : 'Aucune communauté disponible'
      }

      if (!groups.length && list.length) {
        groups = [{ type: 'contacts', id: 'contacts', name: 'Contacts', members: list }]
      }
      groups.forEach(function (g) {
        var section = document.createElement('div')
        section.className = 'ms-picker-section'

        var head = document.createElement('label')
        head.className = 'ms-picker-group'
        var all = document.createElement('input')
        all.type = 'checkbox'
        all.className = 'ms-picker-all-box'
        var title = document.createElement('span')
        title.textContent = (g.type === 'vine' ? 'Vine — ' : g.type === 'cluster' ? 'Cluster — ' : '') + (g.name || g.id)
        head.appendChild(all)
        head.appendChild(title)
        section.appendChild(head)

        var memberBoxes = []
        g.members.forEach(function (c) {
          var row = document.createElement('label')
          row.className = 'ms-picker-row'
          var cb = document.createElement('input')
          cb.type = 'checkbox'
          cb.value = c.did
          var txt = document.createElement('span')
          txt.textContent = c.handle || 'Sans pseudo'
          row.appendChild(cb)
          row.appendChild(txt)
          section.appendChild(row)
          memberBoxes.push(cb)
          cb.addEventListener('change', function () {
            var checked = memberBoxes.filter(function (x) { return x.checked }).length
            all.checked = checked === memberBoxes.length && memberBoxes.length > 0
            all.indeterminate = checked > 0 && checked < memberBoxes.length
            msPickerSummary()
          })
        })
        all.addEventListener('change', function () {
          memberBoxes.forEach(function (cb) { cb.checked = all.checked })
          all.indeterminate = false
          msPickerSummary()
        })
        msToSel.appendChild(section)
      })
      msPickerSummary()
    }).catch(function () {
      var summary = document.getElementById('msPickerSummary')
      if (summary) summary.textContent = 'Contacts indisponibles — réessayer'
    })
}

function msLoad() {
  if (!_unlockedVault) { msNote('Ouvrez votre passport pour voir vos messages.'); return }
  msSetStatus('Chargement…', true)
  _selfSignedBody('messages', 'list', { box: _msBox }, _msScope(), SPID_BOOTSTRAP_HOST)
    .then(function (resp) { return resp.text().then(function (t) {
      var d = null; try { d = JSON.parse(t) } catch (e) { d = null }
      msSetStatus('')
      if (!resp.ok || !d || !Array.isArray(d.messages)) {
        msNote('Indisponible : ' + ((d && (d.error || d.message)) || ('HTTP ' + resp.status)))
        return
      }
      _msLoaded = true
      msRender(d.messages)
    })})
    .catch(function (e) { msSetStatus(''); msNote('Erreur : ' + (e && e.message ? e.message : e)) })
}

function msRender(rows) {
  msList.innerHTML = ''
  if (!rows.length) { msNote(_msBox === 'sent' ? 'Aucun message envoyé.' : 'Boîte vide.'); return }
  rows.forEach(function (m) {
    var el = document.createElement('div')
    el.className = 'ms-msg' + (_msBox === 'inbox' && m.status !== 'read' ? ' unread' : '')
    var peer = document.createElement('div'); peer.className = 'ms-peer'
    peer.textContent = (_msBox === 'inbox' ? 'de ' : 'à ') + (_msBox === 'inbox' ? m.from_did : m.to_did)
    var body = document.createElement('div'); body.className = 'ms-body'; body.textContent = m.body
    var meta = document.createElement('div'); meta.className = 'ms-meta'
    var when = document.createElement('span')
    when.textContent = String(m.created_at || '').replace('T', ' ').slice(0, 16)
    meta.appendChild(when)
    if (_msBox === 'inbox' && m.status !== 'read') {
      var rb = document.createElement('button')
      rb.type = 'button'; rb.className = 'btn btn-ghost'; rb.textContent = 'Marquer lu'
      rb.addEventListener('click', function () { msMarkRead(m.id) })
      meta.appendChild(rb)
    }
    el.appendChild(peer); el.appendChild(body); el.appendChild(meta)
    msList.appendChild(el)
  })
}

function msMarkRead(id) {
  _selfSignedBody('messages', 'read', { id: id }, _msScope(), SPID_BOOTSTRAP_HOST)
    .then(function () { msLoad(); msUpdateDot() })
    .catch(function () {})
}

function msSend() {
  var body = (msBody.value || '').trim()
  var recips = msToSel
    ? Array.prototype.slice.call(
        msToSel.querySelectorAll('input[type="checkbox"]:checked:not(.ms-picker-all-box)')
      ).map(function (cb) { return cb.value })
    : []
  recips = recips.filter(function (v, i, a) { return !!v && a.indexOf(v) === i })
  var typed = (msTo.value || '').trim()
  if (/^did:/.test(typed) && recips.indexOf(typed) === -1) recips.push(typed)
  if (!recips.length) { msSetStatus('Choisis un destinataire (liste ou DID).'); return }
  if (!body) { msSetStatus('Message vide.'); return }
  msSendBtn.disabled = true
  msSetStatus('Envoi… ' + recips.length, true)

  var results = []
  var chain = Promise.resolve()
  recips.forEach(function (to) {
    chain = chain.then(function () {
      return _selfSignedBody('messages', 'send', { to_did: to, body: body }, _msScope(), SPID_BOOTSTRAP_HOST)
        .then(function (resp) { return resp.text().then(function (t) {
          var d = null; try { d = JSON.parse(t) } catch (e) { d = null }
          results.push((resp.ok && d && d.ok) ? '✓' : '✗ ' + ((d && (d.error || d.message)) || resp.status))
        })})
        .catch(function (e) { results.push('✗ ' + (e && e.message ? e.message : e)) })
    })
  })
  chain.then(function () {
    msSendBtn.disabled = false
    msBody.value = ''
    _msBox = 'sent'; msSyncBoxBtns()
    msSetStatus('Envoyé : ' + results.join(' '))
    setTimeout(function () { msSetStatus('') }, 3000)
    msLoad()
  })
}

function msUpdateDot() {
  if (!msDot || !_unlockedVault) return
  _selfSignedBody('messages', 'pending', {}, _msScope(), SPID_BOOTSTRAP_HOST)
    .then(function (resp) { return resp.text() }).then(function (t) {
      var d = null; try { d = JSON.parse(t) } catch (e) { d = null }
      var n = (d && d.pending) || 0
      msDot.style.display = n > 0 ? 'inline-block' : 'none'
    }).catch(function () {})
}

function msSyncBoxBtns() {
  var i = document.getElementById('msInboxBtn'), s = document.getElementById('msSentBtn')
  if (i) i.setAttribute('aria-pressed', _msBox === 'inbox' ? 'true' : 'false')
  if (s) s.setAttribute('aria-pressed', _msBox === 'sent' ? 'true' : 'false')
}

;(function msWire() {
  var i = document.getElementById('msInboxBtn'), s = document.getElementById('msSentBtn'), r = document.getElementById('msRefreshBtn')
  if (i) i.addEventListener('click', function () { _msBox = 'inbox'; msSyncBoxBtns(); msLoad() })
  if (s) s.addEventListener('click', function () { _msBox = 'sent'; msSyncBoxBtns(); msLoad() })
  if (r) r.addEventListener('click', function () { msLoad(); msUpdateDot() })
  if (msSendBtn) msSendBtn.addEventListener('click', msSend)
  var picker = document.querySelector('.ms-picker')
  if (picker) picker.addEventListener('toggle', function () {
    if (picker.open) msLoadContacts()
  })
})()

// ═════════════════════════════════════════════════════════════════════════
// SECTION 10 — RELATIONS (shared contract v1.0.0)
// The DID is the actor; the target scope travels in data.scope for self actions.
// ═════════════════════════════════════════════════════════════════════════

var relStatus  = document.getElementById('relStatus')
var relGrants  = document.getElementById('relGrants')
var _relGrants = []
var relScope   = document.getElementById('relScope')
var relTo      = document.getElementById('relTo')
var relHandle  = document.getElementById('relHandle')
var relInviteBtn = document.getElementById('relInviteBtn')
var _relLoaded = false

function _relContract() {
  return (window.SPIDRelations && window.SPIDRelations.contract) || null
}

function relSetStatus(text, loading) {
  if (!relStatus) return
  if (!text) { relStatus.style.display = 'none'; relStatus.textContent = ''; return }
  relStatus.textContent = text
  relStatus.style.display = 'block'
  relStatus.classList.toggle('loading', !!loading)
}

function relNote(el, text) {
  el.innerHTML = ''
  var p = document.createElement('p'); p.className = 'bb-empty'; p.textContent = text
  el.appendChild(p)
}

function relInit() {
  if (!_relLoaded) relLoad()
}

function _selfSignedBody(service, action, data, scope, host) {
  if (!_unlockedVault) throw new Error('locked')
  var base = String(host || SPID_BOOTSTRAP_HOST).replace(/\/+$/, '')
  return fetch(base + '/api/switch/nonce')
    .then(function (r) { if (!r.ok) throw new Error('nonce'); return r.json() })
    .then(function (n) {
      return importPrivateKey(_unlockedVault.keys.privateKey).then(function (pk) {
        return edSign(pk, n.nonce).then(function (signature) {
          var body = {
            did: _holderDid(),
            nonce: n.nonce,
            self_proof: { nonce: n.nonce, signature: signature },
            service: service,
            action: action,
            data: data || {},
          }
          if (scope && scope.type && scope.id) {
            body.scope_type = scope.type
            body.scope_id = scope.id
          }
          return fetch(base + '/api/switch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          })
        })
      })
    })
}

function _relSelfCall(action, data, scope, host) {
  return _selfSignedBody('relation', action, data, scope, host)
}

function relLoad() {
  if (!_unlockedVault) { relSetStatus('Ouvrez votre passport.'); return }
  var C = _relContract()
  if (!C) { relSetStatus('Contrat Relations indisponible.'); return }
  relSetStatus('Chargement…', true)
  _relSelfCall('list', {}, _msScope(), SPID_BOOTSTRAP_HOST)
    .then(function (resp) { return resp.text().then(function (t) {
      var d = null; try { d = JSON.parse(t) } catch (e) { d = null }
      relSetStatus('')
      if (!resp.ok || !d || !d.relations) {
        relSetStatus('Indisponible : ' + ((d && (d.error || d.message)) || ('HTTP ' + resp.status)))
        return
      }
      _relLoaded = true
      relRender(d, C)
    })})
    .catch(function (e) { relSetStatus('Erreur : ' + (e && e.message ? e.message : e)) })
}

function _relKindLabel(kind) {
  if (!window.spidT) return kind
  var out = spidT('relations.kind.' + kind)
  return out === 'relations.kind.' + kind ? kind : out
}

function _relStatusLabel(status) {
  if (!window.spidT) return status
  var out = spidT('relations.status.' + status)
  return out === 'relations.status.' + status ? status : out
}

function relActive(r) {
  if (r.kind === 'cluster') {
    return r.cluster_status !== 'revoked' &&
      r.status !== 'revoked' && r.status !== 'removed' && r.status !== 'left'
  }
  return r.status !== 'revoked' && r.status !== 'left'
}

function relRender(d, C) {
  var rows = []
  ;(d.relations.vines || []).forEach(function (v) {
    rows.push({ kind: 'vine', id: v.id, name: v.name, status: v.status, role: v.role })
  })
  ;(d.relations.clusters || []).forEach(function (c) {
    rows.push({ kind: 'cluster', id: c.id, name: c.name, status: c.status,
                is_issuer: c.is_issuer, cluster_status: c.cluster_status })
  })
  ;(d.relations.vignards || []).forEach(function (g) {
    rows.push({ kind: 'vignard', id: g.id, name: g.name, status: g.status, role: g.role })
  })

  // "Mes liens" = active relations only. Revoked/deleted/left links are kept
  // in the audit/source data, but are not displayed as active links.
  var activeRows = rows.filter(relActive)

  var previousScope = relScope.value
  relScope.innerHTML = ''
  var placeholder = document.createElement('option')
  placeholder.value = ''
  placeholder.textContent = 'Les communautés disponibles'
  placeholder.disabled = true
  relScope.appendChild(placeholder)
  var scopes = activeRows.filter(function (r) {
    return r.status === 'approved' || r.status === 'admin' || r.is_issuer
  })
  scopes.forEach(function (r) {
    var o = document.createElement('option')
    o.value = r.kind + '|' + r.id
    o.textContent = (r.name || r.id) + ' · ' + _relKindLabel(r.kind)
    relScope.appendChild(o)
  })
  if (previousScope) relScope.value = previousScope
  if (!scopes.length) {
    placeholder.textContent = 'Aucune communauté disponible'
    placeholder.selected = true
  } else if (!relScope.value) {
    placeholder.selected = true
  }

  _relGrants = d.grants || []
  relRenderGrants()
  relLoadMembers()
}

function relGrantLabel(raw) {
  var types = null
  try { types = JSON.parse(raw) } catch (e) { types = null }
  if (!Array.isArray(types) || !types.length) return spidT('relations.minimal_did')
  var labels = {
    handle: spidT('relations.share_handle'),
    icons: spidT('relations.share_icons'),
    feedback: spidT('relations.share_feedback'),
    relations: spidT('relations.share_relations')
  }
  var names = types.map(function (t) {
    if (labels[t]) return labels[t]
    if (t.indexOf(':') !== -1) {
      var p = t.split(':')
      return p[0].charAt(0).toUpperCase() + p[0].slice(1) + ' · ' + p[1]
    }
    return t
  })
  if (types.length === 1 && types[0] === 'handle') return spidT('relations.minimal_did_handle')
  return spidT('relations.did_prefix') + names.join(' · ')
}

function relRenderGrants() {
  if (!relGrants) return
  var target = relMembers()
  relGrants.innerHTML = ''
  if (!target) { relNote(relGrants, spidT('relations.scope_required')); return }
  var gs = _relGrants.filter(function (g) {
    return g.consumer_type === target.type && g.consumer_id === target.id
  })
  if (!gs.length) { relNote(relGrants, spidT('relations.no_share')); return }
  gs.forEach(function (g) {
    var el = document.createElement('div'); el.className = 'bb-row'
    var left = document.createElement('div')
    var n = document.createElement('div'); n.className = 'bb-title'
    n.textContent = 'Partage de données'
    var m = document.createElement('div'); m.className = 'bb-note'
    m.textContent = relGrantLabel(g.types)
    left.appendChild(n); left.appendChild(m); el.appendChild(left)
    if (g.revoked_at) {
      var b = document.createElement('span'); b.className = 'bb-note'; b.textContent = 'révoqué'
      el.appendChild(b)
    } else {
      var btn = document.createElement('button'); btn.type = 'button'
      btn.className = 'btn btn-ghost'; btn.textContent = 'Retirer'
      btn.addEventListener('click', function () {
        relRevoke(g.consumer_type, g.consumer_id)
      })
      el.appendChild(btn)
    }
    relGrants.appendChild(el)
  })
}

function relMembers() {
  var sel = relScope && relScope.value
  if (!sel) return null
  var parts = sel.split('|')
  return { type: parts[0], id: parts.slice(1).join('|') }
}

function relLoadMembers() {
  var C = _relContract()
  var el = document.getElementById('relMembers')
  if (!C || !el) return
  if (!_unlockedVault) { relNote(el, 'Ouvrez votre passport.'); return }
  var target = relMembers()
  if (!target) { relNote(el, 'Choisis une portée.'); return }
  relNote(el, 'Chargement…')
  _relSelfCall('members', {}, target, SPID_BOOTSTRAP_HOST)
    .then(function (resp) { return resp.text().then(function (t) {
      var d = null; try { d = JSON.parse(t) } catch (e) { d = null }
      if (!resp.ok || !d || !Array.isArray(d.members)) {
        relNote(el, 'Indisponible : ' + ((d && (d.error || d.message)) || ('HTTP ' + resp.status)))
        return
      }
      relRenderMembers(el, target, d.members)
    })})
    .catch(function (e) { relNote(el, 'Erreur : ' + (e && e.message ? e.message : e)) })
}

function relRenderMembers(el, target, members) {
  el.innerHTML = ''
  if (!members.length) { relNote(el, 'Aucun membre.'); return }
  members.forEach(function (m) {
    var row = document.createElement('div'); row.className = 'bb-row'
    var left = document.createElement('div')
    var n = document.createElement('div'); n.className = 'bb-title'
    n.textContent = m.handle || 'Sans pseudo'
    var meta = document.createElement('div'); meta.className = 'bb-note'
    meta.textContent = _relStatusLabel(m.status) + (m.is_issuer ? ' · ' + spidT('relations.issuer') : '')
    left.appendChild(n); left.appendChild(meta); row.appendChild(left)

    var copy = document.createElement('button')
    copy.type = 'button'; copy.className = 'btn btn-ghost'
    copy.textContent = '⧉'
    copy.title = 'Copier la DID complète'
    copy.setAttribute('aria-label', 'Copier la DID complète')
    copy.addEventListener('click', function () {
      try {
        navigator.clipboard.writeText(m.did)
        relSetStatus('DID copiée ✓')
        setTimeout(function () { relSetStatus('') }, 1500)
      } catch (e) { relSetStatus('Copie impossible.') }
    })
    row.appendChild(copy)

    if (m.status === 'invited') {
      var approve = document.createElement('button'); approve.type = 'button'
      approve.className = 'btn btn-gold'; approve.textContent = 'Approuver'
      approve.addEventListener('click', function () { relDecide(target, m.did, m.status, 'approved') })
      var refuse = document.createElement('button'); refuse.type = 'button'
      refuse.className = 'btn btn-ghost'; refuse.textContent = 'Refuser'
      refuse.addEventListener('click', function () { relDecide(target, m.did, m.status, 'revoked') })
      row.appendChild(approve); row.appendChild(refuse)
    }
    el.appendChild(row)
  })
}

function relDecide(target, subject, previous, status) {
  var C = _relContract()
  if (!C) { relSetStatus('Contrat Relations indisponible.'); return }
  var actor = _holderDid()
  if (!actor) { relSetStatus('DID actrice inconnue.'); return }
  var issued = new Date().toISOString()
  var payload
  try {
    payload = C.canonicalDecisionPayload({
      scope: target, actor_did: actor, subject_did: subject,
      status: status, previous_status: previous, issued_at: issued, expires_at: null,
    })
  } catch (e) { relSetStatus('Décision invalide.'); return }
  relSetStatus('Signature…', true)
  importPrivateKey(_unlockedVault.keys.privateKey)
    .then(function (pk) { return edSign(pk, JSON.stringify(payload)) })
    .then(function (signature) {
      return _relSelfCall('decision', {
        decision: {
          subject_did: subject, status: status, previous_status: previous,
          issued_at: issued, expires_at: null, signature: signature,
        },
      }, target, SPID_BOOTSTRAP_HOST)
    })
    .then(function (resp) { return resp.text().then(function (t) {
      var d = null; try { d = JSON.parse(t) } catch (e) { d = null }
      relSetStatus('')
      if (!resp.ok || !d || !d.ok) {
        relSetStatus('Refusé : ' + ((d && (d.error || d.message)) || ('HTTP ' + resp.status)))
        return
      }
      relSetStatus('Décision appliquée ✓')
      relLoad()
    })})
    .catch(function (e) { relSetStatus('Erreur : ' + (e && e.message ? e.message : e)) })
}

function relInvite() {
  var C = _relContract()
  if (!C) { relSetStatus('Contrat Relations indisponible.'); return }
  var sel = relScope.value
  if (!sel) { relSetStatus('Choisis une portée.'); return }
  var parts = sel.split('|')
  var kind = parts[0], id = parts.slice(1).join('|')
  var target
  try { target = C.normalizeScope({ type: kind, id: id }) }
  catch (e) { relSetStatus('Portée invalide.'); return }
  var to = (relTo.value || '').trim()
  var handle = (relHandle.value || '').trim() || null
  if (!/^did:/.test(to)) {
    var opt = relScope.options[relScope.selectedIndex]
    var targetName = opt ? opt.textContent.replace(/ · (cluster|vine|vignard)$/, '') : null
    var payload = { scope: target, name: targetName, anchor: SPID_BOOTSTRAP_HOST,
                    requested: ['handle'], handle: handle }
    var b64 = btoa(unescape(encodeURIComponent(JSON.stringify(payload))))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    var link = 'https://sovereign-passport.github.io/passport/passport.html#invite=' + b64
    var wrap = document.getElementById('relLinkWrap')
    var input = document.getElementById('relLink')
    if (wrap && input) { input.value = link; wrap.style.display = 'block' }
    var email = document.getElementById('relEmail')
    if (email) {
      email.href = 'mailto:?subject=' + encodeURIComponent('Invitation SPID') +
        '&body=' + encodeURIComponent(link)
    }
    var sms = document.getElementById('relSms')
    if (sms) {
      sms.href = 'sms:?body=' + encodeURIComponent(link)
    }
    var qr = document.getElementById('relQr')
    if (qr) {
      qr.innerHTML = ''
      var img = document.createElement('img')
      img.alt = 'QR invitation'
      img.src = SPID_BOOTSTRAP_HOST + '/api/qr.svg?text=' + encodeURIComponent(link)
      qr.appendChild(img)
    }
    relSetStatus('Lien et QR prêts — envoie-les à l’invité.')
    return
  }
  var linkWrap = document.getElementById('relLinkWrap')
  if (linkWrap) linkWrap.style.display = 'none'
  relInviteBtn.disabled = true
  relSetStatus('Invitation…', true)
  _relSelfCall('invite',
    { to_did: to, handle: handle, requested: ['handle'] },
    target, SPID_BOOTSTRAP_HOST)
    .then(function (resp) { return resp.text().then(function (t) {
      var d = null; try { d = JSON.parse(t) } catch (e) { d = null }
      relInviteBtn.disabled = false
      relSetStatus('')
      if (!resp.ok || !d || !d.ok) {
        relSetStatus('Refusé : ' + ((d && (d.error || d.message)) || ('HTTP ' + resp.status)))
        return
      }
      relSetStatus('Invité ✓ (' + d.relation + ')')
      relLoad()
    })})
    .catch(function (e) {
      relInviteBtn.disabled = false
      relSetStatus('Erreur : ' + (e && e.message ? e.message : e))
    })
}

function relRevoke(kind, id) {
  var C = _relContract()
  if (!C) return
  var target
  try { target = C.normalizeScope({ type: kind, id: id }) }
  catch (e) { return }
  _relSelfCall('revoke', { scope: target }, _msScope(), SPID_BOOTSTRAP_HOST)
    .then(function () { relLoad() })
    .catch(function () {})
}

;(function relWire() {
  var r = document.getElementById('relRefreshBtn')
  if (r) r.addEventListener('click', function () { relLoad() })
  if (relInviteBtn) relInviteBtn.addEventListener('click', relInvite)
  if (relScope) relScope.addEventListener('change', function () {
    relRenderGrants()
    relLoadMembers()
  })
  var c = document.getElementById('relCopyBtn')
  if (c) c.addEventListener('click', function () {
    var link = document.getElementById('relLink')
    if (!link || !link.value) return
    try { navigator.clipboard.writeText(link.value); relSetStatus('Lien copié ✓') }
    catch (e) { link.select(); relSetStatus('Sélectionne et copie le lien.') }
  })
})()
