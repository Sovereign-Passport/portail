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
      updateBillboardComposer()
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
// SECTION 5 — BILLBOARD (Cluster selected from the unlocked Passport vault)
//
// Clusters come ONLY from canonical cluster_id (UUID) sources; Vines,
// Vignards and legacy memberships are ignored. The Switchboard host is the
// Cluster's own stored endpoint — never DEFAULT_HOST. Reading and creating
// both require the unlocked Passport (Ed25519 key in memory).
// ═════════════════════════════════════════════════════════════════════════

var bbClusterSelect  = document.getElementById('bbClusterSelect')
var bbClusterField   = document.getElementById('bbClusterField')
var bbNoCluster      = document.getElementById('bbNoCluster')
var bbRefreshBtn     = document.getElementById('bbRefreshBtn')
var bbNewBtn         = document.getElementById('bbNewBtn')
var bbCreateHint     = document.getElementById('bbCreateHint')
var bbStatus         = document.getElementById('bbStatus')
var bbList           = document.getElementById('bbList')
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

  function add(clusterId, name, endpoint, status, credentialId, allowNoEndpoint) {
    if (!clusterId || !UUID_RE.test(clusterId)) return        // canonical UUID only
    if (status === 'revoked' || status === 'removed') return
    var host = bbEndpointHost(endpoint)
    var cur = byId[clusterId]
    if (cur) {
      // Enrich an existing Cluster (name / credential / endpoint).
      if (!cur.name && name) cur.name = name
      if (!cur.credential_id && credentialId) cur.credential_id = credentialId
      if (!cur.endpoint && host) cur.endpoint = host
      return
    }
    if (!host && !allowNoEndpoint) return                     // joined Cluster without endpoint → ignore
    byId[clusterId] = {
      cluster_id: clusterId, name: name || null, endpoint: host || null,
      status: status || 'unknown', credential_id: credentialId || null,
    }
  }

  ;(vault.ownClusters || []).forEach(function(c) {
    add(c.id, c.name || c.cluster_name, c.vine_endpoint, c.status || 'active', null, true)
  })
  ;(vault.memberships || []).forEach(function(m) {
    add(m.cluster_id, m.node_name || m.cluster_name, m.vine_endpoint, m.status, null)
  })
  creds.forEach(function(c) {
    if (c.type === 'MembershipCredential' && c.scope === 'cluster') {
      add(c.cluster_id, c.cluster_name, c.vine_endpoint, c.status, c.id)
    }
  })

  var out = []
  Object.keys(byId).forEach(function(k) {
    var o = byId[k]
    var vineName = vineByHost[o.endpoint] || null
    var clusterName = o.name || o.cluster_id
    o.label = clusterName + ' — ' + (vineName || 'My Cluster')
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
  // URL preference is UI-only: select it ONLY if it is a real UUID present here.
  var want = (typeof preferredId === 'string' && UUID_RE.test(preferredId)) ? preferredId : null
  var hasWant = false
  for (var w = 0; w < _bbClusters.length; w++) {
    if (_bbClusters[w].cluster_id === want) { hasWant = true; break }
  }
  if (hasWant) { bbClusterSelect.value = want; return }
  var found = false
  for (var i = 0; i < _bbClusters.length; i++) {
    if (_bbClusters[i].cluster_id === keep) { found = true; break }
  }
  if (found) bbClusterSelect.value = keep
  else if (_bbClusters.length) bbClusterSelect.value = _bbClusters[0].cluster_id
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
    by.textContent = bbShortDid(p.author_did)
    meta.appendChild(by)
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

/** Read the selected Cluster: DID-signed proof + Switchboard cluster/list. */
function loadClusterBillboard() {
  var cluster = bbSelectedCluster()
  if (!_unlockedVault || !cluster) return Promise.resolve()

  if (!cluster.endpoint) {
    // No endpoint → no fetch at all, no creation, clear notice.
    bbNewBtn.style.display = 'none'
    bbHideForm()
    bbConfirm.style.display = 'none'
    bbRenderDisconnected()
    return Promise.resolve()
  }

  bbNewBtn.style.display = 'inline-block'
  bbHideStatus()
  bbList.innerHTML = ''
  var loading = document.createElement('p')
  loading.className = 'bb-empty'
  loading.textContent = 'Loading…'
  bbList.appendChild(loading)

  var did = _unlockedVault.identity.id
  var timestamp = Date.now()
  var proof = { action: 'billboard_cluster_list', did: did, cluster_id: cluster.cluster_id, timestamp: timestamp }

  return importPrivateKey(_unlockedVault.keys.privateKey)
    .then(function(privateKey) { return edSign(privateKey, JSON.stringify(proof)) })
    .then(function(signature) {
      return bbSwitch(cluster.endpoint, {
        service: 'billboard', action: 'cluster/list',
        data: { did: did, cluster_id: cluster.cluster_id, timestamp: timestamp, signature: signature },
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
      if (!r.ok || !r.data || !Array.isArray(r.data.posts)) {
        var msg = (r.data && (r.data.message || r.data.error)) || ('HTTP ' + r.status)
        throw new Error(msg)
      }
      renderBillboardPosts(r.data.posts)
    })
    .catch(function(e) {
      bbList.innerHTML = ''
      var err = document.createElement('p')
      err.className = 'bb-empty'
      err.textContent = 'Could not load announcements: ' + e.message
      bbList.appendChild(err)
      var retry = document.createElement('button')
      retry.type = 'button'
      retry.className = 'btn btn-ghost'
      retry.textContent = 'Retry'
      retry.addEventListener('click', loadClusterBillboard)
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
    return
  }
  bbNoCluster.style.display = 'none'
  bbCreateHint.style.display = 'none'
  loadClusterBillboard()   // sets New post per the selected Cluster's endpoint
}

bbRefreshBtn.addEventListener('click', loadClusterBillboard)
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

  if (target === 'billboard') {
    updateBillboardComposer()
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
