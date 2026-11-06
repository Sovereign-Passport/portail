/**
 * SPID — shared relations contract (browser + Node, pure)
 *
 * Single source for Portail, Passport and spid-js. No DOM, no DB, no crypto
 * implementation: only scope/action/status/payload rules.
 *
 * Version is part of the contract. Client and server must refuse a mismatch.
 */

export const RELATIONS_CONTRACT_VERSION = '1.1.0'

export const RELATION_SCOPES  = Object.freeze(['did', 'cluster', 'vine', 'vignard'])
export const RELATION_TARGET_SCOPES = Object.freeze(['cluster', 'vine', 'vignard'])
export const RELATION_ACTIONS = Object.freeze(['list', 'members', 'invite', 'accept', 'decision', 'revoke', 'share'])
export const SELF_SCOPED_ACTIONS = Object.freeze(['list', 'accept', 'revoke', 'share'])
export const RELATION_MIN_LEVEL = 'grape'

/**
 * Canonical sharing capabilities. A grant is an explicit list of these
 * strings. Read and write are deliberately separate: a relationship that
 * permits reading does not implicitly permit writing.
 *
 * Legacy profile capabilities (handle/icons/feedback/relations) stay valid so
 * existing grants keep working while new grants use the same table.
 */
export const SHARE_TYPES = Object.freeze([
  'handle',
  'icons',
  'feedback',
  'relations',
  'data:read',
  'data:write',
])

export const SHARE_MAX_FUTURE_MS = 5 * 60 * 1000

export function normalizeShareTypes(value) {
  if (value == null) return []
  if (!Array.isArray(value)) throw new Error('SHARE_TYPES_REQUIRED')
  if (value.length > 50) throw new Error('TOO_MANY_SHARE_TYPES')
  const out = []
  for (const raw of value) {
    if (typeof raw !== 'string' || !raw) throw new Error('BAD_SHARE_TYPE')
    if (!SHARE_TYPES.includes(raw)) throw new Error('BAD_SHARE_TYPE')
    if (!out.includes(raw)) out.push(raw)
  }
  return out.sort()
}

/** True when accepted is a subset of requested (both canonicalised). */
export function isShareSubset(accepted, requested) {
  const a = normalizeShareTypes(accepted)
  const r = normalizeShareTypes(requested)
  return a.every((t) => r.includes(t))
}

/**
 * The exact payload signed by the holder for a sharing grant.
 * `signature` is never part of the payload.
 */
export function canonicalShareGrantPayload(g) {
  if (!g || typeof g !== 'object') throw new Error('SHARE_GRANT_REQUIRED')
  if (typeof g.holder_did !== 'string' || !g.holder_did.startsWith('did:')) {
    throw new Error('HOLDER_DID_REQUIRED')
  }
  const scope = normalizeScope(g.scope)
  if (!RELATION_TARGET_SCOPES.includes(scope.type)) throw new Error('BAD_SHARE_SCOPE')
  const types = normalizeShareTypes(g.types)
  if (!types.length) throw new Error('SHARE_TYPES_REQUIRED')
  if (typeof g.issued_at !== 'string') throw new Error('BAD_ISSUED_AT')
  const payload = {
    type:       'ShareGrant',
    holder_did: g.holder_did,
    scope:      { type: scope.type, id: scope.id },
    types:      types,
    issued_at:  g.issued_at,
  }
  if (g.expires_at != null) payload.expires_at = g.expires_at
  return payload
}

export function validateShareGrant(g, now = Date.now()) {
  const payload = canonicalShareGrantPayload(g)
  const issued = Date.parse(payload.issued_at)
  if (!Number.isFinite(issued)) throw new Error('BAD_ISSUED_AT')
  if (issued > now + SHARE_MAX_FUTURE_MS) throw new Error('ISSUED_IN_FUTURE')
  if (payload.expires_at != null) {
    const expires = Date.parse(payload.expires_at)
    if (!Number.isFinite(expires)) throw new Error('BAD_EXPIRES_AT')
    if (expires <= now) throw new Error('SHARE_EXPIRED')
  }
  return payload
}

/** The exact payload signed by the holder to revoke one scope's grant. */
export function canonicalShareRevocationPayload(r) {
  if (!r || typeof r !== 'object') throw new Error('SHARE_REVOCATION_REQUIRED')
  if (typeof r.holder_did !== 'string' || !r.holder_did.startsWith('did:')) {
    throw new Error('HOLDER_DID_REQUIRED')
  }
  const scope = normalizeScope(r.scope)
  if (!RELATION_TARGET_SCOPES.includes(scope.type)) throw new Error('BAD_SHARE_SCOPE')
  if (typeof r.issued_at !== 'string') throw new Error('BAD_ISSUED_AT')
  return {
    type:       'ShareRevocation',
    holder_did: r.holder_did,
    scope:      { type: scope.type, id: scope.id },
    issued_at:  r.issued_at,
  }
}

export function validateShareRevocation(r, now = Date.now()) {
  const payload = canonicalShareRevocationPayload(r)
  const issued = Date.parse(payload.issued_at)
  if (!Number.isFinite(issued)) throw new Error('BAD_ISSUED_AT')
  if (issued > now + SHARE_MAX_FUTURE_MS) throw new Error('ISSUED_IN_FUTURE')
  return payload
}

export const ACCEPT_STATUS = Object.freeze({
  cluster: 'invited',
  vine:    'invited',
  vignard: 'invited',
})

export const DECISION_SCOPES = RELATION_TARGET_SCOPES

export const DECISION_STATUSES = Object.freeze({
  cluster: ['invited', 'approved', 'suspended', 'revoked', 'removed'],
  vine:    ['guest', 'invited', 'approved', 'admin', 'revoked', 'left'],
  vignard: ['guest', 'invited', 'approved', 'admin', 'revoked', 'left'],
})

export const DECISION_TRANSITIONS = Object.freeze({
  cluster: {
    invited:   ['approved', 'revoked', 'removed'],
    candidate: ['approved', 'suspended', 'revoked', 'removed'],
    temporary: ['approved', 'suspended', 'revoked', 'removed'],
    approved:  ['suspended', 'revoked', 'removed'],
    suspended: ['approved', 'revoked', 'removed'],
    revoked:   [],
    removed:   [],
  },
  vine: {
    guest:    ['invited', 'revoked'],
    invited:  ['approved', 'revoked'],
    approved: ['admin', 'invited', 'revoked'],
    admin:    ['approved', 'invited', 'revoked'],
    revoked:  [],
    left:     ['invited', 'approved'],
  },
  vignard: {
    guest:    ['invited', 'revoked'],
    invited:  ['approved', 'revoked'],
    approved: ['admin', 'invited', 'revoked'],
    admin:    ['approved', 'invited', 'revoked'],
    revoked:  [],
    left:     ['invited', 'approved'],
  },
})

export const DECISION_MAX_FUTURE_MS = 5 * 60 * 1000

export function isRelationAction(action) {
  return RELATION_ACTIONS.includes(action)
}

export function isSelfScopedAction(action) {
  return SELF_SCOPED_ACTIONS.includes(action)
}

export function isDid(value) {
  return typeof value === 'string' && value.startsWith('did:')
}

export function normalizeScope(scope) {
  if (!scope || typeof scope !== 'object') throw new Error('SCOPE_REQUIRED')
  const type = typeof scope.type === 'string' ? scope.type.toLowerCase() : ''
  const id   = typeof scope.id === 'string' ? scope.id : ''
  if (!RELATION_SCOPES.includes(type)) throw new Error('BAD_SCOPE_TYPE')
  if (!id) throw new Error('SCOPE_ID_REQUIRED')
  return { type, id }
}

export function actorScopeFor(action, actorDid, targetScope) {
  if (!isRelationAction(action)) throw new Error('BAD_RELATION_ACTION')
  if (!isDid(actorDid)) throw new Error('ACTOR_DID_REQUIRED')
  if (isSelfScopedAction(action)) return { type: 'did', id: actorDid }
  return normalizeScope(targetScope)
}

export function requestScopes(action, actorDid, headerScope, bodyScope) {
  if (!isRelationAction(action)) throw new Error('BAD_RELATION_ACTION')
  if (!isDid(actorDid)) throw new Error('ACTOR_DID_REQUIRED')

  if (isSelfScopedAction(action)) {
    const h = headerScope || {}
    if (String(h.type || '').toLowerCase() !== 'did' || h.id !== actorDid) {
      throw new Error('ACTOR_SCOPE_REQUIRED')
    }
    let target = null
    if (bodyScope) target = normalizeScope(bodyScope)
    else if (action !== 'list') throw new Error('SCOPE_REQUIRED')
    return { actor: { type: 'did', id: actorDid }, target }
  }

  const target = normalizeScope(headerScope)
  if (!RELATION_TARGET_SCOPES.includes(target.type)) throw new Error('BAD_TARGET_SCOPE')
  if (bodyScope) {
    const body = normalizeScope(bodyScope)
    if (body.type !== target.type || body.id !== target.id) throw new Error('SCOPE_MISMATCH')
  }
  return { actor: target, target }
}

export function acceptStatusFor(scope) {
  const { type } = normalizeScope(scope)
  if (!RELATION_TARGET_SCOPES.includes(type)) throw new Error('BAD_ACCEPT_SCOPE')
  return ACCEPT_STATUS[type]
}

export function canTransition(scopeType, from, to) {
  const table = DECISION_TRANSITIONS[scopeType]
  if (!table) return false
  return (table[from] || []).includes(to)
}

export function canonicalDecisionPayload(d) {
  const payload = {
    action:          'relation_decision',
    scope:           { type: d.scope.type, id: d.scope.id },
    actor_did:       d.actor_did,
    subject_did:     d.subject_did,
    status:          d.status,
    previous_status: d.previous_status,
    issued_at:       d.issued_at,
  }
  if (d.expires_at) payload.expires_at = d.expires_at
  return payload
}

export function validateDecision(d, now = Date.now()) {
  if (!d || typeof d !== 'object') throw new Error('DECISION_REQUIRED')
  if (!d.scope || !DECISION_SCOPES.includes(d.scope.type)) throw new Error('BAD_DECISION_SCOPE')
  if (typeof d.scope.id !== 'string' || !d.scope.id) throw new Error('SCOPE_ID_REQUIRED')
  if (typeof d.actor_did !== 'string' || !d.actor_did.startsWith('did:')) throw new Error('ACTOR_DID_REQUIRED')
  if (typeof d.subject_did !== 'string' || !d.subject_did.startsWith('did:')) throw new Error('SUBJECT_DID_REQUIRED')
  if (d.subject_did === d.actor_did) throw new Error('CANNOT_DECIDE_SELF')
  const statuses = DECISION_STATUSES[d.scope.type]
  if (!statuses.includes(d.status)) throw new Error('BAD_DECISION_STATUS')
  if (!statuses.includes(d.previous_status)) throw new Error('BAD_PREVIOUS_STATUS')
  if (!canTransition(d.scope.type, d.previous_status, d.status)) throw new Error('INVALID_TRANSITION')

  const issued = Date.parse(d.issued_at)
  if (!Number.isFinite(issued)) throw new Error('BAD_ISSUED_AT')
  if (issued > now + DECISION_MAX_FUTURE_MS) throw new Error('ISSUED_IN_FUTURE')
  if (d.expires_at != null) {
    const expires = Date.parse(d.expires_at)
    if (!Number.isFinite(expires)) throw new Error('BAD_EXPIRES_AT')
    if (expires <= now) throw new Error('DECISION_EXPIRED')
  }
  return canonicalDecisionPayload(d)
}
