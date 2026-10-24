/**
 * SPID — shared relations contract (browser + Node, pure)
 *
 * Single source for Portail, Passport and spid-js. No DOM, no DB, no crypto
 * implementation: only scope/action/status/payload rules.
 *
 * Version is part of the contract. Client and server must refuse a mismatch.
 */

export const RELATIONS_CONTRACT_VERSION = '1.0.0'

export const RELATION_SCOPES  = Object.freeze(['did', 'cluster', 'vine', 'vignard'])
export const RELATION_TARGET_SCOPES = Object.freeze(['cluster', 'vine', 'vignard'])
export const RELATION_ACTIONS = Object.freeze(['list', 'invite', 'accept', 'decision', 'revoke'])
export const SELF_SCOPED_ACTIONS = Object.freeze(['list', 'accept', 'revoke'])
export const RELATION_MIN_LEVEL = 'grape'

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
