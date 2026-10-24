/**
 * SPID — shared feedback contract (browser + Node, pure)
 *
 * Feedback is a communicated, DID-signed experience report. It is NOT a
 * credential, NOT a global score, and NEVER changes permissions or status.
 *
 * Green / yellow / red = positive / neutral / negative.
 * Private personal markers are a different thing and are not handled here.
 */

export const FEEDBACK_CONTRACT_VERSION = '1.0.1'

export const FEEDBACK_VALUES = Object.freeze(['positive', 'neutral', 'negative'])
export const FEEDBACK_ACTIONS = Object.freeze(['submit', 'mine', 'retract', 'summary'])
export const FEEDBACK_SUBJECTS = Object.freeze(['did', 'cluster', 'vine'])

/** A suspended member may still report an experience. */
export const FEEDBACK_ALLOWED_STATUSES = Object.freeze(['approved', 'admin', 'suspended'])

export const FEEDBACK_MAX_FUTURE_MS = 5 * 60 * 1000

export function isFeedbackValue(value) {
  return FEEDBACK_VALUES.includes(value)
}

export function canGiveFeedback(status) {
  return FEEDBACK_ALLOWED_STATUSES.includes(status)
}

export function normalizeFeedbackSubject(subject) {
  if (!subject || typeof subject !== 'object') throw new Error('SUBJECT_REQUIRED')
  const type = typeof subject.type === 'string' ? subject.type.toLowerCase() : ''
  const id   = typeof subject.id === 'string' ? subject.id : ''
  if (!FEEDBACK_SUBJECTS.includes(type)) throw new Error('BAD_FEEDBACK_SUBJECT')
  if (!id) throw new Error('SUBJECT_ID_REQUIRED')
  return { type, id }
}

/** Exact payload signed by the author. `signature` is never part of it. */
export function canonicalFeedbackPayload(f) {
  const payload = {
    action:    'relation_feedback',
    subject:   { type: f.subject.type, id: f.subject.id },
    author_did: f.author_did,
    value:     f.value,
    issued_at: f.issued_at,
  }
  if (f.expires_at) payload.expires_at = f.expires_at
  return payload
}

export function validateFeedback(f, now = Date.now()) {
  if (!f || typeof f !== 'object') throw new Error('FEEDBACK_REQUIRED')
  const subject = normalizeFeedbackSubject(f.subject)
  if (typeof f.author_did !== 'string' || !f.author_did.startsWith('did:')) {
    throw new Error('AUTHOR_DID_REQUIRED')
  }
  if (subject.type === 'did' && subject.id === f.author_did) {
    throw new Error('CANNOT_FEEDBACK_SELF')
  }
  if (!isFeedbackValue(f.value)) throw new Error('BAD_FEEDBACK_VALUE')
  const issued = Date.parse(f.issued_at)
  if (!Number.isFinite(issued)) throw new Error('BAD_ISSUED_AT')
  if (issued > now + FEEDBACK_MAX_FUTURE_MS) throw new Error('ISSUED_IN_FUTURE')
  if (f.expires_at != null) {
    const expires = Date.parse(f.expires_at)
    if (!Number.isFinite(expires)) throw new Error('BAD_EXPIRES_AT')
    if (expires <= now) throw new Error('FEEDBACK_EXPIRED')
  }
  return canonicalFeedbackPayload(f)
}

/**
 * Local, descriptive synthesis. The denominator is ALWAYS respondents, never
 * the member count. `eligible` is carried separately when known and is never
 * used to compute a percentage.
 */
export function summarizeFeedback(events, now = Date.now(), eligible = null) {
  const latest = new Map()
  for (const e of Array.isArray(events) ? events : []) {
    if (!e || typeof e.author_did !== 'string') continue
    if (e.revoked_at) continue
    if (e.expires_at && Date.parse(e.expires_at) <= now) continue
    const at = Date.parse(e.issued_at)
    if (!Number.isFinite(at)) continue
    const prev = latest.get(e.author_did)
    if (!prev || at > Date.parse(prev.issued_at)) latest.set(e.author_did, e)
  }

  const counts = { positive: 0, neutral: 0, negative: 0 }
  for (const e of latest.values()) {
    if (isFeedbackValue(e.value)) counts[e.value] += 1
  }
  const respondents = latest.size
  const pct = n => respondents ? Math.round((n / respondents) * 100) : null

  return {
    respondents,
    eligible: Number.isInteger(eligible) ? eligible : null,
    counts,
    percentages: {
      positive: pct(counts.positive),
      neutral:  pct(counts.neutral),
      negative: pct(counts.negative),
    },
    // Deliberately explicit: this label never says "members".
    label: respondents
      ? `${pct(counts.positive)} % des répondants (n=${respondents})`
      : 'Aucun répondant',
  }
}
