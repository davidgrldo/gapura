// The audit log's words. The kinds are audit.rs's KINDS, written once here in the same order;
// web/check.mjs fails the build when they drift. These label the kind filter. A row is worded by
// rowLabel() below, because `policy` is three things: the filter for it returns all of them.
export const KIND_LABEL = {
  user: 'Account',
  group_mapping: 'Group mapping',
  workspace: 'Workspace',
  service: 'Service',
  route: 'Route',
  consumer: 'Consumer',
  consumer_key: 'API key',
  policy: 'Policy',
  data_plane: 'Data plane',
  data_plane_token: 'Data plane token',
  setting: 'Setting',
}
export const KINDS = Object.keys(KIND_LABEL)

// What a policy entry is, by the `kind` its before and after bodies record: every policy but a
// key requirement records one. web/check.mjs fails the build when a kind the store writes has no
// label here, since it would read as a key requirement.
export const POLICY_LABEL = { jwt: 'JWT requirement', rate_limit: 'Request limit', ip_restriction: 'IP restriction', request_size_limit: 'Body size limit', request_transformer: 'Request transform', response_transformer: 'Response transform' }
const KEY_REQUIREMENT = 'Key requirement'

// What a row says it is: the kind's own word, except for a policy, which is worded by what it
// holds. `after` is read first, and `before` for a delete, which records no `after`.
export function rowLabel(entry) {
  if (entry.object_kind === 'policy') {
    return POLICY_LABEL[entry.after?.kind ?? entry.before?.kind] ?? KEY_REQUIREMENT
  }
  return KIND_LABEL[entry.object_kind] ?? entry.object_kind
}

export const ACTION_LABEL = { create: 'Created', update: 'Changed', delete: 'Deleted' }

// What `workspace=` sends for the entries with no workspace: audit.rs's NO_WORKSPACE.
export const NO_WORKSPACE = '-'

// The name a person reads for what an entry is about, from whichever side recorded one. Each
// kind records a different field (a service its `name`, a new account its `username`, a change
// to an account or to its direct grants the `account`, a key requirement its `target`, a consumer's
// own request limit its target and the consumer, a key its `prefix`, a mapping its `group`), so the
// first one there is used; an entry that recorded none shows its kind alone.
const NAMED_BY = ['name', 'username', 'account', 'target', 'prefix', 'group']
export function nameOf(entry) {
  for (const field of NAMED_BY) {
    const value = entry.after?.[field] ?? entry.before?.[field]
    if (value != null) {
      // A consumer's own request limit is named by where it sits and whose it is.
      const consumer = field === 'target' ? (entry.after?.consumer ?? entry.before?.consumer) : undefined
      return consumer == null ? String(value) : `${value} for ${consumer}`
    }
  }
  return undefined
}

function same(a, b) {
  if (a === b) return true
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false
  if (Array.isArray(a) !== Array.isArray(b)) return false
  const ak = Object.keys(a)
  if (ak.length !== Object.keys(b).length) return false
  return ak.every((k) => Object.hasOwn(b, k) && same(a[k], b[k]))
}

// The top-level keys whose values differ between before and after, in the order they first
// appear. Only an entry that recorded both sides has a change to name: a created or deleted
// object's every key would be listed, which says nothing the two blocks do not.
export function changedKeys(entry) {
  const { before, after } = entry
  const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
  if (!isObject(before) || !isObject(after)) return []
  const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])]
  return keys.filter((k) => !same(before[k], after[k]))
}
