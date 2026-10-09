// The audit log's words. The kinds are audit.rs's KINDS, written once here in the same order;
// web/check.mjs fails the build when they drift.
export const KIND_LABEL = {
  user: 'Account',
  group_mapping: 'Group mapping',
  workspace: 'Workspace',
  service: 'Service',
  route: 'Route',
  consumer: 'Consumer',
  consumer_key: 'API key',
  policy: 'Key requirement',
  data_plane: 'Data plane',
  data_plane_token: 'Data plane token',
  setting: 'Setting',
}
export const KINDS = Object.keys(KIND_LABEL)

export const ACTION_LABEL = { create: 'Created', update: 'Changed', delete: 'Deleted' }

// What `workspace=` sends for the entries with no workspace: audit.rs's NO_WORKSPACE.
export const NO_WORKSPACE = '-'

// The name a person reads for what an entry is about, from whichever side recorded one. Each
// kind records a different field (a service its `name`, an account its `username`, a key
// requirement its `target`, a key its `prefix`, a mapping its `group`), so the first one there
// is used; an entry that recorded none, such as an account's password reset, shows its kind
// alone.
const NAMED_BY = ['name', 'username', 'target', 'prefix', 'group']
export function nameOf(entry) {
  for (const field of NAMED_BY) {
    const value = entry.after?.[field] ?? entry.before?.[field]
    if (value != null) return String(value)
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
