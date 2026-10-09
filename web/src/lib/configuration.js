// The server's lists, written once here; web/check.mjs fails the build when they drift from
// configuration.rs.
export const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'CONNECT', 'TRACE']
export const PATH_TYPES = ['prefix', 'exact', 'regex']
export const PATH_LABEL = { prefix: 'Prefix', exact: 'Exact', regex: 'Regex' }
// How many headers a route may match; the route sheet stops adding rows there.
export const MAX_HEADERS = 16
// A request limit's bounds and windows, as consumers.rs's MAX_RATE_LIMIT and Per; web/check.mjs
// fails the build when they drift. `PER_SHORT` is how a list's tag writes the window.
export const MAX_RATE_LIMIT = 1_000_000
export const PER = ['second', 'minute', 'hour']
export const PER_SHORT = { second: 's', minute: 'min', hour: 'h' }

export const upstream = (s) => `${s.protocol}://${s.host}:${s.port}`
export const ms = (value) => (value == null ? 'default' : `${value} ms`)
export const anyOf = (list) => (list.length === 0 ? 'any' : list.join(', '))
export const base = (workspace, kind) =>
  `/api/workspaces/${encodeURIComponent(workspace)}/${kind}`
// A time the server gave, in the reader's own locale and zone with the zone named, as the Users
// page shows a sign-in: two admins in different zones then quote the same key's expiry
// differently, with something on screen to say why.
const WHEN = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: 'numeric',
  minute: '2-digit',
  timeZoneName: 'short',
})
export const when = (iso) => WHEN.format(new Date(iso))

// What a delete refused for attached policies adds: the row's own policies, which the controls
// above the footer switch off. `kind` is `service` or `route`, the `from` a row's own carries.
// Empty when none of these is the row's own: the policy is of another kind, written by hand.
const OWN_POLICIES = [
  ['key_auth', 'API key requirement'],
  ['jwt', 'JWT requirement'],
  ['rate_limit', 'request limit'],
]
const HOW_MANY = ['', 'one', 'two', 'three']
export function ownPolicies(row, kind) {
  const names = OWN_POLICIES.filter(([field]) => row?.[field]?.from === kind).map(([, name]) => `the ${name}`)
  if (names.length === 0) return ''
  const listed = names.length === 1 ? names[0] : `${names.slice(0, -1).join(', ')} and ${names.at(-1)}`
  const subject = `T${listed.slice(1)} above`
  return names.length === 1
    ? `${subject} counts as one: switch it off there.`
    : `${subject} count as ${HOW_MANY[names.length]}: switch them off there.`
}
