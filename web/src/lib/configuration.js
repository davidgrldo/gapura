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
// What a request limit can count by, as consumers.rs's limit_by reads it: the client address, the
// consumer an API key names, or one header's value. web/check.mjs fails the build when the server
// reads another. `BY_LABEL` is how the Count per select words each.
export const BY = ['ip', 'consumer', 'header']
export const BY_LABEL = { ip: 'client address', consumer: 'consumer', header: 'header' }
// A limit's `by` as the lists give it (absent for the address, `consumer`, or `header:<name>`)
// taken apart into what the form shows: the mode, and the header's name when it is one.
export function byParts(by) {
  if (by === 'consumer') return { mode: 'consumer', header: '' }
  if (typeof by === 'string' && by.startsWith('header:')) return { mode: 'header', header: by.slice(7) }
  return { mode: 'ip', header: '' }
}
// The form's mode and header put back together as the server reads `by`. The header's name is
// lowercased, as the server stores it, so a name typed in capitals is not "changed" from the
// stored lowercase one, which is how KeyAuthControl compares its header too.
export const byText = (mode, header) => (mode === 'header' ? `header:${header.trim().toLowerCase()}` : mode)
// How a list or a read-only line says what a limit counts by.
export function countedBy(by) {
  const { mode, header } = byParts(by)
  if (mode === 'consumer') return 'per consumer'
  if (mode === 'header') return `per value of the ${header} header`
  return 'per client address'
}
// An IP restriction's bound, as policies.rs's MAX_NETWORKS: addresses and networks, allow and
// deny together. web/check.mjs fails the build when it drifts.
export const MAX_NETWORKS = 1000
// Names as a sentence lists them: "a", "a and b", "a, b and c".
export const listed = (names) =>
  names.length < 2 ? names.join('') : `${names.slice(0, -1).join(', ')} and ${names.at(-1)}`
// What a limit's target is called where it is not obvious from the screen, as a consumer's sheet
// heads each of its own limits.
export function targetWords(target, workspace) {
  if (target === 'workspace') return `Everywhere in ${workspace}`
  const [kind, name] = [target.slice(0, target.indexOf(':')), target.slice(target.indexOf(':') + 1)]
  return `On the ${kind} ${name}`
}

export const upstream = (s) => `${s.protocol}://${s.host}:${s.port}`
export const ms = (value) => (value == null ? 'default' : `${value} ms`)
export const anyOf = (list) => (list.length === 0 ? 'any' : list.join(', '))
export const base = (workspace, kind) =>
  `/api/workspaces/${encodeURIComponent(workspace)}/${kind}`
// A policy kept through `/policies/{kind}`: one endpoint for each kind whose configuration is the
// policy itself.
export const policyBase = (workspace, kind) => base(workspace, `policies/${kind}`)
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
  [(row) => row?.key_auth, 'API key requirement'],
  [(row) => row?.jwt, 'JWT requirement'],
  [(row) => row?.rate_limit, 'request limit'],
  // Kept in the row's `policies` map, as every kind written through `/policies/{kind}` is.
  [(row) => row?.policies?.ip_restriction, 'IP restriction'],
]
const HOW_MANY = ['', 'one', 'two', 'three', 'four']
export function ownPolicies(row, kind) {
  const names = OWN_POLICIES.filter(([of]) => of(row)?.from === kind).map(([, name]) => `the ${name}`)
  if (names.length === 0) return ''
  const joined = listed(names)
  const subject = `T${joined.slice(1)} above`
  return names.length === 1
    ? `${subject} counts as one: switch it off there.`
    : `${subject} count as ${HOW_MANY[names.length]}: switch them off there.`
}
