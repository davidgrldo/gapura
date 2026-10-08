// The server's lists, written once here; web/check.mjs fails the build when they drift from
// configuration.rs.
export const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'CONNECT', 'TRACE']
export const PATH_TYPES = ['prefix', 'exact', 'regex']
export const PATH_LABEL = { prefix: 'Prefix', exact: 'Exact', regex: 'Regex' }

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
