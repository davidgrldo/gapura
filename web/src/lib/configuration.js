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
