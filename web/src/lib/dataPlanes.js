// How the Data planes page and its sheet word what GET /api/data-planes says of each one.

// A span of time in the largest whole unit that fits: "5 minutes", "3 hours", "2 days".
export function since(iso, now = Date.now()) {
  const minutes = Math.max(1, Math.floor((now - new Date(iso).getTime()) / 60_000))
  const [n, unit] =
    minutes < 60 ? [minutes, 'minute'] : minutes < 48 * 60 ? [Math.floor(minutes / 60), 'hour'] : [Math.floor(minutes / 1440), 'day']
  return `${n} ${unit}${n === 1 ? '' : 's'}`
}

// `connected` is a call within the last two minutes.
export const STATUS_TONE = { connected: 'ok', not_seen: 'warn', never: 'idle' }

export function status(plane, now = Date.now()) {
  if (plane.status === 'connected') return 'Connected'
  if (plane.status === 'not_seen') return plane.last_seen_at ? `Not seen for ${since(plane.last_seen_at, now)}` : 'Not seen'
  return 'Never connected'
}

// Whether it held the configuration served now when it last called. `stale` when that call was
// not lately, so a "Current" from yesterday is drawn muted and says when it was true; `null` for
// one that never called, which has nothing to say.
export function sync(plane) {
  if (plane.status === 'never') return null
  const words = plane.in_sync === true ? 'Current' : plane.in_sync === false ? 'Behind' : 'Unknown'
  const tone = plane.in_sync === true ? 'ok' : plane.in_sync === false ? 'warn' : 'idle'
  return { words, tone, stale: plane.status !== 'connected' }
}
