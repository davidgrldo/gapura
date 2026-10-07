// Which workspace the configuration pages show, remembered per browser. Storage can be blocked,
// so every access is in a try, and a reader without it gets their first workspace each time.
const KEY = 'gapura.workspace'

export function remembered(roles) {
  let name
  try {
    name = window.localStorage.getItem(KEY)
  } catch {
    name = null
  }
  return roles.find((r) => r.workspace === name)?.workspace ?? roles[0]?.workspace
}

export function remember(name) {
  try {
    window.localStorage.setItem(KEY, name)
  } catch {
    // Nothing: the page still shows the choice; it is only not remembered.
  }
}

// What a role allows on these pages, ADR 5's matrix. The server decides; this only avoids
// offering a button it would refuse.
export const can = {
  write: (role) => role === 'editor' || role === 'admin',
  delete: (role) => role === 'admin',
}
