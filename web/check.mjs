// Not a test framework: one script that fails if the console cannot render the API's
// answers. It exists because the Rust tests prove the API and nothing proves the page.
import { readdirSync, readFileSync } from 'node:fs'
import { ACCOUNT_STATUS, STATES, TONES } from './src/lib/states.js'
import { ABILITIES, MATRIX, ROLE_LABEL, ROLES } from './src/lib/roles.js'

const html = readFileSync('dist/index.html', 'utf8')
if (!html.includes('<div id="app"')) throw new Error('dist/index.html lost its mount point')
if (!/assets\/.*\.js/.test(html)) throw new Error('dist/index.html references no bundle')

// The badge map is the one place this console makes a judgement of its own instead of
// relaying the server's words, and two of the decisions recorded in src/lib/states.js are
// load-bearing enough to be worth a check. The two assertions above cannot see either of
// them: they would pass happily against a bundle that throws the moment it mounts.

// Which states exist is the server's to say, so they are read from the server rather than
// written down a second time here. A state added to the Rust enum and forgotten in the badge
// map has to fail in this file, and it can only do that if the list comes from rows.rs.
const ROWS = '../crates/gapura-control/src/rows.rs'

function statesTheServerCanReport() {
  const source = readFileSync(ROWS, 'utf8')
  const declaration = source.match(
    /#\[serde\(rename_all = "snake_case"\)\]\s*pub enum State \{([\s\S]*?)\n\}/,
  )
  // Loud failure rather than an empty list. A parser that quietly matched nothing would turn
  // every assertion below into a tautology, and a check that cannot fail is worse than no
  // check at all because it is still believed.
  if (!declaration) {
    throw new Error(`${ROWS}: no snake_case-serialised "pub enum State" to read the states from`)
  }
  const variants = [...declaration[1].matchAll(/^ {4}([A-Z][A-Za-z0-9]*),$/gm)].map((m) => m[1])
  if (variants.length === 0) {
    throw new Error(`${ROWS}: found "pub enum State" but could not read any variants out of it`)
  }
  // What `rename_all = "snake_case"` does to each variant name, which is what reaches the
  // page as a string. Every variant today is one word, but spelling the rule out means a
  // future `NotServed` is compared against `not_served` and not against nonsense.
  return variants.map((name) => name.replace(/(?<!^)[A-Z]/g, (c) => `_${c}`).toLowerCase())
}

const reportable = statesTheServerCanReport()

for (const state of reportable) {
  if (!Object.hasOwn(STATES, state)) {
    throw new Error(`the badge map has no entry for "${state}", which ${ROWS} can report`)
  }
}
for (const state of Object.keys(STATES)) {
  if (!reportable.includes(state)) {
    throw new Error(`the badge map has an entry for "${state}", which ${ROWS} cannot report`)
  }
}
for (const [state, { tone }] of Object.entries(STATES)) {
  if (!Object.hasOwn(TONES, tone)) {
    throw new Error(`"${state}" is toned "${tone}", which TONES in src/lib/states.js has no colours for`)
  }
}

// `unresolved` is a route the gateway installed and is answering every request to with an
// error. `refused` and `missing` are the other two ways traffic is not being served
// correctly, and painting all three the same is the point of having tones at all. The
// decision only means anything while `pending` — a route nobody has reconciled yet, which may
// be perfectly fine — is painted differently: those two have the most similar names in the
// set and the most divergent severities, so they are the pair most likely to be quietly
// regrouped by someone tidying up who has not read why.
const NOT_SERVING_CORRECTLY = ['unresolved', 'refused', 'missing']
const BAD = STATES.unresolved.tone
for (const state of NOT_SERVING_CORRECTLY) {
  if (STATES[state].tone !== BAD) {
    throw new Error(
      `"${state}" is toned "${STATES[state].tone}", but ${NOT_SERVING_CORRECTLY.join(', ')} ` +
        `are all states where traffic is not being served correctly and must share one tone`,
    )
  }
}
if (STATES.pending.tone === BAD) {
  throw new Error(
    `"pending" is toned "${BAD}", the tone that means traffic is not being served correctly ` +
      `— but nobody has ruled on a pending route yet, which is not a fault`,
  )
}

// A label that is only the wire word title-cased has told the reader nothing they did not
// already have, and for one state it does active harm: `unresolved` is the very word that
// caused the confusion this map exists to undo, so "Unresolved" is the one label it must
// never carry. `refused` is exempt, and is the only exemption: there the wire word is also
// the plain English for what happened, and "Refused" is the right thing to put on screen.
const ECHOING_THE_WIRE_WORD_IS_FINE = new Set(['refused'])
for (const [state, { label }] of Object.entries(STATES)) {
  if (ECHOING_THE_WIRE_WORD_IS_FINE.has(state)) continue
  if (label === state[0].toUpperCase() + state.slice(1)) {
    throw new Error(`"${state}" is labelled "${label}", which only repeats the state's own word`)
  }
}

// The account statuses on the Users screen, read from the server for the same reason as the
// states: a status added to `Status` and forgotten in ACCOUNT_STATUS has to fail here rather
// than reach a reader as a bare wire word.
const ACCESS_API = '../crates/gapura-control/src/access_api.rs'
const statusDeclaration = readFileSync(ACCESS_API, 'utf8').match(
  /#\[serde\(rename_all = "lowercase"\)\]\s*pub enum Status \{([\s\S]*?)\n\}/,
)
if (!statusDeclaration) {
  throw new Error(`${ACCESS_API}: no lowercase-serialised "pub enum Status" to read the statuses from`)
}
const statuses = [...statusDeclaration[1].matchAll(/^ {4}([A-Z][A-Za-z0-9]*),$/gm)].map((m) =>
  m[1].toLowerCase(),
)
if (statuses.length === 0) {
  throw new Error(`${ACCESS_API}: found "pub enum Status" but could not read any variants out of it`)
}
if ([...statuses].sort().join() !== Object.keys(ACCOUNT_STATUS).sort().join()) {
  throw new Error(
    `ACCOUNT_STATUS in src/lib/states.js words ${Object.keys(ACCOUNT_STATUS).join(', ')}, but ` +
      `${ACCESS_API} can report ${statuses.join(', ')}`,
  )
}
for (const [status, { tone }] of Object.entries(ACCOUNT_STATUS)) {
  if (!Object.hasOwn(TONES, tone)) {
    throw new Error(`account status "${status}" is toned "${tone}", which TONES has no colours for`)
  }
}

console.log(
  `ok: the build produced a document that mounts the app, and the badge maps cover the ` +
    `${reportable.length} states and ${statuses.length} account statuses the server can report`,
)

// #62: the explanation must reach the document. A `title` attribute is not in the document --
// it is not announced without configuration, has no touch or keyboard path, and everything
// else in this file would keep passing if the sentence quietly moved back into one. This
// reads the component source rather than the bundle because a minifier keeps attribute
// strings and element text indistinguishably, while the source cannot lie about which it is.
// The element is pinned to `sr-only` as well, because hiding the sentence from everyone takes
// one utility: `hidden` would still be element text, and would not be announced.
const stateComponent = readFileSync('src/lib/State.svelte', 'utf8')
if (!/<span class="sr-only">\s*:?\s*\{shown\.detail\}\s*<\/span>/.test(stateComponent)) {
  throw new Error('State.svelte must render shown.detail as sr-only element text, not an attribute or hidden text')
}
const routesScreen = readFileSync('src/routes/Routes.svelte', 'utf8')
if (!/STATES\[parent\.state\]\.detail|STATES\[parent\.state\]\?\.detail/.test(routesScreen)) {
  throw new Error('Routes.svelte must show the state sentence visibly in the expanded row')
}

// The console shows cluster state and may run in a cluster with no route to the internet, so
// it must not ask a third party for anything: no web font or icon CDN, no remote stylesheet,
// script or image. Fonts and icons are bundled, and this fails the build that starts fetching
// them instead. It reads everything the build emits, JavaScript included, because markup
// written in a component is compiled into the bundle: a font <link> in a <svelte:head> never
// reaches index.html. Only requests are matched, not every address: a link to a page (an
// <a href>) fetches nothing, and the bundle carries svelte.dev and w3.org strings in warnings
// and namespaces that are never requested.
const REMOTE =
  /(?:url\(\s*['"]?|<link\b[^>]*?\shref=\s*['"]?|\bsrc(?:set)?=\s*['"]?|@import\s*['"])((?:https?:)?\/\/[^'")\s>]+)/i
function built(extension) {
  const text = readdirSync('dist/assets')
    .filter((file) => file.endsWith(extension))
    .map((file) => readFileSync(`dist/assets/${file}`, 'utf8'))
    .join('\n')
  // Loud rather than empty, for the same reason as the enum parser above: with nothing to
  // read, this check would pass without having looked.
  if (!text) throw new Error(`dist/assets holds no ${extension} file for the third-party check to read`)
  return text
}
for (const [where, text] of [
  ['dist/index.html', html],
  ['the built CSS', built('.css')],
  ['the built JavaScript', built('.js')],
]) {
  const remote = text.match(REMOTE)
  if (remote) {
    throw new Error(
      `${where} asks a third party for ${remote[1]}, and the console may run where no third ` +
        `party can be reached`,
    )
  }
}
console.log('ok: the console asks no third party for anything it needs to render')

// The console's roles are the store's roles, read from the migrations for the reason the states
// are read from rows.rs above: a role added in Postgres and forgotten here has to fail in this
// file. Every migration is read, and one that alters role_name is refused outright rather than
// half understood, because this parser only reads the `create`. Both patterns accept the name
// schema-qualified or quoted, the other spellings Postgres takes, so neither can be stepped
// round by writing `public.role_name`.
const MIGRATIONS = '../crates/gapura-control/migrations'
const ROLE_NAME = String.raw`(?:\w+\.)?"?role_name"?`
const migrationFiles = readdirSync(MIGRATIONS)
  .filter((file) => file.endsWith('.sql'))
  .sort()
for (const file of migrationFiles) {
  const sql = readFileSync(`${MIGRATIONS}/${file}`, 'utf8')
  if (new RegExp(String.raw`alter\s+type\s+${ROLE_NAME}(?!\w)`, 'i').test(sql)) {
    throw new Error(`${MIGRATIONS}/${file} alters role_name, which this check cannot read yet`)
  }
}
const migrations = migrationFiles
  .map((file) => readFileSync(`${MIGRATIONS}/${file}`, 'utf8'))
  .join('\n')
const declaredRoles = migrations.match(
  new RegExp(String.raw`create\s+type\s+${ROLE_NAME}\s+as\s+enum\s*\(([^)]*)\)`, 'i'),
)
if (!declaredRoles) {
  throw new Error(`${MIGRATIONS}: no "create type role_name" to read the roles from`)
}
const storeRoles = [...declaredRoles[1].matchAll(/'([^']+)'/g)].map((m) => m[1])
if (storeRoles.join() !== ROLES.join()) {
  throw new Error(
    `web/src/lib/roles.js lists ${ROLES.join(', ')} but the store declares ` +
      `${storeRoles.join(', ')}; they must match, in the same rising order`,
  )
}
// What the screens draw from: a row of the matrix for each role and for superuser, in the
// same order, and a tick for every ability. `can` is matched to ABILITIES by position, so a
// row of the wrong length would shift every tick after the gap without a word.
const matrixKeys = MATRIX.map((row) => row.key)
if (matrixKeys.join() !== [...ROLES, 'superuser'].join()) {
  throw new Error(
    `web/src/lib/roles.js's MATRIX has rows ${matrixKeys.join(', ')}; it needs one per role, ` +
      `in order, then superuser`,
  )
}
for (const row of MATRIX) {
  if (row.can.length !== ABILITIES.length) {
    throw new Error(
      `web/src/lib/roles.js's ${row.key} row has ${row.can.length} ticks for ` +
        `${ABILITIES.length} abilities`,
    )
  }
}
for (const role of ROLES) {
  if (!ROLE_LABEL[role]) {
    throw new Error(`web/src/lib/roles.js has no label for the role ${role}`)
  }
}
console.log(`ok: the console knows the ${storeRoles.length} roles the store declares`)
