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

// The methods and path types the route form offers are configuration.rs's, read from it for the
// reason the roles are read from the migrations: one added on the server and forgotten here has
// to fail the build, not reach a reader as a choice the server refuses.
const CONFIGURATION = '../crates/gapura-control/src/configuration.rs'
const configurationSource = readFileSync(CONFIGURATION, 'utf8')
function serverList(name) {
  const found = configurationSource.match(new RegExp(`pub const ${name}: \\[&str; \\d+\\] = \\[([^\\]]*)\\]`))
  if (!found) throw new Error(`${CONFIGURATION} has no ${name}`)
  const items = [...found[1].matchAll(/"([^"]+)"/g)].map((m) => m[1])
  // Loud rather than empty, as with the enum parsers above: an empty list on both sides would
  // compare equal and the check would pass without having looked.
  if (items.length === 0) throw new Error(`${CONFIGURATION}: ${name} is declared but nothing could be read from it`)
  return items
}
const { METHODS, PATH_TYPES } = await import('./src/lib/configuration.js')
for (const [name, ours] of [['METHODS', METHODS], ['PATH_TYPES', PATH_TYPES]]) {
  const theirs = serverList(name)
  if (JSON.stringify(theirs) !== JSON.stringify(ours)) {
    throw new Error(`${name} in src/lib/configuration.js is ${ours}, the server's is ${theirs}`)
  }
}
const { MAX_HEADERS } = await import('./src/lib/configuration.js')
const maxHeaders = configurationSource.match(/pub const MAX_HEADERS: usize = (\d+);/)
if (!maxHeaders) throw new Error(`${CONFIGURATION} has no MAX_HEADERS`)
if (Number(maxHeaders[1]) !== MAX_HEADERS) {
  throw new Error(`MAX_HEADERS in src/lib/configuration.js is ${MAX_HEADERS}, the server's is ${maxHeaders[1]}`)
}
console.log('ok: the route form offers the methods, path types and header count the server accepts')

// The request-limit control's bounds and windows are consumers.rs's, read from it for the same
// reason: a window the server adds and this console does not offer could not be chosen, and one
// this console offers that the server does not know is refused.
const CONSUMERS = '../crates/gapura-control/src/consumers.rs'
const consumersSource = readFileSync(CONSUMERS, 'utf8')
const { MAX_RATE_LIMIT, PER, PER_SHORT } = await import('./src/lib/configuration.js')
const maxRateLimit = consumersSource.match(/pub const MAX_RATE_LIMIT: u32 = ([\d_]+);/)
if (!maxRateLimit) throw new Error(`${CONSUMERS} has no MAX_RATE_LIMIT`)
if (Number(maxRateLimit[1].replaceAll('_', '')) !== MAX_RATE_LIMIT) {
  throw new Error(`MAX_RATE_LIMIT in src/lib/configuration.js is ${MAX_RATE_LIMIT}, the server's is ${maxRateLimit[1]}`)
}
const perDeclaration = consumersSource.match(/#\[serde\(rename_all = "lowercase"\)\]\s*pub enum Per \{([\s\S]*?)\n\}/)
if (!perDeclaration) throw new Error(`${CONSUMERS}: no lowercase-serialised "pub enum Per" to read the windows from`)
const serverPer = [...perDeclaration[1].matchAll(/^ {4}([A-Z][A-Za-z0-9]*),$/gm)].map((m) => m[1].toLowerCase())
if (serverPer.length === 0) throw new Error(`${CONSUMERS}: found "pub enum Per" but could not read any variants out of it`)
if (JSON.stringify(serverPer) !== JSON.stringify(PER)) {
  throw new Error(`PER in src/lib/configuration.js is ${PER}, the server's windows are ${serverPer}`)
}
for (const per of PER) {
  if (!PER_SHORT[per]) throw new Error(`PER_SHORT in src/lib/configuration.js has no tag for ${per}`)
}
// What a limit can count by is consumers.rs's limit_by, read from it for the same reason: a way
// the server adds and this console does not offer could not be chosen, and one this console
// offers that the server does not read is refused. Its literal arms are the plain ways, and its
// `header:` prefix is the header one. A prefix of any other form is one this reader does not
// understand, so it fails the build rather than pass without being offered.
const limitBy = consumersSource.match(/fn limit_by\([\s\S]*?\n\}/)
if (!limitBy) throw new Error(`${CONSUMERS} has no fn limit_by`)
const serverBy = [...limitBy[0].matchAll(/^\s*"([a-z_-]+)" =>/gm)].map((m) => m[1])
for (const [, prefix] of limitBy[0].matchAll(/strip_prefix\("([^"]*)"/g)) {
  if (prefix !== 'header:') {
    throw new Error(`${CONSUMERS}: limit_by reads a "${prefix}" prefix, which this check cannot read yet`)
  }
}
if (/strip_prefix\("header:"\)/.test(limitBy[0])) serverBy.push('header')
if (serverBy.length === 0) throw new Error(`${CONSUMERS}: found fn limit_by but could not read any way out of it`)
const { BY, BY_LABEL } = await import('./src/lib/configuration.js')
if (JSON.stringify(serverBy) !== JSON.stringify(BY)) {
  throw new Error(`BY in src/lib/configuration.js is ${BY}, the server's limit_by reads ${serverBy}`)
}
for (const mode of BY) {
  if (!BY_LABEL[mode]) throw new Error(`BY_LABEL in src/lib/configuration.js has no label for ${mode}`)
}
console.log('ok: the request-limit control offers the bounds, windows and counts the server accepts')

// The sheets offer a Reload button when a 409's sentence contains "Reload" (that is how they
// tell a stale save from any other conflict), so the server's stale-edit sentence has to keep
// the word. Reworded without it, the button would silently stop appearing.
const STORE_CONFIGURATION = '../crates/gapura-control/src/store/configuration.rs'
const stale = readFileSync(STORE_CONFIGURATION, 'utf8').match(/const STALE: &str =\s*"([^"]*)"/)
if (!stale) throw new Error(`${STORE_CONFIGURATION} has no STALE sentence`)
if (!stale[1].includes('Reload')) {
  throw new Error(`the STALE sentence in ${STORE_CONFIGURATION} no longer contains "Reload", so the sheets cannot tell a stale edit`)
}
console.log('ok: the stale-edit sentence still says Reload')

// The same for a delete refused because a policy is attached to the row: the sheets find that
// refusal by "attached to this" and then point at the key requirement above, so both of the
// server's sentences, one policy and several, have to keep the words.
const attached = readFileSync(STORE_CONFIGURATION, 'utf8').match(/"[^"]*attached to this \{kind\}[^"]*"/g) ?? []
if (attached.length < 2) {
  throw new Error(`${STORE_CONFIGURATION} no longer says a policy is "attached to this {kind}" in both its sentences, so the sheets cannot tell a delete refused for one`)
}
console.log('ok: the attached-policy sentences still say attached to this')

// The audit log's kind filter offers audit.rs's KINDS, read from it for the reason the methods
// are read from configuration.rs: a kind the store starts writing and this page does not know
// could not be filtered by, and one this page offers that the server does not know is a 400.
const AUDIT = '../crates/gapura-control/src/audit.rs'
const auditKinds = readFileSync(AUDIT, 'utf8').match(/pub const KINDS: &\[&str\] = &\[([\s\S]*?)\];/)
if (!auditKinds) throw new Error(`${AUDIT} has no KINDS`)
const serverKinds = [...auditKinds[1].replace(/\/\/.*$/gm, '').matchAll(/"([^"]+)"/g)].map((m) => m[1])
if (serverKinds.length === 0) throw new Error(`${AUDIT}: KINDS is declared but nothing could be read from it`)
const { KINDS: consoleKinds, KIND_LABEL } = await import('./src/lib/audit.js')
if (JSON.stringify(serverKinds) !== JSON.stringify(consoleKinds)) {
  throw new Error(`KIND_LABEL in src/lib/audit.js has the kinds ${consoleKinds}, the server's are ${serverKinds}`)
}
for (const kind of consoleKinds) {
  if (!KIND_LABEL[kind] || KIND_LABEL[kind] === kind) {
    throw new Error(`src/lib/audit.js has no readable label for the kind ${kind}`)
  }
}
console.log(`ok: the audit log filters by the ${serverKinds.length} kinds the server records`)

// #229: a sheet keeps the `updated_at` it opened with and sends that one, not the stamp of
// whatever list was read since. A policy toggle reloads the list under an open sheet, so a save
// that read the live prop would carry a fresh stamp and overwrite someone else's change instead
// of being refused as stale. There is no component test here, so the source is the check: the
// stamp is captured in `reset()`, which runs when the sheet opens, and the save sends it.
for (const [file, row, sent] of [
  ['src/lib/ServiceSheet.svelte', 'service', /updated_at:\s*seen\b/],
  ['src/lib/RouteSheet.svelte', 'route', /updated_at:\s*seen\.updated_at\b/],
]) {
  const source = readFileSync(file, 'utf8')
  const reset = source.match(/function reset\(\)\s*\{([\s\S]*?)\n  \}/)
  if (!reset) throw new Error(`${file}: no reset() to capture the stamp the sheet opened with`)
  if (!new RegExp(`seen\\s*=[^\\n]*${row}[^\\n]*updated_at`).test(reset[1])) {
    throw new Error(`${file}: reset() no longer records the ${row}'s updated_at in \`seen\` when the sheet opens`)
  }
  if (!sent.test(source)) throw new Error(`${file}: the save no longer sends the stamp kept in \`seen\``)
  // Outside reset(), where the capture itself rightly reads the prop.
  if (new RegExp(`updated_at:\\s*${row}\\??\\.updated_at`).test(source.replace(reset[0], ''))) {
    throw new Error(`${file}: the save sends the live ${row}.updated_at, which a policy toggle refreshes under an open sheet`)
  }
}
console.log('ok: the service and route sheets save with the stamp they opened with')

// The IP restriction, body size and CORS controls' bounds are policies.rs's, and every kind kept through
// `/policies/{kind}` needs a label on the audit page, read from it for the same reasons as the
// request-limit bounds: a bound that drifts refuses what the form allows, and a kind with no label
// reads in the audit log as a key requirement.
const POLICIES = '../crates/gapura-control/src/policies.rs'
const policiesSource = readFileSync(POLICIES, 'utf8')
const { MAX_NETWORKS } = await import('./src/lib/configuration.js')
const maxNetworks = policiesSource.match(/pub const MAX_NETWORKS: usize = ([\d_]+);/)
if (!maxNetworks) throw new Error(`${POLICIES} has no MAX_NETWORKS`)
if (Number(maxNetworks[1].replaceAll('_', '')) !== MAX_NETWORKS) {
  throw new Error(`MAX_NETWORKS in src/lib/configuration.js is ${MAX_NETWORKS}, the server's is ${maxNetworks[1]}`)
}
// The body size bound is written as a shift, `1 << 30`, so both that and plain digits are read.
// Any other form, a product or a named constant, is one this reader does not understand, and it
// fails the build rather than compare against a number it made up.
const { MAX_BODY_BYTES } = await import('./src/lib/configuration.js')
const maxBodyBytes = policiesSource.match(/pub const MAX_BODY_BYTES: u64 = ([^;]+);/)
if (!maxBodyBytes) throw new Error(`${POLICIES} has no MAX_BODY_BYTES`)
const bodyBytesText = maxBodyBytes[1].trim()
const shifted = bodyBytesText.match(/^(\d+) << (\d+)$/)
let serverBodyBytes
if (shifted) serverBodyBytes = Number(shifted[1]) * 2 ** Number(shifted[2])
else if (/^\d[\d_]*$/.test(bodyBytesText)) serverBodyBytes = Number(bodyBytesText.replaceAll('_', ''))
else throw new Error(`${POLICIES}: MAX_BODY_BYTES is written as ${bodyBytesText}, which this check cannot read yet`)
if (serverBodyBytes !== MAX_BODY_BYTES) {
  throw new Error(`MAX_BODY_BYTES in src/lib/configuration.js is ${MAX_BODY_BYTES}, the server's is ${bodyBytesText} (${serverBodyBytes})`)
}
// The CORS control's bounds and the methods it says a preflight is told when none are ticked.
const { MAX_ORIGINS, MAX_AGE_SECS, CORS_METHODS } = await import('./src/lib/configuration.js')
for (const [name, mine, type] of [
  ['MAX_ORIGINS', MAX_ORIGINS, 'usize'],
  ['MAX_AGE_SECS', MAX_AGE_SECS, 'u64'],
]) {
  const server = policiesSource.match(new RegExp(`pub const ${name}: ${type} = ([\\d_]+);`))
  if (!server) throw new Error(`${POLICIES} has no ${name}`)
  if (Number(server[1].replaceAll('_', '')) !== mine) {
    throw new Error(`${name} in src/lib/configuration.js is ${mine}, the server's is ${server[1]}`)
  }
}
const corsMethods = policiesSource.match(/const CORS_METHODS: \[&str; \d+\] = \[([^\]]*)\];/)
if (!corsMethods) throw new Error(`${POLICIES} has no CORS_METHODS`)
const serverCorsMethods = [...corsMethods[1].matchAll(/"([^"]+)"/g)].map((m) => m[1])
if (serverCorsMethods.join() !== CORS_METHODS.join()) {
  throw new Error(`CORS_METHODS in src/lib/configuration.js is ${CORS_METHODS}, the server's is ${serverCorsMethods}`)
}
const policyKinds = policiesSource.match(/pub const KINDS: &\[&str\] = &\[([\s\S]*?)\];/)
if (!policyKinds) throw new Error(`${POLICIES} has no KINDS`)
const serverPolicyKinds = [...policyKinds[1].replace(/\/\/.*$/gm, '').matchAll(/"([^"]+)"/g)].map((m) => m[1])
if (serverPolicyKinds.length === 0) throw new Error(`${POLICIES}: KINDS is declared but nothing could be read from it`)
const { POLICY_LABEL } = await import('./src/lib/audit.js')
for (const kind of serverPolicyKinds) {
  if (!POLICY_LABEL[kind]) throw new Error(`POLICY_LABEL in src/lib/audit.js has no label for ${kind}, which ${POLICIES} keeps`)
}
console.log("ok: the IP restriction, body size and CORS bounds and every policy kind's audit label match the server")

// The stub's data planes carry every field GET /api/data-planes serialises, read off the Rust
// struct, so a field the API gains cannot be missing from what the page is drawn against; and
// one of them is refused a configuration, so the page's warning for that is drawn at all.
{
  const DATA_PLANES = '../crates/gapura-control/src/data_planes.rs'
  const struct = readFileSync(DATA_PLANES, 'utf8').match(/pub struct DataPlaneView \{([\s\S]*?)\n\}/)
  if (!struct) throw new Error(`${DATA_PLANES}: no "pub struct DataPlaneView" to read the fields from`)
  const fields = [...struct[1].matchAll(/^ {4}pub ([a-z_]+):/gm)].map((m) => m[1])
  if (fields.length === 0) throw new Error(`${DATA_PLANES}: DataPlaneView has no fields this could read`)
  const planes = JSON.parse(readFileSync('stub/data-planes.json', 'utf8'))
  for (const plane of planes) {
    const absent = fields.filter((f) => !(f in plane))
    if (absent.length) throw new Error(`stub/data-planes.json: ${plane.name} lacks ${absent.join(', ')}`)
  }
  if (!planes.some((p) => p.missing.length > 0)) {
    throw new Error('stub/data-planes.json: no data plane is refused a configuration, so the page never draws one')
  }
  console.log('ok: the stub data planes carry every field the API serialises, and one of them is refused')
}
