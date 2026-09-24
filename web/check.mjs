// Not a test framework: one script that fails if the console cannot render the API's
// answers. It exists because the Rust tests prove the API and nothing proves the page.
import { readFileSync } from 'node:fs'
import { STATES, TONES } from './src/lib/states.js'

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

console.log(
  `ok: the build produced a document that mounts the app, and the badge map covers the ` +
    `${reportable.length} states the server can report`,
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

