// The seven states crates/gapura-control/src/rows.rs can report, each given the words the
// screen shows and the colour that carries how bad it is. Neither the raw state name nor the
// reader's intuition about it is trusted to say that, because two of these names are actively
// misleading about severity: `unresolved` is a route the gateway installed and is answering
// every single request to with an error, while `pending` is a route nobody has looked at yet
// and which may be perfectly fine. They are the most severity-divergent pair in the set and
// they have the most similar names. So `unresolved` is grouped with `refused` and `missing` —
// the other states where traffic is not being served correctly — and never with `pending`,
// and its label says "Erroring" rather than repeating the word that caused the confusion.
//
// `detail` is the sentence behind the badge, shown on hover and read by screen readers. It is
// here rather than in either screen because both screens show the same badge and the
// explanation of a state must not be allowed to drift between them.
//
// This is a plain module rather than a constant inside State.svelte for one reason: it is the
// only way anything can check it. web/check.mjs imports it under bare Node and asserts the
// grouping and the labelling above, plus that these keys are exactly the states the Rust enum
// can produce. Nothing else does — the built bundle would satisfy every other assertion in
// check.mjs while throwing on mount.
export const STATES = {
  served: {
    label: 'Serving',
    tone: 'ok',
    detail: 'Accepted, and present in what the gateway is actually serving.',
  },
  refused: {
    label: 'Refused',
    tone: 'bad',
    detail: 'The gateway rejected this attachment. The reason below says why.',
  },
  unresolved: {
    label: 'Erroring',
    tone: 'bad',
    detail:
      'Accepted and installed, but a reference it names did not resolve, so it cannot ' +
      'reach a backend: it answers every request with an error.',
  },
  missing: {
    label: 'Not serving',
    tone: 'bad',
    detail: 'Accepted, but absent from what the gateway is actually serving.',
  },
  mixed: {
    label: 'Gateways disagree',
    tone: 'warn',
    detail: 'The gateways this route attaches to are not in the same state. Open the row to see who said what.',
  },
  unknown: {
    label: 'Cannot tell',
    tone: 'warn',
    detail:
      'Accepted, and its references resolved, but the gateway could not be reached — so ' +
      'whether it is really being served is not known.',
  },
  pending: {
    label: 'Not ruled on yet',
    tone: 'idle',
    detail: 'No gateway has ruled on this yet. Not a fault: nobody has looked.',
  },
}
