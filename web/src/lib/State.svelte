<script>
  // The seven states crates/gapura-control/src/rows.rs can report, each given the words the
  // screen shows and the colour that carries how bad it is. Neither the raw state name nor
  // the reader's intuition about it is trusted to say that, because two of these names are
  // actively misleading about severity: `unresolved` is a route the gateway installed and is
  // answering every single request to with an error, while `pending` is a route nobody has
  // looked at yet and which may be perfectly fine. They are the most severity-divergent pair
  // in the set and they have the most similar names. So `unresolved` is grouped with
  // `refused` — the other states where traffic is not being served correctly — and never
  // with `pending`, and its label says "Erroring" rather than repeating the word that caused
  // the confusion.
  //
  // `detail` is the sentence behind the badge, shown on hover and read by screen readers. It
  // is here rather than in either screen because both screens show the same badge and the
  // explanation of a state must not be allowed to drift between them.
  const STATES = {
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

  let { state } = $props()

  // A state this console has not been taught can only come from a server newer than the
  // page, which happens during a rolling upgrade. Showing the raw word uncoloured is more
  // use to a reader than showing nothing, and safer than guessing at a severity.
  const shown = $derived(
    STATES[state] ?? {
      label: state,
      tone: 'idle',
      detail: 'This console does not recognise this state; it may be newer than the page.',
    },
  )
</script>

<span class="badge {shown.tone}" title={shown.detail}>{shown.label}</span>

<style>
  .badge {
    display: inline-block;
    padding: 0.1rem 0.5rem;
    border-radius: 0.75rem;
    border: 1px solid;
    font-size: 0.8125rem;
    font-weight: 600;
    line-height: 1.4;
    white-space: nowrap;
  }

  /* Four tones, not seven colours: the point of the grouping is that two states painted the
     same are the same kind of bad, and seven distinguishable hues would undo that by making
     every state look like its own separate category. */
  .ok {
    background: #e6f4ea;
    border-color: #a8d5b5;
    color: #14532d;
  }

  .bad {
    background: #fdecea;
    border-color: #efa8a2;
    color: #7f1d1d;
  }

  .warn {
    background: #fdf3da;
    border-color: #e5c569;
    color: #713f12;
  }

  .idle {
    background: #edf0f2;
    border-color: #c6ced6;
    color: #374151;
  }
</style>
