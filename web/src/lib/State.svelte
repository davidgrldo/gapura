<script>
  import { STATES } from './states.js'

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
