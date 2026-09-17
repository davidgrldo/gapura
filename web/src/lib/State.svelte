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

<!-- The explanation lives in the document, not in an attribute (#62): a `title` on an element
     that already has text is only the accessible *description*, which not every screen reader
     announces, there is no hover on a touch device, and no keyboard path to it. Rendered as
     text visually hidden from sighted readers, it is announced without configuration; the
     expanded row on the Routes screen shows the same sentence visibly. -->
<span class="badge {shown.tone}">
  {shown.label}<span class="sr-only">: {shown.detail}</span>
</span>

<style>
  /* In the layout, not removed from it: a `display: none` sentence is not announced either. */
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }

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
