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

  // Four tones, not seven colours: the point of the grouping is that two states painted the
  // same are the same kind of bad, and seven distinguishable hues would undo that by making
  // every state look like its own separate category. Written out in full so that Tailwind
  // finds every class in this file.
  const TONE = {
    ok: 'bg-success-soft text-success',
    bad: 'bg-danger-soft text-danger',
    warn: 'bg-warning-soft text-warning',
    idle: 'bg-muted text-muted-foreground',
  }
</script>

<!-- The explanation lives in the document, not in an attribute (#62): a `title` on an element
     that already has text is only the accessible *description*, which not every screen reader
     announces, there is no hover on a touch device, and no keyboard path to it. Rendered as
     text visually hidden from sighted readers (`sr-only` keeps it in the layout, where a
     `display: none` sentence would not be announced either), it is announced without
     configuration; the expanded row on the Routes screen shows the same sentence visibly.
     `justify-self-start` because grid items stretch by default, which made a pill render as a
     full-width bar in the Routes list. -->
<span
  class="inline-flex items-center gap-1.5 justify-self-start whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-medium {TONE[shown.tone]}"
>
  <span class="size-1.5 rounded-full bg-current" aria-hidden="true"></span>{shown.label}<span class="sr-only">: {shown.detail}</span>
</span>
