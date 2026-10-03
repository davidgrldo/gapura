<script>
  import { STATES } from './states.js'
  import Tag from './Tag.svelte'

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
     text visually hidden from sighted readers (`sr-only` keeps it rendered, and so announced,
     where a `display: none` sentence is dropped), it is announced without configuration; the
     expanded row on the Routes screen shows the same sentence visibly. -->
<Tag tone={shown.tone}>
  <span class="size-1.5 rounded-full bg-current" aria-hidden="true"></span>{shown.label}<span class="sr-only">: {shown.detail}</span>
</Tag>
