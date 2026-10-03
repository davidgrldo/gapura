<script>
  import { cn } from '$lib/utils.js'
  import { TONES } from './states.js'

  // The console's one pill. Route states (State.svelte) and the words on the Users screen (how
  // an account signs in, whether it can, which roles it holds) are all drawn by it, so they
  // cannot drift apart. A caller's class is merged last, which lets a long chip wrap.
  let { tone = 'idle', class: className, children } = $props()
</script>

<!-- `justify-self-start` because grid items stretch by default, which made a pill render as a
     full-width bar in the Routes list. The transparent border is for forced-colours mode,
     which drops backgrounds but paints borders, so the pill keeps its outline there. -->
<span
  class={cn(
    'inline-flex items-center gap-1.5 justify-self-start whitespace-nowrap rounded-md border border-transparent px-2 py-px text-xs font-medium',
    TONES[tone],
    className,
  )}
>
  {@render children?.()}
</span>
