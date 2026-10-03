<script>
  import { TONES } from './states.js'

  // A small label in the state badge's shape and tones, for words that are not route states:
  // how an account signs in, whether it can, and which roles it holds. Same classes, so the
  // console has one pill rather than two that drift apart.
  let { tone = 'idle', children } = $props()
</script>

<span class="inline-flex items-center justify-self-start whitespace-nowrap rounded-md border border-transparent px-2 py-px text-xs font-medium {TONES[tone]}">
  {@render children?.()}
</span>
