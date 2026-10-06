<script>
  import { cn } from '$lib/utils.js'

  // A native select drawn like the generated Input. Native rather than a listbox component:
  // the platform's own list is what a keyboard, a phone and a screen reader already know how to
  // work, and choosing one of four roles needs nothing more. Both access sheets use it, so
  // their selects cannot drift apart.
  let { value = $bindable(), class: className, children, ...restProps } = $props()
</script>

<!-- The Input's own classes, so a select and a text field sit side by side looking alike. The
     Input's dark tint is translucent, and some platforms draw the open list in the select's own
     background, which would leave the options on whatever shows through it; so the options are
     given the popover's solid colours, which are also what the sheet around them is drawn in. -->
<select
  bind:value
  class={cn(
    'h-8 w-full min-w-0 rounded-lg border border-input bg-transparent px-2.5 py-1 text-base outline-none transition-colors focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 disabled:pointer-events-none disabled:cursor-not-allowed disabled:bg-input/50 disabled:opacity-50 md:text-sm dark:bg-input/30 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40 dark:disabled:bg-input/80 [&_option]:bg-popover [&_option]:text-popover-foreground',
    className,
  )}
  {...restProps}
>
  {@render children?.()}
</select>
