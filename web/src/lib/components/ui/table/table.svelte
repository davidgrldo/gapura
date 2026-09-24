<script>
	import { cn } from "$lib/utils.js";
	let {
		ref = $bindable(null),
		class: className,
		containerProps,
		children,
		...restProps
	} = $props();
</script>

<!-- gapura: containerProps, so that a page can name the scrolling container and put it in
     the tab order; the rest of the props land on the <table>. The class is merged after the
     spread, so a caller's class adds to the scrolling rather than replacing it, and the
     focus ring is the solid one the rest of the console uses, inset to clear the card's
     rounded border. -->
<div
	data-slot="table-container"
	{...containerProps}
	class={cn(
		"relative w-full overflow-x-auto focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring",
		containerProps?.class
	)}
>
	<table bind:this={ref} data-slot="table" class={cn("w-full caption-bottom text-sm", className)} {...restProps}>
		{@render children?.()}
	</table>
</div>