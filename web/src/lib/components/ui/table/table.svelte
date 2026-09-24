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
     the tab order; the rest of the props land on the <table>. -->
<div data-slot="table-container" class="relative w-full overflow-x-auto" {...containerProps}>
	<table bind:this={ref} data-slot="table" class={cn("w-full caption-bottom text-sm", className)} {...restProps}>
		{@render children?.()}
	</table>
</div>