<script>
  import { mergeProps } from 'bits-ui'
  import * as Sidebar from '$lib/components/ui/sidebar/index.js'

  // The screens, which one is open, and App's navigation function: App owns routing, this
  // component only draws it.
  let { screens, current, go } = $props()

  // On a phone the sidebar is a sheet over the page. Choosing a screen from it has to close
  // the sheet, or the reader is left looking at the menu they just used instead of the
  // screen they chose.
  const sidebar = Sidebar.useSidebar()

  function choose(event, to) {
    go(event, to)
    // `go` prevents the default only when it handled the click itself; a middle-click or a
    // modified click opens a tab and must leave this one as it was.
    if (event.defaultPrevented) sidebar.setOpenMobile(false)
  }
</script>

<Sidebar.Root collapsible="icon">
  <Sidebar.Header>
    <Sidebar.Menu>
      <Sidebar.MenuItem>
        <Sidebar.MenuButton size="lg">
          {#snippet child({ props })}
            <a href="/" {...mergeProps(props, { onclick: (event) => choose(event, '/') })}>
              <span class="flex size-8 shrink-0 items-center justify-center rounded-lg bg-brand text-brand-foreground">
                <!-- The Gapura mark: a candi bentar, the split gate a gapura is. -->
                <svg viewBox="0 0 24 24" fill="currentColor" class="size-[18px]" aria-hidden="true">
                  <path d="M10.6 22V2H9v3H7.5v4H6v4H4.5v4H3v5z" />
                  <path d="M13.4 22V2H15v3h1.5v4H18v4h1.5v4H21v5z" />
                </svg>
              </span>
              <span class="grid leading-tight">
                <span class="font-semibold">Gapura</span>
                <span class="text-xs text-muted-foreground">console</span>
              </span>
            </a>
          {/snippet}
        </Sidebar.MenuButton>
      </Sidebar.MenuItem>
    </Sidebar.Menu>
  </Sidebar.Header>

  <Sidebar.Content>
    <Sidebar.Group>
      <Sidebar.Menu>
        {#each screens as screen (screen.path)}
          {@const here = screen.path === current.path}
          <Sidebar.MenuItem>
            <Sidebar.MenuButton isActive={here} tooltipContent={screen.label}>
              {#snippet child({ props })}
                <!-- Plain links, so that middle-click and "open in new tab" still work and
                     the href is a real URL. -->
                <a
                  href={screen.path}
                  aria-current={here ? 'page' : undefined}
                  {...mergeProps(props, { onclick: (event) => choose(event, screen.path) })}
                >
                  <screen.icon class={here ? 'text-brand' : 'text-muted-foreground'} />
                  <span>{screen.label}</span>
                </a>
              {/snippet}
            </Sidebar.MenuButton>
          </Sidebar.MenuItem>
        {/each}
      </Sidebar.Menu>
    </Sidebar.Group>
  </Sidebar.Content>

  <Sidebar.Rail />
</Sidebar.Root>
