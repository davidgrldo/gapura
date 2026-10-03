<script>
  import { mergeProps } from 'bits-ui'
  import * as Sidebar from '$lib/components/ui/sidebar/index.js'
  import SignOut from 'phosphor-svelte/lib/SignOut'

  // The screens in their groups, which one is open, App's navigation function, and who is
  // signed in: App owns routing and identity, this component only draws them.
  let { groups, current, go, me } = $props()

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
                <svg viewBox="0 0 24 24" fill="currentColor" class="size-[18px]!" aria-hidden="true">
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
    <!-- A landmark, so a screen reader can jump to the console's navigation: the generated
         sidebar renders a <div> and a <ul>, and the only other <nav> is the breadcrumb. -->
    <nav aria-label="Console">
      {#each groups as group (group.label)}
        <Sidebar.Group>
          <Sidebar.GroupLabel>{group.label}</Sidebar.GroupLabel>
          <Sidebar.Menu>
            {#each group.screens as screen (screen.path)}
              {@const here = screen.path === current?.path}
              <Sidebar.MenuItem>
                <Sidebar.MenuButton isActive={here} tooltipContent={screen.label}>
                  {#snippet child({ props })}
                    <!-- Plain links, so that middle-click and "open in new tab" still work and
                         the href is a real URL. The tooltip trigger hands over a button's props,
                         type="button" among them, which a link has no use for. -->
                    <a
                      href={screen.path}
                      aria-current={here ? 'page' : undefined}
                      {...mergeProps(props, { onclick: (event) => choose(event, screen.path) })}
                      type={undefined}
                    >
                      <screen.icon aria-hidden="true" class={here ? 'text-brand' : 'text-muted-foreground'} />
                      <span>{screen.label}</span>
                    </a>
                  {/snippet}
                </Sidebar.MenuButton>
              </Sidebar.MenuItem>
            {/each}
          </Sidebar.Menu>
        </Sidebar.Group>
      {/each}
    </nav>
  </Sidebar.Content>

  <Sidebar.Footer>
    <Sidebar.Menu>
      {#if me?.mode === 'store'}
        <Sidebar.MenuItem>
          <!-- Who is signed in, hidden with the labels when the sidebar is down to icons. -->
          <div class="grid px-2 py-1 leading-tight group-data-[collapsible=icon]:hidden">
            <span class="truncate text-sm font-medium">{me.name}</span>
            <span class="text-xs text-muted-foreground">{me.method === 'oidc' ? 'Signed in with SSO' : 'Console account'}</span>
          </div>
        </Sidebar.MenuItem>
      {/if}
      <Sidebar.MenuItem>
        <!-- A form rather than a fetch: signing out is a navigation, and the server answers it
             with its "signed out" page. -->
        <form method="post" action="/auth/logout">
          <Sidebar.MenuButton tooltipContent="Sign out">
            {#snippet child({ props })}
              <!-- type after the spread: the tooltip trigger's props carry type="button", which
                   would leave a button that submits nothing. -->
              <button {...props} type="submit">
                <SignOut aria-hidden="true" class="text-muted-foreground" />
                <span>Sign out</span>
              </button>
            {/snippet}
          </Sidebar.MenuButton>
        </form>
      </Sidebar.MenuItem>
    </Sidebar.Menu>
  </Sidebar.Footer>

  <Sidebar.Rail />
</Sidebar.Root>
