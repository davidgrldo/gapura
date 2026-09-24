<script>
  import * as Sidebar from '$lib/components/ui/sidebar/index.js'
  import * as Breadcrumb from '$lib/components/ui/breadcrumb/index.js'
  import { Separator } from '$lib/components/ui/separator/index.js'
  import SquaresFour from 'phosphor-svelte/lib/SquaresFour'
  import TreeStructure from 'phosphor-svelte/lib/TreeStructure'
  import AppSidebar from './lib/AppSidebar.svelte'
  import Overview from './routes/Overview.svelte'
  import Routes from './routes/Routes.svelte'

  // Two screens do not earn a router dependency. The server already answers any path it does
  // not own with index.html (see `resolve` in crates/gapura-control/src/assets.rs), so a deep
  // link and a reload both arrive here with the path intact, and matching on it is the whole
  // of the routing.
  let path = $state(window.location.pathname)

  const SCREENS = [
    { path: '/', label: 'Overview', icon: SquaresFour, component: Overview },
    { path: '/routes', label: 'Routes', icon: TreeStructure, component: Routes },
  ]

  // Anything unrecognised shows the overview rather than a "not found" page: the only way to
  // get here with an unknown path is to have typed one, and the landing screen is more use
  // than a dead end.
  const current = $derived(SCREENS.find((s) => s.path === path) ?? SCREENS[0])

  // Whether the sidebar starts open. shadcn-svelte's provider writes its state to a
  // `sidebar_state` cookie on every toggle and expects a server to read it back; nothing here
  // renders on a server, so the one read happens at startup instead.
  const startOpen = !document.cookie.split('; ').includes('sidebar_state=false')

  function go(event, to) {
    // Plain links, so that middle-click and "open in new tab" still work and the href is a
    // real URL; only an ordinary left click is taken over to avoid the full page reload.
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
      return
    }
    event.preventDefault()
    if (to !== path) {
      history.pushState({}, '', to)
      path = to
    }
  }
</script>

<!-- Without this, Back and Forward would change the URL and leave the screen as it was. -->
<svelte:window onpopstate={() => (path = window.location.pathname)} />

<Sidebar.Provider open={startOpen}>
  <AppSidebar screens={SCREENS} {current} {go} />
  <!-- Sidebar.Inset is the page's <main>, so what sits inside it is a <div>. -->
  <Sidebar.Inset>
    <header class="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b bg-background/85 px-4 backdrop-blur">
      <Sidebar.Trigger class="-ml-1" />
      <Separator orientation="vertical" class="mr-2 data-[orientation=vertical]:h-4" />
      <Breadcrumb.Root>
        <Breadcrumb.List>
          <Breadcrumb.Item>
            <Breadcrumb.Page>{current.label}</Breadcrumb.Page>
          </Breadcrumb.Item>
        </Breadcrumb.List>
      </Breadcrumb.Root>
    </header>
    <div class="w-full max-w-7xl px-4 py-6 md:px-8 md:py-7">
      <!-- Keyed on the path so that switching screens builds a fresh component, which is what
           re-runs its fetch. Without the key, Svelte would reuse the instance and the reader
           would be looking at whatever it loaded the first time. -->
      {#key current.path}
        <current.component />
      {/key}
    </div>
  </Sidebar.Inset>
</Sidebar.Provider>
