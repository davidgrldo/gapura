<script>
  import * as Sidebar from '$lib/components/ui/sidebar/index.js'
  import * as Breadcrumb from '$lib/components/ui/breadcrumb/index.js'
  import { Separator } from '$lib/components/ui/separator/index.js'
  import { Skeleton } from '$lib/components/ui/skeleton/index.js'
  import SquaresFour from 'phosphor-svelte/lib/SquaresFour'
  import TreeStructure from 'phosphor-svelte/lib/TreeStructure'
  import UsersThree from 'phosphor-svelte/lib/UsersThree'
  import ShieldCheck from 'phosphor-svelte/lib/ShieldCheck'
  import HardDrives from 'phosphor-svelte/lib/HardDrives'
  import Path from 'phosphor-svelte/lib/Path'
  import Key from 'phosphor-svelte/lib/Key'
  import Broadcast from 'phosphor-svelte/lib/Broadcast'
  import ClockCounterClockwise from 'phosphor-svelte/lib/ClockCounterClockwise'
  import Stack from 'phosphor-svelte/lib/Stack'
  import AppSidebar from './lib/AppSidebar.svelte'
  import ChoosePassword from './lib/ChoosePassword.svelte'
  import Failure from './lib/Failure.svelte'
  import Home from './lib/Home.svelte'
  // Each screen is its own chunk, fetched when it is first opened: the console's one bundle had
  // grown past what a first visit should download, and most readers open two or three screens.
  const Overview = () => import('./routes/Overview.svelte')
  const Routes = () => import('./routes/Routes.svelte')
  const Users = () => import('./routes/Users.svelte')
  const Roles = () => import('./routes/Roles.svelte')
  const Services = () => import('./routes/Services.svelte')
  const StoreRoutes = () => import('./routes/StoreRoutes.svelte')
  const Consumers = () => import('./routes/Consumers.svelte')
  const DataPlanes = () => import('./routes/DataPlanes.svelte')
  const Audit = () => import('./routes/Audit.svelte')
  const Workspaces = () => import('./routes/Workspaces.svelte')
  import { get } from './lib/api.js'

  // A handful of screens does not earn a router dependency. The server already answers any
  // path it does not own with index.html (see `resolve` in crates/gapura-control/src/assets.rs),
  // so a deep link and a reload both arrive here with the path intact, and matching on it is
  // the whole of the routing.
  let path = $state(window.location.pathname)

  // Who is signed in decides which screens exist for them, so it is asked once, before any
  // screen is drawn. `get` deals with a missing session itself, by sending the browser to sign in.
  // It is asked again once an account on a temporary password has chosen its own, and the
  // promise settles then without rejecting.
  let me = $state(undefined)
  let failed = $state(undefined)
  function readMe() {
    return get('/api/me').then(
      (answer) => {
        me = answer
        failed = undefined
      },
      (error) => (failed = error),
    )
  }
  readMe()

  // Asked again after a page changes something /api/me reports, such as the workspaces: the
  // pickers and the access pages read them from here. A failure keeps the answer already on
  // screen rather than replacing every page with it, since the change itself was made. Settles
  // once the answer is taken or has failed, and never rejects.
  function refreshMe() {
    return get('/api/me').then(
      (answer) => (me = answer),
      () => {},
    )
  }

  // An account on a temporary password is shown only the page that replaces it: every other
  // store API refuses it until it has.
  const choosing = $derived(me?.must_change_password === true)

  // In store mode the Kubernetes-reading pages sit beside the store's own Routes page, so they
  // are named for what they read.
  const store = $derived(me?.mode === 'store')
  const GATEWAY = $derived([
    { path: '/', label: store ? 'Cluster overview' : 'Overview', icon: SquaresFour, component: Overview },
    { path: '/routes', label: store ? 'Cluster routes' : 'Routes', icon: TreeStructure, component: Routes },
  ])
  const CONFIGURATION = [
    { path: '/services', label: 'Services', icon: HardDrives, component: Services },
    { path: '/store-routes', label: 'Routes', icon: Path, component: StoreRoutes },
    { path: '/consumers', label: 'Consumers', icon: Key, component: Consumers },
  ]
  const GATEWAYS = [{ path: '/data-planes', label: 'Data planes', icon: Broadcast, component: DataPlanes }]
  const ACCESS = [
    { path: '/users', label: 'Users', icon: UsersThree, component: Users },
    { path: '/roles', label: 'Roles', icon: ShieldCheck, component: Roles },
    { path: '/workspaces', label: 'Workspaces', icon: Stack, component: Workspaces },
  ]
  const ACTIVITY = [{ path: '/audit', label: 'Audit log', icon: ClockCounterClockwise, component: Audit }]

  // The navigation this account gets. The cluster pages read Kubernetes and the gateway's admin
  // port without knowing about workspaces, so in store mode they are a superuser's; the
  // configuration pages are for anyone holding a role in a workspace; the data planes page for
  // the same readers and superusers, though only a superuser changes it; the access pages for
  // superusers and anyone who administers one; the audit log for superusers and anyone holding a
  // role, who read their own workspaces' entries. The server enforces all five. This only avoids
  // offering a page the server would refuse.
  const groups = $derived(
    me === undefined || choosing
      ? []
      : [
          { label: store ? 'Cluster' : 'Gateway', screens: me.mode === 'kubernetes' || me.superuser ? GATEWAY : [] },
          { label: 'Configuration', screens: store && me.roles.length > 0 ? CONFIGURATION : [] },
          { label: 'Gateways', screens: store && (me.superuser || me.roles.length > 0) ? GATEWAYS : [] },
          {
            label: 'Access',
            screens: store && (me.superuser || me.grantable.length > 0) ? ACCESS : [],
          },
          { label: 'Activity', screens: store && (me.superuser || me.roles.length > 0) ? ACTIVITY : [] },
        ].filter((group) => group.screens.length > 0),
  )
  const screens = $derived(groups.flatMap((group) => group.screens))

  // A path this account has no screen for shows the first screen it may open rather than a dead
  // end. An account with no screens at all gets Home, which says why.
  function screenFor(to) {
    return screens.find((s) => s.path === to) ?? screens[0]
  }
  const current = $derived(screenFor(path))

  // The address bar names the screen on show: sign-in with nowhere to return to lands on /, and
  // a stale bookmark can name a screen this account does not have. Replaced rather than pushed, so Back
  // does not return to an address that only ever showed this same screen.
  $effect(() => {
    if (me === undefined || choosing) return
    const shown = current?.path ?? '/'
    if (shown !== path) {
      history.replaceState(history.state, '', shown)
      path = shown
    }
  })

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
    const target = screenFor(to)?.path ?? '/'
    if (target !== path) {
      history.pushState({}, '', target)
      path = target
    }
  }
</script>

<!-- Without onpopstate, Back and Forward would change the URL and leave the screen as it was.
     onpageshow: a browser may restore this page from its back/forward cache after Sign out,
     showing the account that just left without asking the server; reloading asks /api/me again,
     which sends a signed-out browser to sign in. The page is hidden first, or the restored
     screen would stay in view until the reload answers. -->
<svelte:window
  onpopstate={() => (path = window.location.pathname)}
  onpageshow={(event) => {
    if (event.persisted) {
      document.documentElement.style.visibility = 'hidden'
      location.reload()
    }
  }}
/>

<!-- Until an account on a temporary password chooses its own, it gets that page and nothing else,
     the address bar left as it was so the screen it asked for opens after. A failure to read who
     it is afterwards is the console's ordinary failure page. -->
{#if choosing && !failed}
  <ChoosePassword {me} onchosen={readMe} />
{:else}
  <Sidebar.Provider open={startOpen}>
    <AppSidebar {groups} {current} {go} {me} />
    <!-- Sidebar.Inset is the page's <main>, so what sits inside it is a <div>. -->
    <Sidebar.Inset>
      <header class="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b bg-background/85 px-4 backdrop-blur">
        <Sidebar.Trigger class="-ml-1" />
        <!-- self-center on the component's own data-vertical variant, so that cn replaces the
             generated self-stretch, which beats the header's items-center and puts a 16px line at
             the top of the header. -->
        <Separator orientation="vertical" decorative class="mr-2 data-vertical:h-4 data-vertical:self-center" />
        <!-- Only once the page is known: "Home" while loading would be a guess, and on a failure
             there is no page to name. -->
        {#if me}
          <Breadcrumb.Root>
            <Breadcrumb.List>
              <Breadcrumb.Item>
                <Breadcrumb.Page>{current?.label ?? 'Home'}</Breadcrumb.Page>
              </Breadcrumb.Item>
            </Breadcrumb.List>
          </Breadcrumb.Root>
        {/if}
      </header>
      <div class="w-full max-w-7xl px-4 py-6 md:px-8 md:py-7">
        {#if failed}
          <Failure error={failed} what="who you are" />
        {:else if me === undefined}
          <!-- The shape of a screen while the answer is on its way, so the page does not jump
               when it arrives. -->
          <div class="space-y-3" aria-busy="true">
            <span class="sr-only">Loading</span>
            <Skeleton class="h-7 w-40" />
            <Skeleton class="h-24 w-full" />
          </div>
        {:else if current}
          <!-- Keyed on the path so that switching screens builds a fresh component, which is what
               re-runs its fetch. Without the key, Svelte would reuse the instance and the reader
               would be looking at whatever it loaded the first time. Every screen is handed who
               is signed in: the access screens' forms need the workspaces the reader
               administers, and the reader's own id. `refresh` asks /api/me again, for a page whose
               change alters it. -->
          {#key current.path}
            {#await current.component()}
              <div class="space-y-3" aria-busy="true">
                <span class="sr-only">Loading</span>
                <Skeleton class="h-7 w-40" />
                <Skeleton class="h-24 w-full" />
              </div>
            {:then screen}
              <screen.default {me} refresh={refreshMe} />
            {:catch error}
              <!-- A chunk that will not load is usually a console upgraded under an open tab: the
                   old page names files the new build no longer has. Reloading fetches the new one. -->
              <Failure {error} what="this page" />
              <p class="mt-2 text-sm text-muted-foreground">If the console was just upgraded, reload the page.</p>
            {/await}
          {/key}
        {:else}
          <Home {me} />
        {/if}
      </div>
    </Sidebar.Inset>
  </Sidebar.Provider>
{/if}
