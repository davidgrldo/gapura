<script>
  import Overview from './routes/Overview.svelte'
  import Routes from './routes/Routes.svelte'

  // Two screens do not earn a router dependency. The server already answers any path it does
  // not own with index.html (see `resolve` in crates/gapura-control/src/assets.rs), so a deep
  // link and a reload both arrive here with the path intact, and matching on it is the whole
  // of the routing.
  let path = $state(window.location.pathname)

  const SCREENS = [
    { path: '/', label: 'Overview', component: Overview },
    { path: '/routes', label: 'Routes', component: Routes },
  ]

  // Anything unrecognised shows the overview rather than a "not found" page: the only way to
  // get here with an unknown path is to have typed one, and the landing screen is more use
  // than a dead end.
  const current = $derived(SCREENS.find((s) => s.path === path) ?? SCREENS[0])

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

<header>
  <strong>gapura</strong>
  <nav>
    {#each SCREENS as screen (screen.path)}
      <a
        href={screen.path}
        aria-current={screen.path === current.path ? 'page' : undefined}
        onclick={(event) => go(event, screen.path)}
      >
        {screen.label}
      </a>
    {/each}
  </nav>
</header>

<main>
  <!-- Keyed on the path so that switching screens builds a fresh component, which is what
       re-runs its fetch. Without the key, Svelte would reuse the instance and the reader
       would be looking at whatever it loaded the first time. -->
  {#key current.path}
    <current.component />
  {/key}
</main>

<style>
  :global(body) {
    margin: 0;
    font-family:
      system-ui,
      -apple-system,
      'Segoe UI',
      sans-serif;
    font-size: 15px;
    line-height: 1.5;
    color: #1b2127;
    background: #ffffff;
  }

  header {
    display: flex;
    align-items: baseline;
    gap: 1.5rem;
    padding: 0.875rem 1.5rem;
    border-bottom: 1px solid #e3e7eb;
  }

  nav {
    display: flex;
    gap: 1rem;
  }

  nav a {
    color: #374151;
    text-decoration: none;
    padding-bottom: 0.125rem;
    border-bottom: 2px solid transparent;
  }

  nav a:hover {
    text-decoration: underline;
  }

  nav a[aria-current='page'] {
    color: #1b2127;
    font-weight: 600;
    border-bottom-color: #1b2127;
  }

  main {
    padding: 1.5rem;
    max-width: 68rem;
  }
</style>
