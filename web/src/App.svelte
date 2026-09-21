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
  /* Every colour, radius and surface the console uses, defined once here because App is the
     only component each screen is mounted inside.

     The chrome is almost colourless on purpose. On the Routes screen the badge tones ARE the
     data — four colours carrying whether traffic is being served — so anything else that puts
     colour on the page competes with the only colour that means something. The accent is
     spent on links and the active tab and nowhere else.

     ponytail: no web font. A font from a CDN is a request to a third party from a page showing
     cluster state, and a bundled one is several hundred kilobytes inside a binary that ships
     to a cluster. Air-gapped installs break on the first and everybody pays for the second. */
  :global(:root) {
    --bg: #ffffff;
    --surface: #ffffff;
    --raised: #f7f8f9;
    --border: #e3e7eb;
    --border-strong: #c6ced6;
    --hover: #f5f7f9;

    --text: #1b2127;
    --text-muted: #55606b;

    /* Interactive only. Not a brand colour: the console has no branding to do. */
    --accent: #1f5fa8;
    --accent-hover: #17497f;

    --ok-bg: #e6f4ea;
    --ok-border: #a8d5b5;
    --ok-text: #14532d;

    --bad-bg: #fdecea;
    --bad-border: #efa8a2;
    --bad-text: #7f1d1d;

    --warn-bg: #fdf3da;
    --warn-border: #e5c569;
    --warn-text: #713f12;

    --idle-bg: #edf0f2;
    --idle-border: #c6ced6;
    --idle-text: #374151;

    --radius-xs: 4px;
    --radius-md: 6px;
    --radius-xl: 10px;
  }

  /* Follows the operating system rather than offering a switch: nobody opens a gateway console
     to choose a theme, and a switch is state to store, sync and get wrong. */
  @media (prefers-color-scheme: dark) {
    :global(:root) {
      --bg: #14161a;
      --surface: #14161a;
      --raised: #1b1e23;
      --border: #2a2e35;
      --border-strong: #3c424b;
      --hover: #1e2228;

      --text: #e8eaed;
      --text-muted: #9aa3ad;

      --accent: #6fa8dc;
      --accent-hover: #8fbfe8;

      --ok-bg: #10291a;
      --ok-border: #24603a;
      --ok-text: #86e0a4;

      --bad-bg: #2d1414;
      --bad-border: #6d2a2a;
      --bad-text: #f3a6a0;

      --warn-bg: #2b2110;
      --warn-border: #6a5220;
      --warn-text: #e8c073;

      --idle-bg: #1f2126;
      --idle-border: #3c4049;
      --idle-text: #b6bdc6;
    }
  }

  :global(body) {
    margin: 0;
    font-family:
      system-ui,
      -apple-system,
      'Segoe UI',
      sans-serif;
    font-size: 15px;
    line-height: 1.5;
    color: var(--text);
    background: var(--bg);
  }

  header {
    display: flex;
    align-items: baseline;
    gap: 1.5rem;
    padding: 0.875rem 1.5rem;
    border-bottom: 1px solid var(--border);
  }

  nav {
    display: flex;
    gap: 1rem;
  }

  nav a {
    color: var(--text-muted);
    text-decoration: none;
    padding-bottom: 0.125rem;
    border-bottom: 2px solid transparent;
  }

  nav a:hover {
    color: var(--text);
  }

  nav a[aria-current='page'] {
    color: var(--text);
    font-weight: 600;
    border-bottom-color: var(--accent);
  }

  /* No card. The reader is scanning a list of routes, and a card's margin and border spend
     space and a line on decoration that the table rows need for themselves. */
  main {
    padding: 1.5rem;
    max-width: 68rem;
  }
</style>
