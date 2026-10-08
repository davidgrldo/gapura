<script>
  import { get } from '../lib/api.js'
  import Failure from '../lib/Failure.svelte'
  import DataPlaneSheet from '../lib/DataPlaneSheet.svelte'
  import Tag from '../lib/Tag.svelte'
  import * as Table from '$lib/components/ui/table/index.js'
  import { STATUS_TONE, status, sync } from '../lib/dataPlanes.js'

  let { me } = $props()
  const superuser = $derived(me.superuser)
  let answer = $state(undefined)
  let failed = $state(undefined)
  // The newest request's number, so a slow answer cannot overwrite a newer one.
  let latest = 0
  // Requests on their way, so a timed refetch does not start while one is: it would make the
  // one a sheet is waiting on stale, and the sheet would go on before the list was drawn.
  let inflight = 0

  // Settles once the list is drawn or has failed, and never rejects: the sheets wait on it.
  function load() {
    const mine = ++latest
    inflight += 1
    return get('/api/data-planes')
      .then(
        (planes) => {
          if (mine !== latest) return
          answer = planes
          failed = undefined
        },
        (error) => {
          if (mine === latest) failed = error
        },
      )
      .finally(() => (inflight -= 1))
  }

  const refetch = () => inflight === 0 && load()

  // Whether each one is connected changes with no change made here, so the list is read again
  // every 15 seconds while the page is on screen, and at once when it comes back on screen.
  $effect(() => {
    load()
    let timer = null
    const start = () => {
      if (timer === null) timer = setInterval(refetch, 15_000)
    }
    const stop = () => {
      if (timer !== null) clearInterval(timer)
      timer = null
    }
    const changed = () => {
      if (document.visibilityState === 'visible') {
        refetch()
        start()
      } else {
        stop()
      }
    }
    if (document.visibilityState === 'visible') start()
    document.addEventListener('visibilitychange', changed)
    return () => {
      stop()
      document.removeEventListener('visibilitychange', changed)
    }
  })

  // Where focus goes when a saved list no longer has the row a sheet's button was in.
  let heading = $state(undefined)
  const focusHeading = () => heading?.focus()
  const region = (label) => ({ tabindex: 0, role: 'region', 'aria-label': label })
</script>

<h1 bind:this={heading} tabindex="-1" class="mb-4 text-2xl font-semibold tracking-tight outline-none">Data planes</h1>

<div class="mb-3 flex items-start justify-between gap-4">
  <div class="grid max-w-2xl gap-1 text-sm text-muted-foreground">
    <p>
      Gateways that fetch their configuration from this control plane. Behind can show for a few seconds after a
      change, until each one's next call.
    </p>
    {#if !superuser}
      <p>Only a superuser registers data planes: each one can read every workspace's configuration, private keys included.</p>
    {/if}
  </div>
  {#if superuser}<DataPlaneSheet mode="create" {superuser} onsaved={load} onremoved={focusHeading} />{/if}
</div>

{#if failed && answer === undefined}
  <Failure error={failed} what="the data planes" />
{:else if answer === undefined}
  <p class="text-muted-foreground">Reading data planes…</p>
{:else}
  {#if failed}
    <!-- A fetch after a save, or a timed one, failed. The table on screen is kept, and the reader
         is told what it is, as on the Consumers page. -->
    <div class="mb-4 space-y-2" role="status">
      <Failure error={failed} what="the data planes" />
      <p class="text-sm text-muted-foreground">The data planes below are as they were last read.</p>
    </div>
  {/if}
  {#if answer.length === 0}
    <p class="text-muted-foreground">No data planes yet.</p>
  {:else}
    <div class="rounded-lg border bg-card shadow-xs">
      <Table.Root aria-label="Data planes" containerProps={region('Data planes')}>
        <Table.Header>
          <Table.Row class="hover:bg-transparent">
            <Table.Head>Name</Table.Head>
            <Table.Head>Status</Table.Head>
            <Table.Head>In sync</Table.Head>
            <Table.Head>
              Address <span class="font-normal text-muted-foreground">(as the control plane sees it)</span>
            </Table.Head>
            <Table.Head class="text-right">Tokens</Table.Head>
            <Table.Head><span class="sr-only">Actions</span></Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          <!-- Keyed by name, so a fetch after issuing a token keeps each row's sheet, and the token
               on show in it, where it was. -->
          {#each answer as plane (plane.name)}
            {@const insync = sync(plane)}
            <Table.Row>
              <Table.Cell class="font-mono">{plane.name}</Table.Cell>
              <Table.Cell><Tag tone={STATUS_TONE[plane.status] ?? 'idle'}>{status(plane)}</Tag></Table.Cell>
              <Table.Cell>
                {#if insync === null}
                  <span class="text-muted-foreground">—</span>
                {:else if insync.stale}
                  <span class="text-muted-foreground">{insync.words}, as of its last call</span>
                {:else}
                  <Tag tone={insync.tone}>{insync.words}</Tag>
                {/if}
              </Table.Cell>
              <Table.Cell class="font-mono">
                {#if plane.last_seen_address}{plane.last_seen_address}{:else}<span class="font-sans text-muted-foreground">—</span>{/if}
              </Table.Cell>
              <Table.Cell class="text-right tabular-nums">{plane.tokens.length}</Table.Cell>
              <Table.Cell class="text-right">
                <DataPlaneSheet mode="edit" {plane} {superuser} onsaved={load} onremoved={focusHeading} />
              </Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>
    </div>
  {/if}
{/if}
