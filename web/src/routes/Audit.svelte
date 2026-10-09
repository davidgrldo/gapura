<script>
  import { get } from '../lib/api.js'
  import Failure from '../lib/Failure.svelte'
  import NativeSelect from '../lib/NativeSelect.svelte'
  import { Button } from '$lib/components/ui/button/index.js'
  import * as Table from '$lib/components/ui/table/index.js'
  import CaretRight from 'phosphor-svelte/lib/CaretRight'
  import { when } from '../lib/configuration.js'
  import { ACTION_LABEL, KINDS, KIND_LABEL, NO_WORKSPACE, changedKeys, nameOf } from '../lib/audit.js'

  let { me } = $props()
  const id = $props.id()

  // Empty means every one: the server reads `workspace=` and `kind=` sent empty as not sent.
  let workspace = $state('')
  let kind = $state('')
  const filtered = $derived(workspace !== '' || kind !== '')

  // The entries shown, newest first, and what to send as `before` for the page after them: null
  // once the last page is shown.
  let entries = $state(undefined)
  let next = $state(null)
  let failed = $state(undefined)
  let loadingOlder = $state(false)
  // The newest request's number, so a page asked for under filters since changed cannot land
  // under the new ones.
  let latest = 0

  function page(before) {
    const query = new URLSearchParams()
    if (before != null) query.set('before', String(before))
    if (workspace) query.set('workspace', workspace)
    if (kind) query.set('kind', kind)
    const q = query.toString()
    return get(q ? `/api/audit?${q}` : '/api/audit')
  }

  // A change of filter starts again from the top, from nothing, so entries read under the old
  // filters are never shown under the new ones, nor their failure.
  $effect(() => {
    const mine = ++latest
    entries = undefined
    next = null
    failed = undefined
    loadingOlder = false
    page(null).then(
      (answer) => {
        if (mine !== latest) return
        entries = answer.entries
        next = answer.next
      },
      (error) => {
        if (mine === latest) failed = error
      },
    )
  })

  function older() {
    const mine = latest
    loadingOlder = true
    failed = undefined
    page(next)
      .then(
        (answer) => {
          if (mine !== latest) return
          entries = [...entries, ...answer.entries]
          next = answer.next
        },
        (error) => {
          if (mine === latest) failed = error
        },
      )
      .finally(() => {
        if (mine === latest) loadingOlder = false
      })
  }

  // Which rows the reader has opened, by entry id: ids never repeat, so one stays open while
  // older pages are added below it.
  let open = $state({})

  const region = (label) => ({ tabindex: 0, role: 'region', 'aria-label': label })
  const json = (value) => JSON.stringify(value, null, 2)
</script>

<h1 class="mb-4 text-2xl font-semibold tracking-tight">Audit log</h1>

<p class="mb-4 max-w-2xl text-sm text-muted-foreground">
  Every change made through the console, newest first. You see the workspaces you hold a role in; entries about
  accounts, workspaces and data planes are a superuser's.
</p>

<div class="mb-4 flex flex-wrap items-center gap-x-6 gap-y-3">
  <div class="flex items-center gap-2">
    <label for="{id}-ws" class="shrink-0 text-sm font-medium">Workspace</label>
    <NativeSelect id="{id}-ws" class="w-auto" bind:value={workspace}>
      <option value="">All</option>
      {#each me.roles as r (r.workspace_id)}
        <option value={r.workspace}>{r.workspace}</option>
      {/each}
      {#if me.superuser}<option value={NO_WORKSPACE}>No workspace</option>{/if}
    </NativeSelect>
  </div>
  <div class="flex items-center gap-2">
    <label for="{id}-kind" class="shrink-0 text-sm font-medium">Kind</label>
    <NativeSelect id="{id}-kind" class="w-auto" bind:value={kind}>
      <option value="">All</option>
      {#each KINDS as k (k)}
        <option value={k}>{KIND_LABEL[k]}</option>
      {/each}
    </NativeSelect>
  </div>
</div>

{#if failed && entries === undefined}
  <Failure error={failed} what="the audit log" />
{:else if entries === undefined}
  <p class="text-muted-foreground">Reading the audit log…</p>
{:else}
  {#if failed}
    <!-- Reading an older page failed. What is on screen is kept, and the reader is told so. -->
    <div class="mb-4 space-y-2" role="status">
      <Failure error={failed} what="older entries" />
      <p class="text-sm text-muted-foreground">The entries below are the ones read so far.</p>
    </div>
  {/if}
  {#if entries.length === 0}
    <p class="text-muted-foreground">{filtered ? 'No entries match these filters.' : 'Nothing recorded yet.'}</p>
  {:else}
    <div class="rounded-lg border bg-card shadow-xs">
      <Table.Root aria-label="Audit log" containerProps={region('Audit log')}>
        <Table.Header>
          <Table.Row class="hover:bg-transparent">
            <Table.Head>When</Table.Head>
            <Table.Head>Who</Table.Head>
            <Table.Head>Action</Table.Head>
            <Table.Head>What</Table.Head>
            <Table.Head>Workspace</Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each entries as e (e.id)}
            {@const name = nameOf(e)}
            <Table.Row>
              <Table.Cell>
                <button
                  type="button"
                  class="inline-flex items-center gap-2 rounded-sm text-left focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
                  aria-expanded={open[e.id] === true}
                  aria-controls="{id}-entry-{e.id}"
                  onclick={() => (open[e.id] = !open[e.id])}
                >
                  <CaretRight
                    class="shrink-0 text-muted-foreground transition-transform {open[e.id] ? 'rotate-90' : ''}"
                    aria-hidden="true"
                  />
                  <span>{when(e.at)}</span>
                  <span class="sr-only">: before and after</span>
                </button>
              </Table.Cell>
              <Table.Cell>
                {e.actor}{#if e.actor_method === 'oidc'}<span class="ml-1 text-muted-foreground">via identity provider</span>{/if}
              </Table.Cell>
              <Table.Cell>{ACTION_LABEL[e.action] ?? e.action}</Table.Cell>
              <Table.Cell>
                {KIND_LABEL[e.object_kind] ?? e.object_kind}{#if name}<span class="ml-1.5 font-mono">{name}</span>{/if}
              </Table.Cell>
              <Table.Cell>
                {#if e.workspace}{e.workspace}{:else}<span class="text-muted-foreground">—</span>{/if}
              </Table.Cell>
            </Table.Row>
            {#if open[e.id]}
              {@const changed = changedKeys(e)}
              <Table.Row id="{id}-entry-{e.id}" class="hover:bg-transparent">
                <Table.Cell colspan={5} class="whitespace-normal px-4 pb-4">
                  {#if changed.length > 0}
                    <p class="mb-2 text-sm">
                      <span class="font-medium">Changed:</span>
                      <span class="font-mono">{changed.join(', ')}</span>
                    </p>
                  {/if}
                  <div class="grid gap-3 md:grid-cols-2">
                    {@render side('Before', e.before, e.action === 'create' ? 'Did not exist.' : 'Not recorded.')}
                    {@render side('After', e.after, e.action === 'delete' ? 'Deleted.' : 'Not recorded.')}
                  </div>
                </Table.Cell>
              </Table.Row>
            {/if}
          {/each}
        </Table.Body>
      </Table.Root>
    </div>
  {/if}
  {#if next !== null}
    <div class="mt-4">
      <Button variant="outline" disabled={loadingOlder} onclick={older}>
        {loadingOlder ? 'Loading older…' : 'Load older'}
      </Button>
    </div>
  {/if}
{/if}

{#snippet side(label, value, missing)}
  <div class="min-w-0">
    <h3 class="mb-1 text-xs font-medium text-muted-foreground">{label}</h3>
    {#if value == null}
      <p class="text-sm text-muted-foreground">{missing}</p>
    {:else}
      <pre class="rounded-md bg-muted px-3 py-2 font-mono text-xs whitespace-pre-wrap break-words">{json(value)}</pre>
    {/if}
  </div>
{/snippet}
