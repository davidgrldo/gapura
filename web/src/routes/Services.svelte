<script>
  import { get } from '../lib/api.js'
  import Failure from '../lib/Failure.svelte'
  import ServiceSheet from '../lib/ServiceSheet.svelte'
  import WorkspacePicker from '../lib/WorkspacePicker.svelte'
  import * as Table from '$lib/components/ui/table/index.js'
  import { base, ms, upstream } from '../lib/configuration.js'
  import { can, remembered } from '../lib/workspace.js'

  let { me } = $props()
  // Only the starting choice: the picker owns it from here, and `me` is read once when the page
  // is made.
  // svelte-ignore state_referenced_locally
  let workspace = $state(remembered(me.roles))
  const role = $derived(me.roles.find((r) => r.workspace === workspace)?.role)
  let answer = $state(undefined)
  let failed = $state(undefined)
  // The newest request's number, so a slow answer for a workspace the reader has left cannot
  // overwrite the one they are looking at.
  let latest = 0

  // Settles once the list is drawn or has failed, and never rejects: the sheets wait on it.
  function load() {
    const mine = ++latest
    if (!workspace) return Promise.resolve()
    return get(base(workspace, 'services')).then(
      (list) => { if (mine === latest) { answer = list; failed = undefined } },
      (error) => { if (mine === latest) failed = error },
    )
  }
  // Starts again from nothing on a new workspace, so another workspace's rows are never shown
  // under this one's name.
  $effect(() => { workspace; answer = undefined; load() })
  const region = (label) => ({ tabindex: 0, role: 'region', 'aria-label': label })
</script>

<h1 class="mb-4 text-2xl font-semibold tracking-tight">Services</h1>
<WorkspacePicker roles={me.roles} bind:value={workspace} />

{#if !workspace}
  <p class="text-muted-foreground">You hold no role in any workspace yet.</p>
{:else if failed && answer === undefined}
  <Failure error={failed} what="the services" />
{:else if answer === undefined}
  <p class="text-muted-foreground">Reading services…</p>
{:else}
  <div class="mb-3 flex items-center justify-between gap-4">
    <p class="text-sm text-muted-foreground">The upstreams routes in {workspace} send traffic to.</p>
    {#if can.write(role)}<ServiceSheet mode="create" {workspace} {role} onsaved={load} />{/if}
  </div>
  {#if answer.length === 0}
    <p class="text-muted-foreground">No services yet.</p>
  {:else}
    <div class="rounded-lg border bg-card shadow-xs">
      <Table.Root aria-label="Services" containerProps={region('Services')}>
        <Table.Header>
          <Table.Row class="hover:bg-transparent">
            <Table.Head>Name</Table.Head><Table.Head>Upstream</Table.Head>
            <Table.Head>Connect</Table.Head><Table.Head>Read</Table.Head>
            <Table.Head class="text-right">Routes</Table.Head>
            <Table.Head><span class="sr-only">Actions</span></Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each answer as s (s.name)}
            <Table.Row>
              <Table.Cell class="font-mono">{s.name}</Table.Cell>
              <Table.Cell class="font-mono">{upstream(s)}</Table.Cell>
              <Table.Cell>{ms(s.connect_timeout_ms)}</Table.Cell>
              <Table.Cell>{ms(s.read_timeout_ms)}</Table.Cell>
              <Table.Cell class="text-right tabular-nums">{s.routes}</Table.Cell>
              <Table.Cell class="text-right">
                <ServiceSheet mode="edit" service={s} {workspace} {role} onsaved={load} />
              </Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>
    </div>
  {/if}
{/if}
