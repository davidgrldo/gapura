<script>
  import { get } from '../lib/api.js'
  import Failure from '../lib/Failure.svelte'
  import RouteSheet from '../lib/RouteSheet.svelte'
  import Tag from '../lib/Tag.svelte'
  import WorkspacePicker from '../lib/WorkspacePicker.svelte'
  import * as Table from '$lib/components/ui/table/index.js'
  import { anyOf, base } from '../lib/configuration.js'
  import { can, remembered } from '../lib/workspace.js'
  import Lock from 'phosphor-svelte/lib/Lock'

  let { me } = $props()
  // Only the starting choice: the picker owns it from here, and `me` is read once when the page
  // is made.
  // svelte-ignore state_referenced_locally
  let workspace = $state(remembered(me.roles))
  const role = $derived(me.roles.find((r) => r.workspace === workspace)?.role)
  // `{ routes, services }`, read together: the sheet offers the services, and a workspace without
  // any gets a pointer instead of a form that could not be saved.
  let answer = $state(undefined)
  let failed = $state(undefined)
  // The newest request's number, so a slow answer for a workspace the reader has left cannot
  // overwrite the one they are looking at.
  let latest = 0

  // Settles once the lists are drawn or have failed, and never rejects: the sheets wait on it.
  function load() {
    const mine = ++latest
    if (!workspace) return Promise.resolve()
    return Promise.all([get(base(workspace, 'routes')), get(base(workspace, 'services'))]).then(
      ([routes, services]) => {
        if (mine !== latest) return
        answer = { routes, services: services.map((s) => s.name) }
        failed = undefined
      },
      (error) => {
        if (mine === latest) failed = error
      },
    )
  }

  // Starts again from nothing on a new workspace, so another workspace's rows are never shown
  // under this one's name, nor its failure.
  $effect(() => {
    workspace
    answer = undefined
    failed = undefined
    load()
  })

  // Where focus goes when a saved list no longer has the row a sheet's button was in.
  let heading = $state(undefined)
  const focusHeading = () => heading?.focus()

  const paths = (list) =>
    list.length === 0 ? 'any' : list.map((p) => `${p.type} ${p.value}`).join(', ')
  const region = (label) => ({ tabindex: 0, role: 'region', 'aria-label': label })
  // The lock beside a name says a key is required there, and where that is set: on the row
  // itself, or on what it inherits from. The title is for a pointer; the sr-only text says it to
  // everyone else.
  const locked = (row) =>
    row.key_auth ? `Requires an API key in the ${row.key_auth.header} header, set on the ${row.key_auth.from}` : undefined
  // The JWT tag beside it says the same of a token, and whose. An issuer is missing only from a
  // requirement written by hand in SQL, which accepts any.
  const tokened = (row) => `Requires a JWT from ${row.jwt.issuer ?? 'any issuer'} (from the ${row.jwt.from})`
</script>

<h1 bind:this={heading} tabindex="-1" class="mb-4 text-2xl font-semibold tracking-tight outline-none">Routes</h1>
<WorkspacePicker roles={me.roles} bind:value={workspace} />

{#if !workspace}
  <p class="text-muted-foreground">You hold no role in any workspace yet.</p>
{:else if failed && answer === undefined}
  <Failure error={failed} what="the routes" />
{:else if answer === undefined}
  <p class="text-muted-foreground">Reading routes…</p>
{:else}
  {#if failed}
    <!-- A fetch after a save failed. The table on screen is kept, and the reader is told what it
         is, as on the Services page: wiping it would take away the row focus returned to. -->
    <div class="mb-4 space-y-2" role="status">
      <Failure error={failed} what="the routes" />
      <p class="text-sm text-muted-foreground">The routes below are as they were last read.</p>
    </div>
  {/if}
  <div class="mb-3 flex flex-wrap items-center justify-between gap-4">
    <p class="text-sm text-muted-foreground">
      Which requests go to which service in {workspace}, in the order the gateway tries them.
    </p>
    {#if can.write(role) && answer.services.length > 0}
      <RouteSheet mode="create" services={answer.services} {workspace} {role} superuser={me.superuser} onsaved={load} onremoved={focusHeading} />
    {/if}
  </div>
  {#if answer.services.length === 0}
    <p class="text-muted-foreground">
      Routes send traffic to a service, and {workspace} has none yet.
      {#if can.write(role)}
        <a class="underline" href="/services">Create one on the Services page.</a>
      {/if}
    </p>
  {:else if answer.routes.length === 0}
    <p class="text-muted-foreground">No routes yet.</p>
  {:else}
    <div class="rounded-lg border bg-card shadow-xs">
      <Table.Root aria-label="Routes" containerProps={region('Routes')}>
        <Table.Header>
          <Table.Row class="hover:bg-transparent">
            <Table.Head>Name</Table.Head>
            <Table.Head>Service</Table.Head>
            <Table.Head>Hosts</Table.Head>
            <Table.Head>Paths</Table.Head>
            <Table.Head>Methods</Table.Head>
            <Table.Head>Headers</Table.Head>
            <Table.Head class="text-right">Priority</Table.Head>
            <Table.Head><span class="sr-only">Actions</span></Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each answer.routes as r (r.name)}
            <Table.Row>
              <Table.Cell class="font-mono">
                <span class="inline-flex items-center gap-1.5" title={locked(r)}>
                  {r.name}
                  {#if r.key_auth}
                    <Lock aria-hidden="true" class="size-3.5 text-muted-foreground" />
                    <span class="sr-only">, requires an API key (from the {r.key_auth.from})</span>
                  {/if}
                  {#if r.jwt}
                    <span class="inline-flex font-sans" title={tokened(r)}>
                      <Tag tone="idle"><span aria-hidden="true">JWT</span></Tag>
                      <span class="sr-only">, requires a JWT from {r.jwt.issuer ?? 'any issuer'} (from the {r.jwt.from})</span>
                    </span>
                  {/if}
                </span>
              </Table.Cell>
              <Table.Cell class="font-mono">{r.service}</Table.Cell>
              <Table.Cell class="font-mono">{anyOf(r.hosts)}</Table.Cell>
              <Table.Cell class="font-mono">{paths(r.paths)}</Table.Cell>
              <Table.Cell class="font-mono">{anyOf(r.methods)}</Table.Cell>
              <Table.Cell class="font-mono">
                <!-- Each header a chip of its own, since a value may hold spaces and commas that
                     would blur a joined list. The chips wrap within a column of bounded width, and
                     a long value breaks inside its chip only once it no longer fits the column:
                     breaking anywhere would let the table squeeze the column to a sliver. -->
                {#if (r.headers ?? []).length === 0}
                  any
                {:else}
                  <span class="flex min-w-48 max-w-72 flex-wrap gap-1.5">
                    {#each r.headers as h (h.name)}
                      <Tag class="max-w-full font-mono whitespace-normal wrap-break-word">{h.name}: {h.value}</Tag>
                    {/each}
                  </span>
                {/if}
              </Table.Cell>
              <Table.Cell class="text-right tabular-nums">{r.priority}</Table.Cell>
              <Table.Cell class="text-right">
                <RouteSheet mode="edit" route={r} services={answer.services} {workspace} {role} superuser={me.superuser} onsaved={load} onremoved={focusHeading} />
              </Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>
    </div>
  {/if}
{/if}
