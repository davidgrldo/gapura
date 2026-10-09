<script>
  import { get } from '../lib/api.js'
  import Failure from '../lib/Failure.svelte'
  import ServiceSheet from '../lib/ServiceSheet.svelte'
  import Tag from '../lib/Tag.svelte'
  import WorkspacePicker from '../lib/WorkspacePicker.svelte'
  import * as Table from '$lib/components/ui/table/index.js'
  import { base, ms, upstream } from '../lib/configuration.js'
  import { can, remembered } from '../lib/workspace.js'
  import Lock from 'phosphor-svelte/lib/Lock'

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
  $effect(() => { workspace; answer = undefined; failed = undefined; load() })
  // Where focus goes when a saved list no longer has the row a sheet's button was in.
  let heading = $state(undefined)
  const focusHeading = () => heading?.focus()
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

<h1 bind:this={heading} tabindex="-1" class="mb-4 text-2xl font-semibold tracking-tight outline-none">Services</h1>
<WorkspacePicker roles={me.roles} bind:value={workspace} />

{#if !workspace}
  <p class="text-muted-foreground">You hold no role in any workspace yet.</p>
{:else if failed && answer === undefined}
  <Failure error={failed} what="the services" />
{:else if answer === undefined}
  <p class="text-muted-foreground">Reading services…</p>
{:else}
  {#if failed}
    <!-- A fetch after a save failed. The table on screen is kept, and the reader is told what it
         is, as on the Roles page: wiping it would take away the row focus returned to. -->
    <div class="mb-4 space-y-2" role="status">
      <Failure error={failed} what="the services" />
      <p class="text-sm text-muted-foreground">The services below are as they were last read.</p>
    </div>
  {/if}
  <div class="mb-3 flex items-center justify-between gap-4">
    <p class="text-sm text-muted-foreground">The upstreams routes in {workspace} send traffic to.</p>
    {#if can.write(role)}<ServiceSheet mode="create" {workspace} {role} onsaved={load} onremoved={focusHeading} />{/if}
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
              <Table.Cell class="font-mono">
                <span class="inline-flex items-center gap-1.5" title={locked(s)}>
                  {s.name}
                  {#if s.key_auth}
                    <Lock aria-hidden="true" class="size-3.5 text-muted-foreground" />
                    <span class="sr-only">, requires an API key (from the {s.key_auth.from})</span>
                  {/if}
                  {#if s.jwt}
                    <span class="inline-flex font-sans" title={tokened(s)}>
                      <Tag tone="idle"><span aria-hidden="true">JWT</span></Tag>
                      <span class="sr-only">, requires a JWT from {s.jwt.issuer ?? 'any issuer'} (from the {s.jwt.from})</span>
                    </span>
                  {/if}
                </span>
              </Table.Cell>
              <Table.Cell>
                <!-- What an https upstream's TLS settings change from the defaults. A different
                     SNI alone is not tagged: it changes the name, not whether the upstream is
                     trusted. -->
                <span class="inline-flex flex-wrap items-center gap-1.5">
                  <span class="font-mono">{upstream(s)}</span>
                  {#if s.protocol === 'https' && s.tls?.verify === false}<Tag tone="warn">verify off</Tag>{/if}
                  {#if s.protocol === 'https' && s.tls?.ca_pem}<Tag>own CA</Tag>{/if}
                </span>
              </Table.Cell>
              <Table.Cell>{ms(s.connect_timeout_ms)}</Table.Cell>
              <Table.Cell>{ms(s.read_timeout_ms)}</Table.Cell>
              <Table.Cell class="text-right tabular-nums">{s.routes}</Table.Cell>
              <Table.Cell class="text-right">
                <ServiceSheet mode="edit" service={s} {workspace} {role} onsaved={load} onremoved={focusHeading} />
              </Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>
    </div>
  {/if}
{/if}
