<script>
  import { get } from '../lib/api.js'
  import Failure from '../lib/Failure.svelte'
  import ConsumerSheet from '../lib/ConsumerSheet.svelte'
  import KeyAuthControl from '../lib/KeyAuthControl.svelte'
  import JwtControl from '../lib/JwtControl.svelte'
  import RateLimitControl from '../lib/RateLimitControl.svelte'
  import Tag from '../lib/Tag.svelte'
  import WorkspacePicker from '../lib/WorkspacePicker.svelte'
  import * as Table from '$lib/components/ui/table/index.js'
  import { base, when } from '../lib/configuration.js'
  import { can, remembered } from '../lib/workspace.js'

  let { me } = $props()
  // Only the starting choice: the picker owns it from here, and `me` is read once when the page
  // is made.
  // svelte-ignore state_referenced_locally
  let workspace = $state(remembered(me.roles))
  const role = $derived(me.roles.find((r) => r.workspace === workspace)?.role)
  // `{ consumers, keyAuth, jwt, rateLimit }`, read together: the workspace-wide key requirement
  // sits above the table, and is what the consumers' keys are asked for; the workspace-wide JWT
  // requirement and request limit sit under it.
  let answer = $state(undefined)
  let failed = $state(undefined)
  // The newest request's number, so a slow answer for a workspace the reader has left cannot
  // overwrite the one they are looking at.
  let latest = 0

  // Settles once the lists are drawn or have failed, and never rejects: the sheets wait on it.
  function load() {
    const mine = ++latest
    if (!workspace) return Promise.resolve()
    return Promise.all([
      get(base(workspace, 'consumers')),
      get(base(workspace, 'key-auth')),
      get(base(workspace, 'jwt')),
      get(base(workspace, 'rate-limit')),
    ]).then(
      ([consumers, keyAuths, jwts, limits]) => {
        if (mine !== latest) return
        const own = keyAuths.find((r) => r.target === 'workspace')
        const token = jwts.find((r) => r.target === 'workspace')
        const limited = limits.find((r) => r.target === 'workspace')
        answer = {
          consumers,
          keyAuth: own ? { header: own.header, from: 'workspace' } : null,
          jwt: token ? { issuer: token.issuer, from: 'workspace' } : null,
          rateLimit: limited ? { limit: limited.limit, per: limited.per, from: 'workspace' } : null,
        }
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
  const region = (label) => ({ tabindex: 0, role: 'region', 'aria-label': label })
  const active = (c) => c.keys.filter((k) => !k.expired).length
</script>

<h1 bind:this={heading} tabindex="-1" class="mb-4 text-2xl font-semibold tracking-tight outline-none">Consumers</h1>
<WorkspacePicker roles={me.roles} bind:value={workspace} />

{#if !workspace}
  <p class="text-muted-foreground">You hold no role in any workspace yet.</p>
{:else if failed && answer === undefined}
  <Failure error={failed} what="the consumers" />
{:else if answer === undefined}
  <p class="text-muted-foreground">Reading consumers…</p>
{:else}
  {#if failed}
    <!-- A fetch after a save failed. The table on screen is kept, and the reader is told what it
         is, as on the Services page. -->
    <div class="mb-4 space-y-2" role="status">
      <Failure error={failed} what="the consumers" />
      <p class="text-sm text-muted-foreground">The consumers below are as they were last read.</p>
    </div>
  {/if}
  <section class="mb-6 grid max-w-md gap-2" aria-labelledby="workspace-key-auth">
    <h2 id="workspace-key-auth" class="text-sm font-medium">Require an API key on every route in {workspace}</h2>
    <KeyAuthControl {workspace} target="workspace" applies={answer.keyAuth} {role} onchanged={load} />
  </section>
  <section class="mb-6 grid max-w-md gap-2" aria-labelledby="workspace-jwt">
    <h2 id="workspace-jwt" class="text-sm font-medium">Require a JWT on every route in {workspace}</h2>
    <JwtControl {workspace} target="workspace" applies={answer.jwt} {role} onchanged={load} />
  </section>
  <section class="mb-6 grid max-w-md gap-2" aria-labelledby="workspace-rate-limit">
    <h2 id="workspace-rate-limit" class="text-sm font-medium">Limit requests on every route in {workspace}</h2>
    <RateLimitControl {workspace} target="workspace" applies={answer.rateLimit} {role} onchanged={load} />
  </section>
  <div class="mb-3 flex items-center justify-between gap-4">
    <p class="text-sm text-muted-foreground">Who may call the routes in {workspace} that require an API key.</p>
    {#if can.write(role)}<ConsumerSheet mode="create" {workspace} {role} onsaved={load} onremoved={focusHeading} />{/if}
  </div>
  {#if answer.consumers.length === 0}
    <p class="text-muted-foreground">No consumers yet.</p>
  {:else}
    <div class="rounded-lg border bg-card shadow-xs">
      <Table.Root aria-label="Consumers" containerProps={region('Consumers')}>
        <Table.Header>
          <Table.Row class="hover:bg-transparent">
            <Table.Head>Name</Table.Head>
            <Table.Head class="text-right">Active keys</Table.Head>
            <Table.Head>Newest key</Table.Head><Table.Head>Expires</Table.Head>
            <Table.Head><span class="sr-only">Actions</span></Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          <!-- Keyed by name, so a fetch after issuing a key keeps each row's sheet, and the key on
               show in it, where it was. -->
          {#each answer.consumers as c (c.name)}
            <!-- Keys arrive newest first. -->
            {@const newest = c.keys[0]}
            <Table.Row>
              <Table.Cell class="font-mono">{c.name}</Table.Cell>
              <Table.Cell class="text-right tabular-nums">{active(c)}</Table.Cell>
              <Table.Cell class="font-mono">
                {#if newest}{newest.prefix}{:else}<span class="font-sans text-muted-foreground">none</span>{/if}
              </Table.Cell>
              <Table.Cell>
                {#if newest}
                  <span class="inline-flex items-center gap-1.5">
                    {newest.expires_at ? when(newest.expires_at) : 'never'}
                    {#if newest.expired}<Tag tone="idle">Expired</Tag>{/if}
                  </span>
                {/if}
              </Table.Cell>
              <Table.Cell class="text-right">
                <ConsumerSheet mode="edit" consumer={c} {workspace} {role} onsaved={load} onremoved={focusHeading} />
              </Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>
    </div>
  {/if}
{/if}
