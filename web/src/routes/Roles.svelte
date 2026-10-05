<script>
  import { get } from '../lib/api.js'
  import Failure from '../lib/Failure.svelte'
  import MappingSheet from '../lib/MappingSheet.svelte'
  import * as Table from '$lib/components/ui/table/index.js'
  import { ABILITIES, MATRIX, ROLE_LABEL } from '../lib/roles.js'
  import Check from 'phosphor-svelte/lib/Check'
  import Minus from 'phosphor-svelte/lib/Minus'

  // Who is signed in, from App: Map a group offers the workspaces they administer.
  let { me } = $props()

  // Counts and mappings come trimmed to the workspaces the reader administers; the matrix is
  // fixed, so it lives in roles.js rather than coming from the server. Fetched again after every
  // save, in place as on the Users page, so Held by and Seen follow the change.
  let answer = $state(undefined)
  let failed = $state(undefined)
  // Which fetch is the latest. A save fetches again while an earlier fetch may still be on its
  // way, and whichever finished last would win, the older one included.
  let latest = 0

  // The promise settles once the answer has been taken, or the failure noted, and never
  // rejects: the sheets wait on it to see where focus ended up after a row went.
  function load() {
    const mine = ++latest
    return get('/api/roles').then(
      (roles) => {
        if (mine !== latest) return
        answer = roles
        failed = undefined
      },
      (error) => {
        if (mine !== latest) return
        failed = error
      },
    )
  }
  load()

  // Named regions that scroll sideways on a phone, as the Overview table does.
  const region = (label) => ({ tabindex: 0, role: 'region', 'aria-label': label })

  // Where focus goes once a mapping's row, and the buttons in it, are gone and focus has fallen
  // to the page: after a removal, or after a table fetched again that no longer has the row, which
  // a refused edit can lead to as readily as a removal.
  let heading = $state(undefined)

  const focusHeading = () => heading?.focus()

  // "No one yet" beside a new mapping is the quickest sign that its group name does not match
  // what the identity provider sends. Counted from each enabled account's groups at its last
  // sign-in.
  function seen(count) {
    if (count === 0) return 'No one yet'
    return count === 1 ? '1 person' : `${count} people`
  }
</script>

<h1 class="mb-4 text-2xl font-semibold tracking-tight">Roles</h1>

{#if failed && answer === undefined}
  <Failure error={failed} what="the roles" />
{:else if answer === undefined}
  <p class="text-muted-foreground">Reading roles…</p>
{:else}
  {#if failed}
    <!-- A fetch after a save, or after a sheet that showed a refusal was closed, failed. The
         tables already on screen are kept, and the reader is told what they are: wiping them
         would take away the row whose sheet just closed, and with it the button focus returned
         to, over an error that says nothing about them. -->
    <div class="mb-4 space-y-2" role="status">
      <Failure error={failed} what="the roles" />
      <p class="text-sm text-muted-foreground">The tables below are as they were last read.</p>
    </div>
  {/if}
  <!-- Plain sections: each table's scrolling region is already a named landmark, and naming the
       section too would list every name twice. The headings carry the navigation. -->
  <section>
    <h2 class="mb-1 text-base font-semibold">What each role can do</h2>
    <p class="mb-3 max-w-2xl text-sm text-muted-foreground">
      Roles are fixed. A person's role in a workspace is the highest one any of their grants gives
      them there: grant one from Users, or map a group to one below.
    </p>
    <p class="mb-3 max-w-2xl text-sm text-muted-foreground">
      Held by counts the accounts holding each role in at least one of the workspaces you
      administer. An account with different roles in two workspaces counts under both, and a
      superuser counts only as a superuser.
    </p>
    <div class="rounded-lg border bg-card shadow-xs">
      <Table.Root aria-label="What each role can do" containerProps={region('What each role can do')}>
        <Table.Header>
          <Table.Row class="hover:bg-transparent">
            <Table.Head>Role</Table.Head>
            {#each ABILITIES as ability (ability)}
              <Table.Head class="text-center">{ability}</Table.Head>
            {/each}
            <Table.Head class="text-right">Held by</Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each MATRIX as row (row.key)}
            <Table.Row class="hover:bg-transparent">
              <!-- A row header, so a screen reader moving down a column hears which role each
                   Yes or No belongs to. Restyled from the column header's look to a cell's. -->
              <Table.Head scope="row" class="h-auto min-w-48 p-2 align-top font-normal whitespace-normal">
                <span class="font-medium">{row.label}</span>
                <span class="block text-xs text-muted-foreground">{row.scope}</span>
              </Table.Head>
              {#each row.can as allowed, i (ABILITIES[i])}
                <Table.Cell class="text-center align-top">
                  {#if allowed}
                    <Check class="mx-auto" aria-hidden="true" /><span class="sr-only">Yes</span>
                  {:else}
                    <Minus class="mx-auto text-muted-foreground" aria-hidden="true" /><span class="sr-only">No</span>
                  {/if}
                </Table.Cell>
              {/each}
              <Table.Cell class="text-right align-top tabular-nums">{answer.held_by[row.key]}</Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>
    </div>
  </section>

  <section class="mt-8">
    <div class="mb-1 flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
      <!-- tabindex -1: focus is put here when a row has gone, never reached by Tab. -->
      <h2 bind:this={heading} tabindex="-1" class="text-base font-semibold outline-none">Group mappings</h2>
      {#if me.grantable.length > 0}
        <MappingSheet mode="create" {me} mappings={answer.mappings} onsaved={load} />
      {/if}
    </div>
    <p class="mb-3 max-w-2xl text-sm text-muted-foreground">
      Everyone the identity provider put in a group at their last sign-in holds at least that role
      in that workspace. Only the workspaces you administer are shown. Seen counts the enabled
      accounts that were in the group at their last sign-in.
    </p>
    {#if answer.mappings.length === 0}
      <p class="text-muted-foreground">No group mappings in the workspaces you administer.</p>
    {:else}
      <div class="rounded-lg border bg-card shadow-xs">
        <Table.Root aria-label="Group mappings" containerProps={region('Group mappings')}>
          <Table.Header>
            <Table.Row class="hover:bg-transparent">
              <Table.Head>Group</Table.Head>
              <Table.Head>Workspace</Table.Head>
              <Table.Head>Role</Table.Head>
              <Table.Head>Seen</Table.Head>
              <Table.Head><span class="sr-only">Actions</span></Table.Head>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {#each answer.mappings as mapping (mapping.workspace_id + '/' + mapping.group)}
              <Table.Row class="hover:bg-transparent">
                <Table.Cell class="font-mono">{mapping.group}</Table.Cell>
                <Table.Cell>{mapping.workspace}</Table.Cell>
                <Table.Cell>{ROLE_LABEL[mapping.role]}</Table.Cell>
                <Table.Cell class={mapping.seen === 0 ? 'text-muted-foreground' : 'tabular-nums'}>{seen(mapping.seen)}</Table.Cell>
                <Table.Cell>
                  <div class="flex justify-end gap-1">
                    <MappingSheet mode="edit" {mapping} {me} onsaved={load} onremoved={focusHeading} />
                    <MappingSheet mode="remove" {mapping} {me} onsaved={load} onremoved={focusHeading} />
                  </div>
                </Table.Cell>
              </Table.Row>
            {/each}
          </Table.Body>
        </Table.Root>
      </div>
    {/if}
  </section>
{/if}
