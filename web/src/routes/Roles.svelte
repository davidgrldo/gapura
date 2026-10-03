<script>
  import { get } from '../lib/api.js'
  import Failure from '../lib/Failure.svelte'
  import * as Table from '$lib/components/ui/table/index.js'
  import { ABILITIES, MATRIX, ROLE_LABEL } from '../lib/roles.js'
  import Check from 'phosphor-svelte/lib/Check'
  import Minus from 'phosphor-svelte/lib/Minus'

  // Counts and mappings come trimmed to the workspaces the reader administers; the matrix is
  // fixed, so it lives in roles.js rather than coming from the server.
  const roles = get('/api/roles')

  // Named regions that scroll sideways on a phone, as the Overview table does.
  const region = (label) => ({ tabindex: 0, role: 'region', 'aria-label': label })
</script>

<h1 class="mb-4 text-2xl font-semibold tracking-tight">Roles</h1>

{#await roles}
  <p class="text-muted-foreground">Reading roles…</p>
{:then answer}
  <!-- Plain sections: each table's scrolling region is already a named landmark, and naming the
       section too would list every name twice. The headings carry the navigation. -->
  <section>
    <h2 class="mb-1 text-base font-semibold">What each role can do</h2>
    <p class="mb-3 max-w-2xl text-sm text-muted-foreground">
      Roles are fixed. A person's role in a workspace is the highest one any of their grants gives
      them there. The console cannot change who holds which role yet.
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
    <h2 class="mb-1 text-base font-semibold">Group mappings</h2>
    <p class="mb-3 max-w-2xl text-sm text-muted-foreground">
      Everyone the identity provider put in a group at their last sign-in holds at least that role
      in that workspace. Only the workspaces you administer are shown.
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
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {#each answer.mappings as mapping (mapping.workspace_id + '/' + mapping.group)}
              <Table.Row class="hover:bg-transparent">
                <Table.Cell class="font-mono">{mapping.group}</Table.Cell>
                <Table.Cell>{mapping.workspace}</Table.Cell>
                <Table.Cell>{ROLE_LABEL[mapping.role]}</Table.Cell>
              </Table.Row>
            {/each}
          </Table.Body>
        </Table.Root>
      </div>
    {/if}
  </section>
{:catch error}
  <Failure {error} what="the roles" />
{/await}
