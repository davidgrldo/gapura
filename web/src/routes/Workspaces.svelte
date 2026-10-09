<script>
  import { tick } from 'svelte'
  import { get } from '../lib/api.js'
  import Failure from '../lib/Failure.svelte'
  import WorkspaceSheet from '../lib/WorkspaceSheet.svelte'
  import * as Table from '$lib/components/ui/table/index.js'

  // Who is signed in, from App, and App's way of asking /api/me again: creating, renaming or
  // deleting a workspace changes the workspaces /api/me lists, which the pickers and the access
  // pages read.
  let { me, refresh } = $props()
  const superuser = $derived(me.superuser)

  // `/api/workspaces` lists every workspace to a superuser and the ones they administer to a
  // workspace admin, sorted by name. Fetched again after a change, in place as on the Data planes
  // page, so the button that opened a sheet is still there for focus to return to.
  let answer = $state(undefined)
  let failed = $state(undefined)
  // The newest request's number, so a slow answer cannot overwrite a newer one.
  let latest = 0

  function load() {
    const mine = ++latest
    return get('/api/workspaces').then(
      (workspaces) => {
        if (mine !== latest) return
        answer = workspaces
        failed = undefined
      },
      (error) => {
        if (mine === latest) failed = error
      },
    )
  }
  load()

  // What the sheets wait on after a change: the list and who is signed in, both read again.
  // Settles once both are drawn or have failed, and never rejects.
  const saved = () => Promise.all([load(), refresh?.()])

  // Where focus goes when a saved list no longer has the row a sheet's button was in.
  let heading = $state(undefined)
  const focusHeading = () => heading?.focus()

  // After a rename the row is the same workspace under a new name, keyed by it, so its button is
  // a new one: focus goes there, or to the heading if the list read back does not have it.
  let table = $state(undefined)
  async function focusRenamed(name) {
    await tick()
    const button = [...(table?.querySelectorAll('[data-workspace]') ?? [])].find((b) => b.dataset.workspace === name)
    ;(button ?? heading)?.focus()
  }

  const region = (label) => ({ tabindex: 0, role: 'region', 'aria-label': label })
</script>

<h1 bind:this={heading} tabindex="-1" class="mb-4 text-2xl font-semibold tracking-tight outline-none">Workspaces</h1>

<div class="mb-3 flex items-start justify-between gap-4">
  <div class="grid max-w-2xl gap-1 text-sm text-muted-foreground">
    <p>
      {superuser ? 'Every workspace' : 'The workspaces you administer'}, with what each holds. Members counts the direct
      grants and group mappings into it.
    </p>
    {#if !superuser}
      <p>Only a superuser creates, renames and deletes workspaces.</p>
    {/if}
  </div>
  {#if superuser}<WorkspaceSheet mode="create" onsaved={saved} onremoved={focusHeading} />{/if}
</div>

{#if failed && answer === undefined}
  <Failure error={failed} what="the workspaces" />
{:else if answer === undefined}
  <p class="text-muted-foreground">Reading workspaces…</p>
{:else}
  {#if failed}
    <!-- A fetch after a save failed. The table on screen is kept, and the reader is told what it
         is, as on the Data planes page. -->
    <div class="mb-4 space-y-2" role="status">
      <Failure error={failed} what="the workspaces" />
      <p class="text-sm text-muted-foreground">The workspaces below are as they were last read.</p>
    </div>
  {/if}
  {#if answer.length === 0}
    <p class="text-muted-foreground">No workspaces.</p>
  {:else}
    <div bind:this={table} class="rounded-lg border bg-card shadow-xs">
      <Table.Root aria-label="Workspaces" containerProps={region('Workspaces')}>
        <Table.Header>
          <Table.Row class="hover:bg-transparent">
            <Table.Head>Name</Table.Head>
            <Table.Head class="text-right">Services</Table.Head>
            <Table.Head class="text-right">Routes</Table.Head>
            <Table.Head class="text-right">Consumers</Table.Head>
            <Table.Head class="text-right">Members</Table.Head>
            {#if superuser}<Table.Head><span class="sr-only">Actions</span></Table.Head>{/if}
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each answer as workspace (workspace.name)}
            <Table.Row>
              <Table.Cell class="font-mono">{workspace.name}</Table.Cell>
              <Table.Cell class="text-right tabular-nums">{workspace.services}</Table.Cell>
              <Table.Cell class="text-right tabular-nums">{workspace.routes}</Table.Cell>
              <Table.Cell class="text-right tabular-nums">{workspace.consumers}</Table.Cell>
              <Table.Cell class="text-right tabular-nums">{workspace.members}</Table.Cell>
              {#if superuser}
                <Table.Cell class="text-right">
                  <WorkspaceSheet
                    mode="edit"
                    {workspace}
                    only={answer.length === 1}
                    onsaved={saved}
                    onremoved={focusHeading}
                    onrenamed={focusRenamed}
                  />
                </Table.Cell>
              {/if}
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>
    </div>
  {/if}
{/if}
