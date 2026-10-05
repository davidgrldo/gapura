<script>
  import * as Sheet from '$lib/components/ui/sheet/index.js'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import NativeSelect from './NativeSelect.svelte'
  import { Forbidden, write } from './api.js'
  import { ROLES, ROLE_LABEL } from './roles.js'
  import Plus from 'phosphor-svelte/lib/Plus'

  // The Roles page's sheets for group mappings, one component because the three send the same
  // request and fail the same way:
  // - `create` is Map a group: a group, a workspace and a role;
  // - `edit` changes the role only, because another group or another workspace is another
  //   mapping;
  // - `remove` asks first, because members lose the role at their next request.
  //
  // `mapping` is the row being edited or removed, `me` the reader from /api/me, and `mappings`
  // the table as last read, so Map a group can say when that pair is mapped already. `onsaved`
  // fetches the table again. `onremoved` is where focus goes after a removal, which takes the
  // row, and the button that opened this sheet, with it.
  let { mode, mapping = undefined, me, mappings = [], onsaved, onremoved = undefined } = $props()

  const id = $props.id()

  let open = $state(false)
  let group = $state('')
  let workspace = $state('')
  let role = $state('viewer')
  let saving = $state(false)
  let error = $state(undefined)
  // Read once the sheet has closed, to decide where focus goes, so it need not be state.
  let removed = false

  // Each time the sheet opens it starts again: from the row for edit and remove, and from the
  // first workspace the reader administers for a new mapping.
  function reset() {
    group = mapping?.group ?? ''
    workspace = mapping?.workspace_id ?? me.grantable[0]?.workspace_id ?? ''
    role = mapping?.role ?? 'viewer'
    saving = false
    error = undefined
    removed = false
  }

  // The same group already mapped in the chosen workspace, which saving then changes rather than
  // adds to. Said before Save, so nobody replaces a mapping believing they are adding one. The
  // name is compared exactly, as the server compares it with the groups claim.
  const existing = $derived(
    mode === 'create'
      ? mappings.find((m) => m.group === group && m.workspace_id === workspace)
      : undefined,
  )

  // Save waits for something to save: a role that differs from the mapping's, or a new mapping
  // with a name. The rules for a name are the server's, and its sentence is shown as it is, so
  // they are written in one place.
  const ready = $derived(
    mode === 'remove' ||
      (mode === 'edit'
        ? role !== mapping.role
        : group !== '' && workspace !== '' && existing?.role !== role),
  )

  async function save(event) {
    event.preventDefault()
    if (!ready || saving) return
    saving = true
    error = undefined
    try {
      if (mode === 'remove') {
        // In the query, encoded, because a name such as /platform-team has slashes of its own
        // and a path would split it.
        const key = new URLSearchParams({ workspace_id: mapping.workspace_id, group: mapping.group })
        await write('DELETE', `/api/group-mappings?${key}`)
      } else {
        await write('PUT', '/api/group-mappings', { workspace_id: workspace, group, role })
      }
    } catch (failure) {
      saving = false
      error = failure.message
      // Most likely the reader's own access changed since the table was read, so it is fetched
      // again to show what is true now.
      if (failure instanceof Forbidden) onsaved()
      return
    }
    removed = mode === 'remove'
    open = false
    onsaved()
  }

  // Where focus goes as the sheet closes. bits-ui returns it to the button that opened the
  // sheet, but after a removal that button is about to go with its row, so the page says where
  // instead.
  function closeAutoFocus(event) {
    if (removed && onremoved) {
      event.preventDefault()
      onremoved()
    }
  }
</script>

<Sheet.Root bind:open onOpenChange={(next) => next && reset()}>
  <Sheet.Trigger>
    {#snippet child({ props })}
      {#if mode === 'create'}
        <Button size="sm" {...props}><Plus aria-hidden="true" />Map a group</Button>
      {:else if mode === 'edit'}
        <!-- Named in full for a screen reader, which would otherwise hear "Edit" on every row.
             The name starts with the word on screen, so voice control finds it by what it
             shows. -->
        <Button
          variant="ghost"
          size="sm"
          aria-label="Edit the role of {mapping.group} in {mapping.workspace}"
          {...props}>Edit</Button
        >
      {:else}
        <Button
          variant="ghost"
          size="sm"
          class="text-danger"
          aria-label="Remove {mapping.group} from {mapping.workspace}"
          {...props}>Remove</Button
        >
      {/if}
    {/snippet}
  </Sheet.Trigger>
  <!-- Full width on a phone and wider beside a full page, as Edit access is. -->
  <Sheet.Content
    class="data-[side=right]:w-full data-[side=right]:sm:max-w-md"
    onCloseAutoFocus={closeAutoFocus}
  >
    <Sheet.Header>
      <Sheet.Title class="pr-8">
        {mode === 'create' ? 'Map a group' : mode === 'edit' ? 'Edit role' : 'Remove this mapping?'}
      </Sheet.Title>
      <Sheet.Description class="wrap-anywhere">
        {#if mode === 'create'}
          Everyone the identity provider puts in the group holds at least this role in the
          workspace.
        {:else}
          <span class="font-mono">{mapping.group}</span> in {mapping.workspace}.
          {#if mode === 'edit'}Another group or another workspace is another mapping.{/if}
        {/if}
      </Sheet.Description>
    </Sheet.Header>
    <form id="{id}-form" class="grid gap-5 overflow-y-auto px-4" onsubmit={save}>
      {#if mode === 'create'}
        <div class="grid gap-1.5">
          <label for="{id}-group" class="font-medium">Group</label>
          <Input
            id="{id}-group"
            class="font-mono"
            bind:value={group}
            autocomplete="off"
            spellcheck="false"
            aria-describedby="{id}-group-help"
            disabled={saving}
          />
          <p id="{id}-group-help" class="text-xs text-muted-foreground">
            Exactly as the groups claim sends it, for example /platform-team
          </p>
        </div>
        <div class="grid gap-1.5">
          <label for="{id}-workspace" class="font-medium">Workspace</label>
          <NativeSelect id="{id}-workspace" bind:value={workspace} disabled={saving}>
            {#each me.grantable as w (w.workspace_id)}
              <option value={w.workspace_id}>{w.workspace}</option>
            {/each}
          </NativeSelect>
        </div>
      {/if}
      {#if mode !== 'remove'}
        <div class="grid gap-1.5">
          <label for="{id}-role" class="font-medium">Role</label>
          <NativeSelect id="{id}-role" bind:value={role} disabled={saving}>
            {#each ROLES as r (r)}
              <option value={r}>{ROLE_LABEL[r]}</option>
            {/each}
          </NativeSelect>
        </div>
      {/if}
      {#if existing}
        <p class="text-muted-foreground">Already mapped as {ROLE_LABEL[existing.role]}; saving changes it.</p>
      {/if}
      {#if mode === 'remove'}
        <p>
          It will stop giving {ROLE_LABEL[mapping.role]} in {mapping.workspace}. Members lose this
          role at their next request.
        </p>
      {/if}
      {#if error}
        <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
          {error}
        </p>
      {/if}
    </form>
    <Sheet.Footer>
      <Button
        type="submit"
        form="{id}-form"
        variant={mode === 'remove' ? 'destructive' : 'default'}
        disabled={!ready || saving}
      >
        {#if mode === 'remove'}{saving ? 'Removing…' : 'Remove'}{:else}{saving ? 'Saving…' : 'Save'}{/if}
      </Button>
      <Sheet.Close>
        {#snippet child({ props })}
          <Button variant="outline" {...props}>Cancel</Button>
        {/snippet}
      </Sheet.Close>
    </Sheet.Footer>
  </Sheet.Content>
</Sheet.Root>
