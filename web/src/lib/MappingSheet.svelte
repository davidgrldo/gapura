<script>
  import { tick } from 'svelte'
  import * as Sheet from '$lib/components/ui/sheet/index.js'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import NativeSelect from './NativeSelect.svelte'
  import { write } from './api.js'
  import { ROLES, ROLE_LABEL } from './roles.js'
  import Plus from 'phosphor-svelte/lib/Plus'

  // The Roles page's sheets for group mappings, one component because the three go to the same
  // endpoint and fail the same way:
  // - `create` is Map a group: a group, a workspace and a role;
  // - `edit` changes the role only, because another group or another workspace is another
  //   mapping;
  // - `remove` asks first, because members lose the role at their next request.
  // Any of the three asks again before a save that would take the reader's own admin away.
  //
  // `mapping` is the row being edited or removed, `me` the reader from /api/me, and `mappings`
  // the table as last read, so Map a group can say when that pair is mapped already. `onsaved`
  // fetches the table again and returns a promise that settles once the new table is on the page
  // or the fetch has failed, and never rejects. `onremoved` is where focus goes when the new table
  // no longer has the row this sheet's button was in, which takes the button with it: after a
  // removal, or when the row was removed by someone else, or is out of the reader's reach now.
  let { mode, mapping = undefined, me, mappings = [], onsaved, onremoved = undefined } = $props()

  const id = $props.id()

  let open = $state(false)
  // The button that opens the sheet, kept so focus can be put back on it after a save.
  let trigger = $state(null)
  // The submit button, so focus can go back to it after a refusal: disabling it while saving
  // drops focus.
  let submit = $state(null)
  // Cancel, where the remove sheet puts focus when it opens.
  let cancel = $state(null)
  let group = $state('')
  let workspace = $state('')
  let role = $state('viewer')
  let saving = $state(false)
  let error = $state(undefined)
  // When the sheet was opened, by `performance.now()`. Not state: nothing is drawn from it.
  let openedAt = 0
  // Set once the reader has been shown what this save costs them, as in Edit access.
  let confirming = $state(false)
  // When that was, by `performance.now()`. Not state: nothing is drawn from it.
  let askedAt = 0
  // Set when a request was refused, so that the table is fetched again once the sheet closes.
  // Not state: nothing is drawn from it.
  let staleOnClose = false

  // Each time the sheet opens it starts again: from the row for edit and remove, and from the
  // first workspace the reader administers for a new mapping.
  function reset() {
    group = mapping?.group ?? ''
    workspace = mapping?.workspace_id ?? me.grantable[0]?.workspace_id ?? ''
    role = mapping?.role ?? 'viewer'
    saving = false
    error = undefined
    confirming = false
    openedAt = performance.now()
  }

  // The same group already mapped in the chosen workspace, which saving then changes rather than
  // adds to. The name is compared exactly, because that is the store's key: two names that differ
  // only in case are two mappings.
  const mapped = $derived(
    mode === 'create'
      ? mappings.find((m) => m.group === group && m.workspace_id === workspace)
      : undefined,
  )

  // `mapped`, said before Save so nobody replaces a mapping believing they are adding one, and
  // only while the sheet is open. The table is fetched again as the sheet closes, with the
  // mapping just saved in it, and the note would flash up as a fresh status on a sheet on its way
  // out.
  const existing = $derived(open ? mapped : undefined)

  // The mapping this save changes or removes: the row's, or, for Map a group, the one already
  // there for that group and workspace, which saving replaces.
  const target = $derived(mode === 'create' ? mapped : mapping)

  // Whether this save takes the reader's own admin away in the target's workspace with nothing
  // else keeping it: the group gives admin there, the reader is in it, and no other grant of
  // theirs gives admin there, a superuser's included. The server allows it, because an admin may
  // change any mapping in their workspace. The sheet asks first, as Edit access does, because the
  // next thing they might try there is to undo it, and by then they cannot. `me` is as the page
  // read it, with the reader's groups as of their last sign-in.
  const losing = $derived.by(() => {
    if (target?.role !== 'admin' || (mode !== 'remove' && role === 'admin')) return false
    const sources = me.roles.find((r) => r.workspace_id === target.workspace_id)?.sources ?? []
    const through = (s) => s.kind === 'group' && s.name === target.group
    return sources.some(through) && !sources.some((s) => !through(s) && s.role === 'admin')
  })

  // Whether the warning is up: `confirming` alone could outlive what it was asked about, if the
  // fields changed under it.
  const asking = $derived(confirming && losing)

  // Save waits for something to save: a role that differs from the mapping's, or a new mapping
  // with a name. It stays disabled while the pair is already mapped at the chosen role, since
  // saving would change nothing. The rules for a name are the server's, and its sentence is shown
  // as it is, so they are written in one place.
  const ready = $derived(
    mode === 'remove' ||
      (mode === 'edit'
        ? role !== mapping.role
        : group !== '' && workspace !== '' && mapped?.role !== role),
  )

  async function save(event) {
    event.preventDefault()
    if (!ready || saving) return
    // A double-click on a row's Remove opens this sheet with its first click and sends its second
    // to whatever the sheet has put under the pointer, which can be its own Remove, so the
    // mapping would go before anyone had read the question. Half a second is longer than a
    // double-click takes and shorter than anyone takes to read the question and mean it. Enter
    // held down is stopped at the buttons, which ignore key repeats.
    if (mode === 'remove' && performance.now() - openedAt < 500) {
      // The ignored click still focused Remove; the question opens on Cancel, so it goes back.
      cancel?.focus()
      return
    }
    if (losing && !confirming) {
      confirming = true
      askedAt = performance.now()
      return
    }
    // A double-click sends its second submit long before the warning could have been read, as
    // in Edit access, so for half a second after it appears a submit is ignored.
    if (confirming && performance.now() - askedAt < 500) return
    // Where focus is as the request goes: the Group field if Enter sent the form from there, and
    // the button otherwise. Read now, because disabling the fields below takes focus away.
    const from = document.activeElement
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
      // A refused save is not the one that was asked about: saving again asks again.
      confirming = false
      error = failure.message
      // Not fetched again yet. Whatever refused this, a 403 because the reader's access changed,
      // a 404 because the mapping is already gone, or a dropped connection that leaves it unknown
      // whether anything was saved, the table on the page is probably out of date. But for an
      // edit or a removal the new one could drop the row this sheet lives in, and the sheet, with
      // the sentence the reader is meant to read, would go within milliseconds. So it is fetched
      // when they close the sheet, for every mode alike.
      staleOnClose = true
      // The fields were disabled while the request ran, which took focus away from whichever had
      // it. It goes back to that one, so a refusal of a name leaves the reader in the Group field
      // to correct it, with the sentence just below; any other place it was, the button.
      await tick()
      const back = from?.form?.id === `${id}-form` ? from : submit
      back?.focus()
      return
    }
    if (losing) {
      // The reader's own access changed, and with it the navigation App built from /api/me, which
      // still offers this page. A reload asks again.
      location.reload()
      return
    }
    // The table about to be fetched is as new as can be, so nothing is left to fetch on closing.
    staleOnClose = false
    open = false
    // Closing the sheet handed focus back to the button that opened it, and the table is fetched
    // again and drawn before looking where it is now.
    await onsaved()
    await tick()
    keepPlace()
  }

  // Where focus goes once a new table has been drawn under a sheet that has closed. A row that
  // goes takes its buttons with it, and focus falls to the page itself: a removal always does
  // that, an edit or a new mapping does not, since rows are ordered by workspace and group, which
  // a save leaves alone, but the server's order is its own to change. Where focus did fall, it
  // goes back to the button that opened the sheet, or, if that has gone with its row, to where
  // the page says. Focus the reader has put somewhere else in the meantime is left where it is.
  function keepPlace() {
    if (document.activeElement !== document.body) return
    if (trigger?.isConnected) trigger.focus()
    else onremoved?.()
  }

  // Called when the reader's own act has closed the sheet, once per close: bits-ui asks the setter
  // below for every one of them, and the setter says whether they got their way. Closing after a
  // refusal is when the table, left alone while the sheet was showing why, is fetched again.
  async function closed() {
    if (!staleOnClose) return
    staleOnClose = false
    await onsaved()
    await tick()
    keepPlace()
  }

  function setOpen(next) {
    if (!next && saving) return
    open = next
    if (!next) closed()
  }
</script>

<!-- The setter refuses to close while a request is in flight, which stops Escape, a click outside,
     the corner button and Cancel alike, since bits-ui closes through it for every one of them. A
     sheet closed then could be opened again over a request that has not answered, and its error
     would have nowhere to be read. Not `onOpenChange`, which bits-ui calls even for a close the
     setter has refused. -->
<Sheet.Root bind:open={() => open, setOpen} onOpenChange={(next) => next && reset()}>
  <Sheet.Trigger>
    {#snippet child({ props })}
      {#if mode === 'create'}
        <Button bind:ref={trigger} size="sm" {...props}><Plus aria-hidden="true" />Map a group</Button>
      {:else if mode === 'edit'}
        <!-- Named in full for a screen reader, which would otherwise hear "Edit" on every row.
             The name starts with the word on screen, so voice control finds it by what it
             shows. -->
        <Button
          bind:ref={trigger}
          variant="ghost"
          size="sm"
          aria-label="Edit the role of {mapping.group} in {mapping.workspace}"
          {...props}>Edit</Button
        >
      {:else}
        <Button
          bind:ref={trigger}
          variant="ghost"
          size="sm"
          class="text-danger"
          aria-label="Remove {mapping.group} from {mapping.workspace}"
          {...props}>Remove</Button
        >
      {/if}
    {/snippet}
  </Sheet.Trigger>
  <!-- Full width on a phone and wider beside a full page, as Edit access is. The remove sheet
       has no field, so its first focusable control would be Remove itself, and an Enter meant
       for the row's button, or held a moment too long, would remove the mapping unasked; it
       opens on Cancel instead, the way a confirmation should. -->
  <Sheet.Content
    class="data-[side=right]:w-full data-[side=right]:sm:max-w-md"
    onOpenAutoFocus={(event) => {
      if (mode !== 'remove') return
      event.preventDefault()
      cancel?.focus()
    }}
  >
    <Sheet.Header>
      <Sheet.Title class="pr-8">
        {mode === 'create' ? 'Map a group' : mode === 'edit' ? 'Edit role' : 'Remove this mapping?'}
      </Sheet.Title>
      <!-- What removing means is said here, not in the form, so that a screen reader reads it as
           the sheet opens on Cancel, which on its own would be heard as just "Cancel". -->
      <Sheet.Description class="wrap-anywhere">
        {#if mode === 'create'}
          Everyone the identity provider puts in the group holds at least this role in the
          workspace.
        {:else}
          <span class="font-mono">{mapping.group}</span> in {mapping.workspace}.
          {#if mode === 'edit'}
            Another group or another workspace is another mapping.
          {:else}
            It will stop giving {ROLE_LABEL[mapping.role]} in {mapping.workspace}. Members lose
            this role at their next request.
          {/if}
        {/if}
      </Sheet.Description>
    </Sheet.Header>
    <!-- The form scrolls on its own, so a tall form on a short screen never pushes the buttons off
         the bottom of the sheet. The remove sheet has nothing to fill in, so its form is empty,
         there for the button below to submit. -->
    <form
      id="{id}-form"
      class="grid gap-5 overflow-y-auto px-4"
      onsubmit={save}
      oninput={() => (confirming = false)}
    >
      {#if mode === 'create'}
        <div class="grid gap-1.5">
          <label for="{id}-group" class="font-medium">Group</label>
          <!-- Off for a phone's keyboard too: a name it capitalised or corrected would be another
               mapping, and one that nobody is in. -->
          <Input
            id="{id}-group"
            class="font-mono"
            bind:value={group}
            autocomplete="off"
            autocapitalize="off"
            autocorrect="off"
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
    </form>
    <Sheet.Footer>
      <!-- Here rather than at the end of the form: the form scrolls, and on a short screen a
           refusal or a warning at the end of it would be below the fold, so the reader would see
           a button that did nothing and never read why. The footer stays put. -->
      <!-- A status, not an alert: it appears while the reader is typing in the Group field, and
           an alert would cut across the characters being read back. The region is there for as
           long as the sheet is, and only its words come and go, because a screen reader often
           says nothing for a live region that arrives already holding its text. Empty, it stays
           in the page with no height, and its negative margin takes back the footer's gap,
           rather than being hidden, which would take it out of what a screen reader watches. -->
      <div id="{id}-existing" role="status" class="empty:-mb-2">
        {#if existing}
          <p class="rounded-lg border border-warning/30 bg-warning-soft px-3 py-2 wrap-anywhere">
            Already mapped as {ROLE_LABEL[existing.role]}; saving changes it.
          </p>
        {/if}
      </div>
      {#if asking}
        <p
          id="{id}-confirm"
          role="alert"
          class="rounded-lg border border-warning/30 bg-warning-soft px-3 py-2 wrap-anywhere"
        >
          Only this group makes you admin in {target.workspace}, so you will no longer be able to
          grant roles there.
        </p>
      {/if}
      {#if error}
        <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
          {error}
        </p>
      {/if}
      <!-- A key held down repeats, and removing should take a deliberate press, not a key held
           a moment too long: the remove sheet opens on Cancel, but a refusal sends focus back to
           this button, where an Enter still held would press it again. Repeats are dropped on
           Cancel as well,
           where a held Enter on a row's Remove would close the sheet it had just opened, and the
           row's own key handler would open it again, for as long as the key stayed down. -->
      <Button
        bind:ref={submit}
        type="submit"
        form="{id}-form"
        onkeydown={(event) => event.repeat && event.preventDefault()}
        variant={mode === 'remove' || asking ? 'destructive' : 'default'}
        disabled={!ready || saving}
        aria-describedby={[existing && `${id}-existing`, asking && `${id}-confirm`].filter(Boolean).join(' ') || undefined}
      >
        {#if mode === 'remove'}
          {saving ? 'Removing…' : asking ? 'Remove anyway' : 'Remove'}
        {:else}
          {saving ? 'Saving…' : asking ? 'Save anyway' : 'Save'}
        {/if}
      </Button>
      <Sheet.Close disabled={saving}>
        {#snippet child({ props })}
          <!-- After the spread, so that it wraps bits-ui's own key handler, which closes the sheet
               on every Enter, repeats included, instead of being replaced by it. -->
          <Button
            bind:ref={cancel}
            variant="outline"
            {...props}
            onkeydown={(event) => (event.repeat ? event.preventDefault() : props.onkeydown?.(event))}
            >Cancel</Button
          >
        {/snippet}
      </Sheet.Close>
    </Sheet.Footer>
  </Sheet.Content>
</Sheet.Root>
