<script>
  import { tick } from 'svelte'
  import * as Sheet from '$lib/components/ui/sheet/index.js'
  import { Button } from '$lib/components/ui/button/index.js'
  import NativeSelect from './NativeSelect.svelte'
  import AccountSection from './AccountSection.svelte'
  import { write } from './api.js'
  import { ROLES, ROLE_LABEL } from './roles.js'

  // Edit access for one account: a select per workspace the reader administers, holding the
  // account's *direct* grant there. Group mappings and the superuser flag are shown beside it,
  // because they decide what the account can do, but they are not what this form changes. Only
  // the workspaces that changed are sent, in one request the server applies whole or not at
  // all, and grants in workspaces the reader does not administer are never part of it.
  //
  // `user` is the account's row from /api/users and `me` the reader from /api/me. `onsaved`
  // fetches the list again and returns a promise that settles once the new list is on the page or
  // the fetch has failed, and never rejects. `onremoved` is where focus goes when the new list no
  // longer has this sheet's button: the account is gone, or was disabled in the meantime. The
  // trigger is a bits-ui Dialog trigger, so the sheet keeps focus inside while it is open, closes
  // on Escape, and hands focus back to this button.
  //
  // A superuser sees the account itself above the roles (AccountSection), and the sheet of a
  // disabled account, which then holds only that: a disabled account holds nothing, and its grants
  // are not in /api/users. A workspace admin sees only the roles, of enabled accounts.
  //
  // `me` is what the page read when it loaded, and the form does not read it again. A reader
  // whose admin was taken away since still sees that workspace here; saving it is refused with
  // a 403 whose sentence says why, which is shown below, and a reload brings the form back in
  // line.
  let { user, me, onsaved, onremoved = undefined } = $props()

  const id = $props.id()

  let open = $state(false)
  // The button that opens the sheet, kept so focus can be put back on it after a save.
  let trigger = $state(null)
  // Save, so focus can go back to it after a refusal: disabling it while saving drops focus.
  let saveButton = $state(null)
  // What each select holds, by workspace id: a role, or '' for no direct grant.
  let chosen = $state({})
  let saving = $state(false)
  let error = $state(undefined)
  // Set once the reader has been shown what lowering their own admin costs them.
  let confirming = $state(false)
  // When that was, by `performance.now()`. Not state: nothing is drawn from it.
  let askedAt = 0
  // Set when a save was refused, so that the list is fetched again once the sheet closes. Not
  // state: nothing is drawn from it.
  let staleOnClose = false
  // The Account section, whose question and refusal this sheet's footer draws, and the footer's
  // Keep button, which a question opens on.
  let account = $state(null)
  let accountQuestion = $state(null)
  let accountError = $state(undefined)
  let accountBusy = $state(false)
  let keep = $state(null)

  // '' ranks below every role, so a group's role is higher than no direct grant at all.
  const rank = (role) => ROLES.indexOf(role) + 1

  function held(workspaceId) {
    return user.access.find((access) => access.workspace_id === workspaceId)
  }

  function direct(workspaceId) {
    return held(workspaceId)?.sources.find((s) => s.kind === 'direct')?.role ?? ''
  }

  // Each time the sheet opens it starts from the grants as the list last read them, so a sheet
  // closed half-edited does not reopen with the choices that were abandoned.
  function reset() {
    chosen = Object.fromEntries(me.grantable.map((w) => [w.workspace_id, direct(w.workspace_id)]))
    saving = false
    error = undefined
    confirming = false
    accountQuestion = null
    accountError = undefined
    accountBusy = false
  }

  // The body: only the workspaces whose select moved, each with a role or null for none.
  const changes = $derived(
    Object.fromEntries(
      me.grantable
        .filter((w) => w.workspace_id in chosen && chosen[w.workspace_id] !== direct(w.workspace_id))
        .map((w) => [w.workspace_id, chosen[w.workspace_id] || null]),
    ),
  )
  const changed = $derived(Object.keys(changes).length > 0)

  const self = $derived(user.id === me.id)
  const superuser = $derived(me.superuser)
  // The roles are not offered for a disabled account (see above), nor where there is no
  // workspace to grant one in.
  const roles = $derived(user.status !== 'disabled')
  const offered = $derived(roles && me.grantable.length > 0)

  // Where this save would take the reader's own admin away with nothing else keeping it: no
  // group of theirs at admin there, and not a superuser. The server allows it, because an admin
  // may change any grant in their workspace, their own included. The sheet asks first, because
  // the next thing they might try there is to undo it, and by then they cannot.
  const losing = $derived(
    self && !user.superuser
      ? me.grantable.filter(
          (w) =>
            direct(w.workspace_id) === 'admin' &&
            w.workspace_id in changes &&
            changes[w.workspace_id] !== 'admin' &&
            !held(w.workspace_id)?.sources.some((s) => s.kind === 'group' && s.role === 'admin'),
        )
      : [],
  )

  // Whether the warning is up. `confirming` alone could outlive what it was asked about, if the
  // list were fetched again under an open sheet and the reader no longer stood to lose anything.
  const asking = $derived(confirming && losing.length > 0)

  const list = new Intl.ListFormat('en', { type: 'conjunction' })

  async function save(event) {
    event.preventDefault()
    if (!changed || saving) return
    if (losing.length > 0 && !confirming) {
      confirming = true
      askedAt = performance.now()
      return
    }
    // A double-click sends its second submit within milliseconds of the first, long before the
    // warning could have been read, and it would confirm what the reader never saw. Half a second
    // is longer than a double-click takes and shorter than anyone takes to read the sentence and
    // mean it. Enter held down is stopped at the button, which ignores key repeats.
    if (confirming && performance.now() - askedAt < 500) return
    saving = true
    error = undefined
    try {
      await write('PATCH', `/api/users/${encodeURIComponent(user.id)}/roles`, changes)
    } catch (failure) {
      saving = false
      // A refused save is not the one that was asked about: the reader reads the refusal, and
      // saving again asks again if it still costs them their admin.
      confirming = false
      error = failure.message
      // Not fetched again yet. Whatever refused this, a 403 because the reader's access changed,
      // a 404 because the account is gone, or a dropped connection that leaves it unknown whether
      // anything was saved, the list on the page is probably out of date. But the new one could
      // drop the row this sheet lives in, and the sheet, with the sentence the reader is meant to
      // read, would go with it. So it is fetched when they close the sheet.
      staleOnClose = true
      // Save was disabled while the request ran, which took focus away from it; it goes back,
      // so the reader is where they were, with the refusal just above.
      await tick()
      saveButton?.focus()
      return
    }
    if (self) {
      // The reader's own access changed, and with it the navigation App built from /api/me. A
      // reload asks again.
      location.reload()
      return
    }
    // The list about to be fetched is as new as can be, so nothing is left to fetch on closing.
    staleOnClose = false
    // A reset password still on screen and never copied keeps the sheet open: the list is
    // fetched under it, and the footer asks whether to close without copying it.
    if (account?.askToClose()) {
      saving = false
      await onsaved()
      return
    }
    open = false
    // Giving a waiting account its first role moves its row, because waiting accounts sort
    // first, and a row that moves in a keyed list is taken out of the page and put back, which
    // drops focus to the page itself. Closing the sheet had put focus back on the trigger; the
    // list is fetched again and drawn before looking, and if the move took it, it goes back.
    await onsaved()
    await tick()
    keepPlace()
  }

  // Where focus goes once a new list has been drawn under a sheet that has closed. Where it fell
  // to the page itself, it goes back to the button that opened the sheet, or, if that has gone
  // with its row, to where the page says. Focus the reader has put somewhere else in the meantime
  // is left where it is.
  function keepPlace() {
    if (document.activeElement !== document.body) return
    if (trigger?.isConnected) trigger.focus()
    else onremoved?.()
  }

  // Called when the reader's own act has closed the sheet, once per close: bits-ui asks the setter
  // below for every one of them, and the setter says whether they got their way. Closing after a
  // refusal is when the list, left alone while the sheet was showing why, is fetched again.
  async function closed() {
    if (!staleOnClose) return
    staleOnClose = false
    await onsaved()
    await tick()
    keepPlace()
  }

  // The sheet has to close and the list be drawn again without the account: focus then goes to
  // where the page says.
  async function deleted() {
    staleOnClose = false
    open = false
    await onsaved()
    await tick()
    keepPlace()
  }

  async function asked() {
    await tick()
    keep?.focus()
  }

  // A close the reader confirmed over a reset password they never copied.
  function closeAnyway() {
    open = false
    closed()
  }

  function setOpen(next) {
    if (!next && (saving || accountBusy || accountQuestion?.kind === 'close')) return
    // Over a reset password that was never copied, the Account section asks first.
    if (!next && account?.askToClose()) return
    if (!next) accountQuestion = null
    open = next
    if (!next) closed()
  }

  // A key held down repeats, and a repeat must not answer a question or drop it.
  const once = (event) => event.repeat && event.preventDefault()
</script>

<!-- The setter refuses to close while a save is in flight, which stops Escape, a click outside,
     the corner button and Cancel alike, since bits-ui closes through it for every one of them. A
     sheet closed then could be opened again over a request that has not answered, and its
     error would have nowhere to be read. Not `onOpenChange`, which bits-ui calls even for a close
     the setter has refused. -->
<Sheet.Root bind:open={() => open, setOpen} onOpenChange={(next) => next && reset()}>
  <Sheet.Trigger>
    {#snippet child({ props })}
      {#if superuser}
        <Button bind:ref={trigger} variant="outline" size="sm" aria-label="Manage {user.name}" {...props}>Manage</Button>
      {:else}
        <Button bind:ref={trigger} variant="outline" size="sm" {...props}>Edit access</Button>
      {/if}
    {/snippet}
  </Sheet.Trigger>
  <!-- Full width on a phone, where three quarters of 375 px is too narrow for a form, and wider
       than the generated sheet beside a full page, for long workspace names. -->
  <Sheet.Content class="data-[side=right]:w-full data-[side=right]:sm:max-w-md">
    <Sheet.Header>
      <!-- pr-8 keeps a long name clear of the close button in the corner. -->
      {#if superuser}
        <Sheet.Title class="pr-8 wrap-anywhere">Manage {user.name}</Sheet.Title>
        <Sheet.Description>The account, and its direct grant in each workspace.</Sheet.Description>
      {:else}
        <Sheet.Title class="pr-8 wrap-anywhere">Edit access for {user.name}</Sheet.Title>
        <Sheet.Description>
          A direct grant in each workspace you administer. Grants anywhere else stay as they are.
        </Sheet.Description>
      {/if}
    </Sheet.Header>
    <!-- The body scrolls on its own, so a long list of workspaces never pushes Save off the
         bottom of the sheet. -->
    <div class="grid gap-5 overflow-y-auto px-4">
      {#if superuser}
        <AccountSection
          bind:this={account}
          bind:question={accountQuestion}
          bind:error={accountError}
          bind:busy={accountBusy}
          {user}
          {me}
          onchanged={onsaved}
          ondeleted={deleted}
          onasked={asked}
          onclose={closeAnyway}
          onrefused={() => (staleOnClose = true)}
        />
      {/if}
      {#if !roles}
        <p class="text-muted-foreground">A disabled account holds no role. Enable it to grant one.</p>
      {:else if me.grantable.length > 0}
        {#if superuser}
          <h3 class="-mb-2 font-medium">Roles</h3>
        {/if}
        <form id="{id}-form" class="grid gap-5" onsubmit={save}>
          {#if user.superuser}
            <p class="rounded-lg border px-3 py-2 text-muted-foreground">
              {self ? 'You are' : `${user.name} is`} a superuser, and so admin in every workspace
              whatever these say.
            </p>
          {/if}
          {#each me.grantable as workspace (workspace.workspace_id)}
            {@const field = `${id}-${workspace.workspace_id}`}
            {@const higher = (held(workspace.workspace_id)?.sources ?? []).filter(
              (s) => s.kind === 'group' && rank(s.role) > rank(chosen[workspace.workspace_id]),
            )}
            <div class="grid gap-1.5">
              <label for={field} class="font-medium wrap-anywhere">Role in {workspace.workspace}</label>
              <NativeSelect
                id={field}
                bind:value={chosen[workspace.workspace_id]}
                disabled={saving}
                aria-describedby={higher.length > 0 ? `${field}-groups` : undefined}
                onchange={() => (confirming = false)}
              >
                <option value="">No access</option>
                {#each ROLES as role (role)}
                  <option value={role}>{ROLE_LABEL[role]}</option>
                {/each}
              </NativeSelect>
              <!-- What a group gives here beyond the select, so lowering the direct grant is not
                   mistaken for lowering what the account can do. -->
              {#if higher.length > 0}
                <div id="{field}-groups" class="text-xs text-muted-foreground wrap-anywhere">
                  {#each higher as group (group.name)}
                    <p>Group {group.name} gives {ROLE_LABEL[group.role]} here; the highest applies.</p>
                  {/each}
                </div>
              {/if}
            </div>
          {/each}
        </form>
      {/if}
    </div>
    <Sheet.Footer>
      <!-- Here rather than at the end of the form: the form scrolls, and with enough workspaces
           (a superuser administers every one) these would be below the fold while Save turns
           red, so the reader would be asked to confirm something they cannot see. The footer
           stays put. The Account section's questions and refusals are here for the same reason. -->
      {#if asking}
        <p
          id="{id}-confirm"
          role="alert"
          class="rounded-lg border border-warning/30 bg-warning-soft px-3 py-2 wrap-anywhere"
        >
          You will no longer be able to grant roles in {list.format(losing.map((w) => w.workspace))}.
        </p>
      {/if}
      {#if error}
        <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
          {error}
        </p>
      {/if}
      {#if accountError}
        <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
          {accountError}
        </p>
      {/if}
      {#if accountQuestion}
        <!-- The Account section's question, which opens on the button that keeps things as they
             are. -->
        <p class="text-sm wrap-anywhere" role="alert">{accountQuestion.sentence}</p>
        <Button
          variant={accountQuestion.destructive ? 'destructive' : 'default'}
          onclick={() => account?.confirm()}
          onkeydown={once}
          disabled={accountBusy}
        >
          {accountQuestion.confirm}
        </Button>
        <Button bind:ref={keep} variant="outline" onclick={() => account?.dismiss()} onkeydown={once} disabled={accountBusy}>
          {accountQuestion.kind === 'close' ? 'Keep it open' : 'Keep it'}
        </Button>
      {:else}
        {#if offered}
          <Button
            bind:ref={saveButton}
            type="submit"
            form="{id}-form"
            onkeydown={once}
            variant={asking ? 'destructive' : 'default'}
            disabled={!changed || saving}
            aria-describedby={asking ? `${id}-confirm` : undefined}
          >
            {saving ? 'Saving…' : asking ? 'Save anyway' : 'Save'}
          </Button>
        {/if}
        <Sheet.Close disabled={saving || accountBusy}>
          {#snippet child({ props })}
            <Button variant="outline" {...props}>{offered ? 'Cancel' : 'Close'}</Button>
          {/snippet}
        </Sheet.Close>
      {/if}
    </Sheet.Footer>
  </Sheet.Content>
</Sheet.Root>
