<script>
  import { tick } from 'svelte'
  import * as Sheet from '$lib/components/ui/sheet/index.js'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import { write } from './api.js'
  import Plus from 'phosphor-svelte/lib/Plus'

  // The Workspaces page's one sheet, for superusers, built as the Data planes page's is:
  // - `create` is New workspace: a name;
  // - `edit` is one workspace: what it holds, a rename, and its delete. Only an empty workspace is
  //   deleted, and never the only one, so when it holds something or is the only one the sheet
  //   says so instead of offering Delete. Delete is asked first, in the footer, and the question
  //   opens on the button that keeps things as they are.
  // `onsaved` fetches the list and /api/me again and returns a promise that settles once both
  // are drawn or have failed, and never rejects. `onremoved` is where focus goes when the new
  // list no longer has the row this sheet's button was in; `onrenamed(name)` puts it on the
  // renamed row's button, which is a new one, since rows are keyed by name.
  let { mode, workspace = undefined, only = false, onsaved, onremoved = undefined, onrenamed = undefined } = $props()

  const id = $props.id()

  let open = $state(false)
  // The button that opened the sheet, so focus can go back to it after a save.
  let trigger = $state(null)
  // Where focus goes after a refusal that names no field: disabling a button while it is busy
  // drops focus.
  let submit = $state(null)
  let keep = $state(null)
  let del = $state(null)
  let name = $state('')
  let saving = $state(false)
  // `{ sentence, field, stale }` from a refused write; `field` puts the sentence beside its input.
  let error = $state(undefined)
  // Up while Delete is being asked; and when it went up, so a double-click on the button that
  // asked cannot answer it.
  let asking = $state(false)
  let askedAt = 0
  // A refusal leaves the list possibly out of date; it is fetched when the sheet closes, not
  // while the reader is reading why.
  let staleOnClose = false

  function reset() {
    name = mode === 'edit' ? workspace.name : ''
    saving = false
    error = undefined
    asking = false
  }

  const invalid = (field) => error?.field === field
  // Only the name has an input; a refusal naming anything else goes in the footer.
  const shown = $derived(error?.field === 'name')
  const here = () => `/api/workspaces/${encodeURIComponent(workspace.name)}`

  // What is left in it, worded as the server's refusal words it: only the kinds it holds, with
  // their plurals. Empty when there is nothing, which is when Delete is offered.
  const left = $derived.by(() => {
    if (mode !== 'edit') return ''
    const kinds = [
      [workspace.services, 'service', 'services'],
      [workspace.routes, 'route', 'routes'],
      [workspace.consumers, 'consumer', 'consumers'],
      [workspace.policies, 'policy', 'policies'],
      [workspace.certificates, 'certificate', 'certificates'],
    ]
      .filter(([count]) => count > 0)
      .map(([count, one, many]) => `${count} ${count === 1 ? one : many}`)
    if (kinds.length === 0) return ''
    const total = [workspace.services, workspace.routes, workspace.consumers, workspace.policies, workspace.certificates].reduce(
      (sum, n) => sum + (n ?? 0),
      0,
    )
    const list = kinds.length === 1 ? kinds[0] : `${kinds.slice(0, -1).join(', ')} and ${kinds.at(-1)}`
    return `${workspace.name} still has ${list}. Remove ${total === 1 ? 'it' : 'them'} first.`
  })
  const deletable = $derived(mode === 'edit' && !only && !left)

  // One request. Resolves with true once the server has made the change, or with false after a
  // refusal, which is then on screen with focus on the name, or else on what `back` gives.
  async function request(method, url, body, back) {
    saving = true
    error = undefined
    try {
      await write(method, url, body)
      return true
    } catch (failure) {
      saving = false
      error = {
        sentence: failure.message,
        field: failure.field,
        // A 404 on a change to this workspace means someone else renamed or deleted it, and the
        // list is what to look at.
        stale: failure.status === 404 && mode === 'edit',
      }
      staleOnClose = true
      // A refused answer has had its answer: the footer goes back to the sheet's own buttons.
      asking = false
      await tick()
      ;(shown ? document.getElementById(`${id}-name`) : back())?.focus()
      return false
    }
  }

  // Where focus goes once a new list has been drawn under a sheet that has closed. Closing handed
  // it back to the button that opened the sheet, but a row that goes takes its button with it
  // and focus falls to the page; then it goes to where the page says. Focus the reader has put
  // elsewhere in the meantime is left alone.
  function keepPlace(renamed = undefined) {
    if (document.activeElement !== document.body && document.activeElement !== null) return
    if (trigger?.isConnected) trigger.focus()
    else if (renamed !== undefined && onrenamed) onrenamed(renamed)
    else onremoved?.()
  }

  async function closeAndReload(renamed = undefined) {
    staleOnClose = false
    open = false
    await onsaved()
    await tick()
    keepPlace(renamed)
  }

  async function save(event) {
    event.preventDefault()
    if (saving || asking) return
    const to = name.trim()
    if (mode === 'create') {
      if (await request('POST', '/api/workspaces', { name: to }, () => submit)) await closeAndReload()
      return
    }
    // The same name is no change, and the server would answer it with nothing done.
    if (to === workspace.name) {
      open = false
      closed()
      return
    }
    if (await request('PUT', here(), { name: to }, () => submit)) await closeAndReload(to)
  }

  async function ask() {
    if (saving || !deletable) return
    asking = true
    askedAt = performance.now()
    await tick()
    keep?.focus()
  }

  async function confirm() {
    if (saving || !asking || performance.now() - askedAt < 500) return
    if (await request('DELETE', here(), undefined, () => del)) await closeAndReload()
  }

  async function dismiss() {
    asking = false
    await tick()
    del?.focus()
  }

  // A key held down repeats, and a repeat must not answer a question or drop it.
  const once = (event) => event.repeat && event.preventDefault()

  async function closed() {
    if (!staleOnClose) return
    staleOnClose = false
    await onsaved()
    await tick()
    keepPlace()
  }

  // Refuses to close while a request is in flight.
  function setOpen(next) {
    if (next) {
      open = true
      return
    }
    if (saving) return
    asking = false
    open = false
    closed()
  }

  // Who loses what with it: the API counts direct grants and group mappings together, so the
  // sentence cannot say how many of each.
  const sentence = $derived(
    mode === 'edit'
      ? workspace.members > 0
        ? `Delete ${workspace.name}? Everyone's roles in it go with it.`
        : `Delete ${workspace.name}? No one holds a role in it.`
      : '',
  )
</script>

<Sheet.Root bind:open={() => open, setOpen} onOpenChange={(next) => next && reset()}>
  <Sheet.Trigger>
    {#snippet child({ props })}
      {#if mode === 'create'}
        <Button bind:ref={trigger} size="sm" {...props}><Plus aria-hidden="true" />New workspace</Button>
      {:else}
        <Button
          bind:ref={trigger}
          variant="ghost"
          size="sm"
          data-workspace={workspace.name}
          aria-label="Manage the workspace {workspace.name}"
          {...props}>Manage</Button
        >
      {/if}
    {/snippet}
  </Sheet.Trigger>
  <Sheet.Content class="data-[side=right]:w-full data-[side=right]:sm:max-w-md">
    <Sheet.Header>
      <Sheet.Title class="pr-8">
        {#if mode === 'create'}New workspace{:else}Workspace <span class="font-mono">{workspace.name}</span>{/if}
      </Sheet.Title>
      <Sheet.Description>
        {#if mode === 'create'}
          An empty workspace. Superusers act in it at once; anyone else holds no role in it until one is granted.
        {:else}
          What it holds, its name, and whether it can be deleted.
        {/if}
      </Sheet.Description>
    </Sheet.Header>
    <div class="grid gap-5 overflow-y-auto px-4">
      {#if mode === 'edit'}
        <dl class="grid grid-cols-[auto_1fr] items-center gap-x-4 gap-y-1 text-sm">
          <dt class="text-muted-foreground">Services</dt><dd class="tabular-nums">{workspace.services}</dd>
          <dt class="text-muted-foreground">Routes</dt><dd class="tabular-nums">{workspace.routes}</dd>
          <dt class="text-muted-foreground">Consumers</dt><dd class="tabular-nums">{workspace.consumers}</dd>
          <dt class="text-muted-foreground">Policies</dt><dd class="tabular-nums">{workspace.policies}</dd>
          <dt class="text-muted-foreground">Certificates</dt><dd class="tabular-nums">{workspace.certificates}</dd>
          <dt class="text-muted-foreground">Members</dt><dd class="tabular-nums">{workspace.members}</dd>
        </dl>
      {/if}
      <form id="{id}-form" class="grid gap-5" onsubmit={save}>
        <fieldset class="grid gap-1.5" disabled={saving}>
          <label for="{id}-name" class="font-medium">Name</label>
          <Input
            id="{id}-name"
            class="font-mono"
            bind:value={name}
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
            aria-invalid={invalid('name')}
            aria-describedby={invalid('name') ? `${id}-name-error` : undefined}
          />
          {#if invalid('name')}
            <p id="{id}-name-error" class="text-xs text-danger">{error.sentence}</p>
          {/if}
          {#if mode === 'edit'}
            <p class="text-xs text-muted-foreground">
              What it holds and the roles in it follow a rename. Data planes are sent the new name at their next
              call, and its routes' metrics start anew under it.
            </p>
          {/if}
        </fieldset>
      </form>
      {#if mode === 'edit' && !deletable}
        <!-- Instead of a Delete the server would refuse: what keeps it. -->
        <section class="grid gap-1 text-sm" aria-labelledby="{id}-delete">
          <h3 id="{id}-delete" class="font-medium">Delete</h3>
          {#if only}
            <p class="text-muted-foreground">{workspace.name} is the only workspace, and the console needs one. Create another first.</p>
          {/if}
          {#if left}
            <p class="text-muted-foreground">{left}</p>
          {/if}
        </section>
      {/if}
    </div>
    <Sheet.Footer>
      {#if error && !shown}
        <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
          {error.sentence}
        </p>
      {/if}
      {#if error?.stale}
        <Button variant="outline" onclick={() => closeAndReload()}>Reload</Button>
      {/if}
      {#if asking}
        <p class="text-sm" role="alert">{sentence}</p>
        <Button variant="destructive" onclick={confirm} onkeydown={once} disabled={saving}>Delete</Button>
        <Button bind:ref={keep} variant="outline" onclick={dismiss} onkeydown={once} disabled={saving}>Keep it</Button>
      {:else}
        <Button bind:ref={submit} type="submit" form="{id}-form" onkeydown={once} disabled={saving}>
          {#if mode === 'create'}{saving ? 'Creating…' : 'Create'}{:else}{saving ? 'Saving…' : 'Save'}{/if}
        </Button>
        {#if deletable}
          <Button bind:ref={del} variant="ghost" class="text-danger" onclick={ask} onkeydown={once} disabled={saving}>Delete workspace</Button>
        {/if}
        <Sheet.Close disabled={saving}>
          {#snippet child({ props })}
            <Button variant="outline" {...props}>{mode === 'create' ? 'Cancel' : 'Close'}</Button>
          {/snippet}
        </Sheet.Close>
      {/if}
    </Sheet.Footer>
  </Sheet.Content>
</Sheet.Root>
