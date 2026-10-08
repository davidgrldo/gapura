<script>
  import { tick } from 'svelte'
  import * as Sheet from '$lib/components/ui/sheet/index.js'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import SecretBox from './SecretBox.svelte'
  import { write } from './api.js'
  import Plus from 'phosphor-svelte/lib/Plus'

  // New account, on the Users page, for superusers: a username and whether the account is a
  // superuser, which the server answers with a temporary password. The sheet then shows that
  // password, once, and stays open on it while the list is fetched again under it; closing before
  // copying it asks first, in the footer, as the Data planes sheet asks about a token.
  // `onsaved` fetches the list again and returns a promise that settles once it is drawn or has
  // failed, and never rejects.
  let { onsaved } = $props()

  const id = $props.id()

  let open = $state(false)
  let trigger = $state(null)
  // Where focus goes after a refusal that names no field: disabling Create drops focus.
  let submit = $state(null)
  let keep = $state(null)
  let passwordInput = $state(null)
  let username = $state('')
  let superuser = $state(false)
  let saving = $state(false)
  // `{ sentence, field }` from a refused create; `field` puts the sentence beside its input.
  let error = $state(undefined)
  // Up while the reader is asked whether to close without copying the password.
  let asking = $state(false)
  let askedAt = 0
  // `{ id, username, password }`, the server's one answer that carries the password.
  let created = $state(null)
  let copied = $state(false)
  // A refusal leaves the list possibly out of date: a dropped connection may have created the
  // account. It is fetched when the sheet closes, not while the reader is reading why.
  let staleOnClose = false

  function reset() {
    username = ''
    superuser = false
    saving = false
    error = undefined
    asking = false
    created = null
    copied = false
  }

  const invalid = (field) => error?.field === field
  // Only the username has an input; a refusal naming anything else goes in the footer.
  const shown = $derived(error?.field === 'username')

  async function create(event) {
    event.preventDefault()
    if (created || saving) return
    saving = true
    error = undefined
    let answer
    try {
      answer = await write('POST', '/api/users', { username: username.trim(), superuser }, { answers: true })
    } catch (failure) {
      saving = false
      error = { sentence: failure.message, field: failure.field }
      staleOnClose = true
      await tick()
      ;(shown ? document.getElementById(`${id}-username`) : submit)?.focus()
      return
    }
    created = answer
    copied = false
    staleOnClose = false
    await onsaved()
    saving = false
    await tick()
    passwordInput?.focus()
  }

  // Where focus goes once a new list has been drawn under a sheet that has closed: back to New
  // account, unless the reader has put it somewhere else in the meantime.
  function keepPlace() {
    if (document.activeElement === document.body) trigger?.focus()
  }

  async function closed() {
    if (!staleOnClose) return
    staleOnClose = false
    await onsaved()
    await tick()
    keepPlace()
  }

  async function ask() {
    asking = true
    askedAt = performance.now()
    await tick()
    keep?.focus()
  }

  // A double-click on whatever asked must not answer the question it raised.
  function confirm() {
    if (performance.now() - askedAt < 500) return
    asking = false
    open = false
    closed()
  }

  async function dismiss() {
    asking = false
    await tick()
    passwordInput?.focus()
  }

  // Refuses to close while the create is in flight, and asks first while a password that was
  // never copied is on screen. While that question is up, only its own buttons answer it.
  function setOpen(next) {
    if (next) {
      open = true
      return
    }
    if (saving || asking) return
    if (created && !copied) {
      ask()
      return
    }
    open = false
    closed()
  }

  // A key held down repeats, and a repeat must not answer a question or drop it.
  const once = (event) => event.repeat && event.preventDefault()
</script>

<Sheet.Root bind:open={() => open, setOpen} onOpenChange={(next) => next && reset()}>
  <Sheet.Trigger>
    {#snippet child({ props })}
      <Button bind:ref={trigger} size="sm" {...props}><Plus aria-hidden="true" />New account</Button>
    {/snippet}
  </Sheet.Trigger>
  <Sheet.Content class="data-[side=right]:w-full data-[side=right]:sm:max-w-md">
    <Sheet.Header>
      <Sheet.Title class="pr-8">New account</Sheet.Title>
      <Sheet.Description>
        An account that signs in with a username and password. It holds no role until one is granted.
      </Sheet.Description>
    </Sheet.Header>
    <div class="grid gap-5 overflow-y-auto px-4">
      {#if created}
        <SecretBox
          bind:ref={passwordInput}
          bind:copied
          secret={created.password}
          label="Temporary password for"
          code={created.username}
          note="They choose their own password the first time they sign in. Until then this one opens nothing else."
        />
      {:else}
        <form id="{id}-form" class="grid gap-5" onsubmit={create}>
          <fieldset class="grid gap-5" disabled={saving}>
            <div class="grid gap-1.5">
              <label for="{id}-username" class="font-medium">Username</label>
              <Input
                id="{id}-username"
                class="font-mono"
                bind:value={username}
                autocomplete="off"
                autocapitalize="off"
                spellcheck="false"
                aria-invalid={invalid('username')}
                aria-describedby={invalid('username') ? `${id}-username-error` : undefined}
              />
              {#if invalid('username')}
                <p id="{id}-username-error" class="text-xs text-danger">{error.sentence}</p>
              {/if}
            </div>
            <label class="flex items-start gap-2">
              <input type="checkbox" class="mt-1" bind:checked={superuser} aria-describedby="{id}-superuser-note" />
              <span class="grid gap-0.5">
                <span class="font-medium">Superuser</span>
                <span id="{id}-superuser-note" class="text-xs text-muted-foreground">
                  Acts in every workspace and can read every data plane's configuration.
                </span>
              </span>
            </label>
          </fieldset>
        </form>
      {/if}
    </div>
    <Sheet.Footer>
      {#if error && !shown}
        <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
          {error.sentence}
        </p>
      {/if}
      {#if asking}
        <p class="text-sm" role="alert">Close without copying the password? It cannot be shown again.</p>
        <Button onclick={confirm} onkeydown={once}>Close</Button>
        <Button bind:ref={keep} variant="outline" onclick={dismiss} onkeydown={once}>Keep it open</Button>
      {:else}
        {#if !created}
          <Button bind:ref={submit} type="submit" form="{id}-form" onkeydown={once} disabled={saving}>
            {saving ? 'Creating…' : 'Create'}
          </Button>
        {/if}
        <Sheet.Close disabled={saving}>
          {#snippet child({ props })}
            <Button variant="outline" {...props}>{created ? 'Close' : 'Cancel'}</Button>
          {/snippet}
        </Sheet.Close>
      {/if}
    </Sheet.Footer>
  </Sheet.Content>
</Sheet.Root>
