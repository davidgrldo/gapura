<script>
  import { tick } from 'svelte'
  import * as Sheet from '$lib/components/ui/sheet/index.js'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import SecretBox from './SecretBox.svelte'
  import Tag from './Tag.svelte'
  import { write } from './api.js'
  import { when } from './configuration.js'
  import { STATUS_TONE, status, sync } from './dataPlanes.js'
  import Plus from 'phosphor-svelte/lib/Plus'

  // The Data planes page's one sheet, built as the Consumers page's is:
  // - `create` is Register a data plane, for superusers: a name, which the server answers with
  //   the data plane's first token. The sheet then shows that token and stays open on it;
  // - `edit` shows one data plane: whether it calls, from where, and its tokens. A superuser can
  //   issue another token, revoke one and delete the data plane; anyone else sees it all and no
  //   controls.
  // An issued token is shown once, in a box that stays until the sheet closes. Registering,
  // issuing and revoking fetch the list again without closing the sheet: rows are keyed by name,
  // so this sheet stays mounted under the new list and the box with it. Questions (delete,
  // revoke, close without copying) are asked in the footer, and open on the button that keeps
  // things as they are.
  // `onsaved` fetches the list again and returns a promise that settles once it is drawn or has
  // failed, and never rejects. `onremoved` is where focus goes when the new list no longer has the
  // row this sheet's button was in.
  let { mode, plane = undefined, superuser, onsaved, onremoved = undefined } = $props()

  const id = $props.id()
  const admin = $derived(mode === 'edit' && superuser)

  let open = $state(false)
  // The button that opened the sheet, so focus can go back to it after a save.
  let trigger = $state(null)
  // Where focus goes after a refusal that names no field: disabling a button while it is busy
  // drops focus.
  let submit = $state(null)
  let issueButton = $state(null)
  let keep = $state(null)
  let del = $state(null)
  let tokensHeading = $state(null)
  let tokenInput = $state(null)
  let name = $state('')
  let saving = $state(false)
  let issuing = $state(false)
  // `{ sentence, field, stale }` from a refused write; `field` puts the sentence beside its input.
  let error = $state(undefined)
  // The question in the footer: `{ kind: 'delete' }`, `{ kind: 'close' }` or
  // `{ kind: 'revoke', prefix }`; and when it went up, so a double-click on the button that asked
  // cannot answer it.
  let question = $state(null)
  let askedAt = 0
  // The Revoke button that asked, which Keep it hands focus back to.
  let asker = null
  // `{ name, token, prefix }`, the server's one answer that carries a token.
  let issued = $state(null)
  let copied = $state(false)
  // A refusal leaves the list possibly out of date; it is fetched when the sheet closes, not
  // while the reader is reading why.
  let staleOnClose = false

  function reset() {
    name = ''
    saving = false
    issuing = false
    error = undefined
    question = null
    issued = null
    copied = false
  }

  // The fields this sheet draws, and the ids of their inputs. A refusal naming anything else has
  // no input to sit beside, so its sentence goes in the footer.
  const INPUT = $derived(mode === 'create' && !issued ? { name: 'name' } : {})
  const shown = $derived(Object.hasOwn(INPUT, error?.field ?? ''))

  const invalid = (field) => error?.field === field
  const described = (field) => (invalid(field) ? `${id}-${field}-error` : undefined)
  const here = () => `/api/data-planes/${encodeURIComponent(plane.name)}`
  const tokens = $derived(plane?.tokens ?? [])
  const insync = $derived(plane ? sync(plane) : null)
  // Where a gateway is told to fetch from: this control plane's own host on the port it serves
  // data planes on by default. `hostname` keeps an IPv6 address's brackets.
  const command = `gapura --control-plane https://${location.hostname}:8081 --control-plane-token-file /path/to/token`

  // One request. Resolves with `{ answer }` once the server has made the change, or with nothing
  // after a refusal, which is then on screen with focus on the input it names, or else on what
  // `back` gives.
  async function request(method, url, body, back, answers = false) {
    saving = true
    error = undefined
    try {
      return { answer: await write(method, url, body, { answers }) }
    } catch (failure) {
      saving = false
      issuing = false
      error = {
        sentence: failure.message,
        field: failure.field,
        // A 404 on a change to this data plane or one of its tokens means someone else removed
        // it, and the list is what to look at.
        stale:
          (failure.status === 409 && failure.message.includes('Reload')) ||
          (failure.status === 404 && mode === 'edit'),
      }
      staleOnClose = true
      // A refused answer has had its answer: the footer goes back to the sheet's own buttons.
      question = null
      await tick()
      const input = shown ? document.getElementById(`${id}-${INPUT[error.field]}`) : undefined
      ;(input ?? back())?.focus()
      return undefined
    }
  }

  // Where focus goes once a new list has been drawn under a sheet that has closed. Closing handed
  // it back to the button that opened the sheet, but a row that goes takes its buttons with it
  // and focus falls to the page; then it goes to where the page says. Focus the reader has put
  // elsewhere in the meantime is left alone.
  function keepPlace() {
    if (document.activeElement !== document.body) return
    if (trigger?.isConnected) trigger.focus()
    else onremoved?.()
  }

  async function closeAndReload() {
    staleOnClose = false
    open = false
    await onsaved()
    await tick()
    keepPlace()
  }

  // Fetches the list without closing the sheet, after a change made from inside it.
  async function reloadInPlace() {
    staleOnClose = false
    await onsaved()
    saving = false
    issuing = false
    await tick()
  }

  // Registering answers with the first token, so the sheet stays open to show it.
  async function create(event) {
    event.preventDefault()
    if (mode !== 'create' || issued || saving) return
    const done = await request('POST', '/api/data-planes', { name: name.trim() }, () => submit, true)
    if (!done) return
    issued = done.answer
    copied = false
    await reloadInPlace()
    tokenInput?.focus()
  }

  async function issue() {
    if (!admin || saving || question) return
    issuing = true
    const done = await request('POST', `${here()}/tokens`, undefined, () => issueButton, true)
    if (!done) return
    issued = done.answer
    copied = false
    await reloadInPlace()
    tokenInput?.focus()
  }

  async function ask(next, from = null) {
    if (saving) return
    if (next.kind === 'revoke') asker = from
    question = next
    askedAt = performance.now()
    await tick()
    keep?.focus()
  }

  async function confirm() {
    if (saving || !question || performance.now() - askedAt < 500) return
    const asked = question
    if (asked.kind === 'close') {
      question = null
      open = false
      closed()
      return
    }
    if (asked.kind === 'delete') {
      const done = await request('DELETE', here(), undefined, () => del)
      if (done) await closeAndReload()
      return
    }
    const done = await request(
      'DELETE',
      `${here()}/tokens/${encodeURIComponent(asked.prefix)}`,
      undefined,
      () => (asker?.isConnected ? asker : tokensHeading),
    )
    if (!done) return
    question = null
    await reloadInPlace()
    tokensHeading?.focus()
  }

  async function dismiss() {
    const asked = question
    question = null
    await tick()
    if (asked?.kind === 'close') tokenInput?.focus()
    else if (asked?.kind === 'delete') del?.focus()
    else (asker?.isConnected ? asker : tokensHeading)?.focus()
  }

  // A key held down repeats, and a repeat must not answer a question or drop it.
  const once = (event) => event.repeat && event.preventDefault()

  // The stale refusal's way out. Register closes and draws the list as it is now; a data plane's
  // sheet stays open, since it may be holding a token that is shown only once, and takes the new
  // list as it comes. A data plane gone from it takes this sheet with it.
  async function reload() {
    if (mode === 'create') return closeAndReload()
    error = undefined
    await reloadInPlace()
    if (trigger?.isConnected) tokensHeading?.focus()
    else keepPlace()
  }

  async function closed() {
    if (!staleOnClose) return
    staleOnClose = false
    await onsaved()
    await tick()
    keepPlace()
  }

  // Refuses to close while a request is in flight, and asks first while a token that was never
  // copied is on screen. While that question is up, only its own buttons answer it: an Escape
  // held down must not.
  function setOpen(next) {
    if (next) {
      open = true
      return
    }
    if (saving || question?.kind === 'close') return
    if (issued && !copied) {
      ask({ kind: 'close' })
      return
    }
    question = null
    open = false
    closed()
  }

  const sentence = $derived.by(() => {
    if (question?.kind === 'close') return 'Close without copying the token? It cannot be shown again.'
    if (question?.kind === 'revoke') {
      return `Revoke ${question.prefix}? A data plane using it is refused from its next call and keeps serving its cached configuration.`
    }
    const n = tokens.length
    const what = n === 0 ? '' : n === 1 ? ' and its 1 token' : ` and its ${n} tokens`
    return `Delete ${plane?.name}${what}? Its gateway keeps serving its cached configuration but receives no more changes.`
  })
  const CONFIRM = { close: 'Close', revoke: 'Revoke', delete: 'Delete' }
</script>

{#snippet problem(field)}
  {#if invalid(field)}
    <p id="{id}-{field}-error" class="text-xs text-danger">{error.sentence}</p>
  {/if}
{/snippet}

{#snippet howTo()}
  <div class="grid gap-1.5 text-sm">
    <p>Save it to a file the gateway can read, then start the gateway with:</p>
    <pre class="overflow-x-auto rounded-md border bg-background px-3 py-2 font-mono text-xs"><code>{command}</code></pre>
    <p class="text-xs text-muted-foreground">Adjust the address if data planes reach this control plane another way.</p>
  </div>
{/snippet}

<Sheet.Root bind:open={() => open, setOpen} onOpenChange={(next) => next && reset()}>
  <Sheet.Trigger>
    {#snippet child({ props })}
      {#if mode === 'create'}
        <Button bind:ref={trigger} size="sm" {...props}><Plus aria-hidden="true" />Register a data plane</Button>
      {:else}
        <Button
          bind:ref={trigger}
          variant="ghost"
          size="sm"
          aria-label="{admin ? 'Manage' : 'View'} the data plane {plane.name}"
          {...props}>{admin ? 'Manage' : 'View'}</Button
        >
      {/if}
    {/snippet}
  </Sheet.Trigger>
  <Sheet.Content class="data-[side=right]:w-full data-[side=right]:sm:max-w-md">
    <Sheet.Header>
      <Sheet.Title class="pr-8">
        {#if mode === 'create'}Register a data plane{:else}Data plane <span class="font-mono">{plane.name}</span>{/if}
      </Sheet.Title>
      <Sheet.Description>
        A gateway that fetches its configuration from this control plane, known by the tokens it holds.
      </Sheet.Description>
    </Sheet.Header>
    <div class="grid gap-5 overflow-y-auto px-4">
      {#if mode === 'create'}
        {#if issued}
          <SecretBox bind:ref={tokenInput} bind:copied secret={issued.token} label="Token for" code={issued.name} children={howTo} />
        {:else}
          <form id="{id}-form" class="grid gap-5" onsubmit={create}>
            <fieldset class="grid gap-1.5" disabled={saving}>
              <label for="{id}-name" class="font-medium">Name</label>
              <Input id="{id}-name" class="font-mono" bind:value={name} autocomplete="off" autocapitalize="off" spellcheck="false" aria-invalid={invalid('name')} aria-describedby={described('name')} />
              {@render problem('name')}
              <p class="text-xs text-muted-foreground">Registering it issues its first token, shown once.</p>
            </fieldset>
          </form>
        {/if}
      {:else}
        <dl class="grid grid-cols-[auto_1fr] items-center gap-x-4 gap-y-2 text-sm">
          <dt class="text-muted-foreground">Status</dt>
          <dd><Tag tone={STATUS_TONE[plane.status] ?? 'idle'}>{status(plane)}</Tag></dd>
          <dt class="text-muted-foreground">In sync</dt>
          <dd>
            {#if insync === null}
              <span class="text-muted-foreground">—</span>
            {:else if insync.stale}
              <span class="text-muted-foreground">{insync.words}, as of its last call</span>
            {:else}
              <Tag tone={insync.tone}>{insync.words}</Tag>
            {/if}
          </dd>
          <dt class="text-muted-foreground">Address</dt>
          <dd>
            {#if plane.last_seen_address}<span class="font-mono">{plane.last_seen_address}</span>{:else}<span class="text-muted-foreground">—</span>{/if}
            <span class="block text-xs text-muted-foreground">As the control plane sees it.</span>
          </dd>
          <dt class="text-muted-foreground">Last seen</dt>
          <dd>{plane.last_seen_at ? when(plane.last_seen_at) : 'never'}</dd>
        </dl>
        {#if issued}
          <SecretBox bind:ref={tokenInput} bind:copied secret={issued.token} label="Token for" code={issued.name} children={howTo} />
        {/if}
        {#if admin}
          <Button bind:ref={issueButton} variant="outline" size="sm" class="justify-self-start" onclick={issue} onkeydown={once} disabled={saving}>
            {issuing ? 'Issuing…' : 'Issue another token'}
          </Button>
        {/if}
        <section class="grid gap-2" aria-labelledby="{id}-tokens">
          <h3 id="{id}-tokens" bind:this={tokensHeading} tabindex="-1" class="font-medium outline-none">Tokens</h3>
          {#if tokens.length === 0}
            <p class="text-sm text-muted-foreground">No tokens: it cannot fetch its configuration.</p>
          {:else}
            <ul class="divide-y rounded-lg border">
              {#each tokens as t (t.prefix)}
                <li class="grid gap-1 px-3 py-2">
                  <div class="flex min-h-8 items-center gap-2">
                    <code class="font-mono">{t.prefix}</code>
                    {#if admin}
                      <Button
                        variant="ghost"
                        size="sm"
                        class="ml-auto text-danger"
                        aria-label="Revoke {t.prefix}"
                        onclick={(event) => ask({ kind: 'revoke', prefix: t.prefix }, event.currentTarget)}
                        onkeydown={once}
                        disabled={saving}>Revoke</Button
                      >
                    {/if}
                  </div>
                  <dl class="grid grid-cols-[auto_1fr] gap-x-3 text-xs text-muted-foreground">
                    <dt>Created</dt><dd>{when(t.created_at)}</dd>
                    <dt>Last used</dt><dd>{t.last_used_at ? when(t.last_used_at) : 'never'}</dd>
                  </dl>
                </li>
              {/each}
            </ul>
          {/if}
          {#if admin}
            <p class="text-xs text-muted-foreground">
              To rotate: issue another token, give it to the gateway, and revoke the old one once the new one shows as used.
            </p>
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
        <Button variant="outline" onclick={reload}>Reload</Button>
      {/if}
      {#if question}
        <p class="text-sm" role="alert">{sentence}</p>
        <Button variant={question.kind === 'close' ? 'default' : 'destructive'} onclick={confirm} onkeydown={once} disabled={saving}>
          {CONFIRM[question.kind]}
        </Button>
        <Button bind:ref={keep} variant="outline" onclick={dismiss} onkeydown={once} disabled={saving}>
          {question.kind === 'close' ? 'Keep it open' : 'Keep it'}
        </Button>
      {:else}
        {#if mode === 'create' && !issued}
          <Button bind:ref={submit} type="submit" form="{id}-form" onkeydown={once} disabled={saving}>{saving ? 'Registering…' : 'Register'}</Button>
        {/if}
        {#if admin}
          <Button bind:ref={del} variant="ghost" class="text-danger" onclick={() => ask({ kind: 'delete' })} onkeydown={once} disabled={saving}>Delete data plane</Button>
        {/if}
        <Sheet.Close disabled={saving}>
          {#snippet child({ props })}
            <Button variant="outline" {...props}>{mode === 'create' && !issued ? 'Cancel' : 'Close'}</Button>
          {/snippet}
        </Sheet.Close>
      {/if}
    </Sheet.Footer>
  </Sheet.Content>
</Sheet.Root>
