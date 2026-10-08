<script>
  import { tick } from 'svelte'
  import * as Sheet from '$lib/components/ui/sheet/index.js'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import SecretBox from './SecretBox.svelte'
  import Tag from './Tag.svelte'
  import { write } from './api.js'
  import { base, when } from './configuration.js'
  import { can } from './workspace.js'
  import Plus from 'phosphor-svelte/lib/Plus'

  // The Consumers page's one sheet:
  // - `create` is New consumer, for editors and admins: a name, and nothing else;
  // - `edit` shows one consumer's keys. An editor can issue a key, an admin can also revoke one
  //   and delete the consumer; a viewer sees the keys and no controls at all.
  // An issued key is shown once, in a box that stays until the sheet closes. Issuing and revoking
  // fetch the list again without closing the sheet: rows are keyed by name, so this sheet stays
  // mounted under the new list and the box with it. Questions (delete, revoke, close without
  // copying) are asked in the footer, as ServiceSheet asks its delete question, and open on the
  // button that keeps things as they are.
  // `onsaved` fetches the list again and returns a promise that settles once it is drawn or has
  // failed, and never rejects. `onremoved` is where focus goes when the new list no longer has the
  // row this sheet's button was in.
  let { mode, consumer = undefined, workspace, role, onsaved, onremoved = undefined } = $props()

  const id = $props.id()
  const issuer = $derived(mode === 'edit' && can.write(role))
  const admin = $derived(mode === 'edit' && can.delete(role))

  let open = $state(false)
  // The button that opened the sheet, so focus can go back to it after a save.
  let trigger = $state(null)
  // Where focus goes after a refusal that names no field: disabling a button while it is busy
  // drops focus.
  let submit = $state(null)
  let issueButton = $state(null)
  let keep = $state(null)
  let del = $state(null)
  let keysHeading = $state(null)
  let keyInput = $state(null)
  let name = $state('')
  let expires = $state('')
  let saving = $state(false)
  let issuing = $state(false)
  // `{ sentence, field, stale }` from a refused write; `field` puts the sentence beside its input.
  let error = $state(undefined)
  // The question in the footer: `{ kind: 'delete' }`, `{ kind: 'close' }` or
  // `{ kind: 'revoke', prefix }`; and when it went up, so a double-click on the button that asked
  // cannot answer it.
  let question = $state(null)
  let askedAt = 0
  // The Revoke button that asked, which Keep it hands focus back to. Revoke buttons sit in the
  // keys list, which the footer's question does not replace, so the element is still there.
  let asker = null
  // `{ key, prefix, expires_at }`, the server's one answer that carries a key.
  let issued = $state(null)
  let copied = $state(false)
  // A refusal leaves the list possibly out of date; it is fetched when the sheet closes, not
  // while the reader is reading why.
  let staleOnClose = false

  function reset() {
    name = ''
    expires = ''
    saving = false
    issuing = false
    error = undefined
    question = null
    issued = null
    copied = false
  }

  // The fields this sheet draws, and the ids of their inputs. A refusal naming anything else has
  // no input to sit beside, so its sentence goes in the footer.
  const INPUT = $derived(mode === 'create' ? { name: 'name' } : { expires_at: 'expires' })
  const shown = $derived(Object.hasOwn(INPUT, error?.field ?? ''))

  const invalid = (field) => error?.field === field
  const described = (field) => (invalid(field) ? `${id}-${field}-error` : undefined)
  const here = () => `${base(workspace, 'consumers')}/${encodeURIComponent(consumer.name)}`
  const keys = $derived(consumer?.keys ?? [])

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
        // A 404 on a change to this consumer or one of its keys means someone else removed it,
        // and the list is what to look at.
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

  async function create(event) {
    event.preventDefault()
    if (mode !== 'create' || saving) return
    const done = await request('POST', base(workspace, 'consumers'), { name: name.trim() }, () => submit)
    if (done) await closeAndReload()
  }

  async function issue(event) {
    event.preventDefault()
    if (!issuer || saving || question) return
    const body = {}
    if (expires.trim() !== '') {
      const at = new Date(expires)
      if (Number.isNaN(at.getTime())) {
        error = { sentence: 'Give a date and time, or leave it empty for a key that never expires.', field: 'expires_at' }
        await tick()
        document.getElementById(`${id}-expires`)?.focus()
        return
      }
      body.expires_at = at.toISOString()
    }
    issuing = true
    const done = await request('POST', `${here()}/keys`, body, () => issueButton, true)
    if (!done) return
    issued = done.answer
    copied = false
    expires = ''
    await reloadInPlace()
    keyInput?.focus()
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
      `${here()}/keys/${encodeURIComponent(asked.prefix)}`,
      undefined,
      () => (asker?.isConnected ? asker : keysHeading),
    )
    if (!done) return
    question = null
    await reloadInPlace()
    keysHeading?.focus()
  }

  async function dismiss() {
    const asked = question
    question = null
    await tick()
    if (asked?.kind === 'close') keyInput?.focus()
    else if (asked?.kind === 'delete') del?.focus()
    else (asker?.isConnected ? asker : keysHeading)?.focus()
  }

  // A key held down repeats, and a repeat must not answer a question or drop it.
  const once = (event) => event.repeat && event.preventDefault()

  // The stale refusal's way out. New consumer closes and draws the list as it is now; a consumer's
  // sheet stays open, since it may be holding a key that is shown only once, and takes the new
  // list as it comes. A consumer gone from it takes this sheet with it.
  async function reload() {
    if (mode === 'create') return closeAndReload()
    error = undefined
    await reloadInPlace()
    if (trigger?.isConnected) keysHeading?.focus()
    else keepPlace()
  }

  async function closed() {
    if (!staleOnClose) return
    staleOnClose = false
    await onsaved()
    await tick()
    keepPlace()
  }

  // Refuses to close while a request is in flight, for the reason MappingSheet gives, and asks
  // first while a key that was never copied is on screen. While that question is up, only its own
  // buttons answer it: an Escape held down must not.
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
    if (question?.kind === 'close') return 'Close without copying the key? It cannot be shown again.'
    if (question?.kind === 'revoke') {
      return `Revoke ${question.prefix}? Requests with this key are refused from the gateway's next poll.`
    }
    const n = keys.length
    const what = n === 0 ? '' : n === 1 ? ' and its 1 key' : ` and its ${n} keys`
    return `Delete ${consumer?.name}${what}? This cannot be undone.`
  })
  const CONFIRM = { close: 'Close', revoke: 'Revoke', delete: 'Delete' }
</script>

{#snippet problem(field)}
  {#if invalid(field)}
    <p id="{id}-{field}-error" class="text-xs text-danger">{error.sentence}</p>
  {/if}
{/snippet}

<Sheet.Root bind:open={() => open, setOpen} onOpenChange={(next) => next && reset()}>
  <Sheet.Trigger>
    {#snippet child({ props })}
      {#if mode === 'create'}
        <Button bind:ref={trigger} size="sm" {...props}><Plus aria-hidden="true" />New consumer</Button>
      {:else}
        <Button
          bind:ref={trigger}
          variant="ghost"
          size="sm"
          aria-label="{issuer ? 'Manage' : 'View'} the consumer {consumer.name}"
          {...props}>{issuer ? 'Manage' : 'View'}</Button
        >
      {/if}
    {/snippet}
  </Sheet.Trigger>
  <Sheet.Content class="data-[side=right]:w-full data-[side=right]:sm:max-w-md">
    <Sheet.Header>
      <Sheet.Title class="pr-8">
        {#if mode === 'create'}New consumer{:else}Consumer <span class="font-mono">{consumer.name}</span>{/if}
      </Sheet.Title>
      <Sheet.Description>
        A caller of the routes in {workspace} that require an API key, known by the keys it holds.
      </Sheet.Description>
    </Sheet.Header>
    <div class="grid gap-5 overflow-y-auto px-4">
      {#if mode === 'create'}
        <form id="{id}-form" class="grid gap-5" onsubmit={create}>
          <fieldset class="grid gap-1.5" disabled={saving}>
            <label for="{id}-name" class="font-medium">Name</label>
            <Input id="{id}-name" class="font-mono" bind:value={name} autocomplete="off" autocapitalize="off" spellcheck="false" aria-invalid={invalid('name')} aria-describedby={described('name')} />
            {@render problem('name')}
            <p class="text-xs text-muted-foreground">Save it first, then issue it a key.</p>
          </fieldset>
        </form>
      {:else}
        {#if issued}
          <SecretBox
            bind:ref={keyInput}
            bind:copied
            secret={issued.key}
            label="New key"
            code={issued.prefix}
            note={issued.expires_at ? `It expires ${when(issued.expires_at)}.` : 'It never expires.'}
          />
        {/if}
        {#if issuer}
          <form class="grid gap-2" onsubmit={issue}>
            <fieldset class="grid gap-2" disabled={saving}>
              <div class="grid gap-1.5">
                <label for="{id}-expires" class="font-medium">Expires <span class="font-normal text-muted-foreground">(optional)</span></label>
                <Input id="{id}-expires" type="datetime-local" bind:value={expires} aria-invalid={invalid('expires_at')} aria-describedby={[described('expires_at'), `${id}-expires-hint`].filter(Boolean).join(' ')} />
                {@render problem('expires_at')}
                <p id="{id}-expires-hint" class="text-xs text-muted-foreground">In your own time zone. Empty means the key never expires.</p>
              </div>
              <Button bind:ref={issueButton} type="submit" variant="outline" size="sm" class="justify-self-start" onkeydown={once}>
                {issuing ? 'Issuing…' : 'Issue a key'}
              </Button>
            </fieldset>
          </form>
        {/if}
        <section class="grid gap-2" aria-labelledby="{id}-keys">
          <h3 id="{id}-keys" bind:this={keysHeading} tabindex="-1" class="font-medium outline-none">Keys</h3>
          {#if keys.length === 0}
            <p class="text-sm text-muted-foreground">No keys yet.</p>
          {:else}
            <ul class="divide-y rounded-lg border">
              {#each keys as k (k.prefix)}
                <li class="grid gap-1 px-3 py-2">
                  <div class="flex min-h-8 items-center gap-2">
                    <code class="font-mono">{k.prefix}</code>
                    {#if k.expired}<Tag tone="idle">Expired</Tag>{/if}
                    {#if admin}
                      <Button
                        variant="ghost"
                        size="sm"
                        class="ml-auto text-danger"
                        aria-label="Revoke {k.prefix}"
                        onclick={(event) => ask({ kind: 'revoke', prefix: k.prefix }, event.currentTarget)}
                        onkeydown={once}
                        disabled={saving}>Revoke</Button
                      >
                    {/if}
                  </div>
                  <dl class="grid grid-cols-[auto_1fr] gap-x-3 text-xs text-muted-foreground">
                    <dt>Created</dt><dd>{when(k.created_at)}</dd>
                    <dt>Expires</dt><dd>{k.expires_at ? when(k.expires_at) : 'never'}</dd>
                  </dl>
                </li>
              {/each}
            </ul>
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
        {#if mode === 'create'}
          <Button bind:ref={submit} type="submit" form="{id}-form" onkeydown={once} disabled={saving}>{saving ? 'Saving…' : 'Save'}</Button>
        {/if}
        {#if admin}
          <Button bind:ref={del} variant="ghost" class="text-danger" onclick={() => ask({ kind: 'delete' })} onkeydown={once} disabled={saving}>Delete consumer</Button>
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
