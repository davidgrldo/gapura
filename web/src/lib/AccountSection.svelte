<script>
  import { tick } from 'svelte'
  import { Button } from '$lib/components/ui/button/index.js'
  import SecretBox from './SecretBox.svelte'
  import { write } from './api.js'

  // The Account section of a person's sheet, for superusers: reset their password, disable or
  // enable them, make them a superuser or no longer one, and delete them. Every one but Enable is
  // asked first, and the question, like a refusal, is drawn in the sheet's footer, which this
  // section does not own: `question` and `error` are bound by AccessSheet, which draws them and
  // whose footer buttons call `confirm` and `dismiss` below. The same footer asks before closing
  // over a reset password that was never copied, through `askToClose`.
  //
  // `user` is the account's row from /api/users and `me` the reader. `onchanged` fetches the list
  // again without closing the sheet, and returns a promise that settles once it is drawn or has
  // failed, and never rejects; the sheet stays mounted under the new list because rows are keyed
  // by id. `ondeleted` closes the sheet and fetches the list, after which focus goes to the page's
  // heading.
  // `onasked` puts focus on the footer's Keep button once a question is up. `onclose` closes the
  // sheet when the reader confirms closing without copying. `onrefused` says the list may be out
  // of date, to be fetched when the sheet closes.
  let {
    user,
    me,
    onchanged,
    ondeleted,
    onasked,
    onclose,
    onrefused,
    question = $bindable(null),
    error = $bindable(undefined),
    busy = $bindable(false),
  } = $props()

  const id = $props.id()

  // The account's own row: the lock-out controls are hidden, as the server refuses them. A
  // reset of one's own password is hidden too: it signs out every session, this one included,
  // and the temporary password would be on screen in a console about to send the reader to sign
  // in.
  const self = $derived(user.id === me.id)
  const local = $derived(user.local)
  const disabled = $derived(user.status === 'disabled')

  // `{ password }` from a reset, shown until the sheet closes.
  let issued = $state(null)
  let copied = $state(false)
  let passwordInput = $state(null)
  let heading = $state(null)
  // The section's buttons, for focus to go back to after a question or a refusal.
  let resetButton = $state(null)
  let statusButton = $state(null)
  let superuserButton = $state(null)
  let deleteButton = $state(null)
  let askedAt = 0

  const here = () => `/api/users/${encodeURIComponent(user.id)}`

  // Each question: its sentence, and the confirming button's words and tone.
  const QUESTIONS = {
    reset: () => ({
      sentence: `Reset ${user.name}'s password? Every session of theirs is signed out, and they choose a new password at their next sign-in.`,
      confirm: 'Reset password',
      destructive: true,
    }),
    disable: () => ({
      sentence: `Disable ${user.name}? They are signed out everywhere and cannot sign in until enabled again. Their roles stay.`,
      confirm: 'Disable',
      destructive: true,
    }),
    promote: () => ({
      sentence: `Make ${user.name} a superuser? Superusers act in every workspace and can read every data plane's configuration.`,
      confirm: 'Make superuser',
      destructive: false,
    }),
    demote: () => ({
      sentence: `Remove ${user.name}'s superuser? They keep only the roles granted to them.`,
      confirm: 'Remove superuser',
      destructive: true,
    }),
    delete: () => ({
      sentence: `Delete ${user.name}? Their roles go with them. Audit entries keep their name.`,
      confirm: 'Delete',
      destructive: true,
    }),
  }

  function asker(kind) {
    if (kind === 'reset') return resetButton
    if (kind === 'disable' || kind === 'enable') return statusButton
    if (kind === 'promote' || kind === 'demote') return superuserButton
    if (kind === 'delete') return deleteButton
    return passwordInput
  }

  // Back to the button that asked, or the section's heading where it has gone: a refetch may
  // have hidden it.
  function back(kind) {
    const button = asker(kind)
    ;(button?.isConnected ? button : heading)?.focus()
  }

  function ask(kind) {
    if (busy) return
    question = { kind, ...QUESTIONS[kind]() }
    askedAt = performance.now()
    onasked()
  }

  /** Whether closing has to ask first, and if so asks: a reset password never copied. */
  export function askToClose() {
    if (!issued || copied) return false
    if (question?.kind !== 'close') {
      question = {
        kind: 'close',
        sentence: 'Close without copying the password? It cannot be shown again.',
        confirm: 'Close',
        destructive: false,
      }
      askedAt = performance.now()
      onasked()
    }
    return true
  }

  // One request. Resolves with `{ answer }` once the server has made the change, or with nothing
  // after a refusal, which is then in the footer with focus back on the button that asked.
  async function request(kind, method, path, body, answers = false) {
    busy = true
    error = undefined
    try {
      return { answer: await write(method, path, body, { answers }) }
    } catch (failure) {
      busy = false
      error = failure.message
      question = null
      onrefused()
      await tick()
      back(kind)
      return undefined
    }
  }

  // After a change: the list is fetched again under the open sheet, and focus goes back to the
  // button that made it, whose words may have changed with it.
  async function changed(kind) {
    question = null
    await onchanged()
    busy = false
    await tick()
    back(kind)
  }

  async function enable() {
    if (busy) return
    question = null
    if (await request('enable', 'PUT', `${here()}/status`, { disabled: false })) await changed('enable')
  }

  /** The footer's confirming button. */
  export async function confirm() {
    if (busy || !question || performance.now() - askedAt < 500) return
    const kind = question.kind
    if (kind === 'close') {
      question = null
      onclose()
      return
    }
    if (kind === 'reset') {
      const done = await request('reset', 'POST', `${here()}/password`, undefined, true)
      if (!done) return
      issued = done.answer
      copied = false
      question = null
      await onchanged()
      busy = false
      await tick()
      passwordInput?.focus()
      return
    }
    if (kind === 'delete') {
      if (await request('delete', 'DELETE', here())) {
        question = null
        busy = false
        await ondeleted()
      }
      return
    }
    const done =
      kind === 'disable'
        ? await request(kind, 'PUT', `${here()}/status`, { disabled: true })
        : await request(kind, 'PUT', `${here()}/superuser`, { superuser: kind === 'promote' })
    if (done) await changed(kind)
  }

  /** The footer's Keep button. */
  export async function dismiss() {
    const kind = question?.kind
    question = null
    await tick()
    back(kind)
  }

  // A key held down repeats, and a repeat must not ask twice.
  const once = (event) => event.repeat && event.preventDefault()
</script>

<section class="grid gap-3" aria-labelledby="{id}-heading">
  <h3 id="{id}-heading" bind:this={heading} tabindex="-1" class="font-medium outline-none">Account</h3>
  {#if issued}
    <SecretBox
      bind:ref={passwordInput}
      bind:copied
      secret={issued.password}
      label="Temporary password for"
      code={user.name}
      note="They choose their own password at their next sign-in. Until then this one opens nothing else."
    />
  {/if}
  {#if self}
    <p class="text-muted-foreground">You cannot disable, delete or demote yourself; another superuser can.</p>
    {#if local}
      <p class="text-muted-foreground">Change your own password from Change password in the sidebar.</p>
    {/if}
  {:else}
    <div class="flex flex-wrap gap-2">
      {#if local}
        <Button bind:ref={resetButton} variant="outline" size="sm" onclick={() => ask('reset')} onkeydown={once} disabled={busy}>
          Reset password
        </Button>
      {/if}
      {#if disabled}
        <Button bind:ref={statusButton} variant="outline" size="sm" onclick={enable} onkeydown={once} disabled={busy}>Enable</Button>
      {:else}
        <Button bind:ref={statusButton} variant="outline" size="sm" onclick={() => ask('disable')} onkeydown={once} disabled={busy}>
          Disable
        </Button>
      {/if}
      <Button
        bind:ref={superuserButton}
        variant="outline"
        size="sm"
        onclick={() => ask(user.superuser ? 'demote' : 'promote')}
        onkeydown={once}
        disabled={busy}
      >
        {user.superuser ? 'Remove superuser' : 'Make superuser'}
      </Button>
      {#if local}
        <Button bind:ref={deleteButton} variant="ghost" size="sm" class="text-danger" onclick={() => ask('delete')} onkeydown={once} disabled={busy}>
          Delete account
        </Button>
      {/if}
    </div>
    {#if !local}
      <p class="text-muted-foreground">Signs in through the identity provider: disable the account instead of deleting it.</p>
    {/if}
  {/if}
</section>
