<script>
  import { tick } from 'svelte'
  import { Input } from '$lib/components/ui/input/index.js'
  import { write } from './api.js'

  // The three fields of a password change, the reader's own: the current password, the new one,
  // and the new one again. The console checks only that the two new ones match; the rules are the
  // server's, which answers a refusal naming `current` or `new`, put beside that field. Any other
  // refusal (too many tries, an identity-provider account, a dropped connection) is `failure`,
  // for the caller to draw where its buttons are. The form has no button of its own: the caller's
  // submit button names it by `id`. `onchanged` runs after the server's 204, which came with a
  // fresh session, since the change signs out every other one; `onfailed` after `failure` is
  // set, for focus to go back to the button that was disabled while the request ran. `username`
  // goes in a hidden field, so a password manager saves the new password against the right
  // account.
  let { id, username, onchanged, onfailed, saving = $bindable(false), failure = $bindable(undefined) } = $props()

  let current = $state('')
  let next = $state('')
  let again = $state('')
  // `{ field, sentence }`: a refusal about one of the three fields.
  let error = $state(undefined)

  const FIELDS = ['current', 'new', 'again']
  const invalid = (field) => error?.field === field
  const described = (field, ...more) =>
    [invalid(field) ? `${id}-${field}-error` : undefined, ...more].filter(Boolean).join(' ') || undefined

  async function refuse(field, sentence) {
    error = { field, sentence }
    await tick()
    document.getElementById(`${id}-${field}`)?.focus()
  }

  async function submit(event) {
    event.preventDefault()
    if (saving) return
    error = undefined
    failure = undefined
    if (next !== again) {
      await refuse('again', 'The two new passwords differ.')
      return
    }
    saving = true
    try {
      await write('POST', '/api/me/password', { current, new: next })
    } catch (refusal) {
      saving = false
      if (FIELDS.includes(refusal.field)) {
        await refuse(refusal.field, refusal.message)
      } else {
        failure = refusal.message
        await tick()
        onfailed()
      }
      return
    }
    current = ''
    next = ''
    again = ''
    await onchanged()
    saving = false
  }
</script>

{#snippet problem(field)}
  {#if invalid(field)}
    <p id="{id}-{field}-error" class="text-xs text-danger">{error.sentence}</p>
  {/if}
{/snippet}

<form {id} class="grid gap-5" onsubmit={submit}>
  <input type="text" class="hidden" autocomplete="username" value={username} readonly tabindex="-1" aria-hidden="true" />
  <fieldset class="grid gap-5" disabled={saving}>
    <div class="grid gap-1.5">
      <label for="{id}-current" class="font-medium">Current password</label>
      <Input
        id="{id}-current"
        type="password"
        bind:value={current}
        autocomplete="current-password"
        aria-invalid={invalid('current')}
        aria-describedby={described('current')}
      />
      {@render problem('current')}
    </div>
    <div class="grid gap-1.5">
      <label for="{id}-new" class="font-medium">New password</label>
      <Input
        id="{id}-new"
        type="password"
        bind:value={next}
        autocomplete="new-password"
        aria-invalid={invalid('new')}
        aria-describedby={described('new', `${id}-rules`)}
      />
      {@render problem('new')}
      <p id="{id}-rules" class="text-xs text-muted-foreground">At least 12 characters, and not containing your username.</p>
    </div>
    <div class="grid gap-1.5">
      <label for="{id}-again" class="font-medium">New password again</label>
      <Input
        id="{id}-again"
        type="password"
        bind:value={again}
        autocomplete="new-password"
        aria-invalid={invalid('again')}
        aria-describedby={described('again')}
      />
      {@render problem('again')}
    </div>
  </fieldset>
</form>
