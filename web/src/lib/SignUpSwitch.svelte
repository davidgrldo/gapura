<script>
  import { tick } from 'svelte'
  import { Button } from '$lib/components/ui/button/index.js'
  import Failure from './Failure.svelte'
  import { get, write } from './api.js'

  // Whether people may sign themselves up, for superusers on the Users page: read from
  // `GET /api/settings` and changed with `PUT /api/settings`, on its own rather than with any
  // sheet's Save. Opening asks first, in place, because it lets anyone who can reach the console
  // make an account; closing takes nothing from anyone, so it applies at once. A 204 means the
  // server now holds what was sent, so that is what is shown, without reading it back.

  let settings = $state(undefined)
  let failed = $state(undefined)
  let saving = $state(false)
  let asking = $state(false)
  // A refused change, in the server's words.
  let error = $state(undefined)
  // Focus goes back to the button once a request or a question is over: disabling it, or putting
  // the question where it was, dropped focus.
  let toggle = $state(null)
  let keep = $state(null)
  // When the question went up, by `performance.now()`. Not state: nothing is drawn from it.
  let askedAt = 0

  get('/api/settings').then(
    (answer) => (settings = answer),
    (failure) => (failed = failure),
  )

  async function set(open) {
    saving = true
    error = undefined
    try {
      await write('PUT', '/api/settings', { sign_up_open: open })
      settings = { ...settings, sign_up_open: open }
    } catch (failure) {
      error = failure.message
    }
    saving = false
    asking = false
    await tick()
    toggle?.focus()
  }

  async function change() {
    if (saving) return
    if (settings.sign_up_open) return set(false)
    error = undefined
    asking = true
    askedAt = performance.now()
    await tick()
    keep?.focus()
  }

  // A double-click on Open sign-up sends its second click within milliseconds, to whatever is
  // under the pointer by then, which must not be taken as an answer.
  function confirm() {
    if (saving || performance.now() - askedAt < 500) return
    set(true)
  }

  async function dismiss() {
    asking = false
    await tick()
    toggle?.focus()
  }

  // A key held down repeats, and a repeat must not answer the question.
  const once = (event) => event.repeat && event.preventDefault()
</script>

{#if failed}
  <div class="mb-4"><Failure error={failed} what="the sign-up setting" /></div>
{:else if settings === undefined}
  <p class="mb-4 text-sm text-muted-foreground">Reading whether sign-up is open…</p>
{:else}
  <section aria-label="Sign-up" class="mb-4 max-w-2xl rounded-lg border bg-card p-3 text-sm shadow-xs">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <p class="min-w-0 flex-1">
        <span class="font-medium">Sign-up is {settings.sign_up_open ? 'open' : 'closed'}.</span>
        <span class="text-muted-foreground">
          Let people create their own accounts at <code class="font-mono">/auth/signup</code>. They reach
          nothing until someone grants them a role.
        </span>
      </p>
      {#if !asking}
        <Button bind:ref={toggle} variant="outline" size="sm" onclick={change} onkeydown={once} disabled={saving}>
          {#if saving}Saving…{:else}{settings.sign_up_open ? 'Close sign-up' : 'Open sign-up'}{/if}
        </Button>
      {/if}
    </div>
    {#if asking}
      <div class="mt-3 grid gap-2">
        <p role="alert">
          Open sign-up? Anyone who can reach this console can create an account; it reaches nothing
          until someone grants it a role.
        </p>
        <div class="flex flex-wrap gap-2">
          <Button size="sm" onclick={confirm} onkeydown={once} disabled={saving}>{saving ? 'Opening…' : 'Open'}</Button>
          <Button bind:ref={keep} variant="outline" size="sm" onclick={dismiss} onkeydown={once} disabled={saving}>
            Keep it closed
          </Button>
        </div>
      </div>
    {/if}
    {#if error}
      <p role="alert" class="mt-3 rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
        {error}
      </p>
    {/if}
  </section>
{/if}
