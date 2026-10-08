<script>
  import { onMount } from 'svelte'
  import { Button } from '$lib/components/ui/button/index.js'
  import PasswordForm from './PasswordForm.svelte'

  // What App shows in place of the console to an account on a temporary password, which a
  // superuser set when creating it or resetting it: every other store API refuses it until it has
  // chosen its own. `onchosen` reads /api/me again once the server has taken the new password; the
  // 204 came with a fresh session, and the new answer no longer says it must change, so App then
  // draws the console.
  let { me, onchosen } = $props()

  const id = $props.id()

  let saving = $state(false)
  let failure = $state(undefined)
  let submit = $state(null)
  let heading = $state(null)

  // The page replaces the whole console, so focus starts on what it is about.
  onMount(() => heading?.focus())
</script>

<main class="flex min-h-svh items-start justify-center bg-background px-4 py-12 sm:items-center">
  <div class="grid w-full max-w-sm gap-6 rounded-lg border bg-card p-6 shadow-xs">
    <div class="grid gap-1.5">
      <h1 bind:this={heading} tabindex="-1" class="text-xl font-semibold tracking-tight outline-none">Choose a new password</h1>
      <p class="text-sm text-muted-foreground">Your password was set by a superuser. Choose your own to continue.</p>
    </div>
    <PasswordForm
      id="{id}-form"
      username={me.name}
      bind:saving
      bind:failure
      onchanged={onchosen}
      onfailed={() => submit?.focus()}
    />
    {#if failure}
      <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-sm text-danger wrap-anywhere">
        {failure}
      </p>
    {/if}
    <div class="flex items-center justify-between gap-3">
      <!-- The same form as the sidebar's Sign out: signing out is a navigation, and the server
           answers it with its "signed out" page. -->
      <form method="post" action="/auth/logout">
        <Button type="submit" variant="link" class="px-0">Sign out</Button>
      </form>
      <Button
        bind:ref={submit}
        type="submit"
        form="{id}-form"
        onkeydown={(event) => event.repeat && event.preventDefault()}
        disabled={saving}
      >
        {saving ? 'Saving…' : 'Save password'}
      </Button>
    </div>
  </div>
</main>
