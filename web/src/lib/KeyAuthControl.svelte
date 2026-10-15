<script>
  import { tick } from 'svelte'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import { get, write } from './api.js'
  import { base } from './configuration.js'
  import { can } from './workspace.js'

  // One key requirement, applied on its own rather than with the sheet's Save: switching it is a
  // change to who may call, not to where traffic goes, and its refusal should not be mistaken for
  // the sheet's. It is its own form for the same reason, so Enter in the header applies it rather
  // than saving the sheet.
  // - `target` is `workspace`, `service:{name}` or `route:{name}`;
  // - `applies` is the requirement the list says applies to it, `{ header, from, updated_at }` or
  //   null, where `from` may be a broader target: a route without its own takes its service's,
  //   then the workspace's, and that one is changed where it is set, not here. `updated_at` is
  //   the policy row's stamp, which an apply sends back; when it is left out, it is read here;
  // - `onchanged` fetches the list again, which brings the new `applies`, and settles once it is
  //   drawn or has failed without rejecting. It must not close the sheet this sits in.
  let { workspace, target, applies = null, role, onchanged } = $props()

  const id = $props.id()
  const DEFAULT = 'x-api-key'
  const kind = $derived(target.split(':')[0])
  const inherited = $derived(Boolean(applies) && applies.from !== kind)
  // What is set on this target itself, which is what the form starts from and is compared with.
  const own = $derived(applies && !inherited ? applies.header : null)

  let on = $state(false)
  let header = $state(DEFAULT)
  let saving = $state(false)
  // `{ sentence, field }` from a refused apply; a `header` field puts the sentence beside it.
  let error = $state(undefined)
  // Where focus goes once the request is over: disabling the fieldset while it ran dropped it.
  let box = $state(null)
  let input = $state(null)
  let button = $state(null)
  let group = $state(null)
  // The stamp of the requirement set here as it was read, which an apply sends back so that one
  // changed since is refused rather than overwritten (#223); undefined while it is being read.
  let seen = $state(undefined)
  let reading = $state(false)
  // The newest read's number, so a slow answer for a row the sheet has left cannot be used.
  let latest = 0

  // Starts again from what the list says whenever it says something new: after an apply, after
  // the sheet's own save, or for another row. `applies` and `target` are read, not only `own`, so
  // a fresh list that says the same thing still discards an apply the list did not keep.
  $effect.pre(() => {
    applies
    target
    on = own !== null
    header = own ?? DEFAULT
    error = undefined
  })

  // A list that leaves the stamp out has it read from the requirements list. One that no longer
  // says what `applies` does is not this read's, so an empty stamp is kept, which the server
  // refuses as stale.
  $effect(() => {
    applies
    const mine = ++latest
    seen = applies?.updated_at
    reading = own !== null && seen === undefined
    if (!reading) return
    get(base(workspace, 'key-auth')).then(
      (list) => {
        if (mine !== latest) return
        const row = list.find((r) => r.target === target)
        seen = row && row.header === own ? row.updated_at : ''
        reading = false
      },
      () => {
        if (mine !== latest) return
        seen = ''
        reading = false
      },
    )
  })

  const changed = $derived(on !== (own !== null) || (on && header.trim().toLowerCase() !== own))
  const misnamed = $derived(error?.field === 'header')

  async function apply(event) {
    event.preventDefault()
    if (saving || reading || !changed) return
    saving = true
    error = undefined
    try {
      if (on) {
        await write('PUT', base(workspace, 'key-auth'), {
          target,
          header: header.trim(),
          // None when nothing is set here: the server then refuses to replace one set since.
          seen_updated_at: own === null ? undefined : seen,
        })
      } else await write('DELETE', `${base(workspace, 'key-auth')}?target=${encodeURIComponent(target)}`)
    } catch (failure) {
      // `Refused` names the field it is about; `Forbidden` and a connection that failed do not,
      // and their sentence goes in the box below.
      saving = false
      error = {
        sentence: failure.message,
        field: failure.field,
        // Someone changed or removed the requirement since it was read: the list is what to
        // look at, and Reload fetches it.
        stale: failure.status === 409 && failure.message.includes('Reload'),
      }
      await tick()
      ;(misnamed ? input : button)?.focus()
      return
    }
    await settle()
  }

  // Fetches the list again, which starts the form again from it, after an apply or for Reload.
  async function settle() {
    saving = true
    await onchanged()
    saving = false
    // The list now says what applies, and the form has started again from it. The checkbox is
    // where the change was made; when the requirement is now a broader one's there is none, and
    // the group stands in for it.
    await tick()
    ;(box?.isConnected ? box : group)?.focus()
  }
</script>

<form onsubmit={apply}>
  <fieldset bind:this={group} tabindex="-1" class="grid gap-2 rounded-lg border p-3 outline-none" disabled={saving}>
    <legend class="px-1 font-medium">API key</legend>
    {#if inherited}
      <p>Required by the {applies.from}, read from the <code class="font-mono">{applies.header}</code> header.</p>
    {:else if can.write(role)}
      <label class="flex items-center gap-2">
        <input bind:this={box} type="checkbox" bind:checked={on} onchange={() => (error = undefined)} />
        Require an API key
      </label>
      {#if on}
        <div class="grid gap-1.5">
          <label for="{id}-header" class="font-medium">Header</label>
          <Input
            bind:ref={input}
            id="{id}-header"
            class="font-mono"
            bind:value={header}
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
            aria-invalid={misnamed}
            aria-describedby={misnamed ? `${id}-header-error` : undefined}
          />
          {#if misnamed}
            <p id="{id}-header-error" class="text-xs text-danger">{error.sentence}</p>
          {/if}
        </div>
      {/if}
      {#if error && !misnamed}
        <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
          {error.sentence}
        </p>
      {/if}
      {#if error?.stale}
        <Button variant="outline" size="sm" class="justify-self-start" onclick={settle}>Reload</Button>
      {/if}
      <Button bind:ref={button} type="submit" variant="outline" size="sm" class="justify-self-start" disabled={saving || reading || !changed}>
        {saving ? 'Applying…' : 'Apply'}
      </Button>
    {:else if own !== null}
      <p>Required, read from the <code class="font-mono">{own}</code> header.</p>
    {:else}
      <p>Not required.</p>
    {/if}
  </fieldset>
</form>
