<script>
  import { tick } from 'svelte'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import NativeSelect from './NativeSelect.svelte'
  import { write } from './api.js'
  import { base, MAX_RATE_LIMIT, PER } from './configuration.js'
  import { can } from './workspace.js'

  // One request limit, applied on its own as KeyAuthControl's key requirement is, and for the
  // same reasons: it changes how much may be asked rather than where traffic goes, its refusal is
  // not the sheet's, and Enter in its input applies it rather than saving the sheet.
  // - `target` is `workspace`, `service:{name}` or `route:{name}`;
  // - `applies` is the limit the list says applies to it, `{ limit, per, from }` or null, where
  //   `from` may be a broader target, which is changed where it is set, not here;
  // - `onchanged` fetches the list again, which brings the new `applies`, and settles once it is
  //   drawn or has failed without rejecting. It must not close the sheet this sits in.
  let { workspace, target, applies = null, role, onchanged } = $props()

  const id = $props.id()
  const DEFAULT_PER = 'minute'
  const kind = $derived(target.split(':')[0])
  const inherited = $derived(Boolean(applies) && applies.from !== kind)
  // What is set on this target itself, which is what the form starts from and is compared with.
  const own = $derived(applies && !inherited ? applies : null)

  let on = $state(false)
  // A number, or null while the input is empty: what a number input binds to.
  let limit = $state(null)
  let per = $state(DEFAULT_PER)
  let saving = $state(false)
  // `{ sentence, field }` from a refused apply; a `limit` or `per` field puts the sentence beside
  // that input.
  let error = $state(undefined)
  let box = $state(null)
  let input = $state(null)
  let button = $state(null)
  let group = $state(null)

  // Starts again from what the list says whenever it says something new: after an apply, after
  // the sheet's own save, or for another row. `applies` and `target` are read, not only `own`, so
  // a fresh list that says the same thing still discards an apply the list did not keep.
  $effect.pre(() => {
    applies
    target
    on = own !== null
    limit = own?.limit ?? null
    per = own?.per ?? DEFAULT_PER
    error = undefined
  })

  const changed = $derived(on !== (own !== null) || (on && (limit !== own.limit || per !== own.per)))
  const placed = $derived(['limit', 'per'].includes(error?.field) ? error.field : undefined)

  async function apply(event) {
    event.preventDefault()
    if (saving || !changed) return
    saving = true
    error = undefined
    try {
      if (on) await write('PUT', base(workspace, 'rate-limit'), { target, limit, per })
      else await write('DELETE', `${base(workspace, 'rate-limit')}?target=${encodeURIComponent(target)}`)
    } catch (failure) {
      // `Refused` names the field it is about; `Forbidden` and a connection that failed do not,
      // and their sentence goes in the box below.
      saving = false
      error = { sentence: failure.message, field: failure.field }
      await tick()
      const named = placed === 'limit' ? input : placed === 'per' ? document.getElementById(`${id}-per`) : null
      ;(named ?? button)?.focus()
      return
    }
    await onchanged()
    saving = false
    // The list now says what applies, and the form has started again from it. The checkbox is
    // where the change was made; when the limit is now a broader one's there is none, and the
    // group stands in for it.
    await tick()
    ;(box?.isConnected ? box : group)?.focus()
  }

  const described = (field, help) =>
    [placed === field ? `${id}-${field}-error` : null, help].filter(Boolean).join(' ') || undefined
</script>

{#snippet problem(field)}
  {#if placed === field}
    <p id="{id}-{field}-error" class="text-xs text-danger">{error.sentence}</p>
  {/if}
{/snippet}

<form onsubmit={apply}>
  <fieldset bind:this={group} tabindex="-1" class="grid gap-2 rounded-lg border p-3 outline-none" disabled={saving}>
    <legend class="px-1 font-medium">Request limit</legend>
    {#if inherited}
      <p>Limited by the {applies.from}: {applies.limit} per {applies.per}.</p>
    {:else if can.write(role)}
      <label class="flex items-center gap-2">
        <input bind:this={box} type="checkbox" bind:checked={on} onchange={() => (error = undefined)} />
        Limit requests
      </label>
      {#if on}
        <div class="grid grid-cols-2 gap-2">
          <div class="grid gap-1.5">
            <label for="{id}-limit" class="font-medium">Requests</label>
            <Input
              bind:ref={input}
              id="{id}-limit"
              type="number"
              step="1"
              min="1"
              max={MAX_RATE_LIMIT}
              bind:value={limit}
              aria-invalid={placed === 'limit'}
              aria-describedby={described('limit', `${id}-help`)}
            />
          </div>
          <div class="grid gap-1.5">
            <label for="{id}-per" class="font-medium">Window</label>
            <NativeSelect
              id="{id}-per"
              bind:value={per}
              aria-invalid={placed === 'per'}
              aria-describedby={described('per')}
            >
              {#each PER as unit (unit)}<option value={unit}>per {unit}</option>{/each}
            </NativeSelect>
          </div>
        </div>
        {@render problem('limit')}
        {@render problem('per')}
        <p id="{id}-help" class="text-xs text-muted-foreground">
          Per client address, counted by each gateway replica separately: with 3 replicas a client can make up to 3 × this.
        </p>
      {/if}
      {#if error && !placed}
        <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
          {error.sentence}
        </p>
      {/if}
      <Button bind:ref={button} type="submit" variant="outline" size="sm" class="justify-self-start" disabled={saving || !changed}>
        {saving ? 'Applying…' : 'Apply'}
      </Button>
    {:else if own !== null}
      <p>Limited: {own.limit} per {own.per}.</p>
    {:else}
      <p>Not limited.</p>
    {/if}
  </fieldset>
</form>
