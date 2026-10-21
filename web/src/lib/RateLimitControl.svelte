<script>
  import { tick } from 'svelte'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import NativeSelect from './NativeSelect.svelte'
  import { get, write } from './api.js'
  import { base, BY, BY_LABEL, byParts, byText, countedBy, listed, MAX_RATE_LIMIT, PER } from './configuration.js'
  import { can } from './workspace.js'

  // One request limit, applied on its own as KeyAuthControl's key requirement is, and for the
  // same reasons: it changes how much may be asked rather than where traffic goes, its refusal is
  // not the sheet's, and Enter in its input applies it rather than saving the sheet.
  // - `target` is `workspace`, `service:{name}` or `route:{name}`;
  // - `applies` is the limit the list says applies to it, `{ limit, per, by, from, updated_at }`
  //   or null, where `by` is left out for the address and `from` may be a broader target, which
  //   is changed where it is set, not here.
  //   `updated_at` is the policy row's stamp, which an apply sends back; when it is left out, it
  //   is read here;
  // - `consumer` names the consumer whose own limit this is, and is sent with every write; absent
  //   for the limit on everyone. A consumer's own limit is never inherited, so its `applies.from`
  //   is the target's own kind;
  // - `legend` is what the fieldset is called: a consumer's sheet heads each of its limits by
  //   where it sits;
  // - `onchanged` fetches the list again, which brings the new `applies`, and settles once it is
  //   drawn or has failed without rejecting. It must not close the sheet this sits in.
  let { workspace, target, consumer = undefined, legend = 'Request limit', applies = null, role, onchanged } = $props()

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
  // What the limit counts by, as the form shows it: one of BY, and the header's name when it is
  // `header`.
  let mode = $state('ip')
  let header = $state('')
  // The consumers whose own limit on this target replaces this one for them, read from the limits
  // list. Only the limit on everyone has any; empty until read, and when the read fails, which
  // costs nothing but the note.
  let others = $state([])
  let saving = $state(false)
  // `{ sentence, field }` from a refused apply; a `limit`, `per` or `by` field puts the sentence
  // beside that input.
  let error = $state(undefined)
  let box = $state(null)
  let input = $state(null)
  let button = $state(null)
  let group = $state(null)
  // The stamp of the limit set here as it was read, which an apply sends back so that one
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
    limit = own?.limit ?? null
    per = own?.per ?? DEFAULT_PER
    const parts = byParts(own?.by)
    mode = parts.mode
    header = parts.header
    error = undefined
  })

  // A list that leaves the stamp out has it read from the limits list. One that no longer says
  // what `applies` does is not this read's, so an empty stamp is kept, which the server refuses
  // as stale. The limit on everyone reads the list whatever the stamp, for the consumers whose own
  // limit replaces it here. What is decided is kept in locals, and `seen` and `reading` are only
  // ever written in here, never read back: an effect that reads what it writes depends on it, and
  // the list's answer writing them would start the effect over and fetch again, for ever.
  $effect(() => {
    applies
    const mine = ++latest
    const stamp = applies?.updated_at
    const needsStamp = own !== null && stamp === undefined
    const naming = consumer === undefined
    seen = stamp
    reading = needsStamp
    if (!needsStamp && !naming) return
    get(base(workspace, 'rate-limit')).then(
      (list) => {
        if (mine !== latest) return
        if (naming) others = list.filter((r) => r.target === target && r.consumer).map((r) => r.consumer)
        if (!needsStamp) return
        // The row of this very limit: the one on everyone names no consumer, a consumer's names it.
        const row = list.find((r) => r.target === target && r.consumer === consumer)
        // `by` is compared too: a limit changed to count by something else since the list was
        // read is not the one this form shows, and its stamp would let an apply replace it unseen.
        seen = row && row.limit === own.limit && row.per === own.per && row.by === own.by ? row.updated_at : ''
        reading = false
      },
      () => {
        if (mine !== latest) return
        if (naming) others = []
        if (!needsStamp) return
        seen = ''
        reading = false
      },
    )
  })

  // What the limit counts by, as the server reads it, and as the limit set here has it.
  const chosen = $derived(byText(mode, header))
  const changed = $derived(
    on !== (own !== null) ||
      (on && (limit !== own.limit || per !== own.per || chosen !== (own.by ?? 'ip'))),
  )
  const placed = $derived(['limit', 'per', 'by'].includes(error?.field) ? error.field : undefined)

  async function apply(event) {
    event.preventDefault()
    if (saving || reading || !changed) return
    saving = true
    error = undefined
    if (on && mode === 'header' && header.trim() === '') {
      saving = false
      error = { sentence: 'Name the header to count by.', field: 'by' }
      await tick()
      document.getElementById(`${id}-header`)?.focus()
      return
    }
    try {
      if (on) {
        await write('PUT', base(workspace, 'rate-limit'), {
          target,
          // The consumer whose own limit this is; left out of the body for the limit on everyone.
          consumer,
          limit,
          per,
          by: chosen,
          // None when nothing is set here: the server then refuses to replace one set since.
          seen_updated_at: own === null ? undefined : seen,
        })
      } else {
        const whose = consumer === undefined ? '' : `&consumer=${encodeURIComponent(consumer)}`
        await write('DELETE', `${base(workspace, 'rate-limit')}?target=${encodeURIComponent(target)}${whose}`)
      }
    } catch (failure) {
      // `Refused` names the field it is about; `Forbidden` and a connection that failed do not,
      // and their sentence goes in the box below.
      saving = false
      error = {
        sentence: failure.message,
        field: failure.field,
        // Someone changed or removed the limit since it was read: the list is what to look at,
        // and Reload fetches it.
        stale: failure.status === 409 && failure.message.includes('Reload'),
      }
      await tick()
      const named =
        placed === 'limit'
          ? input
          : placed === 'per'
            ? document.getElementById(`${id}-per`)
            : placed === 'by'
              ? document.getElementById(mode === 'header' ? `${id}-header` : `${id}-by`)
              : null
      ;(named ?? button)?.focus()
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
    // where the change was made; when the limit is now a broader one's there is none, and the
    // group stands in for it.
    await tick()
    ;(box?.isConnected ? box : group)?.focus()
  }

  const described = (field, help) =>
    [placed === field ? `${id}-${field}-error` : null, help].filter(Boolean).join(' ') || undefined

  // What the help line under the inputs says, by what the limit counts.
  const counted = $derived(
    mode === 'consumer'
      ? consumer === undefined
        ? 'Per consumer an API key names; a request with no key counts by its address'
        : `All of ${consumer}'s requests together`
      : mode === 'header'
        ? 'Per value of this header; a request without it, or with it sent twice, counts by its address. Only as honest as whoever sets the header: count by one only behind a proxy that overwrites it'
        : consumer === undefined
          ? 'Per client address'
          : `Per client address ${consumer} calls from`,
  )
</script>

{#snippet problem(field)}
  {#if placed === field}
    <p id="{id}-{field}-error" class="text-xs text-danger">{error.sentence}</p>
  {/if}
{/snippet}

<form onsubmit={apply}>
  <fieldset bind:this={group} tabindex="-1" class="grid gap-2 rounded-lg border p-3 outline-none" disabled={saving}>
    <legend class="px-1 font-medium">{legend}</legend>
    {#if inherited}
      <p>Limited by the {applies.from}: {applies.limit} per {applies.per}, {countedBy(applies.by)}.</p>
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
        <div class="grid grid-cols-2 gap-2">
          <div class="grid gap-1.5">
            <label for="{id}-by" class="font-medium">Count per</label>
            <NativeSelect
              id="{id}-by"
              bind:value={mode}
              aria-invalid={placed === 'by' && mode !== 'header'}
              aria-describedby={described('by', `${id}-help`)}
            >
              {#each BY as m (m)}<option value={m}>{BY_LABEL[m]}</option>{/each}
            </NativeSelect>
          </div>
          {#if mode === 'header'}
            <div class="grid gap-1.5">
              <label for="{id}-header" class="font-medium">Header</label>
              <Input
                id="{id}-header"
                class="font-mono"
                bind:value={header}
                autocomplete="off"
                autocapitalize="off"
                spellcheck="false"
                aria-invalid={placed === 'by'}
                aria-describedby={described('by', `${id}-help`)}
              />
            </div>
          {/if}
        </div>
        {@render problem('by')}
        <p id="{id}-help" class="text-xs text-muted-foreground">
          {counted}, counted by each gateway replica separately: with 3 replicas a client can make up to 3 × this.
        </p>
      {/if}
      {#if error && !placed}
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
      <p>Limited: {own.limit} per {own.per}, {countedBy(own.by)}.</p>
    {:else}
      <p>Not limited.</p>
    {/if}
    {#if others.length > 0}
      <p class="text-xs text-muted-foreground">
        {listed(others)}
        {others.length === 1 ? 'has its' : 'have their'} own limit here, which replaces this one for
        {others.length === 1 ? 'it' : 'them'}. Change {others.length === 1 ? 'it' : 'those'} on the Consumers page.
      </p>
    {/if}
  </fieldset>
</form>
