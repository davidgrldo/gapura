<script>
  import { tick } from 'svelte'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import NativeSelect from './NativeSelect.svelte'
  import { get, write } from './api.js'
  import { fromTarget, MAX_BODY_BYTES, policyBase, SIZE_UNITS, sizeParts, sizeText } from './configuration.js'
  import { can } from './workspace.js'

  // One body size limit, applied on its own rather than with the sheet's Save, as the IP
  // restriction is: it changes what may be sent, not where traffic goes.
  // - `target` is `workspace`, `service:{name}` or `route:{name}`;
  // - `applies` is what the row says applies to it, `{ from, updated_at }` or null. `from` may be
  //   a broader target, whose limit is changed where it is set, not here. The workspace has no
  //   row, so its page leaves `applies` out and the list below says whether one is set;
  // - `service` is the service a route sends to, whose limit the route inherits when `from` is
  //   `service`. The rows carry no sizes, so the inherited one is found in the kind's list by its
  //   target, and only the route's own row names that service; left out elsewhere;
  // - `onchanged` fetches the page's list again and settles once it is drawn or has failed
  //   without rejecting. It must not close the sheet this sits in.
  let { workspace, target, service = undefined, applies = null, role, onchanged } = $props()

  const id = $props.id()
  const kind = $derived(target.split(':')[0])
  const inherited = $derived(Boolean(applies) && applies.from !== kind)

  // What is set on this target itself, read from the kind's list, which carries the sizes the
  // rows leave out: `{ max_bytes, updated_at }`, null for none, undefined while it is read.
  let own = $state(undefined)
  // The size of the broader limit that applies here instead, read from the same list; undefined
  // while it is read, when the read failed, or when the list no longer has it.
  let above = $state(undefined)
  let unread = $state(undefined)
  let on = $state(false)
  // A number, or empty while the input is: what a number input binds to.
  let amount = $state(null)
  let unit = $state('MiB')
  let saving = $state(false)
  // `{ sentence, field }` from a refused apply, the form's own refusal included; `max_bytes` puts
  // the sentence beside the number.
  let error = $state(undefined)
  let box = $state(null)
  let input = $state(null)
  let button = $state(null)
  let group = $state(null)
  // The newest read's number, so a slow answer for a row the sheet has left cannot be used.
  let latest = 0

  function read() {
    const mine = ++latest
    // Where the limit in force is set when it is not here, worked out now, while `applies` is
    // the one this read is for.
    const source = inherited ? fromTarget(applies.from, kind, { name: target.slice(kind.length + 1), service }) : undefined
    return get(policyBase(workspace, 'request_size_limit')).then(
      (list) => {
        if (mine !== latest) return
        const row = list.find((r) => r.target === target)
        own = row ? { max_bytes: row.config.max_bytes, updated_at: row.updated_at } : null
        above = list.find((r) => r.target === source)?.config.max_bytes
        unread = undefined
      },
      (failure) => {
        if (mine !== latest) return
        own = undefined
        above = undefined
        unread = failure
      },
    )
  }

  // Reads again whenever the row says something new: after an apply, after the sheet's own
  // save, or for another row. `own` and `above` are only written here and in `read`, never read,
  // so the read's answer does not start this over.
  $effect(() => {
    applies
    target
    service
    workspace
    own = undefined
    above = undefined
    read()
  })

  // The form starts again from what is set here whenever that is read anew, in the largest unit
  // that holds it whole; with nothing set, from an empty number of MiB.
  $effect.pre(() => {
    on = Boolean(own)
    const parts = own ? sizeParts(own.max_bytes) : { amount: null, unit: 'MiB' }
    amount = parts.amount
    unit = parts.unit
    error = undefined
  })

  const factor = $derived(SIZE_UNITS.find(([name]) => name === unit)[1])
  const bytes = $derived(amount * factor)
  // The most the chosen unit can hold under the bound: 1 for GiB, which the sentence words apart.
  const most = $derived(MAX_BODY_BYTES / factor)
  const fits = $derived(Number.isInteger(amount) && amount >= 1 && bytes <= MAX_BODY_BYTES)
  const changed = $derived(on !== Boolean(own) || (on && Boolean(own) && bytes !== own.max_bytes))
  const placed = $derived(error?.field === 'max_bytes' ? 'max_bytes' : undefined)
  const described = $derived([`${id}-help`, placed ? `${id}-max-error` : null].filter(Boolean).join(' '))

  async function apply(event) {
    event.preventDefault()
    if (saving || own === undefined || !changed) return
    error = undefined
    // Refused here before it is sent, in the server's words for the unit chosen: for bytes this
    // is the server's own sentence. The server stays the judge, and its refusal lands in the
    // same place.
    if (on && !fits) {
      error = {
        sentence: most > 1 ? `Use a whole number of ${unit} from 1 to ${most}.` : `Use 1 ${unit}, or a smaller unit.`,
        field: 'max_bytes',
      }
      await tick()
      input?.focus()
      return
    }
    saving = true
    try {
      if (on) {
        await write('PUT', policyBase(workspace, 'request_size_limit'), {
          target,
          config: { max_bytes: bytes },
          // None when nothing is set here: the server then refuses to replace one set since.
          seen_updated_at: own?.updated_at,
        })
      } else await write('DELETE', `${policyBase(workspace, 'request_size_limit')}?target=${encodeURIComponent(target)}`)
    } catch (failure) {
      saving = false
      error = {
        sentence: failure.message,
        field: failure.field,
        stale: failure.status === 409 && failure.message.includes('Reload'),
      }
      await tick()
      ;(placed ? input : button)?.focus()
      return
    }
    await settle()
  }

  // Fetches the page's list and this target's limit again, after an apply or for Reload.
  async function settle() {
    saving = true
    // Reload answers a refusal by reading again. When nothing was set and still nothing is, `own`
    // is null both times, so the form does not start again and would keep the refusal on screen.
    error = undefined
    await onchanged()
    await read()
    saving = false
    await tick()
    ;(box?.isConnected ? box : group)?.focus()
  }
</script>

<!-- `novalidate`: the number's bounds depend on the unit, and the browser's own bubble for a
     value past `max` would say so in its words and never in the server's. The form refuses it
     itself, beside the number, as the server would. -->
<form onsubmit={apply} novalidate>
  <fieldset bind:this={group} tabindex="-1" class="grid gap-2 rounded-lg border p-3 outline-none" disabled={saving}>
    <legend class="px-1 font-medium">Body size limit</legend>
    {#if inherited && (own !== undefined || unread)}
      <!-- An expression, not an {#if}: a block's leading space is trimmed, which ran the words together. -->
      <p>Limited{above ? ` to ${sizeText(above)}` : ''} by the {applies.from}, which is where it is changed.</p>
    {:else if unread}
      <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
        The body size limit could not be read: {unread.message}
      </p>
    {:else if own === undefined}
      <p class="text-muted-foreground">Reading…</p>
    {:else if can.write(role)}
      <label class="flex items-center gap-2">
        <input bind:this={box} type="checkbox" bind:checked={on} onchange={() => (error = undefined)} />
        Limit request body size
      </label>
      {#if on}
        <div class="grid grid-cols-2 gap-2">
          <div class="grid gap-1.5">
            <label for="{id}-max" class="font-medium">Largest body</label>
            <Input
              bind:ref={input}
              id="{id}-max"
              type="number"
              step="1"
              min="1"
              max={most}
              bind:value={amount}
              aria-invalid={placed === 'max_bytes'}
              aria-describedby={described}
            />
          </div>
          <div class="grid gap-1.5">
            <label for="{id}-unit" class="font-medium">Unit</label>
            <NativeSelect id="{id}-unit" bind:value={unit}>
              {#each SIZE_UNITS as [name] (name)}<option value={name}>{name}</option>{/each}
            </NativeSelect>
          </div>
        </div>
        {#if placed}
          <p id="{id}-max-error" class="text-xs text-danger">{error.sentence}</p>
        {/if}
        <p id="{id}-help" class="text-xs text-muted-foreground">
          A request whose Content-Length is over the limit is answered 413 REQUEST_TOO_LARGE before anything reaches the
          upstream. A body sent without one is counted as it streams and cut at the limit. At most {sizeText(MAX_BODY_BYTES)}.
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
      <Button bind:ref={button} type="submit" variant="outline" size="sm" class="justify-self-start" disabled={saving || !changed}>
        {saving ? 'Applying…' : 'Apply'}
      </Button>
    {:else if own}
      <p>Bodies over {sizeText(own.max_bytes)} are refused.</p>
    {:else}
      <p>No limit.</p>
    {/if}
  </fieldset>
</form>
