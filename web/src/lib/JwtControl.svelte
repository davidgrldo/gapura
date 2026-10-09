<script>
  import { tick } from 'svelte'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import { get, write } from './api.js'
  import { base } from './configuration.js'
  import { can } from './workspace.js'

  // One JWT requirement, applied on its own as KeyAuthControl's key requirement is, and for the
  // same reasons: it changes who may call, its refusal is not the sheet's, and Enter in one of its
  // inputs applies it rather than saving the sheet.
  // - `target` is `workspace`, `service:{name}` or `route:{name}`;
  // - `applies` is the requirement the list says applies to it, `{ issuer, from }` or null, where
  //   `from` may be a broader target, which is changed where it is set, not here. `issuer` is null
  //   only for a requirement written by hand in SQL without one: any issuer;
  // - `onchanged` fetches the list again, which brings the new `applies`, and settles once it is
  //   drawn or has failed without rejecting. It must not close the sheet this sits in.
  // The list carries no audience and no keys, so a target with its own requirement reads them
  // with `?target=`, and editing starts from what is stored.
  let { workspace, target, applies = null, role, onchanged } = $props()

  const id = $props.id()
  const kind = $derived(target.split(':')[0])
  const inherited = $derived(Boolean(applies) && applies.from !== kind)
  // What is set on this target itself, as the list says it.
  const own = $derived(applies && !inherited ? applies : null)
  const writer = $derived(can.write(role))

  let on = $state(false)
  let issuer = $state('')
  let audience = $state('')
  let jwks = $state('')
  // This target's own requirement as `?target=` answered it, `{ issuer, audience, jwks }`: what
  // the form starts from and is compared with. Undefined while it is being read, and null when
  // there is none or it could not be read.
  let stored = $state(undefined)
  // Why the stored requirement could not be read, when it could not.
  let unread = $state(undefined)
  let saving = $state(false)
  // `{ sentence, field }` from a refused apply; an `issuer`, `audience` or `jwks` field puts the
  // sentence beside that input.
  let error = $state(undefined)
  let box = $state(null)
  let button = $state(null)
  let group = $state(null)
  const inputs = $state({ issuer: null, audience: null, jwks: null })
  // The newest read's number, so a slow answer for a row the sheet has left cannot fill the form.
  let latest = 0

  // Starts again from what the list says whenever it says something new: after an apply, after
  // the sheet's own save, or for another row. `applies` and `target` are read, not only `own`, so
  // a fresh list that says the same thing still discards an apply the list did not keep.
  $effect.pre(() => {
    applies
    target
    on = own !== null
    issuer = own?.issuer ?? ''
    audience = ''
    jwks = ''
    stored = own ? undefined : null
    unread = undefined
    error = undefined
  })

  // Reads what is set here, for the audience and the JWKS the list leaves out.
  $effect(() => {
    applies
    const mine = ++latest
    if (!own) return
    get(`${base(workspace, 'jwt')}?target=${encodeURIComponent(target)}`).then(
      (document) => {
        if (mine !== latest) return
        stored = { issuer: document.issuer ?? '', audience: document.audience ?? '', jwks: document.jwks }
        issuer = stored.issuer
        audience = stored.audience
        jwks = stored.jwks
      },
      (failure) => {
        if (mine !== latest) return
        stored = null
        unread = failure.message
      },
    )
  })

  const reading = $derived(own !== null && stored === undefined)
  const changed = $derived(
    on !== (own !== null) ||
      (on &&
        (!stored ||
          issuer.trim() !== stored.issuer ||
          audience.trim() !== stored.audience ||
          jwks !== stored.jwks)),
  )
  const FIELDS = ['issuer', 'audience', 'jwks']
  const placed = $derived(FIELDS.includes(error?.field) ? error.field : undefined)
  const anyIssuer = (requirement) => requirement.issuer ?? 'any issuer'

  async function apply(event) {
    event.preventDefault()
    if (saving || reading || !changed) return
    saving = true
    error = undefined
    try {
      if (on) {
        await write('PUT', base(workspace, 'jwt'), {
          target,
          issuer: issuer.trim(),
          audience: audience.trim() || null,
          jwks,
        })
      } else {
        await write('DELETE', `${base(workspace, 'jwt')}?target=${encodeURIComponent(target)}`)
      }
    } catch (failure) {
      // `Refused` names the field it is about; `Forbidden` and a connection that failed do not,
      // and their sentence goes in the box below.
      saving = false
      error = { sentence: failure.message, field: failure.field }
      await tick()
      ;(placed ? inputs[placed] : button)?.focus()
      return
    }
    await onchanged()
    saving = false
    // The list now says what applies, and the form has started again from it. The checkbox is
    // where the change was made; when the requirement is now a broader one's there is none, and
    // the group stands in for it.
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
    <legend class="px-1 font-medium">JWT</legend>
    {#if inherited}
      <p>Required by the {applies.from}: tokens from <span class="font-mono wrap-anywhere">{anyIssuer(applies)}</span>.</p>
    {:else if writer}
      <label class="flex items-center gap-2">
        <input bind:this={box} type="checkbox" bind:checked={on} onchange={() => (error = undefined)} />
        Require a JWT
      </label>
      {#if unread}
        <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
          The keys set here could not be read ({unread}). Paste them again to change this requirement, or switch it off.
        </p>
      {/if}
      {#if on}
        {#if reading}
          <p class="text-muted-foreground">Reading the keys set here…</p>
        {:else}
          <div class="grid gap-1.5">
            <label for="{id}-issuer" class="font-medium">Issuer</label>
            <Input
              bind:ref={inputs.issuer}
              id="{id}-issuer"
              class="font-mono"
              bind:value={issuer}
              autocomplete="off"
              autocapitalize="off"
              spellcheck="false"
              aria-invalid={placed === 'issuer'}
              aria-describedby={described('issuer', `${id}-issuer-help`)}
            />
            <p id="{id}-issuer-help" class="text-xs text-muted-foreground">Required: the iss every token must carry.</p>
            {@render problem('issuer')}
          </div>
          <div class="grid gap-1.5">
            <label for="{id}-audience" class="font-medium">Audience</label>
            <Input
              bind:ref={inputs.audience}
              id="{id}-audience"
              class="font-mono"
              bind:value={audience}
              autocomplete="off"
              autocapitalize="off"
              spellcheck="false"
              aria-invalid={placed === 'audience'}
              aria-describedby={described('audience', audience.trim() ? undefined : `${id}-audience-any`)}
            />
            {#if !audience.trim()}
              <p id="{id}-audience-any" class="rounded-md bg-warning-soft px-2 py-1 text-xs text-warning">Any audience is accepted.</p>
            {/if}
            {@render problem('audience')}
          </div>
          <div class="grid gap-1.5">
            <label for="{id}-jwks" class="font-medium">Keys (JWKS)</label>
            <!-- No textarea in the kit: Input's look, grown to several lines, as the service
                 sheet's CA certificates. -->
            <textarea
              bind:this={inputs.jwks}
              id="{id}-jwks"
              rows="6"
              class="dark:bg-input/30 border-input focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive dark:aria-invalid:border-destructive/50 disabled:bg-input/50 dark:disabled:bg-input/80 w-full min-w-0 rounded-lg border bg-transparent px-2.5 py-1.5 font-mono text-xs transition-colors outline-none placeholder:text-muted-foreground focus-visible:ring-3 aria-invalid:ring-3 disabled:cursor-not-allowed disabled:opacity-50"
              bind:value={jwks}
              placeholder={'{"keys": [ … ]}'}
              autocomplete="off"
              autocapitalize="off"
              spellcheck="false"
              aria-invalid={placed === 'jwks'}
              aria-describedby={described('jwks', `${id}-jwks-help`)}
            ></textarea>
            <p id="{id}-jwks-help" class="text-xs text-muted-foreground">Public keys only. Paste the issuer's JWKS document.</p>
            {@render problem('jwks')}
          </div>
        {/if}
      {/if}
      {#if error && !placed}
        <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
          {error.sentence}
        </p>
      {/if}
      <Button bind:ref={button} type="submit" variant="outline" size="sm" class="justify-self-start" disabled={saving || reading || !changed}>
        {saving ? 'Applying…' : 'Apply'}
      </Button>
    {:else if own !== null}
      <p>
        Required: tokens from <span class="font-mono wrap-anywhere">{anyIssuer(own)}</span>{#if stored}, {#if stored.audience}for
            <span class="font-mono wrap-anywhere">{stored.audience}</span>{:else}for any audience{/if}{/if}.
      </p>
    {:else}
      <p>Not required.</p>
    {/if}
  </fieldset>
</form>
