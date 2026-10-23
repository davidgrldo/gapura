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
  // with `?target=`, and editing starts from what is stored. The keys are either a JWKS pasted
  // here or the URL the issuer publishes them at, which every gateway fetches itself.
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
  // Where the keys come from: 'url', the issuer's published JWKS, or 'paste'. A new requirement
  // starts from the URL, which is how an IdP hands its keys out and stays current as it rotates.
  let source = $state('url')
  let jwksUri = $state('')
  let jwksCaPem = $state('')
  // This target's own requirement as `?target=` answered it, `{ issuer, audience, jwks, jwks_uri,
  // jwks_ca_pem, updated_at }`, the last two '' when unset: what the form starts from and is
  // compared with, and the stamp an apply sends back so that a requirement changed since is
  // refused rather than overwritten (#223).
  // Undefined while it is being read, and null when there is none or it could not be read.
  let stored = $state(undefined)
  // Why the stored requirement could not be read, when it could not.
  let unread = $state(undefined)
  let saving = $state(false)
  // `{ sentence, field }` from a refused apply; an `issuer`, `audience`, `jwks`, `jwks_uri` or
  // `jwks_ca_pem` field puts the sentence beside that input.
  let error = $state(undefined)
  let box = $state(null)
  let button = $state(null)
  let group = $state(null)
  const inputs = $state({ issuer: null, audience: null, jwks: null, jwks_uri: null, jwks_ca_pem: null })
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
    source = 'url'
    jwksUri = ''
    jwksCaPem = ''
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
        stored = {
          issuer: document.issuer ?? '',
          audience: document.audience ?? '',
          jwks: document.jwks ?? '',
          jwks_uri: document.jwks_uri ?? '',
          jwks_ca_pem: document.jwks_ca_pem ?? '',
          updated_at: document.updated_at,
        }
        issuer = stored.issuer
        audience = stored.audience
        jwks = stored.jwks
        source = stored.jwks_uri ? 'url' : 'paste'
        jwksUri = stored.jwks_uri
        jwksCaPem = stored.jwks_ca_pem
      },
      (failure) => {
        if (mine !== latest) return
        stored = null
        unread = failure.message
      },
    )
  })

  const reading = $derived(own !== null && stored === undefined)
  // Whether the keys the form holds differ from the stored ones: another source, or the same
  // source with other contents.
  const rekeyed = $derived(
    Boolean(stored) &&
      ((source === 'url') !== (stored.jwks_uri !== '') ||
        (source === 'url'
          ? jwksUri.trim() !== stored.jwks_uri || jwksCaPem.trim() !== stored.jwks_ca_pem.trim()
          : jwks !== stored.jwks)),
  )
  const changed = $derived(
    on !== (own !== null) ||
      (on && (!stored || issuer.trim() !== stored.issuer || audience.trim() !== stored.audience || rekeyed)),
  )
  const FIELDS = ['issuer', 'audience', 'jwks', 'jwks_uri', 'jwks_ca_pem']
  // With no keys at all the server names `jwks`; from the URL form that sentence belongs beside
  // the URL, the input there is.
  const field = $derived(error?.field === 'jwks' && source === 'url' ? 'jwks_uri' : error?.field)
  const placed = $derived(FIELDS.includes(field) ? field : undefined)
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
          ...(source === 'url'
            ? { jwks_uri: jwksUri.trim(), jwks_ca_pem: jwksCaPem.trim() || null }
            : { jwks }),
          // None when nothing is set here, or when what is set could not be read: the server then
          // replaces only a requirement no read could show, such as one SQL by hand broke.
          seen_updated_at: stored?.updated_at,
        })
      } else {
        await write('DELETE', `${base(workspace, 'jwt')}?target=${encodeURIComponent(target)}`)
      }
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
      ;(placed ? inputs[placed] : button)?.focus()
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
          The keys set here could not be read ({unread}). Give them again to change this requirement, or switch it off.
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
          <fieldset class="grid gap-1.5">
            <legend class="mb-1.5 font-medium">Keys</legend>
            <label class="flex items-center gap-2">
              <input type="radio" name="{id}-source" value="url" bind:group={source} onchange={() => (error = undefined)} />
              From the issuer's URL
            </label>
            <label class="flex items-center gap-2">
              <input type="radio" name="{id}-source" value="paste" bind:group={source} onchange={() => (error = undefined)} />
              Pasted JWKS
            </label>
          </fieldset>
          {#if source === 'url'}
            <div class="grid gap-1.5">
              <label for="{id}-jwks_uri" class="font-medium">JWKS URL</label>
              <Input
                bind:ref={inputs.jwks_uri}
                id="{id}-jwks_uri"
                class="font-mono"
                inputmode="url"
                bind:value={jwksUri}
                placeholder="https://issuer.example/.well-known/jwks.json"
                autocomplete="off"
                autocapitalize="off"
                spellcheck="false"
                aria-invalid={placed === 'jwks_uri'}
                aria-describedby={described('jwks_uri', `${id}-jwks_uri-help`)}
              />
              <p id="{id}-jwks_uri-help" class="text-xs text-muted-foreground">
                Every gateway fetches it, every 10 minutes or as the issuer's max-age says, and keeps the last keys it got while the
                issuer cannot be reached.
              </p>
              {@render problem('jwks_uri')}
            </div>
            <div class="grid gap-1.5">
              <label for="{id}-jwks_ca_pem" class="font-medium">CA certificates (optional)</label>
              <textarea
                bind:this={inputs.jwks_ca_pem}
                id="{id}-jwks_ca_pem"
                rows="4"
                class="dark:bg-input/30 border-input focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive dark:aria-invalid:border-destructive/50 disabled:bg-input/50 dark:disabled:bg-input/80 w-full min-w-0 rounded-lg border bg-transparent px-2.5 py-1.5 font-mono text-xs transition-colors outline-none placeholder:text-muted-foreground focus-visible:ring-3 aria-invalid:ring-3 disabled:cursor-not-allowed disabled:opacity-50"
                bind:value={jwksCaPem}
                placeholder="-----BEGIN CERTIFICATE-----"
                autocomplete="off"
                autocapitalize="off"
                spellcheck="false"
                aria-invalid={placed === 'jwks_ca_pem'}
                aria-describedby={described('jwks_ca_pem', `${id}-jwks_ca_pem-help`)}
              ></textarea>
              <p id="{id}-jwks_ca_pem-help" class="text-xs text-muted-foreground">
                Only for an issuer whose certificate a private CA signed: these replace the public roots for this URL.
              </p>
              {@render problem('jwks_ca_pem')}
            </div>
          {:else}
            <div class="grid gap-1.5">
              <label for="{id}-jwks" class="font-medium">JWKS</label>
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
      <p>
        Required: tokens from <span class="font-mono wrap-anywhere">{anyIssuer(own)}</span>{#if stored}, {#if stored.audience}for
            <span class="font-mono wrap-anywhere">{stored.audience}</span>{:else}for any audience{/if}{/if}.
      </p>
      {#if stored?.jwks_uri}
        <p>Keys from <span class="font-mono wrap-anywhere">{stored.jwks_uri}</span>.</p>
      {/if}
    {:else}
      <p>Not required.</p>
    {/if}
  </fieldset>
</form>
