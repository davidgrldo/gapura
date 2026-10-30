<script>
  import { tick, untrack } from 'svelte'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import { get, write } from './api.js'
  import { CORS_METHODS, MAX_AGE_SECS, MAX_ORIGINS, METHODS, listed, policyBase } from './configuration.js'
  import { can } from './workspace.js'

  // One CORS policy, applied on its own rather than with the sheet's Save, as the IP restriction
  // is: it changes which pages may call, not where traffic goes.
  // - `target` is `workspace`, `service:{name}` or `route:{name}`;
  // - `applies` is what the row says applies to it, `{ from, updated_at }` or null. `from` may be
  //   a broader target, whose policy is changed where it is set, not here. The workspace has no
  //   row, so its page leaves `applies` out and the list below says whether one is set;
  // - `onchanged` fetches the page's list again and settles once it is drawn or has failed
  //   without rejecting. It must not close the sheet this sits in.
  let { workspace, target, applies = null, role, onchanged } = $props()

  const id = $props.id()
  const kind = $derived(target.split(':')[0])
  const inherited = $derived(Boolean(applies) && applies.from !== kind)

  // What is set on this target itself, read from the kind's list, which carries the policy the
  // rows leave out: `{ config, updated_at }`, null for none, undefined while it is read.
  let own = $state(undefined)
  let unread = $state(undefined)
  let on = $state(false)
  let origins = $state('')
  let checked = $state({})
  let headers = $state('')
  let expose = $state('')
  let credentials = $state(false)
  // A number, or empty while the input is: what a number input binds to.
  let maxAge = $state(null)
  let passOn = $state(false)
  // The form as it was read, in the shape `config` builds, so that an edit undone is no change.
  let start = $state('')
  let saving = $state(false)
  // `{ sentence, field, stale }` from a refused apply; a field the form shows puts the sentence
  // beside it.
  let error = $state(undefined)
  let box = $state(null)
  let button = $state(null)
  let group = $state(null)
  // Null, not absent: the kit's Input refuses `bind:ref` to undefined.
  const inputs = $state({ origins: null, methods: null, headers: null, expose_headers: null, max_age: null })
  // The newest read's number, so a slow answer for a row the sheet has left cannot be used.
  let latest = 0

  function read() {
    const mine = ++latest
    return get(policyBase(workspace, 'cors')).then(
      (list) => {
        if (mine !== latest) return
        const row = list.find((r) => r.target === target)
        own = row ? { config: row.config, updated_at: row.updated_at } : null
        unread = undefined
      },
      (failure) => {
        if (mine !== latest) return
        own = undefined
        unread = failure
      },
    )
  }

  // Reads again whenever the row says something new: after an apply, after the sheet's own
  // save, or for another row. `own` is only written here and in `read`, never read, so the read's
  // answer does not start this over.
  $effect(() => {
    applies
    target
    workspace
    own = undefined
    read()
  })

  // Origins one per line; header names split on commas, spaces or lines. Blanks say nothing.
  const lines = (text) => text.split('\n').map((line) => line.trim()).filter(Boolean)
  const names = (text) => text.split(/[\s,]+/).filter(Boolean)

  // The form starts again from what is set here whenever that is read anew; with nothing set,
  // from the methods the server would fill in.
  $effect.pre(() => {
    const c = own?.config
    on = Boolean(own)
    origins = c?.origins.join('\n') ?? ''
    const methods = c?.methods ?? CORS_METHODS
    checked = Object.fromEntries(METHODS.map((m) => [m, methods.includes(m)]))
    headers = c?.headers?.join(', ') ?? ''
    expose = c?.expose_headers?.join(', ') ?? ''
    credentials = c?.credentials ?? false
    maxAge = c?.max_age ?? null
    passOn = c?.preflight_continue ?? false
    // Untracked: the form's own fields, read here, must not start the form over as they change.
    start = untrack(() => JSON.stringify(config()))
    error = undefined
  })

  // What a PUT sends: the server fills in what is left out, lowercases what it stores lowercase,
  // and is the judge of all of it.
  function config() {
    const c = { origins: lines(origins), methods: METHODS.filter((m) => checked[m]) }
    if (names(headers).length) c.headers = names(headers)
    if (names(expose).length) c.expose_headers = names(expose)
    if (credentials) c.credentials = true
    if (maxAge !== null && maxAge !== undefined && maxAge !== '') c.max_age = maxAge
    if (passOn) c.preflight_continue = true
    return c
  }

  const changed = $derived(on !== Boolean(own) || (on && JSON.stringify(config()) !== start))
  const FIELDS = ['origins', 'methods', 'headers', 'expose_headers', 'max_age']
  const placed = $derived(FIELDS.includes(error?.field) ? error.field : undefined)
  const described = (field, help) => [help, placed === field ? `${id}-${field}-error` : null].filter(Boolean).join(' ') || undefined

  async function apply(event) {
    event.preventDefault()
    if (saving || own === undefined || !changed) return
    saving = true
    error = undefined
    try {
      if (on) {
        await write('PUT', policyBase(workspace, 'cors'), {
          target,
          config: config(),
          // None when nothing is set here: the server then refuses to replace one set since.
          seen_updated_at: own?.updated_at,
        })
      } else await write('DELETE', `${policyBase(workspace, 'cors')}?target=${encodeURIComponent(target)}`)
    } catch (failure) {
      saving = false
      error = {
        sentence: failure.message,
        field: failure.field,
        stale: failure.status === 409 && failure.message.includes('Reload'),
      }
      await tick()
      ;(placed ? inputs[placed] : button)?.focus()
      return
    }
    await settle()
  }

  // Fetches the page's list and this target's policy again, after an apply or for Reload.
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

  const textareaClass =
    'dark:bg-input/30 border-input focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive dark:aria-invalid:border-destructive/50 disabled:bg-input/50 dark:disabled:bg-input/80 w-full min-w-0 rounded-lg border bg-transparent px-2.5 py-1.5 font-mono text-xs transition-colors outline-none placeholder:text-muted-foreground focus-visible:ring-3 aria-invalid:ring-3 disabled:cursor-not-allowed disabled:opacity-50'
</script>

{#snippet problem(field)}
  {#if placed === field}
    <p id="{id}-{field}-error" class="text-xs text-danger">{error.sentence}</p>
  {/if}
{/snippet}

{#snippet headerList(field, label, value, set, placeholder, help)}
  <div class="grid gap-1.5">
    <label for="{id}-{field}" class="font-medium">{label}</label>
    <Input
      bind:ref={inputs[field]}
      id="{id}-{field}"
      class="font-mono"
      {value}
      oninput={(e) => set(e.currentTarget.value)}
      {placeholder}
      autocomplete="off"
      autocapitalize="off"
      spellcheck="false"
      aria-invalid={placed === field}
      aria-describedby={described(field, `${id}-${field}-help`)}
    />
    <p id="{id}-{field}-help" class="text-xs text-muted-foreground">{help}</p>
    {@render problem(field)}
  </div>
{/snippet}

<!-- `novalidate`: the server judges the max age and says so beside it, in its own words. -->
<form onsubmit={apply} novalidate>
  <fieldset bind:this={group} tabindex="-1" class="grid gap-2 rounded-lg border p-3 outline-none" disabled={saving}>
    <legend class="px-1 font-medium">CORS</legend>
    {#if inherited}
      <p>Set by the {applies.from}, which is where it is changed.</p>
    {:else if unread}
      <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
        The CORS policy could not be read: {unread.message}
      </p>
    {:else if own === undefined}
      <p class="text-muted-foreground">Reading…</p>
    {:else if can.write(role)}
      <label class="flex items-center gap-2">
        <input bind:this={box} type="checkbox" bind:checked={on} onchange={() => (error = undefined)} />
        Let pages on other origins call this
      </label>
      {#if on}
        <div class="grid gap-1.5">
          <label for="{id}-origins" class="font-medium">Origins</label>
          <!-- No textarea in the kit: Input's look, grown to several lines, as the IP restriction's. -->
          <textarea
            bind:this={inputs.origins}
            id="{id}-origins"
            rows="3"
            class={textareaClass}
            bind:value={origins}
            placeholder={'https://app.example.com\nhttps://*.example.com'}
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
            aria-invalid={placed === 'origins'}
            aria-describedby={described('origins', `${id}-origins-help`)}
          ></textarea>
          <p id="{id}-origins-help" class="text-xs text-muted-foreground">
            One per line, at most {MAX_ORIGINS}: scheme://host, with a port when it is not the scheme's own. *. allows one label
            under a name; * alone allows every origin, but not with credentials.
          </p>
          {@render problem('origins')}
        </div>
        <fieldset class="grid gap-2">
          <legend class="mb-1.5 font-medium">Methods</legend>
          <div class="flex flex-wrap gap-x-4 gap-y-2">
            {#each METHODS as m, k (m)}
              <label class="flex items-center gap-1.5 font-mono text-sm">
                <input
                  bind:this={inputs[k === 0 ? 'methods' : `method-${m}`]}
                  type="checkbox"
                  bind:checked={checked[m]}
                  aria-invalid={k === 0 ? placed === 'methods' : undefined}
                  aria-describedby={k === 0 ? described('methods', `${id}-methods-help`) : undefined}
                />{m}
              </label>
            {/each}
          </div>
          <p id="{id}-methods-help" class="text-xs text-muted-foreground">
            What a preflight is told. None ticked: {listed(CORS_METHODS)}.
          </p>
          {@render problem('methods')}
        </fieldset>
        {@render headerList(
          'headers',
          'Request headers',
          headers,
          (v) => (headers = v),
          'content-type, authorization',
          'What a page may send. Empty: whatever the preflight asks for.',
        )}
        {@render headerList(
          'expose_headers',
          'Exposed headers',
          expose,
          (v) => (expose = v),
          'x-gapura-error, x-request-id',
          'What a page may read of an answer, beyond the few every page may.',
        )}
        <label class="flex items-center gap-2">
          <input type="checkbox" bind:checked={credentials} />
          Allow credentials: cookies and Authorization
        </label>
        <div class="grid gap-1.5">
          <label for="{id}-max_age" class="font-medium">Preflight cache</label>
          <Input
            bind:ref={inputs.max_age}
            id="{id}-max_age"
            type="number"
            step="1"
            min="0"
            max={MAX_AGE_SECS}
            bind:value={maxAge}
            placeholder="the browser's own"
            aria-invalid={placed === 'max_age'}
            aria-describedby={described('max_age', `${id}-max_age-help`)}
          />
          <p id="{id}-max_age-help" class="text-xs text-muted-foreground">Seconds, 0 to {MAX_AGE_SECS}.</p>
          {@render problem('max_age')}
        </div>
        <label class="flex items-center gap-2">
          <input type="checkbox" bind:checked={passOn} />
          Pass preflights to the upstream instead of answering them
        </label>
        <p class="text-xs text-muted-foreground">
          A preflight is answered before any key or token is read: 204 to an allowed origin, 403 CORS_ORIGIN_FORBIDDEN to any
          other. Every answer, the gateway's own refusals included, carries the CORS headers in place of the upstream's. A route
          that lists its methods needs OPTIONS for its preflights to reach this.
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
      <p>Allows <span class="font-mono">{own.config.origins.join(', ')}</span>{own.config.credentials ? ', with credentials' : ''}.</p>
    {:else}
      <p>No other origin is allowed.</p>
    {/if}
  </fieldset>
</form>
