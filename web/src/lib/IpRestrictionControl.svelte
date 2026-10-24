<script>
  import { tick } from 'svelte'
  import { Button } from '$lib/components/ui/button/index.js'
  import { get, write } from './api.js'
  import { MAX_NETWORKS, policyBase } from './configuration.js'
  import { can } from './workspace.js'

  // One IP restriction, applied on its own rather than with the sheet's Save, as the key
  // requirement is: it changes who may call, not where traffic goes.
  // - `target` is `workspace`, `service:{name}` or `route:{name}`;
  // - `applies` is what the row says applies to it, `{ from, updated_at }` or null. `from` may be
  //   a broader target, whose restriction is changed where it is set, not here. The workspace has
  //   no row, so its page leaves `applies` out and the list below says whether one is set;
  // - `onchanged` fetches the page's list again and settles once it is drawn or has failed
  //   without rejecting. It must not close the sheet this sits in.
  let { workspace, target, applies = null, role, onchanged } = $props()

  const id = $props.id()
  const kind = $derived(target.split(':')[0])
  const inherited = $derived(Boolean(applies) && applies.from !== kind)

  // What is set on this target itself, read from the kind's list, which carries the lists the
  // rows leave out: `{ allow, deny, updated_at }`, null for none, undefined while it is read.
  let own = $state(undefined)
  let unread = $state(undefined)
  let on = $state(false)
  let allow = $state('')
  let deny = $state('')
  let saving = $state(false)
  // `{ sentence, field, stale }` from a refused apply; `allow` or `deny` puts the sentence beside
  // that list.
  let error = $state(undefined)
  let box = $state(null)
  let button = $state(null)
  let group = $state(null)
  const inputs = $state({ allow: null, deny: null })
  // The newest read's number, so a slow answer for a row the sheet has left cannot be used.
  let latest = 0

  function read() {
    const mine = ++latest
    return get(policyBase(workspace, 'ip_restriction')).then(
      (list) => {
        if (mine !== latest) return
        const row = list.find((r) => r.target === target)
        own = row ? { allow: row.config.allow ?? [], deny: row.config.deny ?? [], updated_at: row.updated_at } : null
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

  // The form starts again from what is set here whenever that is read anew.
  $effect.pre(() => {
    on = Boolean(own)
    allow = own?.allow.join('\n') ?? ''
    deny = own?.deny.join('\n') ?? ''
    error = undefined
  })

  // One address or network per line; blank lines and the spaces around a line say nothing.
  const lines = (text) => text.split('\n').map((line) => line.trim()).filter(Boolean)
  const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i])
  const changed = $derived(
    on !== Boolean(own) || (on && Boolean(own) && (!same(lines(allow), own.allow) || !same(lines(deny), own.deny))),
  )
  const placed = $derived(error?.field === 'allow' || error?.field === 'deny' ? error.field : undefined)
  const described = (field, help) => [help, placed === field ? `${id}-${field}-error` : null].filter(Boolean).join(' ') || undefined

  async function apply(event) {
    event.preventDefault()
    if (saving || own === undefined || !changed) return
    saving = true
    error = undefined
    try {
      if (on) {
        await write('PUT', policyBase(workspace, 'ip_restriction'), {
          target,
          config: { allow: lines(allow), deny: lines(deny) },
          // None when nothing is set here: the server then refuses to replace one set since.
          seen_updated_at: own?.updated_at,
        })
      } else await write('DELETE', `${policyBase(workspace, 'ip_restriction')}?target=${encodeURIComponent(target)}`)
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

  // Fetches the page's list and this target's restriction again, after an apply or for Reload.
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

{#snippet list(field, label, help)}
  <div class="grid gap-1.5">
    <label for="{id}-{field}" class="font-medium">{label}</label>
    <!-- No textarea in the kit: Input's look, grown to several lines, as the JWT control's. -->
    <textarea
      bind:this={inputs[field]}
      id="{id}-{field}"
      rows="3"
      class={textareaClass}
      value={field === 'allow' ? allow : deny}
      oninput={(e) => (field === 'allow' ? (allow = e.currentTarget.value) : (deny = e.currentTarget.value))}
      placeholder={field === 'allow' ? '10.0.0.0/8' : '203.0.113.7'}
      autocomplete="off"
      autocapitalize="off"
      spellcheck="false"
      aria-invalid={placed === field}
      aria-describedby={described(field, `${id}-${field}-help`)}
    ></textarea>
    <p id="{id}-{field}-help" class="text-xs text-muted-foreground">{help}</p>
    {#if placed === field}
      <p id="{id}-{field}-error" class="text-xs text-danger">{error.sentence}</p>
    {/if}
  </div>
{/snippet}

<form onsubmit={apply}>
  <fieldset bind:this={group} tabindex="-1" class="grid gap-2 rounded-lg border p-3 outline-none" disabled={saving}>
    <legend class="px-1 font-medium">IP restriction</legend>
    {#if inherited}
      <p>Restricted by the {applies.from}, which is where it is changed.</p>
    {:else if unread}
      <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
        The IP restriction could not be read: {unread.message}
      </p>
    {:else if own === undefined}
      <p class="text-muted-foreground">Reading…</p>
    {:else if can.write(role)}
      <label class="flex items-center gap-2">
        <input bind:this={box} type="checkbox" bind:checked={on} onchange={() => (error = undefined)} />
        Restrict by client address
      </label>
      {#if on}
        {@render list('deny', 'Deny', 'Refused first, even inside an allowed network. One address or network per line.')}
        {@render list('allow', 'Allow', 'When any are listed, every other address is refused. One per line.')}
        <p class="text-xs text-muted-foreground">
          Judged on the client address the access log names, the forwarded one behind a trusted proxy. At most {MAX_NETWORKS} in
          both lists together. A refused caller gets 403 IP_FORBIDDEN before any key or token is read.
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
      {#if own.deny.length}<p>Denies <span class="font-mono">{own.deny.join(', ')}</span>.</p>{/if}
      {#if own.allow.length}<p>Allows only <span class="font-mono">{own.allow.join(', ')}</span>.</p>{/if}
    {:else}
      <p>Not restricted.</p>
    {/if}
  </fieldset>
</form>
