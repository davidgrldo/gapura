<script>
  import { tick } from 'svelte'
  import * as Sheet from '$lib/components/ui/sheet/index.js'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import NativeSelect from './NativeSelect.svelte'
  import { write } from './api.js'
  import { METHODS, PATH_LABEL, PATH_TYPES, base } from './configuration.js'
  import { can } from './workspace.js'
  import Plus from 'phosphor-svelte/lib/Plus'

  // The Routes page's one sheet, built as ServiceSheet is:
  // - `create` is New route, for editors and admins;
  // - `edit` shows one route, read-only for a viewer, editable for an editor, and with Delete for
  //   an admin. Delete asks first, in the footer.
  // `services` are the workspace's service names, which the route may send traffic to. `onsaved`
  // fetches the list again and returns a promise that settles once it is drawn or has failed, and
  // never rejects. `onremoved` is where focus goes when the new list no longer has the row this
  // sheet's button was in, which takes the button with it: after a delete, a rename, or a row
  // removed by someone else. `superuser` is whether the signed-in account is one: only a superuser
  // may leave a route's hosts empty, so everyone else is stopped before a request that would be
  // refused.
  let {
    mode,
    route = undefined,
    services,
    workspace,
    role,
    superuser = false,
    onsaved,
    onremoved = undefined,
  } = $props()

  const id = $props.id()
  const editable = $derived(mode === 'create' || can.write(role))

  let open = $state(false)
  // The button that opened the sheet, so focus can go back to it after a save.
  let trigger = $state(null)
  // Save, where focus goes after a refusal that names no field: disabling it while saving drops
  // focus.
  let submit = $state(null)
  // The delete question's buttons: it opens on Keep it, so an Enter meant for Delete route cannot
  // answer it, and Keep it hands focus back to Delete route.
  let keep = $state(null)
  let del = $state(null)
  let name = $state('')
  let service = $state('')
  // A number input that has been cleared binds to null, so this is a number or null.
  let priority = $state(0)
  let hosts = $state([])
  let paths = $state([])
  let checked = $state({})
  let saving = $state(false)
  // `{ sentence, field, stale }` from a refused write; `field` puts the sentence beside its input.
  let error = $state(undefined)
  // Whether the delete question is up, and when it went up: a double-click on Delete must not
  // answer its own question.
  let deleting = $state(false)
  let askedAt = 0
  // A refusal leaves the list possibly out of date; it is fetched when the sheet closes, not
  // while the reader is reading why.
  let staleOnClose = false

  function reset() {
    name = route?.name ?? ''
    service = route?.service ?? services[0] ?? ''
    priority = route?.priority ?? 0
    // A new route starts with one empty host row rather than none: anyone but a superuser must
    // name a host, so a form that began without one would only be refused.
    hosts = route ? [...route.hosts] : ['']
    // A new route starts with one prefix path to fill in, the commonest case.
    paths = route ? route.paths.map((p) => ({ ...p })) : [{ type: 'prefix', value: '/' }]
    checked = Object.fromEntries(METHODS.map((m) => [m, route?.methods.includes(m) ?? false]))
    saving = false
    error = undefined
    deleting = false
  }

  // The id of the input a refused field belongs to, or undefined when this form draws none for it
  // (`updated_at`, or a row that is no longer there), in which case the sentence goes in the
  // footer. The server names a field as `hosts[2]`, `paths[1].value` or `methods[0]`; the
  // methods group takes any of the last, and its first checkbox stands for it.
  function target(field) {
    if (typeof field !== 'string') return undefined
    if (field === 'name' || field === 'service' || field === 'priority') return `${id}-${field}`
    if (field === 'hosts') return `${id}-add-host`
    if (field === 'paths') return `${id}-add-path`
    if (field === 'methods' || /^methods\[\d+\]$/.test(field)) return `${id}-method-${METHODS[0]}`
    const host = /^hosts\[(\d+)\]$/.exec(field)
    if (host) return Number(host[1]) < hosts.length ? `${id}-host-${host[1]}` : undefined
    const path = /^paths\[(\d+)\]\.(type|value)$/.exec(field)
    if (path) return Number(path[1]) < paths.length ? `${id}-path-${path[1]}-${path[2]}` : undefined
    return undefined
  }
  const shown = $derived(target(error?.field) !== undefined)

  const invalid = (field) =>
    error?.field === field || (field === 'methods' && target(error?.field) === `${id}-method-${METHODS[0]}`)
  const described = (field) => (invalid(field) ? `${id}-${field}-error` : undefined)
  const here = () => `${base(workspace, 'routes')}/${encodeURIComponent(route.name)}`

  async function send(method, url, body) {
    saving = true
    error = undefined
    try {
      await write(method, url, body)
    } catch (failure) {
      saving = false
      error = {
        sentence: failure.message,
        field: failure.field,
        // A 404 on a change to this row means someone else deleted or renamed it, which is as
        // stale as an edit made from an old read: the list is what to look at.
        stale:
          (failure.status === 409 && failure.message.includes('Reload')) ||
          (failure.status === 404 && mode === 'edit'),
      }
      staleOnClose = true
      // A refused delete has had its answer: the footer goes back to the sheet's own buttons, with
      // the refusal above them, rather than asking a question that was just refused.
      const asked = deleting
      deleting = false
      // The fields were disabled while the request ran, which took focus away. It goes to the
      // input the server named, whose sentence is then read through aria-describedby, or else to
      // the button that was pressed.
      await tick()
      const input = shown ? document.getElementById(target(error.field)) : undefined
      ;(input ?? (asked ? del : submit))?.focus()
      return
    }
    staleOnClose = false
    open = false
    await onsaved()
    await tick()
    keepPlace()
  }

  // Where focus goes once a new list has been drawn under a sheet that has closed. Closing handed
  // it back to the button that opened the sheet, but a row that goes, or is renamed since rows
  // are keyed by name, takes its buttons with it and focus falls to the page; then it goes to
  // where the page says. Focus the reader has put elsewhere in the meantime is left alone.
  function keepPlace() {
    if (document.activeElement !== document.body) return
    if (trigger?.isConnected) trigger.focus()
    else onremoved?.()
  }

  async function save(event) {
    event.preventDefault()
    // Enter in a field while the delete question is up must not save over it.
    if (!editable || saving || deleting) return
    // Empty rows are left out rather than refused: an unfilled Add host is not a host. The
    // indexes the server names are then of what was sent, which is what these rows show once
    // the empty ones are gone, so they are taken out of the form too.
    const sent = hosts.map((h) => h.trim()).filter(Boolean)
    paths = paths.map((p) => ({ type: p.type, value: p.value.trim() })).filter((p) => p.value !== '')
    // Rows that are all blank are not "any host": an empty list is that, and it should take
    // removing every row on purpose, for a superuser as for anyone, rather than an unfilled row
    // quietly becoming a route for every host.
    if (hosts.length > 0 && sent.length === 0) {
      error = { sentence: 'Fill in this host, or remove the row to route any host.', field: 'hosts[0]' }
      await tick()
      document.getElementById(target(error.field))?.focus()
      return
    }
    // The server refuses these for anyone but a superuser (403), after the reader's rows have been
    // compacted away; say so here, beside the row, and keep one row to type in.
    const wildcard = superuser ? -1 : sent.findIndex((h) => /^\*\.[^.]+$/.test(h))
    if (!superuser && (sent.length === 0 || wildcard >= 0)) {
      hosts = sent.length === 0 ? [''] : sent
      error =
        sent.length === 0
          ? { sentence: 'Name at least one host; only a superuser may route any host.', field: 'hosts[0]' }
          : {
              sentence: 'A wildcard needs at least two labels after *. unless a superuser routes it.',
              field: `hosts[${wildcard}]`,
            }
      await tick()
      document.getElementById(target(error.field))?.focus()
      return
    }
    hosts = sent
    const body = {
      name: name.trim(),
      service,
      // A cleared number input binds to null, which Number() would turn into 0 silently. 0 is the
      // server's default priority, so an empty field is sent as exactly that, on purpose.
      priority: priority == null ? 0 : Number(priority),
      hosts,
      paths,
      methods: METHODS.filter((m) => checked[m]),
    }
    if (mode === 'edit') send('PUT', here(), { ...body, updated_at: route.updated_at })
    else send('POST', base(workspace, 'routes'), body)
  }

  // Removing a row takes the button that was pressed with it when it was the last, so focus goes
  // to the row now at that place, or to Add when none is left.
  // A refusal's mark is on a row by its index, and the rows below the one removed move up, so a
  // mark on any row of the list goes with it rather than stay on a row it was not made for.
  async function dropHost(i) {
    if (error?.field?.startsWith('hosts[')) error = undefined
    hosts.splice(i, 1)
    await tick()
    document.getElementById(hosts.length > 0 ? `${id}-host-${Math.min(i, hosts.length - 1)}` : `${id}-add-host`)?.focus()
  }
  async function dropPath(i) {
    if (error?.field?.startsWith('paths[')) error = undefined
    paths.splice(i, 1)
    await tick()
    document.getElementById(paths.length > 0 ? `${id}-path-${Math.min(i, paths.length - 1)}-value` : `${id}-add-path`)?.focus()
  }

  async function remove() {
    if (saving) return
    if (!deleting) {
      deleting = true
      askedAt = performance.now()
      await tick()
      keep?.focus()
      return
    }
    if (performance.now() - askedAt < 500) return
    send('DELETE', here())
  }

  async function dismiss() {
    deleting = false
    await tick()
    del?.focus()
  }

  // A key held down repeats, and a repeat must not answer the delete question or drop it.
  const once = (event) => event.repeat && event.preventDefault()

  // The stale-edit refusal's way out: close, and draw the list as it is now.
  async function reload() {
    staleOnClose = false
    open = false
    await onsaved()
    await tick()
    keepPlace()
  }

  async function closed() {
    if (!staleOnClose) return
    staleOnClose = false
    await onsaved()
    await tick()
    keepPlace()
  }

  // Refuses to close while a request is in flight, for the reason MappingSheet gives.
  function setOpen(next) {
    if (!next && saving) return
    open = next
    if (!next) closed()
  }
</script>

{#snippet problem(field)}
  {#if invalid(field)}
    <p id="{id}-{field}-error" class="text-xs text-danger">{error.sentence}</p>
  {/if}
{/snippet}

<Sheet.Root bind:open={() => open, setOpen} onOpenChange={(next) => next && reset()}>
  <Sheet.Trigger>
    {#snippet child({ props })}
      {#if mode === 'create'}
        <Button bind:ref={trigger} size="sm" {...props}><Plus aria-hidden="true" />New route</Button>
      {:else}
        <Button
          bind:ref={trigger}
          variant="ghost"
          size="sm"
          aria-label="{editable ? 'Edit' : 'View'} the route {route.name}"
          {...props}>{editable ? 'Edit' : 'View'}</Button
        >
      {/if}
    {/snippet}
  </Sheet.Trigger>
  <Sheet.Content class="data-[side=right]:w-full data-[side=right]:sm:max-w-lg">
    <Sheet.Header>
      <Sheet.Title class="pr-8">
        {mode === 'create' ? 'New route' : editable ? 'Edit route' : 'Route'}
      </Sheet.Title>
      <Sheet.Description>
        Which requests go to a service. A request matches when it matches any host, any path and
        any method listed; an empty list matches everything.
      </Sheet.Description>
    </Sheet.Header>
    <form id="{id}-form" class="grid gap-5 overflow-y-auto px-4" onsubmit={save}>
      <fieldset class="grid gap-5" disabled={!editable || saving}>
        <div class="grid grid-cols-[1fr_6rem] gap-2">
          <div class="grid gap-1.5">
            <label for="{id}-name" class="font-medium">Name</label>
            <Input id="{id}-name" class="font-mono" bind:value={name} autocomplete="off" autocapitalize="off" spellcheck="false" aria-invalid={invalid('name')} aria-describedby={described('name')} />
          </div>
          <div class="grid gap-1.5">
            <label for="{id}-priority" class="font-medium">Priority</label>
            <Input id="{id}-priority" type="number" step="1" min="-2147483648" max="2147483647" bind:value={priority} aria-invalid={invalid('priority')} aria-describedby="{id}-priority-help {described('priority') ?? ''}" />
          </div>
        </div>
        <p id="{id}-priority-help" class="-mt-3 text-xs text-muted-foreground">Higher is tried first.</p>
        {@render problem('name')}
        {@render problem('priority')}
        <div class="grid gap-1.5">
          <label for="{id}-service" class="font-medium">Service</label>
          <NativeSelect id="{id}-service" bind:value={service} aria-invalid={invalid('service')} aria-describedby={described('service')}>
            {#each services as s (s)}
              <option value={s}>{s}</option>
            {/each}
          </NativeSelect>
          {@render problem('service')}
        </div>

        <fieldset class="grid gap-2">
          <legend class="mb-1.5 font-medium">Hosts</legend>
          {#each hosts as _, i (i)}
            <div class="flex gap-2">
              <Input id="{id}-host-{i}" class="font-mono" aria-label="Host {i + 1}" bind:value={hosts[i]} placeholder="api.example.com or *.example.com" autocomplete="off" autocapitalize="off" spellcheck="false" aria-invalid={invalid(`hosts[${i}]`)} aria-describedby={described(`hosts[${i}]`)} />
              {#if editable}
              <Button variant="ghost" size="sm" aria-label="Remove host {i + 1}" onclick={() => dropHost(i)}>Remove</Button>
              {/if}
            </div>
            {@render problem(`hosts[${i}]`)}
          {/each}
          {#if editable}
          <Button id="{id}-add-host" variant="outline" size="sm" class="justify-self-start" onclick={() => hosts.push('')} aria-invalid={invalid('hosts')} aria-describedby={described('hosts')}><Plus aria-hidden="true" />Add host</Button>
          {/if}
          {@render problem('hosts')}
          <p class="text-xs text-muted-foreground">
            At least one host; only a superuser may route any host.
            {#if hosts.length === 0}No hosts: any host.{/if}
          </p>
        </fieldset>

        <fieldset class="grid gap-2">
          <legend class="mb-1.5 font-medium">Paths</legend>
          {#each paths as path, i (i)}
            <div class="grid grid-cols-[6.5rem_1fr_auto] gap-2">
              <NativeSelect id="{id}-path-{i}-type" aria-label="Path {i + 1} match" bind:value={path.type} aria-invalid={invalid(`paths[${i}].type`)} aria-describedby={described(`paths[${i}].type`)}>
                {#each PATH_TYPES as t (t)}
                  <option value={t}>{PATH_LABEL[t]}</option>
                {/each}
              </NativeSelect>
              <Input id="{id}-path-{i}-value" class="font-mono" aria-label="Path {i + 1}" bind:value={path.value} autocomplete="off" autocapitalize="off" spellcheck="false" aria-invalid={invalid(`paths[${i}].value`)} aria-describedby={described(`paths[${i}].value`)} />
              {#if editable}
              <Button variant="ghost" size="sm" aria-label="Remove path {i + 1}" onclick={() => dropPath(i)}>Remove</Button>
              {/if}
            </div>
            {@render problem(`paths[${i}].type`)}
            {@render problem(`paths[${i}].value`)}
          {/each}
          {#if editable}
          <Button id="{id}-add-path" variant="outline" size="sm" class="justify-self-start" onclick={() => paths.push({ type: 'prefix', value: '' })} aria-invalid={invalid('paths')} aria-describedby={described('paths')}><Plus aria-hidden="true" />Add path</Button>
          {/if}
          {@render problem('paths')}
          <p class="text-xs text-muted-foreground">
            A prefix matches whole segments: /api matches /api/x, not /apix. A regex must match
            the whole path; end it with .* to match a prefix. No paths: every path.
          </p>
        </fieldset>

        <fieldset class="grid gap-2">
          <legend class="mb-1.5 font-medium">Methods</legend>
          <div class="flex flex-wrap gap-x-4 gap-y-2">
            {#each METHODS as m, k (m)}
              <label class="flex items-center gap-1.5 font-mono text-sm">
                <input id="{id}-method-{m}" type="checkbox" bind:checked={checked[m]} aria-invalid={k === 0 ? invalid('methods') : undefined} aria-describedby={k === 0 ? described('methods') : undefined} />{m}
              </label>
            {/each}
          </div>
          {@render problem('methods')}
          <p class="text-xs text-muted-foreground">None ticked: any method.</p>
        </fieldset>
      </fieldset>
    </form>
    <Sheet.Footer>
      {#if error && !shown}
        <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
          {error.sentence}
        </p>
      {/if}
      {#if error?.stale}
        <Button variant="outline" onclick={reload}>Reload</Button>
      {/if}
      {#if deleting}
        <p class="text-sm" role="alert">Delete {route.name}? Requests it matched go to the next route that matches, or get no route.</p>
        <Button variant="destructive" onclick={remove} onkeydown={once} disabled={saving}>Delete</Button>
        <Button bind:ref={keep} variant="outline" onclick={dismiss} onkeydown={once} disabled={saving}>Keep it</Button>
      {:else}
        {#if editable}
          <Button bind:ref={submit} type="submit" form="{id}-form" onkeydown={once} disabled={saving}>{saving ? 'Saving…' : 'Save'}</Button>
        {/if}
        {#if mode === 'edit' && can.delete(role)}
          <Button bind:ref={del} variant="ghost" class="text-danger" onclick={remove} onkeydown={once} disabled={saving}>Delete route</Button>
        {/if}
        <Sheet.Close disabled={saving}>
          {#snippet child({ props })}
            <Button variant="outline" {...props}>{editable ? 'Cancel' : 'Close'}</Button>
          {/snippet}
        </Sheet.Close>
      {/if}
    </Sheet.Footer>
  </Sheet.Content>
</Sheet.Root>
