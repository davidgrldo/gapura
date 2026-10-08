<script>
  import { tick } from 'svelte'
  import * as Sheet from '$lib/components/ui/sheet/index.js'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import NativeSelect from './NativeSelect.svelte'
  import KeyAuthControl from './KeyAuthControl.svelte'
  import { write } from './api.js'
  import { base } from './configuration.js'
  import { can } from './workspace.js'
  import Plus from 'phosphor-svelte/lib/Plus'

  // The Services page's one sheet:
  // - `create` is New service, for editors and admins;
  // - `edit` shows one service, read-only for a viewer, editable for an editor, and with Delete
  //   for an admin. Delete asks first, in the footer, as the access sheets do.
  // `onsaved` fetches the list again and returns a promise that settles once it is drawn or has
  // failed, and never rejects. `onremoved` is where focus goes when the new list no longer has the
  // row this sheet's button was in, which takes the button with it: after a delete, a rename, or
  // a row removed by someone else.
  let { mode, service = undefined, workspace, role, onsaved, onremoved = undefined } = $props()

  const id = $props.id()
  const editable = $derived(mode === 'create' || can.write(role))

  let open = $state(false)
  // The button that opened the sheet, so focus can go back to it after a save.
  let trigger = $state(null)
  // Save, where focus goes after a refusal that names no field: disabling it while saving drops
  // focus.
  let submit = $state(null)
  // The delete question's buttons: it opens on Keep it, so an Enter meant for Delete service
  // cannot answer it, and Keep it hands focus back to Delete service.
  let keep = $state(null)
  let del = $state(null)
  let name = $state('')
  let protocol = $state('http')
  let host = $state('')
  let port = $state('')
  let connect = $state('')
  let read = $state('')
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
    name = service?.name ?? ''
    protocol = service?.protocol ?? 'http'
    host = service?.host ?? ''
    port = service ? String(service.port) : ''
    connect = service?.connect_timeout_ms == null ? '' : String(service.connect_timeout_ms)
    read = service?.read_timeout_ms == null ? '' : String(service.read_timeout_ms)
    saving = false
    error = undefined
    deleting = false
  }

  // The fields this form draws, and the ids of their inputs. A refusal naming anything else
  // (`updated_at`) has no input to sit beside, so its sentence goes in the footer.
  const INPUT = {
    name: 'name',
    protocol: 'protocol',
    host: 'host',
    port: 'port',
    connect_timeout_ms: 'connect',
    read_timeout_ms: 'read',
  }
  const shown = $derived(Object.hasOwn(INPUT, error?.field ?? ''))

  const invalid = (field) => error?.field === field
  const described = (field) => (invalid(field) ? `${id}-${field}-error` : undefined)
  // Delete is not asked while routes use the service: the server refuses it, so the question
  // would only lead to a refusal. The sentence says what to do instead.
  const inUse = $derived(mode === 'edit' ? (service?.routes ?? 0) : 0)
  const here = () => `${base(workspace, 'services')}/${encodeURIComponent(service.name)}`
  // A number input that has been cleared binds to null, not '', and either means "use the
  // default". Anything else is sent as it is, 0 included: the server refuses 0 and says so beside
  // the field, which is better than quietly turning it into something else.
  const optional = (value) => (value == null || String(value).trim() === '' ? null : Number(value))

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
        // A delete refused because a policy is attached to the row; when that is its own key
        // requirement, the footer says where to switch it off.
        attached: failure.status === 409 && /attached to this/.test(failure.message),
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
      const input = shown ? document.getElementById(`${id}-${INPUT[error.field]}`) : undefined
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

  function save(event) {
    event.preventDefault()
    // Enter in a field while the delete question is up must not save over it.
    if (!editable || saving || deleting) return
    const body = {
      name: name.trim(),
      protocol,
      host: host.trim(),
      port: Number(port),
      connect_timeout_ms: optional(connect),
      read_timeout_ms: optional(read),
    }
    if (mode === 'edit') send('PUT', here(), { ...body, updated_at: service.updated_at })
    else send('POST', base(workspace, 'services'), body)
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
    // While routes use the service the footer shows why it cannot go and offers no Delete, so
    // this is only reached for a service that is not in use.
    if (inUse > 0 || performance.now() - askedAt < 500) return
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
        <Button bind:ref={trigger} size="sm" {...props}><Plus aria-hidden="true" />New service</Button>
      {:else}
        <Button
          bind:ref={trigger}
          variant="ghost"
          size="sm"
          aria-label="{editable ? 'Edit' : 'View'} the service {service.name}"
          {...props}>{editable ? 'Edit' : 'View'}</Button
        >
      {/if}
    {/snippet}
  </Sheet.Trigger>
  <Sheet.Content class="data-[side=right]:w-full data-[side=right]:sm:max-w-md">
    <Sheet.Header>
      <Sheet.Title class="pr-8">
        {mode === 'create' ? 'New service' : editable ? 'Edit service' : 'Service'}
      </Sheet.Title>
      <Sheet.Description>
        An upstream that routes in {workspace} can send traffic to.
      </Sheet.Description>
    </Sheet.Header>
    <!-- The key requirement is its own form below the sheet's, applied on its own, and scrolls
         with it. Its `onchanged` is `onsaved`, which only fetches the list again: the sheet stays
         open, and the new list brings the control what now applies. -->
    <div class="grid gap-5 overflow-y-auto px-4">
      <form id="{id}-form" class="grid gap-5" onsubmit={save}>
        <fieldset class="grid gap-5" disabled={!editable || saving}>
          <div class="grid gap-1.5">
            <label for="{id}-name" class="font-medium">Name</label>
            <Input id="{id}-name" class="font-mono" bind:value={name} autocomplete="off" autocapitalize="off" spellcheck="false" aria-invalid={invalid('name')} aria-describedby={described('name')} />
            {@render problem('name')}
          </div>
          <div class="grid grid-cols-[7rem_1fr_6rem] gap-2">
            <div class="grid gap-1.5">
              <label for="{id}-protocol" class="font-medium">Protocol</label>
              <NativeSelect id="{id}-protocol" bind:value={protocol} aria-invalid={invalid('protocol')} aria-describedby={described('protocol')}>
                <option value="http">http</option>
                <option value="https">https</option>
              </NativeSelect>
            </div>
            <div class="grid gap-1.5">
              <label for="{id}-host" class="font-medium">Host</label>
              <Input id="{id}-host" class="font-mono" bind:value={host} autocomplete="off" autocapitalize="off" spellcheck="false" aria-invalid={invalid('host')} aria-describedby={described('host')} />
            </div>
            <div class="grid gap-1.5">
              <label for="{id}-port" class="font-medium">Port</label>
              <Input id="{id}-port" type="number" min="1" max="65535" bind:value={port} aria-invalid={invalid('port')} aria-describedby={described('port')} />
            </div>
          </div>
          {@render problem('protocol')}
          {@render problem('host')}
          {@render problem('port')}
          <div class="grid grid-cols-2 gap-2">
            <div class="grid gap-1.5">
              <label for="{id}-connect" class="font-medium">Connect timeout (ms)</label>
              <Input id="{id}-connect" type="number" min="1" max="3600000" placeholder="default" bind:value={connect} aria-invalid={invalid('connect_timeout_ms')} aria-describedby={described('connect_timeout_ms')} />
            </div>
            <div class="grid gap-1.5">
              <label for="{id}-read" class="font-medium">Read timeout (ms)</label>
              <Input id="{id}-read" type="number" min="1" max="3600000" placeholder="default" bind:value={read} aria-invalid={invalid('read_timeout_ms')} aria-describedby={described('read_timeout_ms')} />
            </div>
          </div>
          {@render problem('connect_timeout_ms')}
          {@render problem('read_timeout_ms')}
          <p class="text-xs text-muted-foreground">
            https is verified against the system's trusted certificates, so it needs a host name,
            not an IP address. IPv6 is not accepted. Empty timeouts use the gateway's defaults.
          </p>
        </fieldset>
      </form>
      {#if mode === 'edit'}
        <KeyAuthControl {workspace} target="service:{service.name}" applies={service.key_auth} {role} onchanged={onsaved} />
      {:else}
        <p class="text-xs text-muted-foreground"><span class="font-medium">API key.</span> Save it first, then require a key.</p>
      {/if}
    </div>
    <Sheet.Footer>
      {#if error && !shown}
        <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
          {error.sentence}
          {#if error.attached && service?.key_auth?.from === 'service'}Switch the API key requirement off above first.{/if}
        </p>
      {/if}
      {#if error?.stale}
        <Button variant="outline" onclick={reload}>Reload</Button>
      {/if}
      {#if deleting}
        {#if inUse > 0}
          <p class="text-sm" role="alert">
            {inUse === 1
              ? '1 route uses this service; point it at another service or delete it first.'
              : `${inUse} routes use this service; point them at another service or delete them first.`}
          </p>
          <Button bind:ref={keep} variant="outline" onclick={dismiss} onkeydown={once}>Close</Button>
        {:else}
          <p class="text-sm" role="alert">Delete {service.name}? This cannot be undone.</p>
          <Button variant="destructive" onclick={remove} onkeydown={once} disabled={saving}>Delete</Button>
          <Button bind:ref={keep} variant="outline" onclick={dismiss} onkeydown={once} disabled={saving}>Keep it</Button>
        {/if}
      {:else}
        {#if editable}
          <Button bind:ref={submit} type="submit" form="{id}-form" onkeydown={once} disabled={saving}>{saving ? 'Saving…' : 'Save'}</Button>
        {/if}
        {#if mode === 'edit' && can.delete(role)}
          <Button bind:ref={del} variant="ghost" class="text-danger" onclick={remove} onkeydown={once} disabled={saving}>Delete service</Button>
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
