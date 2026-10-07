<script>
  import { tick } from 'svelte'
  import * as Sheet from '$lib/components/ui/sheet/index.js'
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'
  import NativeSelect from './NativeSelect.svelte'
  import { write } from './api.js'
  import { base } from './configuration.js'
  import { can } from './workspace.js'
  import Plus from 'phosphor-svelte/lib/Plus'

  // The Services page's one sheet:
  // - `create` is New service, for editors and admins;
  // - `edit` shows one service, read-only for a viewer, editable for an editor, and with Delete
  //   for an admin. Delete asks first, in the footer, as the access sheets do.
  // `onsaved` fetches the list again and returns a promise that settles once it is drawn or has
  // failed, and never rejects.
  let { mode, service = undefined, workspace, role, onsaved } = $props()

  const id = $props.id()
  const editable = $derived(mode === 'create' || can.write(role))

  let open = $state(false)
  // The button that opened the sheet, so focus can go back to it after a save.
  let trigger = $state(null)
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

  const invalid = (field) => error?.field === field
  const described = (field) => (invalid(field) ? `${id}-${field}-error` : undefined)
  const here = () => `${base(workspace, 'services')}/${encodeURIComponent(service.name)}`
  const optional = (value) => (String(value).trim() === '' ? null : Number(value))

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
        stale: failure.status === 409 && failure.message.includes('Reload'),
      }
      staleOnClose = true
      return
    }
    staleOnClose = false
    open = false
    await onsaved()
    await tick()
    if (document.activeElement === document.body && trigger?.isConnected) trigger.focus()
  }

  function save(event) {
    event.preventDefault()
    if (!editable || saving) return
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

  function remove() {
    if (saving) return
    if (!deleting) {
      deleting = true
      askedAt = performance.now()
      return
    }
    if (performance.now() - askedAt < 500) return
    send('DELETE', here())
  }

  // The stale-edit refusal's way out: close, and draw the list as it is now.
  async function reload() {
    staleOnClose = false
    open = false
    await onsaved()
  }

  async function closed() {
    if (!staleOnClose) return
    staleOnClose = false
    await onsaved()
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
    <form id="{id}-form" class="grid gap-5 overflow-y-auto px-4" onsubmit={save}>
      <fieldset class="grid gap-5" disabled={!editable || saving}>
        <div class="grid gap-1.5">
          <label for="{id}-name" class="font-medium">Name</label>
          <Input id="{id}-name" class="font-mono" bind:value={name} autocomplete="off" autocapitalize="off" spellcheck="false" aria-invalid={invalid('name')} aria-describedby={described('name')} />
          {@render problem('name')}
        </div>
        <div class="grid grid-cols-[7rem_1fr_6rem] gap-2">
          <div class="grid gap-1.5">
            <label for="{id}-protocol" class="font-medium">Protocol</label>
            <NativeSelect id="{id}-protocol" bind:value={protocol}>
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
            <Input id="{id}-connect" type="number" min="1" placeholder="default" bind:value={connect} aria-invalid={invalid('connect_timeout_ms')} aria-describedby={described('connect_timeout_ms')} />
          </div>
          <div class="grid gap-1.5">
            <label for="{id}-read" class="font-medium">Read timeout (ms)</label>
            <Input id="{id}-read" type="number" min="1" placeholder="default" bind:value={read} aria-invalid={invalid('read_timeout_ms')} aria-describedby={described('read_timeout_ms')} />
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
    <Sheet.Footer>
      {#if error && !error.field}
        <p class="text-sm text-danger" role="alert">{error.sentence}</p>
      {/if}
      {#if error?.stale}
        <Button variant="outline" onclick={reload}>Reload</Button>
      {/if}
      {#if deleting}
        <p class="text-sm" role="alert">Delete {service.name}? Routes can no longer use it.</p>
        <Button variant="destructive" onclick={remove} disabled={saving}>Delete</Button>
        <Button variant="outline" onclick={() => (deleting = false)} disabled={saving}>Keep it</Button>
      {:else}
        {#if editable}
          <Button type="submit" form="{id}-form" disabled={saving}>{saving ? 'Saving…' : 'Save'}</Button>
        {/if}
        {#if mode === 'edit' && can.delete(role)}
          <Button variant="ghost" class="text-danger" onclick={remove} disabled={saving}>Delete service</Button>
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
