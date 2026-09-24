<script>
  import { get } from '../lib/api.js'
  import Failure from '../lib/Failure.svelte'
  import * as Table from '$lib/components/ui/table/index.js'

  // Fetched once on mount and awaited in the markup. `{#await}` is the whole of the loading
  // and error handling this screen needs, which is why there is no state variable here to
  // get out of step with the request.
  const overview = get('/api/overview')

  // A listener id is `namespace/gateway/section`, and the section is the only part that
  // differs between two listeners of the same Gateway. Splitting it here lets the table put
  // the Gateway and the listener in separate columns, so a Gateway with four listeners reads
  // as one Gateway rather than as four unrelated rows of slashes.
  function split(id) {
    const cut = id.lastIndexOf('/')
    return cut === -1 ? { gateway: id, section: null } : { gateway: id.slice(0, cut), section: id.slice(cut + 1) }
  }

  // The server already sends `client_port` as null when it is the same as the bound port, so
  // this is belt and braces: a server that started sending the number unconditionally would
  // otherwise make every listener look like it had a port mapping, which is exactly the
  // detail this column exists to make unusual.
  function mapsPort(listener) {
    return listener.client_port != null && listener.client_port !== listener.port
  }
</script>

<h1 class="mb-4 text-2xl font-semibold tracking-tight">Overview</h1>

{#await overview}
  <p class="text-muted-foreground">Reading the gateway…</p>
{:then data}
  {#if !data.reachable}
    <!-- `reachable: false` means the admin port could not be read, and the server sends no
         listeners with it. Drawing an empty table here would say "this gateway serves
         nothing", which is a different and much more alarming claim than "nobody could ask
         it". -->
    <p class="max-w-2xl rounded-lg border border-warning/30 bg-warning-soft px-4 py-3 text-sm">
      The gateway could not be reached, so there is nothing to show here. This says nothing
      about whether it is serving traffic — only that its admin port did not answer.
    </p>
  {:else if data.listeners.length === 0}
    <p class="text-muted-foreground">The gateway answered, and has no listeners you can see.</p>
  {:else}
    <div class="rounded-lg border bg-card shadow-xs">
      <Table.Root>
        <Table.Header>
          <Table.Row>
            <Table.Head>Gateway</Table.Head>
            <Table.Head>Listener</Table.Head>
            <Table.Head>Port</Table.Head>
            <Table.Head>Protocol</Table.Head>
            <Table.Head>Hostname</Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each data.listeners as listener (listener.id)}
            {@const name = split(listener.id)}
            <Table.Row>
              <Table.Cell class="align-top font-medium">{name.gateway}</Table.Cell>
              <Table.Cell class="align-top">{name.section ?? '—'}</Table.Cell>
              <Table.Cell class="align-top tabular-nums">
                {listener.port}
                {#if mapsPort(listener)}
                  <!-- The mapped-port note is one phrase and reads as nonsense broken across
                       four lines, which is what an auto-sized column does to it when the
                       table is narrow. Its own line, unbroken. -->
                  <span class="block whitespace-nowrap text-muted-foreground">(clients dial {listener.client_port})</span>
                {/if}
              </Table.Cell>
              <!-- Upper-cased here rather than at the source. `gapura_core::config::Protocol`
                   is a plain derived enum with no `rename_all`, so `/debug/config` spells these
                   `Http` and `Https`, while the Gateway API — and therefore `kubectl get
                   gateway`, which is what an operator has open next to this — spells them `HTTP`
                   and `HTTPS`. A console whose whole purpose is to sit beside what Kubernetes
                   was told has to use Kubernetes' spelling. Fixing it in the enum's serde
                   instead would change the admin JSON contract, which is a separate decision
                   with other consumers. -->
              <Table.Cell class="align-top">{listener.protocol ? listener.protocol.toUpperCase() : '—'}</Table.Cell>
              <!-- A listener with no hostname takes any host, which is a real setting rather
                   than missing information, so it is spelled out instead of left blank. -->
              <Table.Cell class="align-top">{listener.hostname ?? 'any host'}</Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>
    </div>
  {/if}
{:catch error}
  <Failure {error} what="the overview" />
{/await}
