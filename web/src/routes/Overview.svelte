<script>
  import { get } from '../lib/api.js'
  import Failure from '../lib/Failure.svelte'

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

<h1>Overview</h1>

{#await overview}
  <p class="muted">Reading the gateway…</p>
{:then data}
  {#if !data.reachable}
    <!-- `reachable: false` means the admin port could not be read, and the server sends no
         listeners with it. Drawing an empty table here would say "this gateway serves
         nothing", which is a different and much more alarming claim than "nobody could ask
         it". -->
    <p class="notice">
      The gateway could not be reached, so there is nothing to show here. This says nothing
      about whether it is serving traffic — only that its admin port did not answer.
    </p>
  {:else if data.listeners.length === 0}
    <p class="muted">The gateway answered, and has no listeners you can see.</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Gateway</th>
          <th>Listener</th>
          <th>Port</th>
          <th>Protocol</th>
          <th>Hostname</th>
        </tr>
      </thead>
      <tbody>
        {#each data.listeners as listener (listener.id)}
          {@const name = split(listener.id)}
          <tr>
            <td>{name.gateway}</td>
            <td>{name.section ?? '—'}</td>
            <td>
              {listener.port}
              {#if mapsPort(listener)}
                <span class="muted">(clients dial {listener.client_port})</span>
              {/if}
            </td>
            <!-- Upper-cased here rather than at the source. `gapura_core::config::Protocol`
                 is a plain derived enum with no `rename_all`, so `/debug/config` spells these
                 `Http` and `Https`, while the Gateway API — and therefore `kubectl get
                 gateway`, which is what an operator has open next to this — spells them `HTTP`
                 and `HTTPS`. A console whose whole purpose is to sit beside what Kubernetes
                 was told has to use Kubernetes' spelling. Fixing it in the enum's serde
                 instead would change the admin JSON contract, which is a separate decision
                 with other consumers. -->
            <td>{listener.protocol ? listener.protocol.toUpperCase() : '—'}</td>
            <!-- A listener with no hostname takes any host, which is a real setting rather
                 than missing information, so it is spelled out instead of left blank. -->
            <td>{listener.hostname ?? 'any host'}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
{:catch error}
  <Failure {error} what="the overview" />
{/await}

<style>
  h1 {
    font-size: 1.375rem;
    margin: 0 0 1rem;
  }

  table {
    border-collapse: collapse;
    width: 100%;
  }

  th,
  td {
    text-align: left;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid #e3e7eb;
    vertical-align: top;
  }

  th {
    font-size: 0.8125rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #55606b;
  }

  .muted {
    color: #55606b;
  }

  .notice {
    background: #fdf3da;
    border: 1px solid #e5c569;
    border-radius: 0.375rem;
    padding: 0.75rem 1rem;
    max-width: 44rem;
  }
</style>
