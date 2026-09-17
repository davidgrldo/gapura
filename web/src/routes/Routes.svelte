<script>
  import { STATES } from '../lib/states.js'
  import { get } from '../lib/api.js'
  import Failure from '../lib/Failure.svelte'
  import State from '../lib/State.svelte'

  // `/api/routes` answers with a bare array of rows, already sorted by id on the server, so
  // the order on screen is stable across polls and nothing here needs to sort.
  const routes = get('/api/routes')

  // Which rows the reader has opened, keyed by route id. A `$state` object is a deep proxy,
  // so assigning one key re-renders that row alone; keying by id rather than by index means
  // an opened row stays open even if the list is reloaded and the rows move.
  let open = $state({})

  function toggle(id) {
    open[id] = !open[id]
  }
</script>

<h1>Routes</h1>

{#await routes}
  <p class="muted">Reading routes…</p>
{:then rows}
  {#if rows.length === 0}
    <p class="muted">
      No routes are visible to you. Either none are declared, or none are in a namespace your
      groups are granted.
    </p>
  {:else}
    <ul class="rows">
      {#each rows as route (route.id)}
        <li>
          <button
            type="button"
            class="summary"
            aria-expanded={open[route.id] === true}
            onclick={() => toggle(route.id)}
          >
            <span class="caret" aria-hidden="true">{open[route.id] ? '▾' : '▸'}</span>
            <span class="id">{route.id}</span>
            <span class="namespace">{route.namespace}</span>
            <State state={route.state} />
          </button>

          {#if open[route.id]}
            <div class="detail">
              {#if route.parents.length === 0}
                <!-- The summary of a route with no parents is `pending`, which on its own
                     reads as "a gateway has not got to it yet". Saying that no gateway was
                     named at all is the difference between waiting for something and waiting
                     for nothing. -->
                <p class="muted">This route names no Gateway that this console can see.</p>
              {:else if route.parents.length === 1}
                <!-- One attachment is written as a sentence, not as a list with a single
                     bullet: a list implies the reader should be comparing entries, and here
                     there is nothing to compare it against. The multi-parent branch below
                     renders the same facts, because the facts are what differ between the
                     two cases and the presentation is what should not. -->
                {@const only = route.parents[0]}
                <p class="attachment">
                  On <code>{only.gateway}</code>{#if only.section}, listener
                    <code>{only.section}</code>{/if}:
                  <State state={only.state} />
                </p>
                {@render why(only)}
              {:else}
                <p class="count">Attached to {route.parents.length} Gateways:</p>
                <ul class="parents">
                  {#each route.parents as parent (parent.gateway + '/' + (parent.section ?? ''))}
                    <li>
                      <p class="attachment">
                        <code>{parent.gateway}</code>{#if parent.section}, listener
                          <code>{parent.section}</code>{/if}:
                        <State state={parent.state} />
                      </p>
                      {@render why(parent)}
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
{:catch error}
  <Failure {error} what="the routes" />
{/await}

<!-- Why an attachment is in the state it is in. The server attaches this to the parent
     rather than to the route, because two Gateways refusing a route for two different causes
     have no single reason between them — so it is rendered here, per attachment, and a
     parent that carries neither field simply renders nothing. -->
{#snippet why(parent)}
  <!-- The state's own sentence, visibly this time (#62): the badge announces it to screen
       readers, the expanded row shows it to everyone, and a phone has no hover to lose. -->
  <p class="means">
    {STATES[parent.state]?.detail ??
      'The server reported a state this page does not know; it may be newer than the page.'}
  </p>
  {#if parent.reason || parent.message}
    <p class="why">
      {#if parent.reason}<code class="reason">{parent.reason}</code>{/if}
      {#if parent.reason && parent.message}<span aria-hidden="true"> — </span>{/if}
      {#if parent.message}{parent.message}{/if}
    </p>
  {/if}
{/snippet}

<style>
  h1 {
    font-size: 1.375rem;
    margin: 0 0 1rem;
  }

  .rows {
    list-style: none;
    margin: 0;
    padding: 0;
    border-top: 1px solid #e3e7eb;
  }

  .rows > li {
    border-bottom: 1px solid #e3e7eb;
  }

  .summary {
    display: grid;
    grid-template-columns: 1.25rem minmax(0, 2fr) minmax(0, 1fr) auto;
    gap: 0.75rem;
    align-items: center;
    width: 100%;
    padding: 0.625rem 0.5rem;
    background: none;
    border: 0;
    font: inherit;
    text-align: left;
    cursor: pointer;
  }

  .summary:hover {
    background: #f5f7f9;
  }

  .caret {
    color: #55606b;
  }

  .id {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    overflow-wrap: anywhere;
  }

  .namespace {
    color: #55606b;
  }

  .detail {
    padding: 0.25rem 0.5rem 1rem 2.75rem;
  }

  .parents {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  .parents > li + li {
    margin-top: 0.875rem;
  }

  .attachment {
    margin: 0 0 0.25rem;
  }

  .count {
    margin: 0 0 0.625rem;
    color: #55606b;
  }

  .why {
    margin: 0;
    color: #374151;
    max-width: 52rem;
  }

  code {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.875em;
  }

  .reason {
    font-weight: 600;
  }

  .muted {
    color: #55606b;
  }
</style>
