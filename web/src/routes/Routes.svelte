<script>
  import { STATES } from '../lib/states.js'
  import { get } from '../lib/api.js'
  import Failure from '../lib/Failure.svelte'
  import State from '../lib/State.svelte'
  import CaretRight from 'phosphor-svelte/lib/CaretRight'

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

<h1 class="mb-4 text-2xl font-semibold tracking-tight">Routes</h1>

{#await routes}
  <p class="text-muted-foreground">Reading routes…</p>
{:then rows}
  {#if rows.length === 0}
    <p class="text-muted-foreground">
      No routes are visible to you. Either none are declared, or none are in a namespace your
      groups are granted.
    </p>
  {:else}
    <ul class="divide-y rounded-lg border bg-card shadow-xs">
      {#each rows as route (route.id)}
        <li>
          <!-- Fixed column widths from `sm` up, not fr: every row is its own grid container,
               so content-sized columns are measured per row and the namespace and badge would
               sit at a different x on each one. Below `sm` the two fixed columns would leave
               the id a few pixels and break it one letter per line, so the namespace column
               goes (the id already starts with it) and the badge takes only its own width. -->
          <button
            type="button"
            class="grid w-full grid-cols-[1.25rem_minmax(0,1fr)_auto] items-center gap-3 px-3 py-2.5 text-left hover:bg-muted/60 focus-visible:outline-2 focus-visible:outline-ring sm:grid-cols-[1.25rem_minmax(0,1fr)_7rem_10rem]"
            aria-expanded={open[route.id] === true}
            onclick={() => toggle(route.id)}
          >
            <CaretRight
              class="text-muted-foreground transition-transform {open[route.id] ? 'rotate-90' : ''}"
              aria-hidden="true"
            />
            <span class="font-mono text-sm break-words">{route.id}</span>
            <span class="hidden text-muted-foreground sm:block">{route.namespace}</span>
            <State state={route.state} />
          </button>

          {#if open[route.id]}
            <div class="pb-4 pl-11 pr-3 text-sm">
              {#if route.parents.length === 0}
                <!-- The summary of a route with no parents is `pending`, which on its own
                     reads as "a gateway has not got to it yet". Saying that no gateway was
                     named at all is the difference between waiting for something and waiting
                     for nothing. -->
                <p class="text-muted-foreground">This route names no Gateway that this console can see.</p>
              {:else if route.parents.length === 1}
                <!-- One attachment is written as a sentence, not as a list with a single
                     bullet: a list implies the reader should be comparing entries, and here
                     there is nothing to compare it against. The multi-parent branch below
                     renders the same facts, because the facts are what differ between the
                     two cases and the presentation is what should not. -->
                {@const only = route.parents[0]}
                <p class="mb-1">
                  On <code>{only.gateway}</code>{#if only.section}, listener
                    <code>{only.section}</code>{/if}:
                  <State state={only.state} />
                </p>
                {@render why(only)}
              {:else}
                <p class="mb-2.5 text-muted-foreground">Attached to {route.parents.length} Gateways:</p>
                <ul class="space-y-3.5">
                  {#each route.parents as parent (parent.gateway + '/' + (parent.section ?? ''))}
                    <li>
                      <p class="mb-1">
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
  <p class="max-w-[52rem]">
    {STATES[parent.state]?.detail ??
      'The server reported a state this page does not know; it may be newer than the page.'}
  </p>
  {#if parent.reason || parent.message}
    <p class="max-w-[52rem] text-muted-foreground">
      {#if parent.reason}<code class="font-semibold">{parent.reason}</code>{/if}
      {#if parent.reason && parent.message}<span aria-hidden="true"> — </span>{/if}
      {#if parent.message}{parent.message}{/if}
    </p>
  {/if}
{/snippet}
