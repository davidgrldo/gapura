<script>
  import { get } from '../lib/api.js'
  import Failure from '../lib/Failure.svelte'
  import Tag from '../lib/Tag.svelte'
  import { ROLE_LABEL } from '../lib/roles.js'
  import { ACCOUNT_STATUS } from '../lib/states.js'
  import CaretRight from 'phosphor-svelte/lib/CaretRight'

  // `/api/users` lists every account, each with its roles trimmed to the workspaces the reader
  // administers, sorted with the accounts waiting for access first; nothing here filters or
  // sorts.
  const users = get('/api/users')

  // Which rows the reader has opened, keyed by account id, as on the Routes screen.
  let open = $state({})

  function toggle(id) {
    open[id] = !open[id]
  }

  // In the reader's own locale and zone, with the zone named: two admins in different zones
  // would otherwise quote different times for the same sign-in, with nothing on screen to say
  // why.
  const when = new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    timeZoneName: 'short',
  })

  function source(s) {
    if (s.kind === 'superuser') return 'Superuser'
    if (s.kind === 'direct') return 'Direct grant'
    return `Group ${s.name}`
  }
</script>

{#snippet signedIn(seconds)}
  {#if seconds == null}Never{:else}<time datetime={new Date(seconds * 1000).toISOString()}>{when.format(seconds * 1000)}</time>{/if}
{/snippet}

<h1 class="mb-4 text-2xl font-semibold tracking-tight">Users</h1>

{#await users}
  <p class="text-muted-foreground">Reading accounts…</p>
{:then rows}
  <!-- The same card, rows and focus ring as Routes: role="list" because Tailwind's base styles
       take the bullets off and Safari then stops announcing a list; overflow-hidden keeps a
       row's hover inside the rounded corners, which is why the ring is inset and the detail
       breaks long words. @container: the columns below are chosen by the list's own width, not
       the window's, which the sidebar shares. -->
  <ul class="@container divide-y overflow-hidden rounded-lg border bg-card shadow-xs" role="list">
    {#each rows as user (user.id)}
      <!-- A status this console has not been taught can only come from a newer server, during
           a rolling upgrade; the raw word uncoloured is more use than a screen that fails. -->
      {@const status = ACCOUNT_STATUS[user.status] ?? { label: user.status, tone: 'idle' }}
      <li>
        <!-- From a 56rem list (@4xl) up: caret, account, access, status and last sign-in, with
             fixed status and sign-in columns so they line up across rows that are each their own
             grid. The fixed columns, gaps and padding take about 28rem and the account 14rem,
             which leaves the roles at least 13.75rem; a chip longer than that wraps inside
             itself rather than running under the status. Below that only the account and its
             status stay; the rest is in the opened row. -->
        <button
          type="button"
          class="grid w-full grid-cols-[1.25rem_minmax(0,1fr)_auto] items-center gap-3 px-3 py-2.5 text-left hover:bg-muted/50 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring @4xl:grid-cols-[1.25rem_minmax(0,14rem)_minmax(0,1fr)_10rem_12.5rem]"
          aria-expanded={open[user.id] === true}
          onclick={() => toggle(user.id)}
        >
          <CaretRight
            class="text-muted-foreground transition-transform {open[user.id] ? 'rotate-90' : ''}"
            aria-hidden="true"
          />
          <span class="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
            <!-- wrap-anywhere rather than break-words: in a flex row only a break the browser
                 counts when sizing lets a long address shrink instead of running past the cell. -->
            <span class="text-sm font-medium wrap-anywhere">{user.name}</span>
            <Tag>{user.method === 'oidc' ? 'SSO' : 'Local'}</Tag>
            {#if user.superuser}<Tag>Superuser</Tag>{/if}
          </span>
          <span class="hidden min-w-0 flex-wrap gap-1.5 @4xl:flex">
            {#each user.access as held (held.workspace_id)}
              <!-- Workspace names have no length limit, so a chip may wrap. -->
              <Tag class="max-w-full whitespace-normal wrap-anywhere">{held.workspace} · {ROLE_LABEL[held.role]}</Tag>
            {:else}
              <!-- A disabled account holds nothing anywhere, so "not in your workspaces" would
                   suggest the reader is missing something. -->
              <span class="text-sm text-muted-foreground">
                {user.status === 'disabled' ? 'Holds nothing while disabled' : 'Not in your workspaces'}
              </span>
            {/each}
          </span>
          <Tag tone={status.tone}>{status.label}</Tag>
          <span class="hidden text-sm text-muted-foreground @4xl:block">
            <span class="sr-only">Last sign-in: </span>{@render signedIn(user.last_sign_in_at)}
          </span>
        </button>

        {#if open[user.id]}
          <!-- pl-11 starts the detail under the account name: the button's px-3, plus the
               1.25rem caret column, plus gap-3. -->
          <div class="pb-4 pl-11 pr-3 text-sm break-words">
            <p class="mb-2 text-muted-foreground @4xl:hidden">Last sign-in: {@render signedIn(user.last_sign_in_at)}</p>
            {#if user.status === 'disabled'}
              <p class="text-muted-foreground">A disabled account holds no role.</p>
            {:else if user.access.length === 0}
              <!-- The same sentence whether the account is waiting or holds roles elsewhere:
                   which, is not the reader's to know. -->
              <p class="text-muted-foreground">No role in the workspaces you administer.</p>
            {:else}
              <!-- wrap-anywhere on the workspace and sources cells: a table sizes its columns
                   from the longest word, and a long group name would otherwise push the table
                   past the card, which clips it. Not on the headings or the role, whose words
                   then set each column's least width, so short words are not split as well. -->
              <table class="w-full max-w-2xl text-left">
                <caption class="sr-only">Roles {user.name} holds in the workspaces you administer</caption>
                <thead class="text-muted-foreground">
                  <tr>
                    <th scope="col" class="py-1 pr-4 font-medium">Workspace</th>
                    <th scope="col" class="py-1 pr-4 font-medium">Role</th>
                    <th scope="col" class="py-1 font-medium">Sources</th>
                  </tr>
                </thead>
                <tbody>
                  {#each user.access as held (held.workspace_id)}
                    <tr class="border-t">
                      <td class="py-1.5 pr-4 wrap-anywhere">{held.workspace}</td>
                      <td class="py-1.5 pr-4 font-medium">{ROLE_LABEL[held.role]}</td>
                      <td class="py-1.5 wrap-anywhere">{held.sources.map(source).join(', ')}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
              {#if user.access.some((held) => held.sources.some((s) => s.kind === 'group'))}
                <p class="mt-2 text-muted-foreground">Groups are as of this account's last sign-in.</p>
              {/if}
            {/if}
          </div>
        {/if}
      </li>
    {/each}
  </ul>
{:catch error}
  <Failure {error} what="the accounts" />
{/await}
