<script>
  import { Button } from '$lib/components/ui/button/index.js'
  import { ROLE_LABEL } from './roles.js'

  // What an account with no screens sees. Every account holding a role in a workspace now gets
  // the Configuration pages, so the account with no screens is, in practice, one nobody has
  // granted anything yet, and that is the first branch. The second, for an account holding roles
  // with no screen to show, is defensive: it keeps the page honest if a role is ever added that
  // opens nothing, rather than leaving a blank page that would read as broken.
  let { me } = $props()
</script>

{#if me.waiting}
  <h1 class="mb-4 text-2xl font-semibold tracking-tight">Waiting for access</h1>
  <p class="max-w-2xl text-muted-foreground">
    Signed in as <strong class="font-medium text-foreground">{me.name}</strong>. Your account has
    no access yet; a workspace admin or a superuser grants it.
  </p>
{:else}
  <h1 class="mb-4 text-2xl font-semibold tracking-tight">Nothing to show yet</h1>
  <p class="max-w-2xl text-muted-foreground">
    Signed in as <strong class="font-medium text-foreground">{me.name}</strong>, holding:
  </p>
  <ul class="my-3 space-y-1 text-sm" role="list">
    {#each me.roles as held (held.workspace_id)}
      <li><span class="font-medium">{ROLE_LABEL[held.role]}</span> in {held.workspace}</li>
    {/each}
  </ul>
  <p class="max-w-2xl text-muted-foreground">
    None of this console's screens is open to these roles. Ask a workspace admin or a superuser
    if you expected one.
  </p>
{/if}

<!-- A form rather than a fetch: signing out is a navigation, and the server answers it with
     its "signed out" page. -->
<form class="mt-6" method="post" action="/auth/logout">
  <Button variant="outline" size="sm" type="submit">Sign out</Button>
</form>
