<script>
  import { Button } from '$lib/components/ui/button/index.js'
  import { ROLE_LABEL } from './roles.js'

  // What an account with no screens sees. There are two reasons to have none, and each gets its
  // own words: an account nobody has granted anything yet, and one whose roles nothing on the
  // console shows yet. A blank page would read as broken in both.
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
