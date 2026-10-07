<script>
  import NativeSelect from './NativeSelect.svelte'
  import { ROLE_LABEL } from './roles.js'
  import { remember } from './workspace.js'

  // The workspaces from /api/me's `roles`, and the chosen one, bound by the page.
  let { roles, value = $bindable() } = $props()
  const id = $props.id()
</script>

{#if roles.length > 1}
  <div class="mb-4 flex max-w-sm items-center gap-2">
    <label for="{id}-ws" class="shrink-0 text-sm font-medium">Workspace</label>
    <NativeSelect id="{id}-ws" bind:value onchange={() => remember(value)}>
      {#each roles as r (r.workspace_id)}
        <option value={r.workspace}>{r.workspace} — {ROLE_LABEL[r.role]}</option>
      {/each}
    </NativeSelect>
  </div>
{/if}
