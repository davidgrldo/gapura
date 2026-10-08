<script>
  import { tick } from 'svelte'
  import * as Sheet from '$lib/components/ui/sheet/index.js'
  import { Button } from '$lib/components/ui/button/index.js'
  import PasswordForm from './PasswordForm.svelte'

  // Change password, the reader's own, from the sidebar, for a local account. `trigger` is a
  // snippet drawing the button that opens the sheet, handed the props bits-ui needs on it, so the
  // sidebar keeps its own menu button. A refusal about a field is beside it; any other, such as too
  // many tries, is in the footer. Once the server has made the change, the sheet says so in place
  // of the form, which it does not offer again until it is reopened.
  let { me, trigger } = $props()

  const id = $props.id()

  let open = $state(false)
  let saving = $state(false)
  let failure = $state(undefined)
  let done = $state(false)
  let submit = $state(null)
  let said = $state(null)

  async function changed() {
    done = true
    await tick()
    said?.focus()
  }

  // Refuses to close while the request is in flight: its answer would have nowhere to be read.
  function setOpen(next) {
    if (!next && saving) return
    open = next
  }

  // Each opening starts from empty fields: the form is drawn only while the sheet is open.
  function reset() {
    saving = false
    failure = undefined
    done = false
  }
</script>

<Sheet.Root bind:open={() => open, setOpen} onOpenChange={(next) => next && reset()}>
  <Sheet.Trigger>
    {#snippet child({ props })}
      {@render trigger(props)}
    {/snippet}
  </Sheet.Trigger>
  <Sheet.Content class="data-[side=right]:w-full data-[side=right]:sm:max-w-md">
    <Sheet.Header>
      <Sheet.Title class="pr-8">Change password</Sheet.Title>
      <Sheet.Description>Changing it signs out your other sessions.</Sheet.Description>
    </Sheet.Header>
    <div class="grid gap-5 overflow-y-auto px-4">
      {#if done}
        <p bind:this={said} tabindex="-1" role="status" class="rounded-lg border border-success/30 bg-success-soft px-3 py-2 outline-none">
          Password changed. Your other sessions are signed out.
        </p>
      {:else}
        <PasswordForm
          id="{id}-form"
          username={me.name}
          bind:saving
          bind:failure
          onchanged={changed}
          onfailed={() => submit?.focus()}
        />
      {/if}
    </div>
    <Sheet.Footer>
      {#if failure}
        <p role="alert" class="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-danger wrap-anywhere">
          {failure}
        </p>
      {/if}
      {#if !done}
        <Button
          bind:ref={submit}
          type="submit"
          form="{id}-form"
          onkeydown={(event) => event.repeat && event.preventDefault()}
          disabled={saving}
        >
          {saving ? 'Changing…' : 'Change password'}
        </Button>
      {/if}
      <Sheet.Close disabled={saving}>
        {#snippet child({ props })}
          <Button variant="outline" {...props}>{done ? 'Close' : 'Cancel'}</Button>
        {/snippet}
      </Sheet.Close>
    </Sheet.Footer>
  </Sheet.Content>
</Sheet.Root>
