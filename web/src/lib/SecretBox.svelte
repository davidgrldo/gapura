<script>
  import { Button } from '$lib/components/ui/button/index.js'
  import { Input } from '$lib/components/ui/input/index.js'

  // A secret the server answers with once, such as a consumer's new key or a data plane's token,
  // shown in a box that stays until its sheet closes. A readonly input rather than text, so it
  // can be selected whole and read character by character.
  // - `label` names it, and `code` (optional) follows the label in monospace, such as a prefix;
  // - `note` (optional) follows "This is the only time it is shown.";
  // - `copied` is bindable: the sheet asks before closing while it is false, and sets it back to
  //   false when it shows a new secret;
  // - `ref` is bindable, the input, which the sheet focuses after issuing and after its close
  //   question is dismissed;
  // - `children` (optional) is drawn below, such as an example of where the secret goes.
  let { secret, label, code = undefined, note = undefined, copied = $bindable(false), ref = $bindable(null), children = undefined } = $props()

  const id = $props.id()
  // The secret a copy failed for: a new secret starts without the failure.
  let failedFor = $state(null)
  const copyFailed = $derived(failedFor !== null && failedFor === secret)

  async function copy() {
    try {
      // `navigator.clipboard` is missing outside a secure context, which throws here too.
      await navigator.clipboard.writeText(secret)
      copied = true
      failedFor = null
    } catch {
      failedFor = secret
      ref?.focus()
    }
  }

  const selectAll = (event) => event.currentTarget.select()
  // A key held down repeats, and a repeat must not copy twice.
  const once = (event) => event.repeat && event.preventDefault()
</script>

<div class="grid gap-2 rounded-lg border border-success/30 bg-success-soft p-3">
  <label for="{id}-secret" class="font-medium">{label}{#if code}{' '}<span class="font-mono">{code}</span>{/if}</label>
  <div class="flex gap-2">
    <Input
      bind:ref
      id="{id}-secret"
      class="bg-background font-mono"
      readonly
      value={secret}
      spellcheck="false"
      autocomplete="off"
      aria-describedby="{id}-once"
      onfocus={selectAll}
      onclick={selectAll}
      oncopy={() => {
        copied = true
        failedFor = null
      }}
    />
    <Button variant="outline" size="sm" onclick={copy} onkeydown={once}>{copied ? 'Copied' : 'Copy'}</Button>
  </div>
  <p id="{id}-once" class="text-sm">
    This is the only time it is shown.
    {note ?? ''}
  </p>
  <p role="status" class={copyFailed ? 'text-xs text-danger' : 'sr-only'}>
    {copyFailed ? 'Copy failed — select it and copy it yourself.' : copied ? 'Copied.' : ''}
  </p>
  {@render children?.()}
</div>
