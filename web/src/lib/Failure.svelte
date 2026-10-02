<script>
  import { SessionNotSticking, retrySignIn } from './api.js'
  import { Button } from '$lib/components/ui/button/index.js'

  // Both screens fail in the same two ways, and one of the two takes several sentences to
  // explain. It lives here rather than in either screen for the same reason the state badge
  // does: the reader must not be told a different story about the same failure depending on
  // which screen happened to notice it. `what` — the noun the screen was loading — is the
  // only part that legitimately differs, so it is the only part a screen passes.
  let { error, what } = $props()
</script>

{#if error instanceof SessionNotSticking}
  <div class="max-w-2xl space-y-3 rounded-lg border border-warning/30 bg-warning-soft px-4 py-3 text-sm">
    <p>
      <strong>Signing in worked, but the session is not coming back.</strong> This tab went
      through the sign-in flow, returned, and the console still treats every request as
      unauthenticated — so it has stopped rather than bouncing you round that loop, which
      would leave you looking at a blank page for as long as the tab stayed open.
    </p>
    <!-- Naming the likeliest cause, because "unauthorized" is not something an operator can
         act on. The session cookie is issued Secure, so a browser on a plain http:// origin
         that is not localhost completes the sign-in and then discards the cookie without
         saying anything: that is every NodePort, every port-forward bound to a LAN address,
         and every direct Service hit while an ingress is being debugged — which is to say,
         most of the ways this console gets reached for the first time. -->
    <p>
      The usual cause is reaching the console over <code>http://</code> on something other than
      <code>localhost</code>. The session cookie is marked <code>Secure</code>, so the browser
      accepts the sign-in and then drops the cookie. Opening the same console over
      <code>https://</code>, or port-forwarding it to <code>localhost</code>, is what fixes
      that. A proxy in front of it that strips <code>Set-Cookie</code>, or a clock far enough
      out that the session is expired the moment it is issued, look identical from here.
    </p>
    <p>
      <Button variant="outline" size="sm" onclick={retrySignIn}>Try signing in again</Button>
    </p>
  </div>
{:else}
  <p class="max-w-2xl rounded-lg border border-warning/30 bg-warning-soft px-4 py-3 text-sm">
    Could not load {what}: {error.message}
  </p>
{/if}
