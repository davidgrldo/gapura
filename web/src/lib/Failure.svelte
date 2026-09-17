<script>
  import { SessionNotSticking, retrySignIn } from './api.js'

  // Both screens fail in the same two ways, and one of the two takes several sentences to
  // explain. It lives here rather than in either screen for the same reason the state badge
  // does: the reader must not be told a different story about the same failure depending on
  // which screen happened to notice it. `what` — the noun the screen was loading — is the
  // only part that legitimately differs, so it is the only part a screen passes.
  let { error, what } = $props()
</script>

{#if error instanceof SessionNotSticking}
  <div class="notice">
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
      <button type="button" onclick={retrySignIn}>Try signing in again</button>
    </p>
  </div>
{:else}
  <p class="notice">Could not load {what}: {error.message}</p>
{/if}

<style>
  .notice {
    background: #fdf3da;
    border: 1px solid #e5c569;
    border-radius: 0.375rem;
    padding: 0.75rem 1rem;
    max-width: 44rem;
  }

  .notice p {
    margin: 0 0 0.75rem;
  }

  .notice p:last-child {
    margin-bottom: 0;
  }

  code {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.875em;
  }

  button {
    font: inherit;
    padding: 0.3125rem 0.875rem;
    border: 1px solid #b08c22;
    border-radius: 0.25rem;
    background: #ffffff;
    color: #713f12;
    cursor: pointer;
  }

  button:hover {
    background: #fffaf0;
  }
</style>
