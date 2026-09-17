// The console's one way of reaching its backend. Every screen goes through `get`, which is
// what makes signing back in a property of this file rather than something each screen has
// to remember: a session lasts an hour by default (gapura-control's
// --session-lifetime-seconds), so expiry is the ordinary end of a reading session, not an
// exceptional case, and a screen that forgot to handle it would render an error page where
// the right answer is a sign-in.

// Where the server begins the OpenID Connect authorization-code flow. Named once so that a
// screen can never invent a slightly different path and quietly get the 404 fallback. The
// query carries the screen the reader was on, so a session that ran out mid-task returns
// them there instead of to the overview (#61); the server decides what is safe to honour.
const LOGIN = '/auth/login'

function loginUrl() {
  return LOGIN + '?return_to=' + encodeURIComponent(
    window.location.pathname + window.location.search + window.location.hash
  )
}

// Records that this tab has already been sent to the sign-in flow once for a 401, so that a
// second 401 can be read as "signing in did not help" instead of being answered by signing in
// again. It has to be sessionStorage rather than a variable in this module: the redirect is a
// full page navigation, which tears down every module in the document, so a variable would be
// back at its initial value in exactly the document that needs to remember.
//
// Per-tab is the right scope here rather than a limitation to work around. Two tabs are two
// independent attempts to get in — the reader may well have changed something between opening
// them — and each one still redirects at most once, so neither can loop, and neither inherits
// a verdict from a tab it cannot see.
const SENT_TO_SIGN_IN = 'gapura.sent-to-sign-in'

// `sessionStorage` is not always there to be used: a browser with site data blocked throws on
// the property itself, and private windows have historically thrown on write. Every access
// goes through these three so that a reader who has turned storage off keeps the ordinary
// behaviour — one redirect per 401 — rather than getting a console that fails to load at all.
// What they give up is the loop detection below, which is exactly where this file already
// stood, so the fallback can only be an improvement on nothing.
function wasSentToSignIn() {
  try {
    return window.sessionStorage.getItem(SENT_TO_SIGN_IN) !== null
  } catch {
    return false
  }
}

function rememberSentToSignIn() {
  try {
    window.sessionStorage.setItem(SENT_TO_SIGN_IN, '1')
  } catch {
    // Deliberately nothing: the redirect that follows is the half that matters, and a reader
    // without storage is no worse off than they were before this marker existed.
  }
}

function forgetSentToSignIn() {
  try {
    window.sessionStorage.removeItem(SENT_TO_SIGN_IN)
  } catch {
    // Deliberately nothing: if the write never landed there is nothing here to clear.
  }
}

/**
 * Thrown in place of a second redirect when the server says 401 to a tab that has already
 * been all the way through the sign-in flow. It is its own type rather than a plain `Error`
 * so a screen can tell it apart from a backend that merely failed: what a reader needs to be
 * told here is about their connection to the console, not about whichever request happened to
 * be the one that noticed.
 */
export class SessionNotSticking extends Error {
  constructor() {
    super(
      'Signing in succeeded, but the browser is not sending the session back, so every ' +
        'request still arrives unauthenticated.',
    )
    this.name = 'SessionNotSticking'
  }
}

/**
 * Go to the sign-in flow because the reader asked to. This is the only way a tab gets a
 * second attempt: an automatic one is precisely what was looping, so every attempt after the
 * first has to be one a person pressed — typically after changing the cause, by reopening the
 * console over https or port-forwarding it to localhost.
 *
 * The marker is set again here rather than cleared, because clearing it would buy the tab
 * another automatic bounce: a retry that fixes nothing would go out to the identity provider,
 * come back, and go out once more before saying so. Setting it means an unsuccessful retry
 * lands straight back on the explanation, and a successful one clears the marker in `get` the
 * moment the first request is answered.
 */
export function retrySignIn() {
  rememberSentToSignIn()
  window.location.replace(loginUrl())
}

/**
 * GET `path` as JSON, signed in. Resolves with the parsed body, redirects the browser to the
 * sign-in flow on the first 401, throws `SessionNotSticking` on a later one, and throws on
 * anything else so the caller's `{:catch}` can say what went wrong.
 */
export async function get(path) {
  // `same-origin` rather than the default `omit`: the session lives in a cookie the server
  // set on this same origin, and without this every request would arrive unauthenticated and
  // bounce straight back to the identity provider in a loop.
  const response = await fetch(path, { credentials: 'same-origin' })

  if (response.status === 401) {
    // Being sent to sign in is the right answer to an expired session, but only the first
    // time. A second 401 in the same tab means the round trip through the identity provider
    // completed and changed nothing — the server is issuing a session the browser never sends
    // back — and redirecting again would do that forever: no frame is ever rendered, and the
    // control plane and the identity provider each take hundreds of requests a second for as
    // long as the tab stays open. Since `replace` leaves no history, Back cannot rescue the
    // reader either. Not knowing and knowing nothing must not look the same, so the reader is
    // told instead.
    if (wasSentToSignIn()) {
      throw new SessionNotSticking()
    }
    rememberSentToSignIn()
    // `replace` rather than `assign` so the expired page does not stay in the history: a
    // reader who presses Back after signing in would otherwise land on the page that just
    // bounced them and be bounced again.
    window.location.replace(loginUrl())
    // Leaving the browser is not instantaneous, and the caller is waiting on this promise.
    // Never settling leaves the screen exactly as the reader left it until the new document
    // arrives, instead of flashing a parse error against a body that was never JSON.
    await new Promise(() => {})
  }

  if (!response.ok) {
    throw new Error(`${path} answered ${response.status} ${response.statusText}`.trim())
  }

  // The session demonstrably works, so the next 401 in this tab is an ordinary expiry an hour
  // from now and has earned a redirect of its own rather than the explanation above.
  forgetSentToSignIn()

  return response.json()
}
