// The console's one way of reaching its backend. Every screen reads through `get` and every
// form writes through `write`, which is what makes signing back in a property of this file
// rather than something each screen has to remember: a session lasts an hour by default
// (gapura-control's --session-lifetime-seconds), so expiry is the ordinary end of a reading
// session, not an exceptional case, and a screen that forgot to handle it would render an error
// page where the right answer is a sign-in.

// Where the server begins sign-in: the identity provider's authorization-code flow, or the
// console's own form, which store mode always shows first. Named once so that a screen cannot
// invent a slightly different path and quietly get the 404 fallback. The query carries the
// screen the reader was on, so a session that ran out mid-task returns them there instead of
// to the overview (#61); the server decides what is safe to honour.
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
 * Thrown on a 403: the server refused this, usually because it is not the reader's to see or to
 * change. Its own type so a screen can say exactly that, instead of reporting it as a backend
 * that failed. A refused write carries the server's own sentence, which says why; a refused
 * read keeps the general one.
 */
export class Forbidden extends Error {
  constructor(path, message = 'You do not have access to this page.') {
    super(message)
    this.name = 'Forbidden'
    this.path = path
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
 * What `get` and `write` both do with a 401. Being sent to sign in is the right answer to an
 * expired session, but only the first time. A second 401 in the same tab means the round trip
 * through the identity provider completed and changed nothing — the server is issuing a
 * session the browser never sends back — and redirecting again would do that forever: no frame
 * is ever rendered, and the control plane and the identity provider each take hundreds of
 * requests a second for as long as the tab stays open. Since `replace` leaves no history, Back
 * cannot rescue the reader either. Not knowing and knowing nothing must not look the same, so
 * the reader is told instead.
 */
async function signInAgain() {
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

/**
 * GET `path` as JSON, signed in. Resolves with the parsed body, redirects the browser to the
 * sign-in flow on the first 401, throws `SessionNotSticking` on a later one, throws `Forbidden`
 * on a 403, and throws on anything else so the caller's `{:catch}` can say what went wrong.
 */
export async function get(path) {
  // `same-origin` rather than the default `omit`: the session lives in a cookie the server
  // set on this same origin, and without this every request would arrive unauthenticated and
  // bounce straight back to the identity provider in a loop.
  const response = await fetch(path, { credentials: 'same-origin' })

  if (response.status === 401) await signInAgain()

  if (response.status === 403) {
    // A 403 proves the session works — the server knew who was asking — so the next 401 in
    // this tab is an ordinary expiry again, not a sign-in that failed to stick.
    forgetSentToSignIn()
    throw new Forbidden(path)
  }

  if (!response.ok) {
    throw new Error(`${path} answered ${response.status} ${response.statusText}`.trim())
  }

  // The session demonstrably works, so the next 401 in this tab is an ordinary expiry an hour
  // from now and has earned a redirect of its own rather than the explanation above.
  forgetSentToSignIn()

  return response.json()
}

// The sentence in a refused write's `{"error": …}` body, which a form shows as it is, and the
// field the server named, when it did: the configuration API answers a rejected input as
// `{"error": …, "field": "paths[1].value"}` so a form can put the sentence beside the input it
// is about. A body without a sentence, such as a proxy's error page, is not the server's
// answer, and whether the change was made is then unknown, so that is what the reader is told.
async function refusal(response) {
  try {
    const body = await response.json()
    if (typeof body?.error === 'string') {
      return { sentence: body.error, field: typeof body.field === 'string' ? body.field : undefined }
    }
  } catch {
    // Not JSON: the sentence below says what can be said.
  }
  return {
    sentence:
      `The console answered ${response.status} without saying why, so this change may not ` +
      'have been saved. Check the list, then try again.',
    field: undefined,
  }
}

/**
 * A refused write: the server's sentence, its status, and the field it named, if any. The
 * status lets a form tell a conflict (409: such as an edit made from a stale read, a name
 * already taken, or a host another workspace routes) from a rejected input (400), and it is an
 * `Error` so a caller that only shows `message` keeps working.
 */
export class Refused extends Error {
  constructor(status, { sentence, field }) {
    super(sentence)
    this.name = 'Refused'
    this.status = status
    this.field = field
  }
}

/**
 * Send `body` to `path` with `method`, as JSON and signed in: the console's writes. Resolves
 * with nothing once the server has made the change. A 401 is answered as `get` answers it, a
 * 403 throws `Forbidden` carrying the server's sentence, and anything else that is not a
 * success throws `Refused`, whose message is the server's sentence, which the form shows as it
 * is, and which also carries the status and the field.
 *
 * `Content-Type: application/json` goes on every write, a DELETE with no body included. The
 * server refuses a write to the API without it, because a page on another site cannot send it
 * without asking first, and the server never says yes.
 */
export async function write(method, path, body) {
  let response
  try {
    response = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch (cause) {
    // The connection failed, perhaps after the server had already committed, so the outcome
    // is unknown. The browser's own words ("Failed to fetch", "Load failed") say neither.
    throw new Error(
      'The console could not be reached, so this change may not have been saved. Check the ' +
        'list, then try again.',
      { cause },
    )
  }

  if (response.status === 401) await signInAgain()

  // The sign-in marker is not forgotten here as `get` forgets it: a write's 403 may come from
  // the cross-site check, before the session is looked at, so it proves nothing about the
  // session. A write is only ever sent after a read has already cleared the marker.
  if (response.status === 403) throw new Forbidden(path, (await refusal(response)).sentence)

  // The server's one success is 204. Anything else, a 200 page from a proxy included, did not
  // come from the write, so it is not taken as one.
  if (response.status !== 204) throw new Refused(response.status, await refusal(response))

  forgetSentToSignIn()
}
