// The console's one way of reaching its backend. Every screen goes through `get`, which is
// what makes signing back in a property of this file rather than something each screen has
// to remember: a session lasts an hour by default (gapura-control's
// --session-lifetime-seconds), so expiry is the ordinary end of a reading session, not an
// exceptional case, and a screen that forgot to handle it would render an error page where
// the right answer is a sign-in.

// Where the server begins the OpenID Connect authorization-code flow. Named once so that a
// screen can never invent a slightly different path and quietly get the 404 fallback.
const LOGIN = '/auth/login'

/**
 * GET `path` as JSON, signed in. Resolves with the parsed body, redirects the browser to
 * the sign-in flow on a 401, and throws on anything else so the caller's `{:catch}` can say
 * what went wrong.
 */
export async function get(path) {
  // `same-origin` rather than the default `omit`: the session lives in a cookie the server
  // set on this same origin, and without this every request would arrive unauthenticated and
  // bounce straight back to the identity provider in a loop.
  const response = await fetch(path, { credentials: 'same-origin' })

  if (response.status === 401) {
    // `replace` rather than `assign` so the expired page does not stay in the history: a
    // reader who presses Back after signing in would otherwise land on the page that just
    // bounced them and be bounced again.
    window.location.replace(LOGIN)
    // Leaving the browser is not instantaneous, and the caller is waiting on this promise.
    // Never settling leaves the screen exactly as the reader left it until the new document
    // arrives, instead of flashing a parse error against a body that was never JSON.
    await new Promise(() => {})
  }

  if (!response.ok) {
    throw new Error(`${path} answered ${response.status} ${response.statusText}`.trim())
  }

  return response.json()
}
