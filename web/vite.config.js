import path from 'node:path'
import { randomBytes, randomUUID } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'

// `web/public/.gitkeep` is not decoration. Vite empties `outDir` before every build, which
// would otherwise delete the tracked `web/dist/.gitkeep` that keeps that folder present in a
// fresh clone — and with no folder there, `rust-embed` has nothing to compile against and the
// Rust build fails for the next person who clones. Everything under `public/` is copied into
// `dist/` after the emptying, so the file survives the build that would have removed it, and
// building the console never breaks building the server.

// `outDir` and `base` are both load-bearing rather than defaults left alone. The Rust side
// embeds exactly `web/dist` (see the `#[folder]` attribute in
// crates/gapura-control/src/assets.rs), so renaming the output directory would leave the
// binary embedding an empty folder and serving its "console has not been built" page with no
// other sign that anything is wrong. `base` is `/` because gapura-control serves the console
// from the root of its own listener and never from a sub-path, so the asset URLs baked into
// index.html must be absolute from the root — a relative base would break the moment a
// client-side route one level deep, such as /routes, was reloaded.

// Answers the console's API from web/stub/ so that its screens can be looked at without a
// control plane or a cluster. `apply: 'serve'` keeps it out of every build, and it does nothing
// unless STUB is set, so a plain `npm run dev` behaves exactly as it did before this existed.
//
// STUB_AS picks whose eyes the console is seen through: web/stub/as-<persona>/ holds that
// account's /api/me, /api/users and /api/roles, and superuser is the default. A file a persona
// lacks answers 403, which is what the server says to an account that may not see it; the
// kubernetes persona is the console with no store at all. Overview and Routes are served to
// every persona, where the server keeps them for superusers in store mode, but the console only
// asks for them when its navigation offers them.
//
// A workspace's services and routes are the same for every persona: web/stub/workspaces/<name>/
// holds that workspace's services.json and routes.json, as `GET /api/workspaces/<name>/services`
// and `/routes` answer them, `updated_at` and each service's `routes` count included. The three
// workspaces are the ones the personas hold roles in, so each persona's pages show what its
// me.json says it may see; a workspace with no folder answers 404, as the server does for one the
// caller holds no role in.
//
// The same folder holds that workspace's consumers.json, as `GET /api/workspaces/<name>/consumers`
// answers it (each consumer's keys newest first, a key's prefix and times and `expired` flag, never
// the key), and key-auth.json, the `[{ target, header }]` of the API-key requirements set on the
// workspace, a service or a route. Each service and route row carries the `key_auth` the server
// would have worked out for it, so keep those rows and key-auth.json telling the same story.
//
// The console's writes — a change to an account's roles, a group mapping put or removed, a
// service or route created on its list, replaced or deleted by name, a consumer created or
// deleted, a key revoked, an API-key requirement put or removed — answer 204 and store nothing,
// for every persona, so the lists read back as they were. Issuing a key is the one write that
// answers with a body, as the server does: a made-up key, shown once like the real one, and the
// expiry the request asked for. That is enough to look at the forms and at what follows a save.
// Data planes are the same for every persona too: web/stub/data-planes.json is `GET /api/data-planes`,
// sorted by name, one row per data plane with its status, whether it holds the configuration served
// now, the address it called from and its tokens (a prefix and times, never the token). Registering
// one and issuing another token answer with a made-up token, shown once like the real one; deleting a
// data plane or revoking a token answers 204 and stores nothing.
// The audit log is the same for every persona and the same whatever the query asks:
// web/stub/audit.json is one page of `GET /api/audit`, newest first, with `next` null, so the
// filters reload it as it is and Load older is never offered.
// Account administration answers the same way for every persona. Creating an account answers with a
// made-up temporary password next to the new id and name, and resetting one answers with another,
// both shown once like the real ones; changing the status or superuser flag, deleting an account
// and changing your own password answer 204 and store nothing. web/stub/as-must-change/ is the
// account that has just been given a temporary password and may do nothing but choose another.
// What a write does is proven against Postgres by the Rust tests, and by a pass against a real
// server. Each answers only the method the server serves it on, so a form that sends the wrong
// one fails here as it would there.
function stubApi() {
  const shared = {
    '/api/overview': 'overview.json',
    '/api/routes': 'routes.json',
    '/api/data-planes': 'data-planes.json',
    '/api/audit': 'audit.json',
  }
  const personal = { '/api/me': 'me.json', '/api/users': 'users.json', '/api/roles': 'roles.json' }
  // `/api/workspaces/<name>/services`, `/routes`, `/consumers` and `/key-auth`, and one row of
  // the first three by name. Only the first three are created by POST; `/key-auth` is put and
  // deleted whole.
  const lists = /^\/api\/workspaces\/([^/]+)\/(services|routes|consumers|key-auth)$/
  const rows = /^\/api\/workspaces\/[^/]+\/(services|routes|consumers)\/[^/]+$/
  const keys = /^\/api\/workspaces\/[^/]+\/consumers\/[^/]+\/keys$/
  const revoke = /^\/api\/workspaces\/[^/]+\/consumers\/[^/]+\/keys\/[^/]+$/
  const keyAuth = /^\/api\/workspaces\/[^/]+\/key-auth$/
  // Registering a data plane and issuing it another token both answer with a token.
  const issued = /^\/api\/data-planes(\/[^/]+\/tokens)?$/
  const dataPlaneWrites = /^\/api\/data-planes\/[^/]+(\/tokens\/[^/]+)?$/
  // Creating an account and resetting a password both answer with a temporary password.
  const created = /^\/api\/users$/
  const reset = /^\/api\/users\/[^/]+\/password$/
  const writes = [
    ['PATCH', /^\/api\/users\/[^/]+\/roles$/],
    ['PUT', /^\/api\/users\/[^/]+\/(status|superuser)$/],
    ['DELETE', /^\/api\/users\/[^/]+$/],
    ['POST', /^\/api\/me\/password$/],
    ['PUT', /^\/api\/group-mappings$/],
    ['DELETE', /^\/api\/group-mappings$/],
    ['POST', /^\/api\/workspaces\/[^/]+\/(services|routes|consumers)$/],
    ['PUT', rows],
    ['DELETE', rows],
    ['DELETE', revoke],
    ['PUT', keyAuth],
    ['DELETE', keyAuth],
    ['DELETE', dataPlaneWrites],
  ]
  return {
    name: 'gapura-stub-api',
    apply: 'serve',
    configureServer(server) {
      if (!process.env.STUB) return
      const stub = path.join(import.meta.dirname, 'stub')
      const persona = path.join(stub, `as-${process.env.STUB_AS || 'superuser'}`)
      // Every persona has an /api/me, which the server never refuses a signed-in account; a
      // persona without one is a typo, or a path that is not a persona at all.
      if (!existsSync(path.join(persona, 'me.json'))) {
        throw new Error(`STUB_AS=${process.env.STUB_AS}: there is no ${persona}/me.json`)
      }
      server.middlewares.use((req, res, next) => {
        const url = req.url.split('?')[0]
        // The server answers sign-out with a "signed out" page; the stub keeps no session to
        // end, so it goes straight back to the console.
        if (url === '/auth/logout') {
          res.statusCode = 303
          res.setHeader('location', '/')
          return res.end()
        }
        if (req.method === 'POST' && keys.test(url)) {
          let body = ''
          req.on('data', (chunk) => (body += chunk))
          req.on('end', () => {
            let expires_at = null
            try {
              expires_at = JSON.parse(body).expires_at ?? null
            } catch {
              // A body that is not JSON asks for no expiry.
            }
            const key = `gpak_${randomBytes(32).toString('hex')}`
            res.setHeader('content-type', 'application/json')
            res.end(JSON.stringify({ key, prefix: key.slice(0, 13), expires_at }))
          })
          return
        }
        if (req.method === 'POST' && (created.test(url) || reset.test(url))) {
          const id = url.split('/')[3]
          let body = ''
          req.on('data', (chunk) => (body += chunk))
          req.on('end', () => {
            let username = null
            try {
              username = JSON.parse(body).username ?? null
            } catch {
              // A body that is not JSON names no account.
            }
            // Twenty letters and digits, without the ones that read alike: 0 O 1 l I.
            const alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
            const password = Array.from(randomBytes(20), (b) => alphabet[b % alphabet.length]).join('')
            res.setHeader('content-type', 'application/json')
            res.end(JSON.stringify(id ? { password } : { id: randomUUID(), username, password }))
          })
          return
        }
        if (req.method === 'POST' && issued.test(url)) {
          const name = url.split('/')[3]
          let body = ''
          req.on('data', (chunk) => (body += chunk))
          req.on('end', () => {
            let registered = name
            try {
              registered = name ?? JSON.parse(body).name
            } catch {
              // A body that is not JSON names no data plane.
            }
            const token = `gpdp_${randomBytes(32).toString('hex')}`
            res.setHeader('content-type', 'application/json')
            res.end(JSON.stringify({ name: registered ?? null, token, prefix: token.slice(0, 13) }))
          })
          return
        }
        if (writes.some(([method, pattern]) => req.method === method && pattern.test(url))) {
          res.statusCode = 204
          return res.end()
        }
        const list = req.method === 'GET' ? lists.exec(url) : null
        if (list) {
          // Only a plain name is looked up, so a request cannot walk out of web/stub/workspaces/.
          let name
          try {
            name = decodeURIComponent(list[1])
          } catch {
            name = ''
          }
          const known = /^[\w-]+$/.test(name) && existsSync(path.join(stub, 'workspaces', name))
          const file = path.join(stub, 'workspaces', name, `${list[2]}.json`)
          if (!known || !existsSync(file)) {
            res.statusCode = 404
            return res.end()
          }
          res.setHeader('content-type', 'application/json')
          return res.end(readFileSync(file))
        }
        const file = shared[url]
          ? path.join(stub, shared[url])
          : personal[url]
            ? path.join(persona, personal[url])
            : null
        if (!file) return next()
        if (!existsSync(file)) {
          res.statusCode = 403
          return res.end()
        }
        res.setHeader('content-type', 'application/json')
        res.end(readFileSync(file))
      })
    },
  }
}

// `$lib` is the alias every shadcn-svelte component imports from (see components.json).
// SvelteKit would provide it; this is a plain Vite app, so it is declared here, and
// jsconfig.json repeats it only so that the CLI and editors resolve what the build resolves.
export default defineConfig({
  plugins: [tailwindcss(), svelte(), stubApi()],
  resolve: {
    alias: { $lib: path.resolve(import.meta.dirname, 'src/lib') },
  },
  base: '/',
  build: {
    outDir: 'dist',
  },
})
