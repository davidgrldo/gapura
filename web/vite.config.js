import path from 'node:path'
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
function stubApi() {
  const shared = { '/api/overview': 'overview.json', '/api/routes': 'routes.json' }
  const personal = { '/api/me': 'me.json', '/api/users': 'users.json', '/api/roles': 'roles.json' }
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
