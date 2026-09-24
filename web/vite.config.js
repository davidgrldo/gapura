import path from 'node:path'
import { readFileSync } from 'node:fs'
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

// Answers the console's two API paths from web/stub/ so that its screens can be looked at
// without a control plane or a cluster. `apply: 'serve'` keeps it out of every build, and it
// does nothing unless STUB is set, so a plain `npm run dev` behaves exactly as it did
// before this existed.
function stubApi() {
  const answers = { '/api/overview': 'overview.json', '/api/routes': 'routes.json' }
  return {
    name: 'gapura-stub-api',
    apply: 'serve',
    configureServer(server) {
      if (!process.env.STUB) return
      server.middlewares.use((req, res, next) => {
        const file = answers[req.url.split('?')[0]]
        if (!file) return next()
        res.setHeader('content-type', 'application/json')
        res.end(readFileSync(path.join(import.meta.dirname, 'stub', file)))
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
