import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

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
export default defineConfig({
  plugins: [svelte()],
  base: '/',
  build: {
    outDir: 'dist',
  },
})
