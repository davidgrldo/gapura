// Not a test framework: one script that fails if the console cannot render the API's
// answers. It exists because the Rust tests prove the API and nothing proves the page.
import { readFileSync } from 'node:fs'
const html = readFileSync('dist/index.html', 'utf8')
if (!html.includes('<div id="app"')) throw new Error('dist/index.html lost its mount point')
if (!/assets\/.*\.js/.test(html)) throw new Error('dist/index.html references no bundle')
console.log('ok: the build produced a document that mounts the app')
