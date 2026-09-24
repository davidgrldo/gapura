import './app.css'
import { mount } from 'svelte'
import App from './App.svelte'

// The mount point is created in index.html rather than here so that check.mjs can assert on
// the built document: a build that dropped the div would still produce a page, and the only
// symptom would be a blank screen in a browser nobody is watching during CI.
export default mount(App, { target: document.getElementById('app') })
