// The roles a person can hold in a workspace, in rising order, spelled as the store spells them.
// It is a plain module rather than a constant in a screen for the reason states.js is one:
// web/check.mjs imports it under bare Node and fails the build when it stops matching the
// role_name enum in crates/gapura-control/migrations, so a role added to the store cannot reach
// the console as a word it has never seen.
export const ROLES = ['viewer', 'editor', 'admin']

// What each role may do, for the Roles page. Roles are fixed rather than editable: a new need
// is a new role, not a new combination of ticks, so this table is the whole of it. A person's
// role in a workspace is the highest any of their grants gives them there.
export const ABILITIES = ['Read', 'Create', 'Update', 'Delete', 'Grant roles']

export const MATRIX = [
  { key: 'viewer', label: 'Viewer', can: [true, false, false, false, false], scope: 'In workspaces where it is granted.' },
  { key: 'editor', label: 'Editor', can: [true, true, true, false, false], scope: 'In workspaces where it is granted.' },
  { key: 'admin', label: 'Admin', can: [true, true, true, true, true], scope: 'In workspaces where it is granted; grants roles there.' },
  { key: 'superuser', label: 'Superuser', can: [true, true, true, true, true], scope: 'In every workspace, and over every account.' },
]

// The label each role is shown under, taken from the matrix so it is written once.
export const ROLE_LABEL = Object.fromEntries(MATRIX.map((row) => [row.key, row.label]))
