# Security policy

## Supported versions

For as long as Gapura is on a `0.x` version, **only the most recent release receives security
fixes**. There are no backports to earlier `0.x` releases: a fix lands on `main` and goes out in
the next release.

v0.1.0 is the first release; nothing was tagged before it. So anything older than v0.1.0 is a
checkout of this repository rather than a version there is anything to backport to, and the upgrade
path from one is forward, to the most recent release.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting:

**<https://github.com/davidgrldo/gapura/security/advisories/new>**

That form is the only reporting channel. Please do not open a public issue, a pull request, or a
discussion for a suspected vulnerability — Gapura sits in the request path of whatever it fronts,
so a public report is a working description of how to attack every deployment that has not upgraded
yet. The form is private between you and the maintainer, and it is also where a fix and an advisory
are coordinated.

A useful report says which version or commit you tested, how Gapura was configured (the chart
values, the command-line flags, or the Gateway API resources involved), what you observed, and what
you expected instead. A minimal reproduction — a fixture under
`crates/gapura-core/tests/fixtures/`, a `curl` invocation, a set of manifests — is worth more than
a description of the class of bug.

## What to expect, honestly

Gapura is maintained by one person, part time. Handling of a report is **best effort**: there is no
service level agreement, and none is implied by this document. I will not promise a response time
I cannot keep.

What I will do:

- Acknowledge the report when I get to it, and tell you whether I think it is a vulnerability.
- Keep you updated through the advisory rather than going quiet.
- Credit you in the advisory and the changelog unless you ask me not to.
- Tell you plainly if I am not going to fix something, so you can decide what to do next.

If a report is urgent and you have heard nothing, comment on the advisory thread to bump it. If you
need a guaranteed response window, Gapura is not the right dependency for that requirement today.

Please give me a reasonable chance to ship a fix before disclosing publicly. I am not going to name
a fixed embargo period I might miss; if you intend to disclose on a schedule, say so in the report
and we will work to it.

## Scope

In scope: the `gapura` data plane and its Kubernetes controller, the translation library
`gapura-core`, the published container image, and the defaults shipped by the Helm chart in
`charts/gapura` (including its RBAC).

Also in scope, and genuinely useful: a case where Gapura's translation of Gateway API resources
grants access that the Gateway API says it should refuse — a cross-namespace backend or TLS secret
reached without a `ReferenceGrant`, an `HTTPRoute` attaching to a listener that should not admit
it, a hostname or path match that routes a request somewhere the spec does not allow. Those are
authorization bugs even when they look like routing bugs.

Out of scope: vulnerabilities in Kubernetes, in Pingora, or in other upstream dependencies, unless
Gapura's own use of them is what creates the exposure — report those upstream. Also out of scope:
findings that require cluster-admin access you were already granted, and reports that a deliberate
opt-in is insecure, such as the `gapura.dev/backend-tls: insecure` annotation, which is documented
as encrypting without verifying.
