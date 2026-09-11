# Releasing Gapura

This is the procedure for cutting a release. It is written for one reader: the maintainer, at the
moment of releasing, who would rather not make a mistake that cannot be taken back.

**Read the marks.** Every command below carries one:

| Mark | Meaning |
|---|---|
| *(none)* | Changes nothing outside this machine. A read-only query to GitHub counts as nothing. |
| `# PUBLIC` | Changes something outside this machine. Other people can see the result. |
| `# PUBLIC, IRREVERSIBLE` | Changes something outside this machine, and you cannot take it back. |

Everything before the first `# PUBLIC` is rehearsal and can be repeated as often as you like.
Everything after it edits a record other people read.

The examples use the real values for this project: owner `davidgrldo`, repository `gapura`,
version `0.1.0`, tag `v0.1.0`. Substitute the version for later releases; the owner and the
repository name are load-bearing and section 1.4 explains why.

## What cannot be undone

Four things here are permanent. Nothing else in this document is.

1. **Pushing `main` publishes the entire git history.** Every commit, every commit message and
   every file ever committed, back to the first one — not just the tree you can see today. Making
   the repository private again later does not recall a clone, a fork or an archive.
2. **A pushed tag is a name other people now have.** `git push origin :refs/tags/v0.1.0` removes it
   from GitHub, but not from anyone who already fetched it, and not from the packages the workflow
   published under that version in the meantime.
3. **A published package version is public content at a permanent address.** Once
   `ghcr.io/davidgrldo/gapura:0.1.0` exists, deleting it breaks anyone who pinned it. If the
   contents turn out to be wrong, the fix is `0.1.1`. Never re-push a version that has shipped.
4. **Making the repository public is not reliably reversible.** Flipping it back to private hides it
   from GitHub, not from whoever cloned, forked or indexed it while it was up. What is permanent is
   the content, not the repository: `gh repo create --public` in section 2 makes an *empty* public
   repository, and until the push there is nothing in it to clone, fork or index — so if the name
   comes out wrong (findings 1 and 2 in 1.4 are two ways it can), deleting it and creating it again
   costs nothing. That is why section 2 marks the create `# PUBLIC` and the push
   `# PUBLIC, IRREVERSIBLE`, and why it keeps them two separate commands.

Checks are free. Run all of them.

## 1. Preflight — nothing leaves this machine

### 1.1 The verification gates

These are the checks CI runs, and all of them must be green on the commit you are about to release:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
RUSTUP_TOOLCHAIN=1.89 cargo check --workspace --all-targets --locked
./hack/check-identity.sh
./hack/chart-render.sh
cargo deny check all
```

The fifth line is the MSRV gate — `ci.yml`'s `msrv` job, invoked the way that job invokes it. It is
the only check here that fails on a change which compiles on stable but not on the minimum supported
Rust version, and nothing in `release.yml` runs it, so a release can ship that regression unless you
run it now. It needs the toolchain installed once (`rustup toolchain install 1.89`), and it needs
the environment variable rather than a bare `cargo check`, because `rust-toolchain.toml` pins
`stable` and would otherwise decide which compiler you got.

The release is cut from `main`, so the branch the work was done on has to be merged first. Confirm
you are standing on the commit you actually verified:

```bash
git switch main
git log --oneline -1
git status --porcelain          # must print nothing
```

### 1.2 The release dry run

`hack/release-dry-run.sh` runs the same sequence `release.yml` does — build each architecture
separately, push by digest, join the digests into one manifest list, package the chart, push it to
an OCI registry, install from there — against a `registry:2` container on this machine. It then
proves the result by pulling it into kind and sending one request through a Gateway. It never
contacts ghcr.io.

```bash
./hack/release-dry-run.sh
```

It needs docker with buildx, kind, kubectl, helm 4.1.4, and jq. Two helm floors meet in that script
and the higher one is the requirement: `--plain-http`, which is what lets it push to and install
from a registry with no TLS, landed in 3.13 — but the script also runs `./hack/chart-render.sh`, and
the golden renders under `charts/gapura/tests/golden/` were produced by helm 4.1.4, the version
`CONTRIBUTING.md` and all three CI workflows pin. On any other helm the dry run dies on a golden
diff that has nothing to do with the release. It also needs disk: two from-scratch Rust release
builds with vendored OpenSSL. The script watches both the host filesystem and the docker VM during
each build and stops at a floor rather than filling a disk, so a run that exits early with
`FAIL out of disk` has told you the truth about this machine, not about the release. Clear space and
run it again.

This is the only rehearsal of the release path that exists. The workflow itself has no other
trigger than a pushed tag, and by then a mistake is already public.

### 1.3 The version is written down in three places, consistently

```bash
grep -n '^## ' CHANGELOG.md | head -3
helm show chart charts/gapura | grep -E '^(version|appVersion):'
helm show values charts/gapura | awk '$1 == "repository:" { print $2 }'
```

The CHANGELOG needs a `## 0.1.0 — <date>` section that is not `## Unreleased`; `version` and
`appVersion` in `Chart.yaml` both need to be `0.1.0`; and the chart's default image repository must
read `ghcr.io/davidgrldo/gapura`. That last line is checked again, for a different reason, in 1.4.

### 1.4 Four things `release.yml` gets wrong

These came out of the dry run. Each of them is invisible until the tag already exists.

#### 1. ghcr.io rejects any uppercase letter in the path

`release.yml` sets `IMAGE: ghcr.io/${{ github.repository }}` and pushes the chart to
`oci://ghcr.io/${{ github.repository_owner }}/charts`. Neither is lowercased anywhere in the
workflow. Those contexts return the account and repository exactly as they were registered, so a
single capital letter in either name — `Davidgrldo`, `Gapura` — makes every push in the workflow
fail with `repository name must be lowercase`, at a point where the tag already exists.

```bash
gh api /user --jq .login
```

Must be all lowercase. Check the repository name the same way once it exists (section 2).

#### 2. The repository must be named `gapura`

The workflow publishes to `ghcr.io/<owner>/<repo>`, and the chart's default image reference is baked
in independently:

```bash
helm show values charts/gapura | awk '$1 == "repository:" { print $2 }'
# ghcr.io/davidgrldo/gapura
```

If the repository is called anything else, the image lands at a path the chart does not point at.
The symptom is not a failed release — it is a chart that installs cleanly and pods that sit in
`ImagePullBackOff` forever against an image that was never pushed. **No job in `release.yml` catches
this.** The `chart` job runs `hack/chart-render.sh` and packages the chart; nothing in that path
knows what `IMAGE` was. The two strings agree only because you checked them here.

#### 3. `ubuntu-24.04-arm` is allocated by repository visibility, not by the label

The arm64 leg of the `build` matrix asks for `ubuntu-24.04-arm`. GitHub-hosted Linux arm64 runners
have been generally available for **public** repositories since early 2025, so the label should be
allocated the moment this repository is public; what gates it is public status and the account's
plan, not whether the label is spelled correctly.

Prove it anyway, because the failure mode is ugly. An unallocated label does not fail fast — it
queues until the job times out. `fail-fast: false` meanwhile lets the amd64 leg finish and push its
blobs by digest, with no tag attached. `image` needs `build` and so never runs, which means the
manifest list is never created; `chart` needs `image` and never runs either. What you are left with
is a tag that exists, blobs nobody can address, nothing at `:0.1.0`, and no chart at all.

The probe that settles it is free, but it is two `# PUBLIC` pushes and it cannot run from here: it
needs the remote section 2 adds, and it belongs after the repository is public and before the tag.
It is section 3. Nothing in section 1 leaves this machine.

#### 4. The `workflow_dispatch` path is broken — release by pushing a tag

Two separate faults, and the second is the one that matters.

The tag string: `docker/metadata-action` emits `type=semver` only on a tag ref. On a dispatch the
ref is a branch, so the only tag produced is `type=sha`, while `steps.meta.outputs.version` becomes
the branch slug — and the closing `docker buildx imagetools inspect "${IMAGE}:...version"` then
inspects a tag that was never created.

The source code: `build`, `image` and `chart` all call `actions/checkout@v7` with no `ref:`. On a
dispatch that checks out the branch the dispatch was started from, not the tag you typed in. The
`tag` input therefore selects no source code whatsoever; the only thing it influences is the chart's
version string in the `chart` job. One dispatch can publish a chart labelled with a release version
whose contents were built from an arbitrary branch — an artifact claiming to be 0.1.0 that never
touched `v0.1.0`.

The tag-push path, the one this document uses, has neither problem: `GITHUB_REF_NAME` is the tag,
and `actions/checkout` with no `ref:` checks that tag out. This was not exercised directly; it is
read off the documented behaviour of those actions and off `release.yml` itself.

So: **release by pushing a tag.** Before using the dispatch path for anything, put
`ref: ${{ inputs.tag }}` on all three checkouts and give it a tag strategy that works from a branch
ref.

## 2. Publish the repository — PUBLIC from here on

Create it empty and public, then add the remote yourself, so that creating the repository and
publishing the history stay two separate decisions:

```bash
gh repo create davidgrldo/gapura --public \
  --description "The Rust API gateway. Kubernetes Gateway API-native, one binary, no database."   # PUBLIC
gh repo view davidgrldo/gapura --json nameWithOwner --jq .nameWithOwner
```

That second line must print exactly `davidgrldo/gapura`, lowercase — findings 1 and 2 above.

**Turn on private vulnerability reporting before the history goes up.** It is off by default on a
new repository, and `SECURITY.md` names the advisory form as the only reporting channel. Left off,
that link 404s for the first security researcher who follows it, and the only thing they can do
instead is the public issue the same document asks them not to open.

```bash
gh api -X PUT /repos/davidgrldo/gapura/private-vulnerability-reporting                            # PUBLIC
gh api /repos/davidgrldo/gapura/private-vulnerability-reporting --jq .enabled
```

The second command must print `true`. In the web UI the same switch is under **Settings → Advanced
Security → Private vulnerability reporting**. If the `PUT` is refused on a repository with no
commits in it yet, run it again immediately after the push below and re-check — but do not let it
slide to "later", because `SECURITY.md` is live from the moment the push lands.

Then publish the history — see item 1 under "What cannot be undone" for what that actually means:

```bash
git remote add origin git@github.com:davidgrldo/gapura.git
git push -u origin main                                        # PUBLIC, IRREVERSIBLE
```

## 3. Prove the arm64 runner label

Now, while a mistake still only costs a branch; 1.4 finding 3 is the argument for it. Push a
throwaway branch carrying a workflow that asks for the label and does nothing else:

```bash
git switch -c probe/arm64-runner
cat > .github/workflows/arm-probe.yml <<'YAML'
name: arm-probe
on: push
jobs:
  probe:
    runs-on: ubuntu-24.04-arm
    steps:
      - run: uname -m
YAML
git add .github/workflows/arm-probe.yml
git commit -m "chore: probe the arm64 runner label"
git push -u origin probe/arm64-runner                 # PUBLIC
gh run watch
```

A runner that picks the job up inside a minute and prints `aarch64` settles it. Clean up:

```bash
git push origin --delete probe/arm64-runner           # PUBLIC
git switch main && git branch -D probe/arm64-runner
```

Deleting the branch does not remove the commit from GitHub — it stays reachable by its SHA. For a
probe that is fine; do not use this trick for anything you would not want read.

Do not tag until it has come back green, or until you have switched the workflow to the QEMU
fallback. If instead it queues, change `release.yml` before tagging, and merge that change to
`main`:

- collapse the `build` matrix into a single `runs-on: ubuntu-latest` job;
- add `- uses: docker/setup-qemu-action@v3` ahead of `docker/setup-buildx-action`;
- give `docker/build-push-action` `platforms: linux/amd64,linux/arm64` and the tags from
  `docker/metadata-action` directly, instead of `outputs: ...push-by-digest=true`;
- delete the digest artifacts and the `image` job's join step, and point `chart`'s `needs:` at
  whatever job now publishes the tags.

The cost is a Rust release build with vendored OpenSSL running under emulation for arm64, which is
far slower than a native runner. Budget for a long job, not a failing one.

## 4. Tag, and let the workflow publish

The workflow triggers on `tags: ["v*"]`, and `docker/metadata-action` turns `v0.1.0` into the image
tags `0.1.0` and `0.1`, plus `sha-<full sha>`. The chart job strips the leading `v` and packages at
`0.1.0`.

```bash
git tag -a v0.1.0 -m "Gapura v0.1.0"
git push origin v0.1.0                                         # PUBLIC, IRREVERSIBLE
gh run watch
```

At that point three jobs run in order: `build` (both architectures, pushed by digest), `image`
(joins the digests into one manifest list and attaches the tags), `chart` (packages and pushes to
`oci://ghcr.io/davidgrldo/charts`). All three must be green before anything below means anything.

## 5. After the workflow — what to check

### 5.1 The image is one manifest list with both architectures

```bash
docker buildx imagetools inspect ghcr.io/davidgrldo/gapura:0.1.0
docker buildx imagetools inspect ghcr.io/davidgrldo/gapura:0.1.0 --raw \
  | jq -r '.manifests[] | select(.platform.os != "unknown") | .platform.os + "/" + .platform.architecture' \
  | sort
```

Exactly `linux/amd64` and `linux/arm64`. The `unknown/unknown` entries the `jq` filter drops are
attestation manifests, not platforms. This is the same assertion `hack/release-dry-run.sh` makes
against the local registry.

### 5.2 The chart pulls from OCI

```bash
helm show chart oci://ghcr.io/davidgrldo/charts/gapura --version 0.1.0
```

`version` and `appVersion` both `0.1.0`.

### 5.3 Both GHCR packages are public — the one that usually goes wrong

**A new GHCR package is private.** The image and the chart are two separate packages, `gapura` and
`charts/gapura`, and each defaults to private on first publish. Private packages pull perfectly for
you, because you are authenticated, and fail for everyone else — so the install command in the
README works on your machine and 401s for every reader. This is the most common way a first GHCR
release is broken, and it is invisible from the maintainer's own terminal.

Ask GitHub directly:

```bash
gh api /user/packages/container/gapura --jq '.visibility, .html_url'
gh api /user/packages/container/charts%2Fgapura --jq '.visibility, .html_url'
```

Both must print `public`. Two ways those calls fail while telling you nothing about the packages:

- **403, or `Resource not accessible by ...`.** `gh auth login` does not request `read:packages`, so
  this endpoint is forbidden on most maintainers' tokens. Run `gh auth refresh -s read:packages`,
  approve the scope in the browser, and ask again. A 403 is a fact about your token; it is not
  evidence that anything is private.
- **404 on the second one.** The encoded slash. List the packages instead with
  `gh api '/user/packages?package_type=container' --jq '.[].name'` and open the one you need from
  the web UI.

To fix: open the `html_url` those commands printed, then **Package settings → Danger Zone →
Change visibility → Public**. GitHub's packages REST API documents no endpoint for changing
visibility, so this is a web-UI change. Do it for both packages.

Then prove it the way a stranger would, without credentials. This check, not the one above, is the
authority: nothing in it is authenticated — the `ghcr.io/token` request is anonymous and `curl`
reads neither your `gh` token nor your docker keychain — so what it returns is a fact about the
package and can never be a fact about your scopes:

```bash
tok=$(curl -s "https://ghcr.io/token?scope=repository:davidgrldo/gapura:pull&service=ghcr.io" | jq -r .token)
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $tok" \
  -H 'Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json' \
  https://ghcr.io/v2/davidgrldo/gapura/manifests/0.1.0

tok=$(curl -s "https://ghcr.io/token?scope=repository:davidgrldo/charts/gapura:pull&service=ghcr.io" | jq -r .token)
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $tok" \
  -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
  https://ghcr.io/v2/davidgrldo/charts/gapura/manifests/0.1.0
```

`200` twice means public. `401` means the package is still private: ghcr.io issues the anonymous
token either way, but it carries no pull access to a private package. Since no credential of yours
is in play, a `401` here cannot mean "I am missing a scope" — that reading belongs to the `gh api`
calls above and nowhere else. If you would rather test with the real clients,
`helm registry logout ghcr.io` and `docker logout ghcr.io` first — that costs you the stored
credential, nothing else.

### 5.4 Private vulnerability reporting is still on

```bash
gh api /repos/davidgrldo/gapura/private-vulnerability-reporting --jq .enabled
```

Enabled in section 2; confirmed here because it is a repository setting rather than anything the
release produces, and a setting nobody re-checks is a setting that quietly reverts.

### 5.5 The quickstart, from a cluster that has never seen Gapura

With both packages public, the README quickstart is finally runnable as written. Create a throwaway
cluster and paste steps 1 to 4. Only once that works should a **separate commit** remove the
pre-publication notices, which stop being true the moment the tag exists:

- the "Step 2 does not work yet" block in `README.md` — it sits above step **1**, with the
  `kind create cluster` block in between, not immediately above the step it is about;
- the `<!-- REMOVE WHEN PUBLIC: ... -->` paragraph under the table of contents in
  `conformance/reports/v1.6/davidgrldo-gapura/README.md`, together with **both**
  `markdown-link-check-disable`/`markdown-link-check-enable` pairs wrapping the links above it —
  one on the "Source and issues" line, one inside the table;
- the `<!-- REMOVE WHEN PUBLIC: ... -->` sentence in the Reproduce section of
  `conformance/README.md`.

## 6. What this release does not do

**It does not submit the conformance report upstream.** The report in
`conformance/reports/v1.6/davidgrldo-gapura/` is not sent to `kubernetes-sigs/gateway-api` with this
release, and that is a decision rather than an oversight.

The upstream reports rules require every profile's `result` to be `success` or `partial`. Gapura's
GATEWAY-HTTP profile is `failure`: 36 of 37 core tests pass, and `HTTPRouteMultipleGateways` fails.
That test attaches two routes which both match `PathPrefix /` with no hostname, to two different
Gateways, and expects a different backend from each. Gapura serves every Gateway of its class from
one Deployment with one published address, so nothing in the request distinguishes the two.

`partial` is not a way around it: it covers tests that were **skipped**, or a run that needed
steps the suite did not expect — never a test that failed. Skipping a test we know fails would be
claiming conformance we do not have.

Submission waits for an address per Gateway, which section 5.1 of the design spec defers to SP4, and
which would take the profile to 37 of 37. The report folder already carries the `README.md` upstream
requires, so when that day comes the submission is a folder copy rather than a rewrite.

## 7. If something goes wrong after the tag

**The run failed for a reason outside the repository** — a flaky runner, a registry hiccup, a
queue that timed out. Re-running it is the whole fix:

```bash
gh run rerun --failed                                          # PUBLIC, IRREVERSIBLE
gh run watch
```

It is safe in the one sense that the source is identical, so the artifacts it produces are the ones
the tag always meant. It is not safe in the sense of undoable: a re-run is what finishes the
release. It pushes blobs, creates the `0.1.0` and `0.1` manifest list and pushes the chart, and a
published package version is permanent — item 3 under "What cannot be undone". Run it when you
believe the failure was infrastructure and the commit under the tag is the one you want published.
Blobs a half-finished run pushed by digest carry no tag and are harmless; they are addressed only by
a digest nobody published.

**The fix is a change to the repository, `release.yml` included.** A re-run will *not* pick it up: a
run is pinned to the commit the tag points at, and so is the workflow file it executes. Land the fix
on `main` and cut the next version. Do not move the tag onto the new commit — the version number is
already spent, whether or not anything was published under it.

**The content is wrong.** Release `0.1.1`. Do not re-push `0.1.0`: someone may already have pulled
it, and a version that changes underneath its consumers is worse than a version with a known bug.
See item 3 under "What cannot be undone".

**The tag itself was a mistake and nothing has been published under it.** Delete it from GitHub,
and delete it here as well — otherwise the next `git push --tags` puts it straight back:

```bash
git push origin :refs/tags/v0.1.0                              # PUBLIC
git tag -d v0.1.0
```

Treat the version number as spent regardless: you cannot know who fetched it in between. Move to the
next one.
