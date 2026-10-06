# Releasing Gapura

This is the procedure for cutting a release candidate and a release. It is written for one reader:
the maintainer, at the moment of releasing, who would rather not make a mistake that cannot be
taken back.

**Read the marks.** Every command below carries one:

| Mark | Meaning |
|---|---|
| *(none)* | Changes nothing outside this machine. A read-only query to GitHub counts as nothing. |
| `# PUBLIC` | Changes something outside this machine. Other people can see the result. |
| `# PUBLIC, IRREVERSIBLE` | Changes something outside this machine, and you cannot take it back. |

The examples use version `0.2.0`, its candidates `0.2.0-rc.N`, owner `davidgrldo` and repository
`gapura`. Substitute the version. The owner and the repository name are load-bearing; section 2
says why.

## The two paths

| | Release candidate | Release |
|---|---|---|
| Trigger | `workflow_dispatch` with a `tag` input | pushing a `v*` tag |
| Built from | the commit the dispatched branch pointed at when the run started | the tagged commit |
| Version | must be a prerelease, `0.2.0-rc.N`; the `guard` job refuses anything else | `0.2.0` |
| Image tags | `0.2.0-rc.N`, `sha-<commit>` | `0.2.0`, `0.2`, `sha-<commit>` |
| Chart | `0.2.0-rc.N` | `0.2.0` |
| Git tag | none | the one you pushed |
| GitHub release | none; the `notes` job is skipped | created from the CHANGELOG section, with the conformance report attached |
| Quickstart | runs after the release run succeeds, against `0.2.0-rc.N` | runs after the release run succeeds, against `0.2.0` |

Both paths publish two images, `ghcr.io/davidgrldo/gapura` (the data plane) and
`ghcr.io/davidgrldo/gapura-control` (the control plane and console), each for linux/amd64 and
linux/arm64, plus the chart at `oci://ghcr.io/davidgrldo/charts/gapura`.

A release normally goes out as one or more candidates, then a tag on the commit the last good
candidate was built from.

## What cannot be undone

1. **A published version is public content at a permanent address.** That includes every
   candidate. Once `ghcr.io/davidgrldo/gapura:0.2.0-rc.3` exists, someone may have pulled it.
   ghcr.io tags are mutable, so publishing the same version again does not fail: it silently
   replaces what that version means for everyone who pulls it next. Never publish a version twice.
   If a candidate is wrong, the fix is `rc.4`; if a release is wrong, the fix is `0.2.1`.
2. **A pushed tag is a name other people now have.** `git push origin :refs/tags/v0.2.0` removes it
   from GitHub, but not from anyone who already fetched it, and not from the packages the workflow
   published under that version in the meantime.

Checks are free. Run all of them.

## 1. Preflight — nothing leaves this machine

### 1.1 The verification gates

These are the checks CI runs. All of them must be green on the commit you are about to publish:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
RUSTUP_TOOLCHAIN=1.89 cargo check --workspace --all-targets --locked
(cd web && npm ci && npm run build && npm run check)
./hack/check-identity.sh
./hack/chart-render.sh
cargo deny check all
```

The fifth line is the MSRV gate, invoked the way `ci.yml`'s `msrv` job invokes it. It needs the
toolchain installed once (`rustup toolchain install 1.89`) and the environment variable, because
`rust-toolchain.toml` pins `stable`. Nothing in `release.yml` runs it, so a release can ship an MSRV
regression unless you run it here. The sixth line is the console's own guard, the `console` job.

Both paths publish from `main`, so the work has to be merged first. Confirm you are standing on
the commit you verified:

```bash
git switch main
git pull --ff-only
git log --oneline -1
git status --porcelain          # must print nothing
```

### 1.2 The release dry run

`hack/release-dry-run.sh` runs the same sequence `release.yml` does against a `registry:2`
container on this machine: build each architecture separately, push by digest, join the digests
into one manifest list, package the chart, push it, install it into kind and send one request
through a Gateway. It never contacts ghcr.io.

```bash
./hack/release-dry-run.sh
```

It needs docker with buildx, kind, kubectl, helm 4.1.4 and jq. Helm has to be 4.1.4: the script
runs `./hack/chart-render.sh`, whose golden renders were produced by that version, and any other
helm dies on a golden diff that has nothing to do with the release. It also needs disk for two
from-scratch Rust release builds with vendored OpenSSL. It watches free space and stops at a floor
rather than filling a disk, so `FAIL out of disk` is a fact about this machine. Clear space and run
it again.

The dry run is the only rehearsal that publishes nothing. A candidate is the rehearsal on the real
registry, and it is public.

### 1.3 For a release only: the version is written down consistently

A candidate needs none of this: `release.yml` packages the chart with the dispatched version, and
the `notes` job, which reads the CHANGELOG, does not run on a dispatch.

```bash
grep -n '^## ' CHANGELOG.md | head -3
helm show chart charts/gapura | grep -E '^(version|appVersion):'
helm show values charts/gapura | awk '$1 == "repository:" { print $2 }'
```

- The CHANGELOG needs a `## 0.2.0 — <date>` section. Move the `## Unreleased` entries into it. The
  `notes` job fails the run when the section is missing or empty, after the images and the chart
  are already published, so check it now.
- `version` and `appVersion` in `Chart.yaml` both read `0.2.0`. The workflow overrides both when it
  packages, but the repository should not disagree with what it published.
- The chart's default image repository reads `ghcr.io/davidgrldo/gapura`; section 2 says why.

### 1.4 For a release only: the conformance report

The `notes` job attaches `conformance/reports/*/*/*v0.2.0-*.yaml` to the GitHub release when one is
committed, and skips the asset when none is. Produce it from the commit you will tag, and commit it
before tagging:

```bash
VERSION=v0.2.0 ./hack/conformance.sh
git add conformance/reports
git commit -m "conformance: report for v0.2.0"
```

The report may not be hand-edited; it is whatever the run records. If the counts change, update
`conformance/README.md` and the report folder's `README.md` in the same commit.

## 2. Standing facts `release.yml` depends on

These held for every release so far. Each one is invisible until a version is already being
published, so re-check them when the repository, the account or the workflow changes.

- **ghcr.io rejects any uppercase letter in the path.** The workflow pushes to
  `ghcr.io/${{ github.repository }}` and `oci://ghcr.io/${{ github.repository_owner }}/charts`, and
  lowercases neither. `gh api /user --jq .login` must print all lowercase.
- **The repository must be named `gapura`.** The chart's default image repository is
  `ghcr.io/davidgrldo/gapura`, written independently of the workflow. A repository under another
  name publishes images the chart does not point at, and the symptom is pods in `ImagePullBackOff`,
  not a failed run. No job catches it.
- **The arm64 legs need `ubuntu-24.04-arm`.** GitHub allocates it to public repositories. An
  unallocated label does not fail fast: the leg queues until it times out, the amd64 leg pushes
  untagged blobs, and the `image` and `chart` jobs never run. If that ever happens, build both
  platforms on one `ubuntu-latest` job with `docker/setup-qemu-action` and expect a much slower
  arm64 build.
- **A new GHCR package is private.** The three existing packages are public. A package the
  workflow publishes for the first time, such as a new image, is private until you change it in
  the web UI; section 5.3 shows how to check.

## 3. A release candidate

```bash
gh workflow run release.yml --ref main -f tag=v0.2.0-rc.1      # PUBLIC, IRREVERSIBLE
gh run list --workflow release.yml --limit 1 --json databaseId,displayTitle,headSha
gh run watch
```

The run is named `release v0.2.0-rc.1`. Write down its `headSha`: there is no tag, so that SHA and
the image's `sha-<commit>` tag are the only record of what the candidate was built from.

The `guard` job refuses a version that is not a prerelease. A dispatch builds whatever the
dispatched branch holds, and without the guard a dispatch of `v0.2.0` would publish the release
from `main`; the later tag push would then replace it, because ghcr.io tags are mutable.

**Do not push a tag for a candidate.** A `v0.2.0-rc.1` tag starts the tag path, which rebuilds the
same version and replaces the published images with new digests. It breaks item 1 under "What
cannot be undone".

When the run succeeds, the `quickstart` workflow starts on its own. It reads the version from the
run's name, installs that candidate on a fresh kind cluster with no credentials, and checks the
console image is published under the run's `sha-<commit>` tag. A candidate is good when both runs are green:

```bash
gh run list --workflow quickstart.yml --limit 1
```

A bad candidate is fixed on `main` and followed by `rc.2`. Its version number is spent.

## 4. The release

Tag the commit the last good candidate was built from, not whatever `main` is now:

```bash
git tag -a v0.2.0 <headSha of the last good candidate> -m "Gapura v0.2.0"
git log --oneline -1 v0.2.0
git push origin v0.2.0                                         # PUBLIC, IRREVERSIBLE
gh run watch
```

If `main` moved since that candidate, either the new commits are only the CHANGELOG section and
the conformance report from section 1, or they need a candidate of their own first. A commit with
code changes that no candidate has run does not get tagged.

The run goes `guard`, `build` (four legs: two images by two architectures, pushed by digest),
`image` (joins each image's digests into one manifest list and attaches the tags), `chart`
(packages and pushes), then `notes` (creates the GitHub release from the CHANGELOG section and
attaches the conformance report). The `quickstart` workflow follows on success.

## 5. After the workflow — what to check

### 5.1 Each image is one manifest list with both architectures

```bash
for image in gapura gapura-control; do
  docker buildx imagetools inspect "ghcr.io/davidgrldo/$image:0.2.0" --raw \
    | jq -r '.manifests[] | select(.platform.os != "unknown") | .platform.os + "/" + .platform.architecture' \
    | sort
done
```

Exactly `linux/amd64` and `linux/arm64` for each image. The `unknown/unknown` entries the filter
drops are attestation manifests: the release builds with `provenance: mode=max` and an SBOM, so
expect at least one per architecture.

### 5.2 The chart pulls from OCI

```bash
helm show chart oci://ghcr.io/davidgrldo/charts/gapura --version 0.2.0
```

`version` and `appVersion` both `0.2.0`.

### 5.3 The packages are public

The `quickstart` workflow is the standing detector: it pulls anonymously after every release run
and weekly, and goes red the moment a package is private. Run this by hand when it is red, or after
the workflow publishes a package for the first time. Nothing in it is authenticated: the
`ghcr.io/token` request is anonymous and `curl` reads no stored credential of yours, so the answer
is a fact about the package, never about your scopes.

```bash
for repo in davidgrldo/gapura davidgrldo/gapura-control; do
  tok=$(curl -s "https://ghcr.io/token?scope=repository:$repo:pull&service=ghcr.io" | jq -r .token)
  curl -s -o /dev/null -w "$repo %{http_code}\n" -H "Authorization: Bearer $tok" \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    "https://ghcr.io/v2/$repo/manifests/0.2.0"
done
tok=$(curl -s "https://ghcr.io/token?scope=repository:davidgrldo/charts/gapura:pull&service=ghcr.io" | jq -r .token)
curl -s -o /dev/null -w 'chart %{http_code}\n' -H "Authorization: Bearer $tok" \
  -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
  https://ghcr.io/v2/davidgrldo/charts/gapura/manifests/0.2.0
```

`200` three times means public. `401` means that package is private. To fix it, open the package
on GitHub, then **Package settings → Danger Zone → Change visibility → Public**. GitHub documents no
REST endpoint for this, so it is a web-UI change.

`gh api /user/packages/container/<name>` answers the same question with your token, but `gh auth
login` does not request `read:packages`. A 403 there is a fact about your token; fix it with
`gh auth refresh -s read:packages`.

### 5.4 The quickstart is green

```bash
gh run list --workflow quickstart.yml --limit 1
```

It must have run against `0.2.0`, after the release run. If it did not start, run it by hand with
`gh workflow run quickstart.yml -f version=0.2.0` and watch it.

### 5.5 Private vulnerability reporting is still on

```bash
gh api /repos/davidgrldo/gapura/private-vulnerability-reporting --jq .enabled
```

`SECURITY.md` names the advisory form as the only reporting channel, so this must print `true`. It
is a repository setting nobody re-checks otherwise.

## 6. If something goes wrong

**The run failed for a reason outside the repository**, such as a flaky runner, a registry hiccup
or a queue that timed out. Re-running it is the whole fix:

```bash
gh run rerun --failed                                          # PUBLIC, IRREVERSIBLE
gh run watch
```

The source is identical, so the artifacts are the ones the version always meant. A re-run is what
finishes publishing, so run it only when the failure was infrastructure and the commit is the one
you want published. Blobs a half-finished run pushed by digest carry no tag and are harmless.

**The fix is a change to the repository, `release.yml` included.** A re-run will not pick it up: a
run is pinned to its commit, and so is the workflow file it executes. Land the fix on `main` and
publish the next candidate or the next version. Do not move a tag onto the new commit; the version
is spent whether or not anything was published under it.

**Only the `notes` job failed**, usually because the CHANGELOG has no section for the version. The
images and the chart are already published. Do not re-run the whole workflow, which rebuilds and
replaces them. Create the release by hand from the tagged commit:

```bash
gh release create v0.2.0 --verify-tag --title "gapura v0.2.0" --notes-file <notes>   # PUBLIC
```

**The content is wrong.** Publish `0.2.1`, or the next candidate. Never re-publish a version.

**The tag was a mistake and nothing was published under it.** Delete it from GitHub and here, or
the next `git push --tags` puts it back:

```bash
git push origin :refs/tags/v0.2.0                              # PUBLIC
git tag -d v0.2.0
```

Treat the version as spent anyway: you cannot know who fetched it in between.

## 7. Listings and the upstream conformance report

None of this blocks a release.

- **The conformance report upstream.** The report folder `conformance/reports/v1.6/davidgrldo-gapura/`
  already carries the `README.md` that `kubernetes-sigs/gateway-api` requires, and the report's
  result is `success`, so submitting it is a folder copy into that repository.
- **The Gateway API implementations page.** A PR there lists Gapura with exactly what the
  committed report says. Claim nothing the report does not.
- **Artifact Hub.** The chart already carries `artifacthub.io/*` annotations. Registering the OCI
  chart repository also needs an `artifacthub-repo.yml` pushed as an OCI artifact; Artifact Hub
  validates its shape, so read its docs first.
- **The README badge.** Once listed, link the implementations page rather than a self-asserted
  badge. The report is the artifact; the page is the witness.
