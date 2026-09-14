#!/usr/bin/env bash
# Dress rehearsal for .github/workflows/release.yml against a registry that only exists on this
# machine. The workflow has never run, and the only way it normally runs is by pushing a tag --
# by which point a mistake is already public and the tag already exists. This script runs the same
# sequence (build each arch separately, push by digest, join the digests into one manifest list,
# package the chart, push it to an OCI registry, install from there) against `registry:2` in
# docker, then proves the result by pulling it into kind and sending one request through a Gateway.
#
# Nothing here ever contacts ghcr.io. The only registry is the local container.
#
# Needs: docker (with buildx), kind, kubectl, helm 4.1.4, jq. Two helm floors meet here and the
# higher one is the requirement. `--plain-http` is what lets `push` and `install` talk to a registry
# with no TLS; it landed in 3.13 and there is no substitute on an older helm. But this script also
# runs ./hack/chart-render.sh, and the golden renders under charts/gapura/tests/golden/ were produced
# by helm 4.1.4 -- the version CONTRIBUTING.md and all three CI workflows pin -- so on any other
# helm the run dies on a golden diff that has nothing to do with the release. Runs under bash, not
# sh: the manifest-list join relies on word splitting and on process substitution, exactly as
# release.yml's `run:` does.
#
# Two addresses, one registry. The registry container publishes 5000 on the host as
# localhost:5001, and is also joined to the `kind` docker network, where the node reaches it by
# container name at gapura-dry-run-registry:5000. buildx, helm push and helm install run on the
# host and use the first; `image.repository` is consumed by the node's containerd and must use the
# second. A registry stores blobs by repository path, not by the hostname used to reach it, so
# both names see the same image. Swapping them fails in two different confusing ways
# (ImagePullBackOff, or helm unable to resolve the chart), so they are kept in separate variables
# below and never mixed.
#
# Plain HTTP, three consumers, three different mechanisms:
#   buildx   -- `registry.insecure=true` on the --output, plus `http = true` in the builder's
#               buildkitd.toml. The builder also needs --driver-opt network=host, or `localhost`
#               inside the buildkit container would mean the buildkit container.
#   helm     -- `--plain-http` on both `push` and `install`. No `helm registry login`: the
#               registry wants no auth, and logging in would only invent a credential to leak.
#   imagetools / docker -- nothing. 127.0.0.0/8 is insecure by default, which is the whole reason
#               the host-side name is localhost rather than the container name.
#
# This touches the kind node's containerd: kind's node image ships `config_path = ''`, so
# /etc/containerd/certs.d is not read and there is no other way to tell containerd v2 that a
# registry speaks plain HTTP (the old registry.mirrors/configs keys were removed in containerd
# 2.0). The node's config.toml is `version = 2`, so the grpc.v1.cri key below is migrated onto
# containerd 2.x's io.containerd.cri.v1.images plugin; that migration is asserted rather than
# assumed, because when it silently does not happen the only symptom is an opaque
# ImagePullBackOff. The original /etc/containerd/config.toml is backed up and restored on the way
# out.
#
# Disk is the real constraint, and on a VM-backed docker (Docker Desktop, OrbStack, colima) it is
# two constraints: the VM's own filesystem, and the host, whose disk image grows as the VM writes
# and does *not* shrink when you prune. Two from-scratch Rust release builds with vendored OpenSSL
# do not both fit in a few spare gigabytes. So: the buildx cache is dropped between the two legs,
# which costs nothing in fidelity -- in the workflow each arch gets its own fresh runner and its
# own gha cache scope, so neither leg ever sees the other's cache either -- and a watchdog samples
# both filesystems *during* each build and cancels it at the floor. Checking only between legs
# would notice the disk was full one build too late.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=${VERSION:-0.1.0-dryrun}
OWNER=${OWNER:-davidgrldo}
CLUSTER=${CLUSTER:-gapura}
# Floors, in GiB. Below either one the run stops and cleans up rather than filling a disk.
MIN_FREE_GB=${MIN_FREE_GB:-2}
MIN_VM_FREE_GB=${MIN_VM_FREE_GB:-1}

REG_NAME=gapura-dry-run-registry
HOST_REG="localhost:5001"        # from the host: buildx, imagetools, helm
NODE_REG="${REG_NAME}:5000"      # from inside the cluster: containerd on the kind node
IMAGE="${HOST_REG}/${OWNER}/gapura"
NODE_IMAGE="${NODE_REG}/${OWNER}/gapura"
CHART_REPO="oci://${HOST_REG}/${OWNER}/charts"

NODE="${CLUSTER}-control-plane"
BUILDER=gapura-dry-run-builder
RELEASE=gapura-dryrun
NS=gapura-dryrun
FIXTURE_NS=gapura-dryrun-e2e
BACKUP=/etc/containerd/config.toml.gapura-dryrun-bak

WORK=$(mktemp -d)
# The chart tarball is written into this run's own directory, never the repo root. cleanup removes
# $WORK whole, and with VERSION overridden to a real release version a tarball in the repo root
# would be named gapura-0.1.0.tgz -- the same name a `helm package` the user ran themselves leaves
# there. A rehearsal must not be able to delete a file it did not create.
TGZ="${WORK}/gapura-${VERSION}.tgz"
PF_PID=
WD_PID=
CONTAINERD_PATCHED=0

# Free space on the host filesystem, in GiB.
free_gb() { df -Pk / | awk 'NR==2 { print int($4 / 1048576) }'; }
# Free space inside the docker VM, in GiB, read through the kind node: its overlay sits on the
# same device as everything else docker writes. On a native-Linux docker this is the same
# filesystem as free_gb and the two guards simply agree.
vm_free_gb() {
  docker exec "$NODE" df -Pk / 2>/dev/null | awk 'NR==2 { print int($4 / 1048576) }' || echo 99
}

disk_report() { echo "==> free disk: host $(free_gb)G, vm $(vm_free_gb)G ($1)"; }

disk_guard() {
  local h v
  h=$(free_gb); v=$(vm_free_gb)
  disk_report "$1"
  if [ "$h" -lt "$MIN_FREE_GB" ] || [ "$v" -lt "$MIN_VM_FREE_GB" ]; then
    echo "FAIL floor reached (host ${h}G < ${MIN_FREE_GB}G or vm ${v}G < ${MIN_VM_FREE_GB}G):" >&2
    echo "     stopping before the disk fills. This machine cannot complete the dry run." >&2
    exit 1
  fi
}

# Sample both filesystems while a build runs and cancel it at the floor. `docker buildx build`
# cancels the build server-side when its client gets SIGTERM, so the partial work is released.
watchdog() {
  local pid=$1 h v
  while kill -0 "$pid" 2>/dev/null; do
    sleep 5
    h=$(free_gb); v=$(vm_free_gb)
    if [ "$h" -lt "$MIN_FREE_GB" ] || [ "$v" -lt "$MIN_VM_FREE_GB" ]; then
      echo "" >&2
      echo "==> DISK FLOOR HIT mid-build (host ${h}G, vm ${v}G): cancelling" >&2
      touch "$WORK/floor-hit"
      kill -TERM "$pid" 2>/dev/null || true
      # One signal is not a guarantee. A build that is slow to unwind, or that never handles the
      # TERM at all, keeps writing while the script sits in `wait` -- the disk filling is exactly
      # what this function exists to prevent, so do not leave it to the build's good manners.
      for _ in $(seq 6); do
        sleep 5
        kill -0 "$pid" 2>/dev/null || return 0
      done
      echo "==> build still alive 30s after SIGTERM: SIGKILL" >&2
      kill -KILL "$pid" 2>/dev/null || true
      return 0
    fi
  done
}

cleanup() {
  local rc=$?
  echo "==> cleanup"
  [ -n "$WD_PID" ] && kill "$WD_PID" 2>/dev/null || true
  [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true
  helm uninstall "$RELEASE" --namespace "$NS" --wait --timeout 2m >/dev/null 2>&1 || true
  kubectl delete ns "$FIXTURE_NS" "$NS" --ignore-not-found --timeout=90s >/dev/null 2>&1 || true
  # The node caches whatever it pulled; it is ours and the registry behind it is about to go.
  docker exec "$NODE" crictl rmi "${NODE_IMAGE}:${VERSION}" >/dev/null 2>&1 || true
  if [ "$CONTAINERD_PATCHED" = 1 ]; then
    docker exec "$NODE" sh -c "test -f $BACKUP && mv $BACKUP /etc/containerd/config.toml" >/dev/null 2>&1 || true
    docker exec "$NODE" rm -rf "/etc/containerd/certs.d/${NODE_REG}" >/dev/null 2>&1 || true
    docker exec "$NODE" systemctl restart containerd >/dev/null 2>&1 || true
    for _ in $(seq 30); do
      docker exec "$NODE" crictl info >/dev/null 2>&1 && break
      sleep 2
    done
  fi
  # `buildx rm` takes the builder's volume with it, so this drops the whole cache we created and
  # leaves the user's other builders and their caches alone. Prune first so the reclaim is visible.
  docker buildx prune --all --force --builder "$BUILDER" >/dev/null 2>&1 || true
  docker buildx rm "$BUILDER" >/dev/null 2>&1 || true
  docker rm --force --volumes "$REG_NAME" >/dev/null 2>&1 || true
  docker volume rm "${REG_NAME}-data" >/dev/null 2>&1 || true
  rm -rf "$WORK"   # the chart tarball lives in here, so it goes with it
  disk_report "after cleanup"
  return $rc
}
trap cleanup EXIT

disk_guard "before"

echo "==> the packaged chart is the chart in charts/gapura"
# The Grafana dashboard and prometheus-rule.yaml reach the rendered output only through
# `.Files.Get`, which returns an empty string with no error for a file the chart did not load, and
# what the chart loads is decided by charts/gapura/.helmignore -- a file nothing else reads.
#
# This is deliberately an assertion about the tarball, not an inference from a render. helm applies
# .helmignore to a directory load as well as to `helm package`, so today a mistake there does show
# up locally: it trips the `fail` guards in those two templates, on the values-metrics permutation
# hack/chart-render.sh renders. But that is helm's behaviour rather than this repo's, and the guards
# and the permutation that expose it are each one edit away from being gone, while none of it ever
# says the two files are inside the chart a user installs. So say that, about the artifact, in the
# rehearsal of the release that ships it.
#
# It runs first, ahead of the cluster and the builds: it costs a second and no network, and the
# watchdog above cancels the run when the disk floor is hit mid-build -- on the machines this script
# was written for, a check placed after the builds is one that often never runs at all.
CHART_VERSION=$(helm show chart charts/gapura | awk '$1 == "version:" { print $2 }')
CHECK_TGZ="$WORK/gapura-${CHART_VERSION}.tgz"
# Deliberately without the --version/--app-version the `chart` job below passes. Stamping a version
# rewrites Chart.yaml inside the tarball, and that alone makes the two renders differ in the
# helm.sh/chart label, in app.kubernetes.io/version and in the default image tag -- three carve-outs
# to maintain in the comparison below, each one a place a real difference could hide. Packaging at
# the chart's own version asks the only question this check exists to ask, whether the packaged
# content is the directory's content, and lets the answer be an empty diff with nothing explained
# away. The version flags are exercised for real further down, where the chart that gets pushed is
# packaged with them and then installed.
helm package charts/gapura --destination "$WORK" >/dev/null
tar tzf "$CHECK_TGZ" | sort | tee "$WORK/packaged"
for f in gapura/prometheus-rule.yaml gapura/dashboards/gapura-overview.json; do
  grep -qxF "$f" "$WORK/packaged" \
    || { echo "FAIL ${f} is not in the packaged chart: charts/gapura/.helmignore excludes it" >&2; exit 1; }
done
echo "    both files .Files.Get reads are packaged"

# Same chart version on both sides, so nothing is expected to differ and the comparison is the whole
# rendered output, unfiltered: any difference at all is a finding, and diff prints it. This is the
# arm that would notice helm's package path and its directory-load path drifting apart -- they agree
# today, which is exactly what is worth pinning down. values-metrics.yaml is the permutation that
# turns the PrometheusRule and the dashboard on, so it is the one that reads both files; it comes
# from the working tree, since .helmignore keeps tests/ out of the tarball on purpose.
helm template gapura "$CHECK_TGZ" --namespace gapura-system \
  --values charts/gapura/tests/values-metrics.yaml > "$WORK/from-tgz.yaml"
helm template gapura charts/gapura --namespace gapura-system \
  --values charts/gapura/tests/values-metrics.yaml > "$WORK/from-dir.yaml"
diff "$WORK/from-tgz.yaml" "$WORK/from-dir.yaml" \
  || { echo "FAIL the packaged chart renders differently from charts/gapura (above)" >&2; exit 1; }
echo "    the packaged chart renders byte for byte as charts/gapura does"
rm -f "$CHECK_TGZ" "$WORK/packaged" "$WORK/from-tgz.yaml" "$WORK/from-dir.yaml"

echo "==> cluster"
# REQUIRE_PORTS=0: this script never dials a Gateway through host port 80. It installs its own
# release next to whatever is already in the cluster, with its own namespace, its own GatewayClass
# and a ClusterIP Service, and reaches the data plane through kubectl port-forward, so it needs
# neither the host port mappings nor the NodePorts the other hack/ scripts claim.
REQUIRE_PORTS=0 ./hack/kind-up.sh

echo "==> clearing anything a previous run left in the cluster"
# Same pre-run reset the registry, its volume and the builder get below, for the two things that
# outlive a run this script did not get to finish: a SIGKILL skips cleanup entirely, and cleanup's
# own `helm uninstall --timeout 2m` can expire on a namespace that is slow to drain. What survives
# is a release name, and `helm install` refuses a name that is still in use. Left to the install
# step that refusal arrives after both builds -- the forty expensive minutes -- for a leftover that
# costs seconds to clear here. Same order as cleanup: the release first, so its objects go while
# their namespace still exists, then the namespaces. On a clean machine both are no-ops.
helm uninstall "$RELEASE" --namespace "$NS" --wait --timeout 2m >/dev/null 2>&1 || true
kubectl delete ns "$FIXTURE_NS" "$NS" --ignore-not-found --timeout=90s >/dev/null 2>&1 || true

echo "==> registry ${REG_NAME} on ${HOST_REG} (host) and ${NODE_REG} (cluster)"
docker rm --force --volumes "$REG_NAME" >/dev/null 2>&1 || true
docker volume rm "${REG_NAME}-data" >/dev/null 2>&1 || true
docker volume create "${REG_NAME}-data" >/dev/null
docker run -d --restart=no --name "$REG_NAME" \
  -p 127.0.0.1:5001:5000 -v "${REG_NAME}-data:/var/lib/registry" registry:2 >/dev/null
# Without this the node can resolve nothing: the registry would only exist on the default bridge.
docker network connect kind "$REG_NAME"
for _ in $(seq 30); do
  curl -sf -o /dev/null "http://${HOST_REG}/v2/" && break
  sleep 1
done
curl -sf -o /dev/null "http://${HOST_REG}/v2/" || { echo "registry never answered on ${HOST_REG}" >&2; exit 1; }
docker exec "$NODE" curl -sf -o /dev/null "http://${NODE_REG}/v2/" \
  || { echo "the kind node cannot reach the registry at ${NODE_REG}" >&2; exit 1; }
echo "    both addresses answer /v2/"

echo "==> teaching the kind node that ${NODE_REG} is plain HTTP"
# kind's node image leaves registry.config_path empty, so certs.d is ignored until config.toml
# says otherwise, and that needs a containerd restart. hosts.toml itself is read per pull.
if docker exec "$NODE" test -f "$BACKUP"; then
  docker exec "$NODE" cp "$BACKUP" /etc/containerd/config.toml   # leftover from a run that died
fi
docker exec "$NODE" cp /etc/containerd/config.toml "$BACKUP"
CONTAINERD_PATCHED=1
docker exec -i "$NODE" sh -c 'cat >> /etc/containerd/config.toml' <<'EOF'

# added by hack/release-dry-run.sh, removed again on the way out
[plugins."io.containerd.grpc.v1.cri".registry]
  config_path = "/etc/containerd/certs.d"
EOF
docker exec "$NODE" mkdir -p "/etc/containerd/certs.d/${NODE_REG}"
docker exec -i "$NODE" sh -c "cat > /etc/containerd/certs.d/${NODE_REG}/hosts.toml" <<EOF
[host."http://${NODE_REG}"]
  capabilities = ["pull", "resolve"]
EOF
docker exec "$NODE" systemctl restart containerd
for _ in $(seq 30); do
  docker exec "$NODE" crictl info >/dev/null 2>&1 && break
  sleep 2
done
docker exec "$NODE" crictl info >/dev/null || { echo "containerd did not come back" >&2; exit 1; }
# Assert the migration landed. Without this an unmigrated key reads as a plain ImagePullBackOff
# half a build later, with nothing pointing back at this block.
#
# The dump holds two keys spelled `config_path`, and on an unpatched node both read '': the one
# this block means, under [plugins.'io.containerd.cri.v1.images'.registry], and an unrelated one
# under [plugins.'io.containerd.transfer.v1.local']. A bare grep for the value is satisfied by
# either, so it names its table and looks for the value only inside it -- four lines of context,
# which is the whole table today plus slack, and still nowhere near the transfer plugin two hundred
# lines further down.
#
# The same dump says `use_local_image_pull = false`, so a CRI pull is handed to the transfer service
# rather than resolved in process -- which raises the question of whether the transfer plugin's
# config_path is the one that decides whether certs.d is read. It is not, and the key written above
# is enough. The CRI image service passes its own registry.config_path into the transfer request as
# the request's host directory: in the node's containerd (v2.3.4) the only call site of
# core/transfer/registry.WithHostDir is CRIImageService.pullImageWithTransferService, and the
# transfer API's OCIRegistry message carries a host_dir field to put it in. The transfer plugin's
# own config_path is the fallback for transfer clients that send no host directory, ctr among them;
# kubelet is not one of them. So: one key, asserted exactly.
docker exec "$NODE" containerd config dump 2>/dev/null \
  | grep -F -A4 "[plugins.'io.containerd.cri.v1.images'.registry]" \
  | grep -qF "config_path = '/etc/containerd/certs.d'" \
  || { echo "the grpc.v1.cri registry key did not migrate onto io.containerd.cri.v1.images;" >&2
       echo "certs.d is still ignored and the pull below would ImagePullBackOff" >&2; exit 1; }
echo "    io.containerd.cri.v1.images registry config_path is /etc/containerd/certs.d"
kubectl wait --for=condition=Ready "node/$NODE" --timeout=120s

echo "==> buildx builder ${BUILDER}"
# network=host so the buildkit container reaches the registry at the same localhost:5001 the host
# does; the default bridge would leave localhost pointing at buildkit itself. The config file is
# what makes buildkit talk plain HTTP to it.
docker buildx rm "$BUILDER" >/dev/null 2>&1 || true
cat > "$WORK/buildkitd.toml" <<EOF
[registry."${HOST_REG}"]
  http = true
EOF
docker buildx create --name "$BUILDER" --driver docker-container \
  --driver-opt network=host --config "$WORK/buildkitd.toml" --bootstrap >/dev/null

mkdir -p "$WORK/digests"
for arch in arm64 amd64; do
  echo "==> build linux/${arch}, push by digest (the workflow's \`build\` matrix leg)"
  disk_report "starting linux/${arch}"
  docker buildx build --builder "$BUILDER" --platform "linux/${arch}" \
    --output "type=image,name=${IMAGE},push-by-digest=true,name-canonical=true,push=true,registry.insecure=true" \
    --provenance=mode=max --sbom=true \
    --metadata-file "$WORK/metadata-${arch}.json" --progress plain . &
  build_pid=$!
  watchdog "$build_pid" &
  WD_PID=$!
  build_rc=0
  wait "$build_pid" || build_rc=$?
  kill "$WD_PID" 2>/dev/null || true
  WD_PID=
  if [ -f "$WORK/floor-hit" ]; then
    echo "" >&2
    echo "FAIL out of disk building linux/${arch}. The release path could not be rehearsed here." >&2
    echo "     Everything this script created is being removed; nothing was pushed off this machine." >&2
    exit 1
  fi
  [ "$build_rc" = 0 ] || { echo "FAIL linux/${arch} build exited ${build_rc}" >&2; exit "$build_rc"; }
  jq -r '."containerimage.digest"' "$WORK/metadata-${arch}.json" > "$WORK/digests/${arch}"
  echo "==> ${arch} digest: $(cat "$WORK/digests/${arch}")"
  # One leg's cache is dead weight to the other, and together they do not fit. On a runner each
  # leg starts empty anyway. Print the reclaim so "the cache was dropped" is a fact, not a hope.
  docker buildx du --builder "$BUILDER" 2>/dev/null | tail -1
  docker buildx prune --all --force --builder "$BUILDER" >/dev/null
  docker buildx du --builder "$BUILDER" 2>/dev/null | tail -1
  disk_guard "after linux/${arch}"
done

echo "==> join the per-arch digests into one manifest list (the workflow's \`image\` job)"
test -n "$(ls -A "$WORK/digests" 2>/dev/null)"
refs=$(for f in "$WORK"/digests/*; do printf '%s@%s ' "$IMAGE" "$(cat "$f")"; done)
# shellcheck disable=SC2086
docker buildx imagetools create --tag "${IMAGE}:${VERSION}" $refs
docker buildx imagetools inspect "${IMAGE}:${VERSION}"

echo "==> the manifest list holds both architectures"
# buildx attaches an attestation manifest per platform, which reports unknown/unknown; the real
# platforms are what is being asserted here.
docker buildx imagetools inspect "${IMAGE}:${VERSION}" --raw \
  | jq -r '.manifests[] | select(.platform.os != "unknown") | .platform.os + "/" + .platform.architecture' \
  | sort > "$WORK/arches"
cat "$WORK/arches"
diff <(printf 'linux/amd64\nlinux/arm64\n') "$WORK/arches" \
  || { echo "manifest list is not exactly linux/amd64 + linux/arm64" >&2; exit 1; }

echo "==> the manifest list still carries its attestations"
# release.yml builds with provenance=mode=max and an SBOM per platform; the join above must carry
# them into the list instead of dropping everything that is not a runnable platform. At least one
# unknown/unknown entry per architecture.
docker buildx imagetools inspect "${IMAGE}:${VERSION}" --raw \
  | jq -e '[.manifests[] | select(.platform.os == "unknown")] | length >= 2' >/dev/null \
  || { echo "attestations lost from the manifest list: provenance/SBOM did not survive the join" >&2; exit 1; }

echo "==> package and push the chart (the workflow's \`chart\` job)"
./hack/chart-render.sh
helm package charts/gapura --version "$VERSION" --app-version "$VERSION" --destination "$WORK"
# helm push appends the chart name, so the remote is the parent path: this lands the chart at
# ${HOST_REG}/${OWNER}/charts/gapura, exactly as release.yml's oci://ghcr.io/<owner>/charts does.
# --plain-http because the registry has no TLS; no `helm registry login`, it wants no auth.
helm push "$TGZ" "$CHART_REPO" --plain-http

echo "==> what is in the registry now"
curl -sf "http://${HOST_REG}/v2/_catalog" | jq .
# This is the assertion that `helm push` appended the chart name to the parent path.
curl -sf "http://${HOST_REG}/v2/${OWNER}/charts/gapura/tags/list" | jq .

echo "==> install the chart straight from OCI"
# The chart comes from the host-reachable address; the image reference inside it has to be the
# node-reachable one, because containerd on the node is what resolves it.
helm install "$RELEASE" "${CHART_REPO}/gapura" --version "$VERSION" --plain-http \
  --namespace "$NS" --create-namespace \
  --set image.repository="$NODE_IMAGE" \
  --set image.tag="$VERSION" \
  --set image.pullPolicy=Always \
  --set replicaCount=1 \
  --set threads=2 \
  --set service.type=ClusterIP \
  --set publishService=false \
  --set 'publishAddresses={127.0.0.1}' \
  --set podDisruptionBudget.enabled=false \
  --set gatewayClass.name="$RELEASE" \
  --set controllerName=gapura.dev/dryrun \
  --wait --timeout 5m

echo "==> the pod is running the image the registry served"
kubectl -n "$NS" get pods -o wide
kubectl -n "$NS" get pod -l app.kubernetes.io/instance="$RELEASE" \
  -o jsonpath='{.items[0].status.containerStatuses[0].image}{"\n"}{.items[0].status.containerStatuses[0].imageID}{"\n"}'

echo "==> fixture behind the gateway"
kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata: { name: ${FIXTURE_NS} }
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: main, namespace: ${FIXTURE_NS} }
spec:
  gatewayClassName: ${RELEASE}
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes: { namespaces: { from: Same } }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: echo, namespace: ${FIXTURE_NS} }
spec:
  parentRefs: [{ name: main }]
  hostnames: [echo.dryrun]
  rules:
  - backendRefs: [{ name: echo, port: 80 }]
---
apiVersion: v1
kind: Service
metadata: { name: echo, namespace: ${FIXTURE_NS} }
spec:
  selector: { app: echo }
  ports: [{ name: http, port: 80, targetPort: 8080 }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: echo, namespace: ${FIXTURE_NS} }
spec:
  replicas: 1
  selector: { matchLabels: { app: echo } }
  template:
    metadata: { labels: { app: echo } }
    spec:
      containers:
      - name: echo
        image: registry.k8s.io/e2e-test-images/agnhost:2.53
        args: [netexec, --http-port=8080]
        ports: [{ containerPort: 8080, name: http }]
EOF
kubectl -n "$FIXTURE_NS" rollout status deploy/echo --timeout=120s

echo "==> waiting for Programmed=True"
for _ in $(seq 60); do
  [ "$(kubectl -n "$FIXTURE_NS" get gateway main -o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}')" = "True" ] && break
  sleep 2
done
kubectl -n "$FIXTURE_NS" get gateway main -o wide
kubectl -n "$FIXTURE_NS" get httproute echo \
  -o jsonpath='{.status.parents[0].conditions[*].type}={.status.parents[0].conditions[*].status}{"\n"}'

echo "==> one request through the gateway"
# No host port and no NodePort here on purpose (the cluster's are already spoken for), so the
# data-plane listener is reached through a forward. The hop from gapura to the backend is the
# part being tested, and that happens inside the cluster either way.
kubectl -n "$NS" port-forward "svc/${RELEASE}" 18080:80 >"$WORK/pf.log" 2>&1 &
PF_PID=$!
answered=0
for attempt in $(seq 20); do
  if body=$(curl -sS --fail-with-body --max-time 5 -H 'Host: echo.dryrun' http://127.0.0.1:18080/ 2>&1); then
    printf '%s\n' "$body" | head -5
    answered=1
    break
  fi
  [ "$attempt" = 20 ] && echo "no answer through the gateway after 20 tries: $body" >&2
  sleep 2
done
if [ "$answered" != 1 ]; then
  cat "$WORK/pf.log" >&2
  kubectl -n "$NS" logs -l app.kubernetes.io/instance="$RELEASE" --tail=40 >&2 || true
  exit 1
fi
curl -sS --fail-with-body --max-time 5 -H 'Host: echo.dryrun' \
  -o /dev/null -w 'gateway answered %{http_code} in %{time_total}s\n' "http://127.0.0.1:18080/echo?msg=release-dry-run"
curl -sS --fail-with-body --max-time 5 -H 'Host: echo.dryrun' "http://127.0.0.1:18080/echo?msg=release-dry-run"

disk_guard "after"
echo "==> the release path works against ${HOST_REG}; nothing was pushed anywhere else"
