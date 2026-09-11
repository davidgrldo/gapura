#!/usr/bin/env bash
# Fail if a placeholder owner still appears in anything that ships.
#
# Gapura is published at github.com/davidgrldo/gapura. `gapura-dev` was the placeholder used
# before the owner was decided; left in a chart, a script or a conformance report it points
# users at a repository that does not exist. Plans under docs/superpowers/plans/ are a record
# of what was true when they were written, so they keep their old strings. This script has to
# name the string it bans, so it excludes itself as well.
set -euo pipefail
cd "$(dirname "$0")/.."
if hits=$(grep -rn 'gapura-dev' \
      --exclude-dir=target --exclude-dir=.git --exclude-dir=plans --exclude-dir=_check \
      --exclude=check-identity.sh \
      . 2>/dev/null); then
  echo "placeholder owner 'gapura-dev' is still referenced:" >&2
  echo "$hits" >&2
  exit 1
fi
echo "ok identity"
