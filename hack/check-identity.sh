#!/usr/bin/env bash
# Fail if a placeholder owner still appears in anything that ships.
#
# Gapura is published at github.com/davidgrldo/gapura. The needle below is the owner name used as
# a placeholder before that was decided; left in a chart, a script or a conformance report it
# points users at a repository that does not exist.
#
# Two details are the whole point of the shape below. The needle is written with the hyphen in a
# character class so this file never matches itself, which means the script scans its own text and
# an edit that reintroduces the placeholder here is caught like any other. And the exit status is
# branched on all three cases: grep returns 2 on a tooling error even when it selected lines, so a
# script that only asks "did it exit 0" passes silently on an unreadable path and lets the
# placeholder ship. An unknown status is a failure here, never a pass.
set -euo pipefail
cd "$(dirname "$0")/.."

NEEDLE='gapura[-]dev'

hits=$(git grep -n "$NEEDLE") && rc=0 || rc=$?
case "$rc" in
  0)
    echo "the placeholder owner is still referenced:" >&2
    echo "$hits" >&2
    exit 1
    ;;
  1)
    echo "ok identity"
    ;;
  *)
    echo "git grep exited $rc: could not prove the placeholder is gone, so this is a failure" >&2
    exit 1
    ;;
esac
