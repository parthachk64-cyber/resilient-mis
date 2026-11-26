#!/usr/bin/env sh
# Fresh disposable directory, nothing outside it is touched.
set -eu
d="$(mktemp -d)/demo"
resilient-mis walkthrough --dir "$d" --fast
echo "trace written to $d/recovery_trace.md"
