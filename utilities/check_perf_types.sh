#!/bin/bash

set -e

cd "$(dirname "$0")"

FILES=( perf*.h )

cmd="$(printf '%q ' git grep -h '^struct .* {' "${FILES[@]}") | $(printf '%q ' sed  "s/^struct \(.*\) {/\1/")"

[ "$(eval "$cmd" | wc -l)" -eq "$(eval "$cmd" | sort | uniq | wc -l)" ]

BIN="$1"

if [ -z "$BIN" ]; then
  echo "no binary specified, skip check" >&2
  exit 0
fi

export HOME=/invalid_path

gdb_type(){
  gdb -quiet -ex 'set pagination  off' "$1"
}

while IFS= read -r ; do
  echo -ne "ptype struct $REPLY\np sizeof(struct $REPLY)\n"
done < <(eval "$cmd") | gdb_type "$BIN"
