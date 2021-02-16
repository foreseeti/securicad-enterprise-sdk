#!/bin/sh

set -eu

cd "$(dirname "$0")/../../.."

echo_changed_json() {
  set +e
  git diff --cached --name-only --diff-filter=ACMR | grep "\.json$"
  set -e
}

format_json() {
  echo "Formatting $(echo "$changed_json" | wc -l) json files"
  echo "$changed_json" | while IFS= read -r file; do
    # shellcheck disable=SC2005
    echo "$(jq . "$file")" >"$file"
  done
  echo "$changed_json" | tr "\n" "\0" | xargs -0 git add -f
}

main() {
  changed_json="$(echo_changed_json)"
  if [ -z "$changed_json" ]; then
    exit
  fi
  format_json
}

main
