#!/usr/bin/env bash
# Compares the event and device type enums of internal/vaultwarden/enums.go
# with the Vaultwarden sources of a release, so that a new upstream type (or an
# extraction mistake) is caught. Usage: check-enums.sh [vaultwarden version]
set -euo pipefail

version="${1:-1.37.5}"
raw="https://raw.githubusercontent.com/dani-garcia/vaultwarden/${version}/src/db/models"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Enum variants are "Name = code," (names may contain digits: UserFailedLogIn2fa)
upstream() {
  curl -sSfL "$raw/$1" | sed -n "/pub enum $2/,/^}/p" \
    | grep -E '^\s+[A-Za-z0-9_]+ = -?[0-9]+' | sed -E 's/^\s+([A-Za-z0-9_]+) = (-?[0-9]+).*/\2 \1/' | sort
}
ours() {
  awk -v map="$1" '$0 ~ "^var "map" = map" {on=1; next} on && /^}/ {on=0} on' internal/vaultwarden/enums.go \
    | sed -E 's/^\s*(-?[0-9]+):\s+"([^"]+)",/\1 \2/' | sort
}

status=0
for spec in "event.rs EventType EventTypes" "device.rs DeviceType DeviceTypes"; do
  read -r file enum var <<<"$spec"
  upstream "$file" "$enum" >"$work/up"
  ours "$var" >"$work/ours"
  if ! diff -u "$work/up" "$work/ours" >"$work/diff"; then
    echo "$var differs from Vaultwarden $version $enum (- upstream, + ours):" >&2
    cat "$work/diff" >&2
    status=1
  else
    echo "$var: $(wc -l <"$work/up") values, in sync with Vaultwarden $version"
  fi
done
exit "$status"
