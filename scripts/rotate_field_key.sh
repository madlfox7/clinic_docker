#!/usr/bin/env sh
# Rotate the medical field encryption key without losing older rows.
# The current key moves to secrets/field_encryption_previous_keys (still used
# for reading), and a new key with a new key_id becomes current for writes.
# Key values are never printed.
#
#   ./scripts/rotate_field_key.sh [new_key_id]   # default: v<N+1>
set -eu

umask 077
cd "$(dirname "$0")/.."
key=secrets/field_encryption_key
previous=secrets/field_encryption_previous_keys

if [ ! -s "$key" ]; then
  echo "missing $key; run scripts/init_secrets.sh first" >&2
  exit 1
fi
[ -e "$previous" ] || : > "$previous"

current_id=$(sed -n '1s/:.*//p' "$key")
new_id=${1:-}
if [ -z "$new_id" ]; then
  case "$current_id" in
    v*[!0-9]* | v) echo "cannot derive the next key id from '$current_id'; pass one" >&2; exit 1 ;;
    v*) new_id="v$(( ${current_id#v} + 1 ))" ;;
    *) echo "cannot derive the next key id from '$current_id'; pass one" >&2; exit 1 ;;
  esac
fi
if ! printf '%s' "$new_id" | grep -Eq '^[A-Za-z0-9_-]{1,32}$'; then
  echo "invalid key id '$new_id' (letters, digits, '_' or '-', up to 32)" >&2
  exit 1
fi
if [ "$new_id" = "$current_id" ] || grep -q "^$new_id:" "$previous"; then
  echo "key id '$new_id' is already in use" >&2
  exit 1
fi

# Keep the old key for reading first, then replace the current key in place
# (same file, so its permissions and ACL stay).
{ printf '\n'; cat "$key"; printf '\n'; } >> "$previous"
printf '%s:%s' "$new_id" "$(openssl rand -hex 32)" > "$key"
./scripts/init_secrets.sh >/dev/null

echo "rotated field encryption key: $current_id -> $new_id (old key kept for reading)"
echo "next: docker compose up -d --force-recreate api"
echo "optional, re-encrypt older rows with $new_id:"
echo "      docker compose exec api python -m migrate_medical_fields --reencrypt"
