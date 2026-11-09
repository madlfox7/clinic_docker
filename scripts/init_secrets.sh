#!/usr/bin/env sh
# Create the Docker secret files in secrets/. Existing files are never overwritten.
set -eu

umask 077
cd "$(dirname "$0")/.."
mkdir -p secrets

generate() {
  file="secrets/$1"
  if [ -e "$file" ]; then
    echo "keep    $file"
    return
  fi
  printf '%s' "$(openssl rand -hex 32)" > "$file"
  echo "created $file"
}

generate postgres_password
generate clinic_api_password
generate session_secret
if [ -e secrets/demo_password ]; then
  echo "keep    secrets/demo_password"
else
  generate demo_password
  echo "        demo account password is in secrets/demo_password"
fi

# Medical field encryption key: "<key_id>:<64 hex chars>". Never overwritten,
# or rows written with it could no longer be decrypted. Rotate with
# scripts/rotate_field_key.sh, which keeps the old key for reading.
if [ -e secrets/field_encryption_key ]; then
  echo "keep    secrets/field_encryption_key"
else
  printf 'v1:%s' "$(openssl rand -hex 32)" > secrets/field_encryption_key
  echo "created secrets/field_encryption_key"
fi
if [ -e secrets/field_encryption_previous_keys ]; then
  echo "keep    secrets/field_encryption_previous_keys"
else
  : > secrets/field_encryption_previous_keys
  echo "created secrets/field_encryption_previous_keys (empty until the first key rotation)"
fi

if [ -e secrets/smtp_password ]; then
  echo "keep    secrets/smtp_password"
else
  : > secrets/smtp_password
  echo "created secrets/smtp_password (empty, fill in for a real SMTP server)"
fi

# Compose bind-mounts each file with host ownership and mode, so non-root
# container users (api/seed run as uid 10001, postgres as uid 999) need read
# access to the file itself. The directory stays private to the host user.
chmod 700 secrets
chmod 644 secrets/postgres_password secrets/clinic_api_password \
  secrets/session_secret secrets/smtp_password secrets/demo_password

# The field keys must not be world-readable. Keep them 600 for the host user
# and grant read access only to the api user (uid 10001) through an ACL.
# Without setfacl, root can hand the file to uid 10001 instead.
API_UID=10001
for key_file in secrets/field_encryption_key secrets/field_encryption_previous_keys; do
  if [ ! -O "$key_file" ]; then
    echo "note    $key_file is not owned by you; permissions left as they are"
    continue
  fi
  chmod 600 "$key_file"
  if command -v setfacl >/dev/null 2>&1 && setfacl -m "u:$API_UID:r" "$key_file" 2>/dev/null; then
    continue
  fi
  if [ "$(id -u)" = 0 ]; then
    chown "$API_UID:$API_UID" "$key_file"
    continue
  fi
  echo "warning $key_file: cannot grant read access to the api user (uid $API_UID)." >&2
  echo "        Install the acl package and rerun, or: sudo chown $API_UID:$API_UID $key_file" >&2
done

# Older clones may still have unused secret variables in .env.
# The app no longer reads them; strip the lines without printing values.
if [ -f .env ] && grep -E '^(POSTGRES_PASSWORD|CLINIC_API_PASSWORD|SESSION_SECRET|SMTP_PASSWORD)=' .env >/dev/null 2>&1; then
  sed -i -E '/^(POSTGRES_PASSWORD|CLINIC_API_PASSWORD|SESSION_SECRET|SMTP_PASSWORD)=/d' .env
  echo "removed leftover secret variables from .env"
fi
