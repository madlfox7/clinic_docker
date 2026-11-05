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
  secrets/session_secret secrets/smtp_password
