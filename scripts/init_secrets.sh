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

# Older clones may still have unused secret variables in .env.
# The app no longer reads them; strip the lines without printing values.
if [ -f .env ] && grep -E '^(POSTGRES_PASSWORD|CLINIC_API_PASSWORD|SESSION_SECRET|SMTP_PASSWORD)=' .env >/dev/null 2>&1; then
  sed -i -E '/^(POSTGRES_PASSWORD|CLINIC_API_PASSWORD|SESSION_SECRET|SMTP_PASSWORD)=/d' .env
  echo "removed leftover secret variables from .env"
fi
