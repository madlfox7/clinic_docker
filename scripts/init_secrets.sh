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

# --- TLS for the proxy ---------------------------------------------------------
# CLINIC_TLS_MODE comes from the environment, else from a CLINIC_TLS_MODE= line
# in .env (read with grep, .env is never sourced); empty means local.
#   local:    our own CA (secrets/tls/ca.*, name constraints: localhost,
#             127.0.0.1 and ::1 only) signs the server certificate. ca.key
#             never leaves this host: it is not mounted into any container.
#   provided: server.crt (full chain) and server.key are yours; this script
#             never creates or overwrites them, it only checks them.
# The proxy (uid 101) reads only server.key and server.crt (Compose secrets).
. scripts/tls_lib.sh

tls_create_ca() {
  tls_tmp ca_cfg
  tls_tmp ca_key_new
  tls_tmp ca_crt_new
  cat > "$ca_cfg" <<'CA_CONFIG'
[req]
distinguished_name = clinic_ca_dn
prompt = no
x509_extensions = clinic_ca_ext
[clinic_ca_dn]
CN = Clinic stand local CA
[clinic_ca_ext]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
nameConstraints = critical, permitted;DNS:localhost, permitted;IP:127.0.0.1/255.255.255.255, permitted;IP:::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff, excluded;DNS:.localhost
CA_CONFIG
  openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$ca_key_new" -out "$ca_crt_new" -days 1825 -config "$ca_cfg" 2>/dev/null \
    || tls_fail "could not create the local CA"
  cat "$ca_key_new" > "$TLS_DIR/ca.key"
  cat "$ca_crt_new" > "$TLS_DIR/ca.crt"
  echo "created $TLS_DIR/ca.key, $TLS_DIR/ca.crt (local CA, 1825 days; the key never leaves this host)"
}

# Reasons to issue the server certificate again; empty = keep it.
tls_leaf_problem() {
  if [ ! -s "$TLS_DIR/server.crt" ] || [ ! -s "$TLS_DIR/server.key" ]; then
    echo "missing"
  elif ! openssl x509 -checkend 2592000 -noout -in "$TLS_DIR/server.crt" >/dev/null 2>&1; then
    echo "expires within 30 days"
  elif ! openssl verify -x509_strict -CAfile "$TLS_DIR/ca.crt" "$TLS_DIR/server.crt" >/dev/null 2>&1; then
    echo "not signed by the current CA"
  elif ! tls_pair_matches "$TLS_DIR/server.crt" "$TLS_DIR/server.key"; then
    echo "key does not match certificate"
  fi
}

tls_issue_leaf() {
  ca_days="$(tls_days_left "$TLS_DIR/ca.crt")"
  leaf_days=365
  if [ $((ca_days - 1)) -lt "$leaf_days" ]; then
    leaf_days=$((ca_days - 1))
  fi
  [ "$leaf_days" -ge 1 ] || tls_fail "$TLS_DIR/ca.crt expires too soon to sign a server certificate; move secrets/tls away and rerun to create a new CA"
  tls_tmp leaf_cfg
  tls_tmp leaf_key_new
  tls_tmp leaf_csr
  tls_tmp leaf_crt_new
  cat > "$leaf_cfg" <<'LEAF_CONFIG'
[req]
distinguished_name = clinic_leaf_dn
prompt = no
[clinic_leaf_dn]
CN = localhost
[clinic_leaf_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
LEAF_CONFIG
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$leaf_key_new" -out "$leaf_csr" -config "$leaf_cfg" 2>/dev/null \
    || tls_fail "could not create the server key"
  openssl x509 -req -in "$leaf_csr" -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" \
    -set_serial "0x$(openssl rand -hex 16)" -days "$leaf_days" \
    -extfile "$leaf_cfg" -extensions clinic_leaf_ext -out "$leaf_crt_new" 2>/dev/null \
    || tls_fail "could not sign the server certificate"
  # Check the candidate before the live files are touched.
  openssl verify -x509_strict -CAfile "$TLS_DIR/ca.crt" "$leaf_crt_new" >/dev/null 2>&1 \
    || tls_fail "the new server certificate does not verify against $TLS_DIR/ca.crt"
  tls_pair_matches "$leaf_crt_new" "$leaf_key_new" \
    || tls_fail "the new server key does not match its certificate"
  if [ -e "$TLS_DIR/server.key" ] || [ -e "$TLS_DIR/server.crt" ]; then
    tls_backup_live
  fi
  tls_write_live "$leaf_key_new" "$leaf_crt_new"
  echo "created $TLS_DIR/server.key, $TLS_DIR/server.crt (localhost, 127.0.0.1, ::1; $leaf_days days)"
  # A running proxy keeps the old pair in memory until nginx reloads.
  : > "$TLS_DIR/.leaf_reissued"
  echo "        a running proxy needs: docker compose exec proxy nginx -s reload (make start does it)"
}

tls_settings
tls_check_settings

mkdir -p "$TLS_DIR"
chmod 700 "$TLS_DIR"
if [ "$TLS_MODE" = local ]; then
  if [ -e "$TLS_DIR/ca.key" ] && [ -e "$TLS_DIR/ca.crt" ]; then
    echo "keep    $TLS_DIR/ca.key, $TLS_DIR/ca.crt"
  elif [ -e "$TLS_DIR/ca.key" ] || [ -e "$TLS_DIR/ca.crt" ]; then
    tls_fail "only one of $TLS_DIR/ca.key and $TLS_DIR/ca.crt exists; restore the other one or move both away to create a new CA"
  else
    tls_create_ca
  fi
  for ca_file in "$TLS_DIR/ca.key" "$TLS_DIR/ca.crt"; do
    chmod 600 "$ca_file"
    if command -v setfacl >/dev/null 2>&1; then
      setfacl -b "$ca_file" 2>/dev/null || true
    fi
  done
  if ! openssl x509 -checkend 5184000 -noout -in "$TLS_DIR/ca.crt" >/dev/null 2>&1; then
    tls_warn "$TLS_DIR/ca.crt expires within 60 days; it is not renewed automatically."
  fi
  if ! openssl x509 -noout -ext extendedKeyUsage -in "$TLS_DIR/ca.crt" 2>/dev/null | grep -q "TLS Web Server Authentication"; then
    tls_warn "$TLS_DIR/ca.crt is not limited to server certificates (made by an older version); move secrets/tls away and rerun to create a new CA"
  fi
  leaf_problem="$(tls_leaf_problem)"
  if [ -n "$leaf_problem" ]; then
    echo "issue   $TLS_DIR/server.crt: $leaf_problem"
    tls_issue_leaf
  else
    echo "keep    $TLS_DIR/server.key, $TLS_DIR/server.crt"
  fi
else
  # provided: never generate, never overwrite.
  if [ -e "$TLS_DIR/ca.key" ]; then
    tls_warn "$TLS_DIR/ca.key is not used in provided mode, move it off this host"
  fi
  if [ ! -s "$TLS_DIR/server.crt" ] || [ ! -s "$TLS_DIR/server.key" ]; then
    tls_fail "provided mode: put your full-chain certificate in $TLS_DIR/server.crt and its key in $TLS_DIR/server.key"
  fi
fi
tls_check_pair "$TLS_DIR/server.key" "$TLS_DIR/server.crt"
echo "check   $TLS_DIR/server.crt: key, dates, $CERT_HOST in SAN, chain ($TLS_MODE)"
tls_cleanup
TLS_TMP_FILES=

# Compose bind-mounts each file with host ownership and mode, so non-root
# container users (api/seed run as uid 10001, postgres as uid 999) need read
# access to the file itself. The directory stays private to the host user.
# Each file is 600 for the host user plus a read ACL for the one container uid
# that reads it (migrate runs as root in its container and needs no ACL).
# chmod must come before setfacl: a later chmod would reset the ACL mask.
# Fallback without ACL support: root hands the file to that uid (0400);
# anyone else keeps 644 so the stack still starts, with a warning.
chmod 700 secrets
for entry in postgres_password:999 clinic_api_password:10001 \
  session_secret:10001 smtp_password:10001 demo_password:10001 \
  tls/server.key:101 tls/server.crt:101; do
  secret_file="secrets/${entry%%:*}"
  reader_uid="${entry##*:}"
  if [ ! -O "$secret_file" ]; then
    echo "note    $secret_file is not owned by you; permissions left as they are"
    continue
  fi
  chmod 600 "$secret_file"
  if command -v setfacl >/dev/null 2>&1 && setfacl -m "u:$reader_uid:r" "$secret_file" 2>/dev/null; then
    continue
  fi
  if [ "$(id -u)" = 0 ]; then
    chown "$reader_uid:$reader_uid" "$secret_file"
    chmod 400 "$secret_file"
    continue
  fi
  chmod 644 "$secret_file"
  echo "warning $secret_file stays world-readable (644): no ACL support." >&2
  echo "        Install the acl package and rerun, or: chmod 600 $secret_file && sudo setfacl -m u:$reader_uid:r $secret_file" >&2
  echo "        or: sudo chown $reader_uid:$reader_uid $secret_file && sudo chmod 400 $secret_file" >&2
done

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
