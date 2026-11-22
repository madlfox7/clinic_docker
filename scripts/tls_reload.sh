#!/usr/bin/env sh
# Safely reload the live certificate; restore backups on failure.
set -eu
umask 077
[ "$#" -eq 2 ] || { echo "error   usage: scripts/tls_reload.sh NEW_KEY NEW_FULLCHAIN" >&2; exit 1; }
# Resolve input paths before changing directories.
key_arg="$1"
cert_arg="$2"
case "$key_arg" in /*) new_key="$key_arg" ;; *) new_key="$PWD/$key_arg" ;; esac
case "$cert_arg" in /*) new_cert="$cert_arg" ;; *) new_cert="$PWD/$cert_arg" ;; esac
cd "$(dirname "$0")/.."
. scripts/tls_lib.sh

COMPOSE="${COMPOSE:-docker compose}"
[ -d "$TLS_DIR" ] || tls_fail "$TLS_DIR does not exist; run scripts/init_secrets.sh"

: >> "$TLS_DIR/.reload.lock"
chmod 600 "$TLS_DIR/.reload.lock"
exec 9>> "$TLS_DIR/.reload.lock"
flock -n 9 || tls_fail "reload already running (lock $TLS_DIR/.reload.lock)"

tls_settings
tls_check_settings
# Copy candidates before replacing live files.
tls_tmp cand_key
tls_tmp cand_cert
[ -r "$new_key" ] && [ -f "$new_key" ] || tls_fail "cannot read $key_arg"
[ -r "$new_cert" ] && [ -f "$new_cert" ] || tls_fail "cannot read $cert_arg"
cat "$new_key" > "$cand_key" || tls_fail "cannot read $key_arg"
cat "$new_cert" > "$cand_cert" || tls_fail "cannot read $cert_arg"
tls_check_pair "$cand_key" "$cand_cert" "$key_arg" "$cert_arg"
cand_serial="$(tls_serial "$cand_cert")"

tls_backup_live
tls_write_live "$cand_key" "$cand_cert"
# shellcheck disable=SC2086 # COMPOSE is a command line, like in the Makefile
if ! $COMPOSE exec -T proxy nginx -t >/dev/null 2>&1; then
  tls_write_live "$TLS_BACKUP_DIR/server.key" "$TLS_BACKUP_DIR/server.crt"
  tls_fail "nginx -t failed with the new certificate; restored the previous files from $TLS_BACKUP_DIR (nginx keeps running with the old pair)"
fi
# shellcheck disable=SC2086
$COMPOSE exec -T proxy nginx -s reload >/dev/null 2>&1 || tls_fail "nginx -s reload failed; the new files are in place, check the proxy"
echo "reload  proxy, candidate serial $cand_serial"

if tls_host_is_ip "$CERT_HOST"; then sni=-noservername; else sni="-servername $CERT_HOST"; fi
# Verify serial at the proxy's published address.
bind="$(env_or_dotenv CLINIC_PROXY_BIND)"
case "$bind" in
  ''|0.0.0.0) check_addr="127.0.0.1:$TLS_PORT" ;;
  ::|'[::]') check_addr="[::1]:$TLS_PORT" ;;
  *:*) check_addr="[${bind#[}"; check_addr="${check_addr%]}]:$TLS_PORT" ;;
  *) check_addr="$bind:$TLS_PORT" ;;
esac
served=
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  # shellcheck disable=SC2086
  served="$(openssl s_client -connect "$check_addr" $sni </dev/null 2>/dev/null \
    | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2)" || served=
  [ "$served" = "$cand_serial" ] && break
  sleep 1
done
if [ "$served" != "$cand_serial" ]; then
  echo "WARN served serial ${served:-none} != candidate $cand_serial (checked $check_addr)" >&2
  exit 1
fi
echo "OK      served serial $served on $check_addr"
