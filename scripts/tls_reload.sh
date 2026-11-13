#!/usr/bin/env sh
# Put a new certificate in place without stopping the proxy (certbot
# deploy-hook or a reissued stand leaf):
#   scripts/tls_reload.sh NEW_KEY NEW_FULLCHAIN
# 1. check the candidate (same checks as tls-check); live files untouched on error;
# 2. back up the live pair to secrets/tls/backup-<UTC>/ (700, files 600);
# 3. write into the existing files (same inode as the Compose secrets), key first;
# 4. nginx -t in the running proxy; on error restore the backup and stop;
# 5. nginx -s reload (graceful);
# 6. compare the serial the server hands out with the candidate's.
# COMPOSE comes from the environment like in the Makefile (default
# "docker compose"). Nothing is deleted; backup-* directories are yours.
set -eu
umask 077
cd "$(dirname "$0")/.."
. scripts/tls_lib.sh

[ "$#" -eq 2 ] || tls_fail "usage: scripts/tls_reload.sh NEW_KEY NEW_FULLCHAIN"
new_key="$1"
new_cert="$2"
COMPOSE="${COMPOSE:-docker compose}"
[ -d "$TLS_DIR" ] || tls_fail "$TLS_DIR does not exist; run scripts/init_secrets.sh"

: >> "$TLS_DIR/.reload.lock"
chmod 600 "$TLS_DIR/.reload.lock"
exec 9>> "$TLS_DIR/.reload.lock"
flock -n 9 || tls_fail "reload already running (lock $TLS_DIR/.reload.lock)"

tls_settings
tls_check_settings
# Copies first: the arguments may be the live files' own backups, or paths
# certbot replaces while we run.
tls_tmp cand_key
tls_tmp cand_cert
cat "$new_key" > "$cand_key" || tls_fail "cannot read $new_key"
cat "$new_cert" > "$cand_cert" || tls_fail "cannot read $new_cert"
tls_check_pair "$cand_key" "$cand_cert"
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

case "$URL_HOST" in
  *:*|*[!0-9.]*) case "$URL_HOST" in *:*) sni=-noservername ;; *) sni="-servername $URL_HOST" ;; esac ;;
  *) sni=-noservername ;;
esac
served=
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  # shellcheck disable=SC2086
  served="$(openssl s_client -connect "127.0.0.1:$TLS_PORT" $sni </dev/null 2>/dev/null \
    | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2)" || served=
  [ "$served" = "$cand_serial" ] && break
  sleep 1
done
if [ "$served" != "$cand_serial" ]; then
  echo "WARN served serial ${served:-none} != candidate $cand_serial" >&2
  exit 1
fi
echo "OK      served serial $served on 127.0.0.1:$TLS_PORT"
