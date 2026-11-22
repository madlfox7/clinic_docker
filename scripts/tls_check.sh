#!/usr/bin/env sh
# Check the proxy certificate before startup.
# Use Compose-resolved TLS settings.
set -eu
umask 077
cd "$(dirname "$0")/.."
. scripts/tls_lib.sh

key="${1:-$TLS_DIR/server.key}"
cert="${2:-$TLS_DIR/server.crt}"
[ -d "$TLS_DIR" ] || tls_fail "$TLS_DIR does not exist; run scripts/init_secrets.sh"
tls_settings
tls_check_settings
if [ "$TLS_MODE" = provided ] && [ -e "$TLS_DIR/ca.key" ]; then
  tls_warn "$TLS_DIR/ca.key is not used in provided mode, move it off this host"
fi
if [ "$TLS_MODE" = local ]; then
  [ -s "$TLS_DIR/ca.crt" ] || tls_fail "$TLS_DIR/ca.crt is missing; run scripts/init_secrets.sh"
  if ! openssl x509 -checkend 5184000 -noout -in "$TLS_DIR/ca.crt" >/dev/null 2>&1; then
    tls_warn "$TLS_DIR/ca.crt expires within 60 days; it is not renewed automatically."
  fi
fi
tls_check_pair "$key" "$cert"
echo "OK      $cert: key matches, $(tls_days_left "$cert") days left, $CERT_HOST in SAN, chain verified ($TLS_MODE); HTTPS port $TLS_PORT"
