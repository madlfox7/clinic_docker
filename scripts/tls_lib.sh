# Shared TLS helpers for init_secrets.sh, tls_check.sh and tls_reload.sh.
# POSIX sh, sourced from the repository root (each script cds there first).
# Nothing here prints key material: only paths, names, dates and serials.

TLS_DIR=secrets/tls

# env_or_dotenv NAME: the environment first, else the last NAME= line of .env
# (read with grep, .env is never sourced), surrounding quotes removed.
env_or_dotenv() {
  eval "value_is_set=\${$1+x}"
  if [ -n "$value_is_set" ]; then
    eval "printf '%s' \"\${$1}\""
    return 0
  fi
  [ -f .env ] || return 0
  grep "^$1=" .env | tail -n 1 | cut -d= -f2- | tr -d '\r' \
    | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

TLS_TMP_FILES=
tls_cleanup() {
  for tmp_file in $TLS_TMP_FILES; do
    rm -f "$tmp_file"
  done
  TLS_TMP_FILES=
}
trap tls_cleanup EXIT INT TERM
# tls_tmp NAME: a new private temporary file in secrets/tls, path in $NAME,
# removed on exit.
tls_tmp() {
  tmp_file="$(mktemp "$TLS_DIR/.tmp.XXXXXX")"
  TLS_TMP_FILES="$TLS_TMP_FILES $tmp_file"
  eval "$1=\$tmp_file"
}
tls_fail() {
  echo "error   $*" >&2
  exit 1
}
tls_warn() {
  echo "warning $*" >&2
}

# Public key of a certificate and of a private key, to compare the pair.
tls_cert_pubkey() { openssl x509 -noout -pubkey -in "$1" 2>/dev/null; }
tls_key_pubkey() { openssl pkey -pubout -in "$1" 2>/dev/null; }
tls_pair_matches() {
  cert_pub="$(tls_cert_pubkey "$1")" || return 1
  key_pub="$(tls_key_pubkey "$2")" || return 1
  [ -n "$cert_pub" ] && [ "$cert_pub" = "$key_pub" ]
}
# Whole days until the certificate expires (0 when expired or unreadable).
tls_days_left() {
  end="$(openssl x509 -noout -enddate -in "$1" 2>/dev/null | cut -d= -f2-)"
  end_s="$(date -u -d "$end" +%s 2>/dev/null)" || { echo 0; return 0; }
  now_s="$(date -u +%s)"
  if [ "$end_s" -le "$now_s" ]; then echo 0; else echo $(( (end_s - now_s) / 86400 )); fi
}
tls_serial() { openssl x509 -noout -serial -in "$1" 2>/dev/null | cut -d= -f2; }

# tls_settings: TLS_MODE, PUBLIC_URL, URL_HOST (no brackets), URL_PORT,
# HTTPS_ONLY, PROXY_PORT, TLS_PORT from the environment or .env.
tls_settings() {
  TLS_MODE="$(env_or_dotenv CLINIC_TLS_MODE)"
  [ -n "$TLS_MODE" ] || TLS_MODE=local
  case "$TLS_MODE" in
    local|provided) ;;
    *) tls_fail "CLINIC_TLS_MODE must be local or provided, got '$TLS_MODE'" ;;
  esac
  PUBLIC_URL="$(env_or_dotenv PUBLIC_BASE_URL)"
  [ -n "$PUBLIC_URL" ] || PUBLIC_URL=https://localhost:8450
  HTTPS_ONLY="$(env_or_dotenv SESSION_HTTPS_ONLY)"
  [ -n "$HTTPS_ONLY" ] || HTTPS_ONLY=true
  PROXY_PORT="$(env_or_dotenv CLINIC_PROXY_PORT)"
  TLS_PORT="$(env_or_dotenv CLINIC_PROXY_TLS_PORT)"
  url_authority="${PUBLIC_URL#*://}"
  url_authority="${url_authority%%/*}"
  case "$url_authority" in
    \[*\]:*) URL_PORT="${url_authority##*]:}"; URL_HOST="${url_authority%%]*}" ;;
    \[*) URL_PORT=443; URL_HOST="${url_authority%%]*}" ;;
    *:*) URL_PORT="${url_authority##*:}"; URL_HOST="${url_authority%%:*}" ;;
    *) URL_PORT=443; URL_HOST="$url_authority" ;;
  esac
  URL_HOST="${URL_HOST#[}"
  # CLINIC_PUBLIC_TUNNEL: the public address is a tunnel (ngrok demo) in
  # front of the local stand; see tls_check_settings.
  PUBLIC_TUNNEL="$(env_or_dotenv CLINIC_PUBLIC_TUNNEL)"
  case "$PUBLIC_TUNNEL" in
    1|true) PUBLIC_TUNNEL=1 ;;
    ''|0|false) PUBLIC_TUNNEL=0 ;;
    *) tls_fail "CLINIC_PUBLIC_TUNNEL must be 1 or 0, got '$PUBLIC_TUNNEL'" ;;
  esac
  # The name the stand certificate must carry: the PUBLIC_BASE_URL host, or
  # localhost behind a tunnel (the tunnel connects to https://localhost:<port>).
  CERT_HOST="$URL_HOST"
  [ "$PUBLIC_TUNNEL" = 0 ] || CERT_HOST=localhost
}

# A mismatch is an error in local mode and a warning in provided mode
# (a provided setup may sit behind another forwarder).
tls_port_problem() {
  if [ "$TLS_MODE" = local ]; then
    tls_fail "$1"
  fi
  tls_warn "$1"
}

# Ports and PUBLIC_BASE_URL must agree: the HTTP redirect and the links in
# mail go to the port of PUBLIC_BASE_URL.
# 0 when HOST (no brackets) is an IPv4 or IPv6 literal.
tls_host_is_ip() {
  case "$1" in
    *:*) return 0 ;;
    *[!0-9.]*|'') return 1 ;;
  esac
  return 0
}

# Tunnel mode: only with the stand CA (local). The public address must be a
# real https domain on the default port; the port check against the
# published HTTPS port is skipped for it, nothing else is.
tls_check_tunnel() {
  [ "$TLS_MODE" = local ] || tls_fail "CLINIC_PUBLIC_TUNNEL=1 works only with CLINIC_TLS_MODE=local"
  case "$PUBLIC_URL" in
    https://*) ;;
    *) tls_fail "CLINIC_PUBLIC_TUNNEL=1 needs an https:// PUBLIC_BASE_URL" ;;
  esac
  [ "$URL_PORT" = 443 ] || tls_fail "CLINIC_PUBLIC_TUNNEL=1 needs PUBLIC_BASE_URL without a port (443), got port $URL_PORT"
  if tls_host_is_ip "$URL_HOST"; then
    tls_fail "CLINIC_PUBLIC_TUNNEL=1 needs a domain name in PUBLIC_BASE_URL, not the IP address $URL_HOST"
  fi
  case "$URL_HOST" in
    localhost|*.localhost) tls_fail "CLINIC_PUBLIC_TUNNEL=1 needs the public tunnel domain in PUBLIC_BASE_URL, not $URL_HOST" ;;
    *.*) ;;
    *) tls_fail "CLINIC_PUBLIC_TUNNEL=1 needs a full domain name in PUBLIC_BASE_URL, got $URL_HOST" ;;
  esac
  echo "tunnel  PUBLIC_BASE_URL $PUBLIC_URL is a tunnel to https://localhost:${TLS_PORT:-8450}; the stand certificate is checked for localhost"
}

tls_check_settings() {
  if [ "$TLS_MODE" = provided ] && tls_host_is_ip "$URL_HOST"; then
    tls_fail "provided mode needs a domain name in PUBLIC_BASE_URL, not the IP address $URL_HOST (public certificates and SNI are issued for names)"
  fi
  case "$PUBLIC_URL" in
    https://*) ;;
    *)
      if [ "$HTTPS_ONLY" = true ]; then
        tls_fail "PUBLIC_BASE_URL must start with https:// while SESSION_HTTPS_ONLY is true"
      fi
      ;;
  esac
  if [ -n "$PROXY_PORT" ] && [ "$PROXY_PORT" != 8080 ] && { [ -z "$TLS_PORT" ] || [ "$TLS_PORT" = 8450 ]; }; then
    tls_port_problem "CLINIC_PROXY_PORT=$PROXY_PORT but CLINIC_PROXY_TLS_PORT is empty, so HTTPS would take 8450 of the default stand; set CLINIC_PROXY_TLS_PORT (HTTP port + 370)"
  fi
  [ -n "$TLS_PORT" ] || TLS_PORT=8450
  if [ "$PUBLIC_TUNNEL" = 1 ]; then
    tls_check_tunnel
  elif [ "$URL_PORT" != "$TLS_PORT" ]; then
    tls_port_problem "redirect and mail links point to port $URL_PORT (PUBLIC_BASE_URL), proxy publishes HTTPS on $TLS_PORT (CLINIC_PROXY_TLS_PORT)"
  fi
}

# tls_name_matches CERT HOST: -checkip for IP literals (one per call),
# -checkhost for names. Older OpenSSL returned 0 on a mismatch, so the
# "does match" line is required as well as exit code 0.
tls_name_matches() {
  if tls_host_is_ip "$2"; then name_flag=-checkip; else name_flag=-checkhost; fi
  name_out="$(openssl x509 -noout -in "$1" "$name_flag" "$2" 2>/dev/null)" || return 1
  case "$name_out" in
    *"does match"*) return 0 ;;
  esac
  return 1
}

# tls_check_pair KEY CERT: the checks of section 5.2, error = exit 1.
#   local:    chain against secrets/tls/ca.crt (strict);
#   provided: first block of the fullchain is the leaf, the rest are
#             intermediates; trust = CLINIC_TLS_CA_FILE (host only) or the
#             system store.
# Optional KEY_LABEL CERT_LABEL name the files in messages (the paths the
# user gave, when KEY and CERT are private working copies).
tls_check_pair() {
  key_label="${3:-$1}"
  cert_label="${4:-$2}"
  [ -s "$1" ] || tls_fail "$key_label is missing or empty"
  [ -s "$2" ] || tls_fail "$cert_label is missing or empty"
  tls_pair_matches "$2" "$1" || tls_fail "$key_label: key does not match certificate $cert_label"
  tls_tmp leaf_only
  tls_tmp chain_rest
  awk -v leaf="$leaf_only" -v rest="$chain_rest" '
    /-----BEGIN CERTIFICATE-----/ { n++ }
    n == 1 { print > leaf; next }
    n > 1 { print > rest }
  ' "$2"
  [ -s "$leaf_only" ] || tls_fail "$cert_label has no certificate"
  if ! openssl x509 -checkend 0 -noout -in "$leaf_only" >/dev/null 2>&1; then
    tls_fail "$cert_label has expired"
  fi
  if ! openssl x509 -checkend 604800 -noout -in "$leaf_only" >/dev/null 2>&1; then
    tls_fail "$cert_label expires within 7 days; renew it first"
  fi
  if ! openssl x509 -checkend 1814400 -noout -in "$leaf_only" >/dev/null 2>&1; then
    tls_warn "$cert_label expires within 21 days"
  fi
  tls_name_matches "$leaf_only" "$CERT_HOST" \
    || tls_fail "$CERT_HOST (PUBLIC_BASE_URL) is not in certificate SAN of $cert_label"
  if [ "$TLS_MODE" = local ]; then
    openssl verify -x509_strict -CAfile "$TLS_DIR/ca.crt" "$leaf_only" >/dev/null 2>&1 \
      || tls_fail "$cert_label does not verify against $TLS_DIR/ca.crt"
    return 0
  fi
  set -- "$leaf_only"
  if [ -s "$chain_rest" ]; then
    set -- -untrusted "$chain_rest" "$@"
  fi
  ca_file="$(env_or_dotenv CLINIC_TLS_CA_FILE)"
  if [ -n "$ca_file" ]; then
    [ -s "$ca_file" ] || tls_fail "CLINIC_TLS_CA_FILE=$ca_file is missing or empty"
    set -- -CAfile "$ca_file" "$@"
  fi
  openssl verify -purpose sslserver "$@" >/dev/null 2>&1 \
    || tls_fail "the certificate chain does not verify (system trust store${ca_file:+ or CLINIC_TLS_CA_FILE}); server.crt must be the full chain"
}

# tls_backup_live: copy server.key and server.crt to secrets/tls/backup-<UTC>/
# (700, files 600); prints the directory in TLS_BACKUP_DIR.
tls_backup_live() {
  TLS_BACKUP_DIR="$TLS_DIR/backup-$(date -u +%Y%m%dT%H%M%SZ)"
  suffix=1
  while ! mkdir -m 700 "$TLS_BACKUP_DIR" 2>/dev/null; do
    [ "$suffix" -lt 100 ] || tls_fail "could not create a backup directory in $TLS_DIR"
    TLS_BACKUP_DIR="$TLS_DIR/backup-$(date -u +%Y%m%dT%H%M%SZ)-$suffix"
    suffix=$((suffix + 1))
  done
  for live in server.key server.crt; do
    if [ -e "$TLS_DIR/$live" ]; then
      cat "$TLS_DIR/$live" > "$TLS_BACKUP_DIR/$live"
      chmod 600 "$TLS_BACKUP_DIR/$live"
    fi
  done
  echo "backup  $TLS_BACKUP_DIR"
}

# tls_write_live KEY CERT: write into the existing files (same inode, so the
# bind-mounted Compose secrets see it after nginx -s reload). Key first.
tls_write_live() {
  cat "$1" > "$TLS_DIR/server.key"
  cat "$2" > "$TLS_DIR/server.crt"
}
