# Shared POSIX sh TLS helpers.
# Never print key material.

TLS_DIR=secrets/tls

# Read .env without sourcing it.
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
# Create a private temporary TLS file.
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

tls_cert_pubkey() { openssl x509 -noout -pubkey -in "$1" 2>/dev/null; }
tls_key_pubkey() { openssl pkey -pubout -in "$1" 2>/dev/null; }
tls_pair_matches() {
  cert_pub="$(tls_cert_pubkey "$1")" || return 1
  key_pub="$(tls_key_pubkey "$2")" || return 1
  [ -n "$cert_pub" ] && [ "$cert_pub" = "$key_pub" ]
}
tls_days_left() {
  end="$(openssl x509 -noout -enddate -in "$1" 2>/dev/null | cut -d= -f2-)"
  end_s="$(date -u -d "$end" +%s 2>/dev/null)" || { echo 0; return 0; }
  now_s="$(date -u +%s)"
  if [ "$end_s" -le "$now_s" ]; then echo 0; else echo $(( (end_s - now_s) / 86400 )); fi
}
tls_serial() { openssl x509 -noout -serial -in "$1" 2>/dev/null | cut -d= -f2; }

tls_parse_url() {
  # Do not echo URLs; they may contain credentials.
  url_bad=PUBLIC_BASE_URL
  url_nl='
'
  url_cr="$(printf '\r')"
  case "$PUBLIC_URL" in
    *"$url_nl"*|*"$url_cr"*|*' '*|*'	'*) tls_fail "PUBLIC_BASE_URL must not contain spaces or line breaks" ;;
  esac
  case "$PUBLIC_URL" in
    https://*) url_authority="${PUBLIC_URL#https://}" ;;
    http://*) url_authority="${PUBLIC_URL#http://}" ;;
    *) tls_fail "$url_bad must start with https://" ;;
  esac
  url_authority="${url_authority%/}"
  case "$url_authority" in
    ''|*/*|*'?'*|*'#'*|*@*|*'\'*|*'%'*)
      tls_fail "$url_bad must be https://host[:port] without path, query, fragment or user info" ;;
  esac
  case "$url_authority" in
    \[*\]|\[*\]:*)
      URL_HOST="${url_authority%%]*}"
      url_rest="${url_authority#"$URL_HOST"]}"
      URL_HOST="${URL_HOST#[}"
      case "$URL_HOST" in
        ''|*[!0-9a-fA-F:.]*) tls_fail "$url_bad has a bad IPv6 address" ;;
        *:*) ;;
        *) tls_fail "$url_bad has a bad IPv6 address" ;;
      esac
      ;;
    *\[*|*\]*) tls_fail "$url_bad has a bad host" ;;
    *)
      URL_HOST="${url_authority%%:*}"
      url_rest="${url_authority#"$URL_HOST"}"
      case "$URL_HOST" in
        ''|*[!a-z0-9.-]*|.*|*.|-*|*-|*..*)
          tls_fail "$url_bad host must be lower-case letters, digits, dots and dashes (no trailing dot)" ;;
      esac
      ;;
  esac
  case "$url_rest" in
    '') URL_PORT=443 ;;
    :*)
      URL_PORT="${url_rest#:}"
      case "$URL_PORT" in
        ''|*[!0-9]*|0*) tls_fail "$url_bad has a bad port" ;;
      esac
      if [ "${#URL_PORT}" -gt 5 ] || [ "$URL_PORT" -gt 65535 ]; then
        tls_fail "$url_bad has a bad port"
      fi
      ;;
    *) tls_fail "$url_bad has a bad host" ;;
  esac
}

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
  tls_parse_url
  # Tunnel mode uses the local stand.
  PUBLIC_TUNNEL="$(env_or_dotenv CLINIC_PUBLIC_TUNNEL)"
  case "$PUBLIC_TUNNEL" in
    1|true) PUBLIC_TUNNEL=1 ;;
    ''|0|false) PUBLIC_TUNNEL=0 ;;
    *) tls_fail "CLINIC_PUBLIC_TUNNEL must be 1 or 0, got '$PUBLIC_TUNNEL'" ;;
  esac
  CERT_HOST="$URL_HOST"
  [ "$PUBLIC_TUNNEL" = 0 ] || CERT_HOST=localhost
}

# Local mismatches fail; provided mode warns.
tls_port_problem() {
  if [ "$TLS_MODE" = local ]; then
    tls_fail "$1"
  fi
  tls_warn "$1"
}

tls_host_is_ip() {
  case "$1" in
    *:*) return 0 ;;
    *[!0-9.]*|'') return 1 ;;
  esac
  return 0
}

# Tunnels require local TLS and a default-port domain.
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

# Require explicit match output; old OpenSSL may misreport success.
tls_name_matches() {
  if tls_host_is_ip "$2"; then name_flag=-checkip; else name_flag=-checkhost; fi
  name_out="$(openssl x509 -noout -in "$1" "$name_flag" "$2" 2>/dev/null)" || return 1
  case "$name_out" in
    *"does match"*) return 0 ;;
  esac
  return 1
}

# Validate certificate identity and trust.
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

# Back up live TLS files with private permissions.
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

# Preserve mounted-secret inodes; write the key first.
tls_write_live() {
  cat "$1" > "$TLS_DIR/server.key"
  cat "$2" > "$TLS_DIR/server.crt"
}
