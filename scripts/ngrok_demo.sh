#!/usr/bin/env sh
# Public demo of the local stand through ngrok (make ngrok / make ngrok-off).
#   scripts/ngrok_demo.sh on    start the stand with the tunnel address, then
#                               run ngrok in the foreground (Ctrl+C closes the
#                               tunnel; the stand keeps running)
#   scripts/ngrok_demo.sh off   start the stand again with the .env settings
#                               (tunnel off): links and the 308 go to localhost
# NGROK_DOMAIN (environment or .env) is the reserved ngrok domain, for example
# outspoken-wiry-fabric.ngrok-free.dev. The authtoken stays in ngrok's own
# config (ngrok config add-authtoken) or NGROK_AUTHTOKEN; it is never read
# into this script, stored in the repository or printed.
# The settings go to `make start` through the environment, which beats .env
# for init_secrets.sh (env_or_dotenv) and for Compose interpolation; .env is
# not edited. COMPOSE, MAKE and PYTHON come from the Makefile.
# Exit codes: 0 done (or ngrok closed with Ctrl+C), 1 a configuration error
# (tls_fail: domain, ngrok, ports, the address in the containers), 2 usage;
# otherwise ngrok's own code. make ngrok itself reports 2 for any failure.
set -eu
umask 077
cd "$(dirname "$0")/.."
. scripts/tls_lib.sh
trap - INT

COMPOSE="${COMPOSE:-docker compose}"
MAKE="${MAKE:-make}"
PYTHON="${PYTHON:-python3}"

# The published HTTPS port of the proxy (container 8443) as Compose will use
# it, override files and environment included; the tunnel must go there, the
# HTTP port only answers with a 308 to PUBLIC_BASE_URL (a loop).
proxy_https_port() {
  $COMPOSE config --format json | "$PYTHON" -c '
import json, sys
proxy = json.load(sys.stdin)["services"]["proxy"]
ports = [p for p in proxy.get("ports") or [] if int(p["target"]) == 8443]
if len(ports) != 1:
    sys.exit("error   proxy must publish container port 8443 exactly once, found %d" % len(ports))
host_ip = str(ports[0].get("host_ip") or "")
if host_ip not in ("", "0.0.0.0", "127.0.0.1", "::", "::1"):
    sys.exit("error   the proxy HTTPS port is bound to %s; ngrok connects to localhost, "
             "set CLINIC_PROXY_BIND=127.0.0.1 (or leave it empty)" % host_ip)
print(ports[0]["published"])
'
}

# What the running stand actually uses. `sudo docker compose` (COMPOSE="sudo
# ...") drops PUBLIC_BASE_URL and CLINIC_PUBLIC_TUNNEL from the environment,
# so the containers would keep the .env address while the tunnel points at
# them. Only these two non-secret variables are read, by name.
effective_value() {
  $COMPOSE exec -T "$1" printenv "$2" 2>/dev/null | tr -d '\r' | tail -n 1
}

check_effective_address() {
  want="https://$NGROK_DOMAIN"
  for service in api proxy; do
    got="$(effective_value "$service" PUBLIC_BASE_URL || true)"
    if [ "$got" != "$want" ]; then
      tls_fail "the $service container uses PUBLIC_BASE_URL=${got:-<unset>}, not $want; ngrok not started.
        The tunnel settings did not reach Docker Compose: with sudo the environment is dropped.
        Run docker without sudo (add yourself to the docker group) or keep the environment:
        make ngrok COMPOSE=\"sudo -E docker compose\". Then make ngrok again."
    fi
  done
  tunnel="$(effective_value proxy CLINIC_PUBLIC_TUNNEL || true)"
  [ "$tunnel" = 1 ] || tls_fail "the proxy container has CLINIC_PUBLIC_TUNNEL=${tunnel:-<unset>}, not 1; ngrok not started.
        With sudo use sudo -E (make ngrok COMPOSE=\"sudo -E docker compose\") or run docker without sudo."
  echo "check   api and proxy use PUBLIC_BASE_URL=$want (tunnel mode)"
}

ngrok_on() {
  cp -n .env.example .env
  NGROK_DOMAIN="$(env_or_dotenv NGROK_DOMAIN)"
  [ -n "$NGROK_DOMAIN" ] \
    || tls_fail "NGROK_DOMAIN is not set; add NGROK_DOMAIN=<your-domain>.ngrok-free.dev to .env (the domain from the ngrok dashboard)"
  # The same rules as PUBLIC_BASE_URL in tunnel mode: a bare lower-case domain.
  case "$NGROK_DOMAIN" in
    *://*|*/*|*:*) tls_fail "NGROK_DOMAIN must be the bare domain (like name.ngrok-free.dev), without https://, port or path" ;;
  esac
  PUBLIC_URL="https://$NGROK_DOMAIN"
  tls_parse_url
  case "$URL_HOST" in
    *.*) ;;
    *) tls_fail "NGROK_DOMAIN must be a full domain name, got $URL_HOST" ;;
  esac

  command -v ngrok >/dev/null 2>&1 \
    || tls_fail "ngrok is not installed or not in PATH; see README, Demo via ngrok"
  if ! check_out="$(ngrok config check 2>&1)"; then
    tls_fail "ngrok config check failed; run: ngrok config add-authtoken <token from the ngrok dashboard>"
  fi
  if [ -z "${NGROK_AUTHTOKEN:-}" ]; then
    # Only whether an authtoken line exists is checked; its value is not read
    # into a variable or printed.
    config_file="$(printf '%s\n' "$check_out" | sed -n 's/^Valid configuration file at //p' | tail -n 1)"
    if [ -z "$config_file" ] || ! [ -f "$config_file" ] \
      || ! grep -Eq '^[[:space:]]*authtoken:[[:space:]]*[^[:space:]#"'"'"']' "$config_file"; then
      tls_fail "ngrok has no authtoken; run: ngrok config add-authtoken <token from the ngrok dashboard>"
    fi
  fi

  CLINIC_PUBLIC_TUNNEL=1
  PUBLIC_BASE_URL="https://$NGROK_DOMAIN"
  export CLINIC_PUBLIC_TUNNEL PUBLIC_BASE_URL
  https_port="$(proxy_https_port)" || exit 1
  echo "start   PUBLIC_BASE_URL=$PUBLIC_BASE_URL CLINIC_PUBLIC_TUNNEL=1 (environment, .env unchanged)"
  "$MAKE" --no-print-directory start COMPOSE="$COMPOSE"
  check_effective_address
  ca="$PWD/$TLS_DIR/ca.crt"
  [ -s "$ca" ] || tls_fail "$TLS_DIR/ca.crt is missing; the tunnel verifies the stand certificate with it"

  echo
  echo "Site:   https://$NGROK_DOMAIN   (ngrok shows a \"Visit Site\" page first)"
  echo "        PUBLIC: anyone with the link reaches the stand. Close the tunnel after the demo."
  echo "        Ctrl+C closes the tunnel; the stand keeps running with the tunnel links until: make ngrok-off"
  echo "ngrok http https://localhost:$https_port --url https://$NGROK_DOMAIN --upstream-tls-verify --upstream-tls-verify-cas $ca"
  # Not exec: after Ctrl+C the reminder below is still printed.
  trap ':' INT
  rc=0
  ngrok http "https://localhost:$https_port" --url "https://$NGROK_DOMAIN" \
    --upstream-tls-verify --upstream-tls-verify-cas "$ca" || rc=$?
  echo "tunnel closed; the stand still sends links to https://$NGROK_DOMAIN. Back to localhost: make ngrok-off"
  [ "$rc" = 0 ] || [ "$rc" = 130 ] || exit "$rc"
}

ngrok_off() {
  # Drop the tunnel settings of this shell too, so .env (or its default) wins.
  unset PUBLIC_BASE_URL
  CLINIC_PUBLIC_TUNNEL=0
  export CLINIC_PUBLIC_TUNNEL
  echo "start   PUBLIC_BASE_URL from .env, CLINIC_PUBLIC_TUNNEL=0"
  "$MAKE" --no-print-directory start COMPOSE="$COMPOSE"
  PUBLIC_URL="$(env_or_dotenv PUBLIC_BASE_URL)"
  echo "Site:   ${PUBLIC_URL:-https://localhost:8450}   (close the ngrok tunnel if it is still open)"
}

case "${1:-}" in
  on) ngrok_on ;;
  off) ngrok_off ;;
  *) echo "usage: $0 on|off" >&2; exit 2 ;;
esac
