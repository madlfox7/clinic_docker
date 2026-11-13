#!/bin/sh
# Runs from /docker-entrypoint.d before nginx starts. Turns the proxy
# environment into small nginx snippets under /tmp/nginx/clinic (the rest of
# the file system is read-only). Any bad value stops the container: the
# official entrypoint runs with `set -e`, and a missing snippet makes nginx
# refuse to start, so this fails closed.
set -eu

OUT=/tmp/nginx/clinic
NL='
'
CR=$(printf '\r')

fail() {
    echo "15-clinic-tls.sh: $*" >&2
    exit 1
}

# --- CLINIC_TLS_MODE -----------------------------------------------------------
mode=${CLINIC_TLS_MODE:-local}
case $mode in
    local|provided) ;;
    *) fail "CLINIC_TLS_MODE must be local or provided" ;;
esac

# --- CLINIC_HSTS_MAX_AGE (seconds, digits only, at most two years) --------------
max_age=${CLINIC_HSTS_MAX_AGE:-3600}
case $max_age in
    ''|*[!0-9]*) fail "CLINIC_HSTS_MAX_AGE must be a whole number of seconds" ;;
esac
case $max_age in
    0?*) fail "CLINIC_HSTS_MAX_AGE must not have leading zeros" ;;
esac
if [ "${#max_age}" -gt 8 ] || [ "$max_age" -gt 63072000 ]; then
    fail "CLINIC_HSTS_MAX_AGE must be at most 63072000"
fi

# --- PUBLIC_BASE_URL: https://host[:port] and nothing else ----------------------
url=${PUBLIC_BASE_URL:-}
case $url in
    *"$NL"*|*"$CR"*|*' '*|*'	'*) fail "PUBLIC_BASE_URL must not contain spaces or line breaks" ;;
esac
case $url in
    https://*) ;;
    *) fail "PUBLIC_BASE_URL must start with https://" ;;
esac
authority=${url#https://}
# One trailing slash is the same origin (the api strips it too).
authority=${authority%/}
case $authority in
    ''|*/*|*'?'*|*'#'*|*@*|*'\'*|*'%'*) fail "PUBLIC_BASE_URL must be https://host[:port] without path, query or user info" ;;
esac
case $authority in
    \[*\]|\[*\]:*)
        host=${authority%%]*}]
        rest=${authority#"$host"}
        inner=${host#[}
        inner=${inner%]}
        case $inner in
            ''|*[!0-9a-fA-F:.]*) fail "PUBLIC_BASE_URL has a bad IPv6 address" ;;
            *:*) ;;
            *) fail "PUBLIC_BASE_URL has a bad IPv6 address" ;;
        esac
        ;;
    *\[*|*\]*) fail "PUBLIC_BASE_URL has a bad host" ;;
    *)
        host=${authority%%:*}
        rest=${authority#"$host"}
        case $host in
            ''|*[!a-z0-9.-]*|.*|*.|-*|*..*) fail "PUBLIC_BASE_URL host must be lower-case letters, digits, dots and dashes" ;;
        esac
        ;;
esac
case $rest in
    '') ;;
    :*)
        port=${rest#:}
        case $port in
            ''|*[!0-9]*|0*) fail "PUBLIC_BASE_URL has a bad port" ;;
        esac
        if [ "${#port}" -gt 5 ] || [ "$port" -gt 65535 ]; then
            fail "PUBLIC_BASE_URL has a bad port"
        fi
        ;;
    *) fail "PUBLIC_BASE_URL has a bad host" ;;
esac
origin="https://$host$rest"

# --- Snippets ------------------------------------------------------------------
umask 022
mkdir -p "$OUT"
printf 'return 308 %s$request_uri;\n' "$origin" > "$OUT/redirect.conf"
printf 'add_header Strict-Transport-Security "max-age=%s" always;\n' "$max_age" > "$OUT/hsts.conf"
# The ACME webroot exists only for provided certificates (later step); empty here.
: > "$OUT/acme.conf"
# One server per port in local mode: it answers every name the tests use.
printf 'server_name localhost 127.0.0.1 [::1];\n' > "$OUT/server_name.conf"

echo "15-clinic-tls.sh: mode $mode, redirect to $origin, HSTS max-age=$max_age"
