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
# --- CLINIC_PUBLIC_TUNNEL: PUBLIC_BASE_URL is a tunnel (ngrok demo) -----------
tunnel=${CLINIC_PUBLIC_TUNNEL:-0}
case $tunnel in
    1|true) tunnel=1 ;;
    0|false) tunnel=0 ;;
    *) fail "CLINIC_PUBLIC_TUNNEL must be 1 or 0" ;;
esac
host_is_ip=
case $host in
    \[*) host_is_ip=yes ;;
    *[!0-9.]*) ;;
    *) host_is_ip=yes ;;
esac
if [ "$mode" = local ]; then
    if [ "$tunnel" = 1 ]; then
        # The public domain of the tunnel on the default port; the tunnel
        # itself connects to https://localhost:<published port>.
        [ -z "$rest" ] || [ "$rest" = ":443" ] || fail "CLINIC_PUBLIC_TUNNEL=1 needs PUBLIC_BASE_URL without a port (443)"
        [ -z "$host_is_ip" ] || fail "CLINIC_PUBLIC_TUNNEL=1 needs a domain name in PUBLIC_BASE_URL, not an IP address"
        case $host in
            localhost|*.localhost) fail "CLINIC_PUBLIC_TUNNEL=1 needs the public tunnel domain in PUBLIC_BASE_URL, not localhost" ;;
            *.*) ;;
            *) fail "CLINIC_PUBLIC_TUNNEL=1 needs a full domain name in PUBLIC_BASE_URL" ;;
        esac
    else
        # Without a tunnel the stand is reached under the names of its certificate.
        case $host in
            localhost|127.0.0.1|\[::1\]) ;;
            *) fail "PUBLIC_BASE_URL host must be localhost, 127.0.0.1 or [::1] with the stand CA (set CLINIC_PUBLIC_TUNNEL=1 for a tunnel)" ;;
        esac
    fi
elif [ "$tunnel" = 1 ]; then
    fail "CLINIC_PUBLIC_TUNNEL=1 works only with CLINIC_TLS_MODE=local"
fi
if [ "$mode" = provided ]; then
    case $host in
        \[*|*[!0-9.]*) ;;
        *) host_is_ip=yes ;;
    esac
    case $host in \[*) host_is_ip=yes ;; esac
    if [ "${host_is_ip:-}" = yes ]; then
        fail "provided mode needs a domain name in PUBLIC_BASE_URL, not an IP address"
    fi
fi

# --- CLINIC_ACME_WEBROOT (HTTP-01 webroot, provided mode only) -------------------
acme=${CLINIC_ACME_WEBROOT:-false}
case $acme in
    true|false) ;;
    *) fail "CLINIC_ACME_WEBROOT must be true or false" ;;
esac

# --- Snippets ------------------------------------------------------------------
umask 022
mkdir -p "$OUT"
printf 'return 308 %s$request_uri;\n' "$origin" > "$OUT/redirect.conf"
printf 'add_header Strict-Transport-Security "max-age=%s" always;\n' "$max_age" > "$OUT/hsts.conf"
if [ "$mode" = provided ]; then
    # Only the name from PUBLIC_BASE_URL is served; any other Host gets the
    # connection closed (444) and any other SNI a rejected handshake.
    printf 'server_name %s;\n' "$host" > "$OUT/server_name.conf"
    cat > "$OUT/default_servers.conf" <<'DEFAULT_SERVERS'
server {
    listen 8080 default_server;
    server_name _;
    server_tokens off;
    access_log /var/log/nginx/access.log clinic_path;
    return 444;
}
server {
    listen 8443 ssl default_server;
    server_name _;
    server_tokens off;
    access_log /var/log/nginx/access.log clinic_path;
    ssl_reject_handshake on;
    return 444;
}
DEFAULT_SERVERS
    if [ "$acme" = true ]; then
        # Webroot mounted read-only by docker-compose.acme.yml; everything else on HTTP is 308.
        cat > "$OUT/acme.conf" <<'ACME'
location ^~ /.well-known/acme-challenge/ {
    include /etc/nginx/clinic/security_headers.conf;
    root /var/www/acme;
    default_type text/plain;
}
ACME
    else
        : > "$OUT/acme.conf"
    fi
else
    # One server per port in local mode: it answers every name the tests use.
    printf 'server_name localhost 127.0.0.1 [::1];\n' > "$OUT/server_name.conf"
    : > "$OUT/default_servers.conf"
    # No ACME webroot with the stand CA, even if CLINIC_ACME_WEBROOT=true.
    : > "$OUT/acme.conf"
fi

echo "15-clinic-tls.sh: mode $mode, tunnel $tunnel, redirect to $origin, HSTS max-age=$max_age, ACME webroot $acme"
