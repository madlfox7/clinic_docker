#!/bin/sh
# Generate nginx snippets; invalid values fail closed.
set -eu

OUT=/tmp/nginx/clinic
NL='
'
CR=$(printf '\r')

fail() {
    echo "15-clinic-tls.sh: $*" >&2
    exit 1
}

mode=${CLINIC_TLS_MODE:-local}
case $mode in
    local|provided) ;;
    *) fail "CLINIC_TLS_MODE must be local or provided" ;;
esac

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

url=${PUBLIC_BASE_URL:-}
case $url in
    *"$NL"*|*"$CR"*|*' '*|*'	'*) fail "PUBLIC_BASE_URL must not contain spaces or line breaks" ;;
esac
case $url in
    https://*) ;;
    *) fail "PUBLIC_BASE_URL must start with https://" ;;
esac
authority=${url#https://}
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
        # Use local TLS for public tunnels.
        [ -z "$rest" ] || [ "$rest" = ":443" ] || fail "CLINIC_PUBLIC_TUNNEL=1 needs PUBLIC_BASE_URL without a port (443)"
        [ -z "$host_is_ip" ] || fail "CLINIC_PUBLIC_TUNNEL=1 needs a domain name in PUBLIC_BASE_URL, not an IP address"
        case $host in
            localhost|*.localhost) fail "CLINIC_PUBLIC_TUNNEL=1 needs the public tunnel domain in PUBLIC_BASE_URL, not localhost" ;;
            *.*) ;;
            *) fail "CLINIC_PUBLIC_TUNNEL=1 needs a full domain name in PUBLIC_BASE_URL" ;;
        esac
    else
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

acme=${CLINIC_ACME_WEBROOT:-false}
case $acme in
    true|false) ;;
    *) fail "CLINIC_ACME_WEBROOT must be true or false" ;;
esac

umask 022
mkdir -p "$OUT"
printf 'return 308 %s$request_uri;\n' "$origin" > "$OUT/redirect.conf"
printf 'add_header Strict-Transport-Security "max-age=%s" always;\n' "$max_age" > "$OUT/hsts.conf"
if [ "$mode" = provided ]; then
    # Reject unknown Host and SNI values.
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
        # Serve ACME challenges only; redirect other HTTP requests.
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
    printf 'server_name localhost 127.0.0.1 [::1];\n' > "$OUT/server_name.conf"
    : > "$OUT/default_servers.conf"
    # Disable ACME challenges with the local CA.
    : > "$OUT/acme.conf"
fi

echo "15-clinic-tls.sh: mode $mode, tunnel $tunnel, redirect to $origin, HSTS max-age=$max_age, ACME webroot $acme"
