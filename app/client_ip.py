import ipaddress

from fastapi import Request

from trusted_proxy import SCOPE_KEY


def client_ip(request: Request) -> str:
    """Use the proxy-overwritten X-Real-IP only from the trusted proxy; otherwise use the peer."""
    peer = request.client.host if request.client else "unknown"
    if request.scope.get(SCOPE_KEY):
        raw = request.headers.get("x-real-ip", "")
        try:
            return str(ipaddress.ip_address(raw.strip()))
        except ValueError:
            return peer
    return peer
