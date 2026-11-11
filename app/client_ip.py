import ipaddress

from fastapi import Request

from trusted_proxy import SCOPE_KEY


def client_ip(request: Request) -> str:
    """Client address for rate limits and the journal.

    X-Real-IP is used only when the peer is the trusted proxy (which overwrites
    it with $remote_addr) and it is a valid IP; otherwise the peer address.
    """
    peer = request.client.host if request.client else "unknown"
    if request.scope.get(SCOPE_KEY):
        raw = request.headers.get("x-real-ip", "")
        try:
            return str(ipaddress.ip_address(raw.strip()))
        except ValueError:
            return peer
    return peer
