"""Accept HTTP requests only from the nginx proxy (or loopback inside the container).

The proxy's address is dynamic, so it is resolved by name (TRUSTED_PROXY_HOST,
default "proxy") lazily, cached for 30 s, and re-resolved on a miss at most
once every 5 s. Any other peer, such as a neighbour container on a shared
network, gets 403 before the app runs. Requests from the proxy are marked in
the ASGI scope so client_ip() can trust X-Real-IP from it and from nobody else.
"""
import asyncio
import ipaddress
import logging
import os
import socket
import time

log = logging.getLogger("clinic")

TRUSTED_PROXY_HOST = os.environ.get("TRUSTED_PROXY_HOST", "proxy")
CACHE_SECONDS = 30.0
MISS_RETRY_SECONDS = 5.0
SCOPE_KEY = "clinic.via_trusted_proxy"


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class TrustedProxyMiddleware:
    def __init__(self, app, host: str = TRUSTED_PROXY_HOST):
        self.app = app
        self.host = host
        self._addresses: frozenset[str] = frozenset()
        self._resolved_at = 0.0
        self._lock = asyncio.Lock()

    async def _resolve(self) -> None:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                self.host, None, type=socket.SOCK_STREAM
            )
            self._addresses = frozenset(
                str(ipaddress.ip_address(info[4][0])) for info in infos
            )
        except (OSError, ValueError):
            self._addresses = frozenset()
        self._resolved_at = time.monotonic()

    async def is_trusted(self, peer: str) -> bool:
        try:
            peer = str(ipaddress.ip_address(peer))
        except ValueError:
            return False
        age = time.monotonic() - self._resolved_at
        if age > CACHE_SECONDS or (peer not in self._addresses and age > MISS_RETRY_SECONDS):
            async with self._lock:
                age = time.monotonic() - self._resolved_at
                if age > CACHE_SECONDS or (
                    peer not in self._addresses and age > MISS_RETRY_SECONDS
                ):
                    await self._resolve()
        return peer in self._addresses

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        peer = client[0] if client else ""
        if await self.is_trusted(peer):
            scope[SCOPE_KEY] = True
        elif not _is_loopback(peer):
            log.warning("direct api request rejected from %s", peer or "unknown")
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            await send({
                "type": "http.response.start",
                "status": 403,
                "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                            (b"content-length", b"9")],
            })
            await send({"type": "http.response.body", "body": b"Forbidden"})
            return
        await self.app(scope, receive, send)
