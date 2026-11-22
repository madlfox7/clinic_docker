"""Validate the public link origin once at startup; invalid configuration stops the API."""
import ipaddress
import os
import re

from session_config import HTTPS_ONLY

DEFAULT = "https://localhost:8450"
_HOST_NAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")
_PORT = re.compile(r"[1-9][0-9]{0,4}")
_SCHEME = re.compile(r"(https?)://")


def _bad(reason: str) -> RuntimeError:
    return RuntimeError(f"PUBLIC_BASE_URL {reason}")


def _check_host(host: str) -> None:
    if host.startswith("["):
        if not host.endswith("]"):
            raise _bad("has a bad IPv6 address")
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise _bad("has a bad IPv6 address") from None
        return
    if not _HOST_NAME.fullmatch(host) or ".." in host:
        raise _bad("host must be lower-case letters, digits, dots and dashes")


def parse(raw: str, https_only: bool) -> str:
    """Return the origin (scheme://host[:port], no trailing slash) or raise."""
    if any(char.isspace() for char in raw):
        raise _bad("must not contain spaces or line breaks")
    scheme = _SCHEME.match(raw)
    if not scheme:
        raise _bad("must start with https://")
    if scheme.group(1) != "https" and https_only:
        raise _bad("must be https:// while SESSION_HTTPS_ONLY is true")
    authority = raw[scheme.end():]
    if authority.endswith("/"):
        authority = authority[:-1]
    if not authority or any(char in authority for char in "/?#@\\%"):
        raise _bad("must be scheme://host[:port] without path, query, fragment or user info")
    if authority.startswith("["):
        host, _, rest = authority.partition("]")
        host += "]"
    else:
        host, sep, port = authority.partition(":")
        rest = sep + port
    _check_host(host)
    if rest:
        port = rest[1:]
        if not rest.startswith(":") or not _PORT.fullmatch(port) or int(port) > 65535:
            raise _bad("has a bad port")
    return f"{scheme.group(1)}://{authority}"


PUBLIC_BASE_URL = parse(os.environ.get("PUBLIC_BASE_URL", DEFAULT), HTTPS_ONLY)


def public_base_url() -> str:
    return PUBLIC_BASE_URL
