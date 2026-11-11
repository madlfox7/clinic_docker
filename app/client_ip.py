from fastapi import Request

from db import contains_nul, within_length


def client_source(request: Request) -> str:
    client_source = request.headers.get("x-real-ip")
    if (
        not client_source
        or contains_nul(client_source)
        or not within_length(client_source, 128)
    ):
        return request.client.host if request.client else "unknown"
    return client_source
