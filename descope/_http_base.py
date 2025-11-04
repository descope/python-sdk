from __future__ import annotations

from descope.http_client import HTTPClient


class HTTPBase:
    """Base class for classes that only need HTTP access."""

    def __init__(self, http_client: HTTPClient):
        self._http = http_client
