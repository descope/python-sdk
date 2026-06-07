from __future__ import annotations

from typing import TYPE_CHECKING

from descope.http_client import HTTPClient

if TYPE_CHECKING:
    from descope.async_http_client import AsyncHTTPClient


class HTTPBase:
    """Base class for classes that only need HTTP access."""

    def __init__(self, http_client: HTTPClient):
        self._http = http_client


class AsyncHTTPBase:
    """Base for async management classes."""

    def __init__(self, http_client: AsyncHTTPClient):
        self._http = http_client
