# This is not part of the public API but a code helper
from __future__ import annotations

from typing import TYPE_CHECKING

from descope.auth import Auth

if TYPE_CHECKING:
    from descope.http_client_async import HTTPClientAsync


class AuthBase:
    """Base class for classes having auth"""

    def __init__(self, auth: Auth):
        self._auth = auth
        self._http = auth.http_client


class AsyncAuthBase:
    """Base for async auth-method classes.

    Holds a sync Auth instance (used only for pure-computation helpers —
    generate_jwt_response, validate_email, extract_masked_address, etc. — no I/O)
    and an AsyncHTTPClient for all network calls.
    """

    def __init__(self, auth: Auth, http: HTTPClientAsync):
        self._auth = auth
        self._http = http
