# This is not part of the public API but a code helper
from __future__ import annotations

import contextvars
import os
import platform
import ssl
import threading
from functools import cached_property
from http import HTTPStatus
from importlib.metadata import version

import certifi
import httpx

from descope.common import (
    DEFAULT_BASE_URL,
    DEFAULT_DOMAIN,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_URL_PREFIX,
)
from descope.exceptions import (
    API_RATE_LIMIT_RETRY_AFTER_HEADER,
    ERROR_TYPE_API_RATE_LIMIT,
    ERROR_TYPE_INVALID_ARGUMENT,
    ERROR_TYPE_SERVER_ERROR,
    AuthException,
    RateLimitException,
)


def sdk_version():
    return version("descope")


# Longest non-JSON body echoed into str()/repr() of a response
_MAX_TEXT_PREVIEW = 200

# HTTP status codes that should trigger automatic retries
_RETRY_STATUS_CODES = {503, 520, 521, 522, 524, 530}
# Delays in seconds between retries: first retry after 100ms, subsequent retries after 5s
_RETRY_DELAYS_SECONDS = [0.1, 5.0, 5.0]

_default_headers = {
    "Content-Type": "application/json",
    "x-descope-sdk-name": "python",
    "x-descope-sdk-python-version": platform.python_version(),
    "x-descope-sdk-version": sdk_version(),
}


class DescopeResponse:
    """
    Wrapper around httpx.Response that provides dict-like access to JSON data
    while preserving access to HTTP metadata (headers, status_code, etc.).

    This allows backward compatibility (acting like a dict) while exposing
    HTTP metadata like cf-ray headers for debugging.

    Members that need the parsed body (``json()``, ``__getitem__``, ``get``,
    ``keys``, ``values``, ``items``, ``__len__``, ``__iter__``, ``__contains__``)
    raise on a non-JSON body. Inspecting the response itself never does:
    ``bool()`` is always True, and ``str()``/``repr()`` fall back to the raw
    text, so a response is always loggable. Use ``is_json`` to check first.
    """

    def __init__(self, response: httpx.Response):
        self.raw = response

    @cached_property
    def _json_data(self):
        return self.raw.json()

    def json(self):
        """Get the parsed JSON response, cached after first access."""
        return self._json_data

    @cached_property
    def is_json(self) -> bool:
        """True if the response body can be parsed as JSON."""
        try:
            self.json()
        except ValueError:
            return False
        return True

    # Dict-like interface for backward compatibility
    def __getitem__(self, key):
        return self.json()[key]

    def __contains__(self, key):
        return key in self.json()

    def keys(self):
        return self.json().keys()

    def values(self):
        return self.json().values()

    def items(self):
        return self.json().items()

    def get(self, key, default=None):
        return self.json().get(key, default)

    def _text_preview(self):
        """Bounded view of a non-JSON body: its size is upstream-controlled."""
        text = self.raw.text
        if len(text) <= _MAX_TEXT_PREVIEW:
            return text
        return f"{text[:_MAX_TEXT_PREVIEW]}... ({len(text)} chars, use .text for the full body)"

    # Inspection dunders never parse-fail: a non-JSON body (an nginx 502 HTML
    # page, for example) must still be loggable and truthy as a response object.
    def __str__(self):
        try:
            return str(self.json())
        except ValueError:
            return self._text_preview()

    def __repr__(self):
        try:
            return f"DescopeResponse({repr(self.json())})"
        except ValueError:
            return f"DescopeResponse(status_code={self.raw.status_code}, text={self._text_preview()!r})"

    def __bool__(self):
        # A response object is always truthy: truthiness answers "did I get a
        # response", not "is the body non-empty". Must stay explicit — without
        # it Python falls back to __len__, which parses the body.
        return True

    def __len__(self):
        return len(self.json())

    def __eq__(self, other):
        try:
            if isinstance(other, DescopeResponse):
                return self.json() == other.json()
            return self.json() == other
        except ValueError:
            return self is other

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        return iter(self.json())

    # HTTP metadata properties
    @property
    def headers(self):
        """Access response headers (e.g., response.headers.get('cf-ray'))."""
        return self.raw.headers

    @property
    def status_code(self):
        """HTTP status code."""
        return self.raw.status_code

    @property
    def cookies(self):
        """Response cookies."""
        return self.raw.cookies

    @property
    def text(self):
        """Raw response text."""
        return self.raw.text

    @property
    def content(self):
        """Raw response content (bytes)."""
        return self.raw.content

    @property
    def url(self):
        """Request URL."""
        return self.raw.url

    @property
    def ok(self):
        """True if status code indicates success (2xx)."""
        return self.raw.is_success


class ThreadLocalLastResponseStore:
    """One last-response slot, isolated per thread."""

    def __init__(self) -> None:
        self._local = threading.local()

    def set(self, response: DescopeResponse) -> None:
        self._local.last_response = response

    def get(self) -> DescopeResponse | None:
        return getattr(self._local, "last_response", None)


class ContextVarLastResponseStore:
    """One last-response slot, isolated per async task.

    ContextVar rather than threading.local: every asyncio task runs on the same
    event-loop thread, so a thread-local slot would be a single slot shared by
    all concurrent tasks.
    """

    def __init__(self) -> None:
        self._var: contextvars.ContextVar[DescopeResponse | None] = contextvars.ContextVar(
            "descope_async_last_response", default=None
        )

    def set(self, response: DescopeResponse) -> None:
        self._var.set(response)

    def get(self) -> DescopeResponse | None:
        return self._var.get()


class HTTPClientBase:
    """Shared, I/O-free base for HTTP client classes.

    Holds only validation guards, SSL setup, header composition, and response
    parsing — no network I/O, no ``__init__`` transport.  The two concrete
    subclasses add the network layer:

    - ``HTTPClient(HTTPClientBase)`` — sync, uses httpx module-level functions
    - ``HTTPClientAsync(HTTPClientBase)`` — async, uses ``httpx.AsyncClient``
    """

    def __init__(
        self,
        project_id: str,
        base_url: str | None = None,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        secure: bool = True,
        management_key: str | None = None,
        verbose: bool = False,
    ) -> None:
        if not project_id:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                (
                    "Project ID is required to initialize HTTP client"
                    "Set environment variable DESCOPE_PROJECT_ID or pass your Project ID to the init function."
                ),
            )

        env_base = os.getenv("DESCOPE_BASE_URI")
        self.base_url = base_url or env_base or self.base_url_for_project_id(project_id)

        self.project_id = project_id
        self.timeout_seconds = timeout_seconds
        self.secure = secure
        self.management_key = management_key
        self.verbose = verbose
        # Populated by the license handshake when a management key is configured.
        # Sent in the x-descope-license header so Cloudflare can apply the right
        # rate limit bucket per customer tier.
        self.rate_limit_tier: str | None = None

        self.client_verify: bool | ssl.SSLContext = False
        if secure:
            ssl_ctx = ssl.create_default_context(
                cafile=os.environ.get("SSL_CERT_FILE", certifi.where()),
                capath=os.environ.get("SSL_CERT_DIR"),
            )
            if os.environ.get("REQUESTS_CA_BUNDLE"):
                ssl_ctx.load_verify_locations(cafile=os.environ.get("REQUESTS_CA_BUNDLE"))
            self.client_verify = ssl_ctx

    @staticmethod
    def base_url_for_project_id(project_id: str) -> str:
        if len(project_id) >= 32:
            region = project_id[1:5]
            return ".".join([DEFAULT_URL_PREFIX, region, DEFAULT_DOMAIN])
        return DEFAULT_BASE_URL

    def get_default_headers(self, pswd: str | None = None) -> dict:
        return self._get_default_headers(pswd)

    def _parse_retry_after(self, headers) -> int:
        try:
            return int(headers.get(API_RATE_LIMIT_RETRY_AFTER_HEADER, 0))
        except (ValueError, TypeError):
            return 0

    def _raise_rate_limit_exception(self, response):
        try:
            resp = response.json()
            raise RateLimitException(
                resp.get("errorCode", HTTPStatus.TOO_MANY_REQUESTS),
                ERROR_TYPE_API_RATE_LIMIT,
                resp.get("errorDescription", ""),
                resp.get("errorMessage", ""),
                rate_limit_parameters={API_RATE_LIMIT_RETRY_AFTER_HEADER: self._parse_retry_after(response.headers)},
            )
        except RateLimitException:
            raise
        except Exception:
            raise RateLimitException(
                status_code=HTTPStatus.TOO_MANY_REQUESTS,
                error_type=ERROR_TYPE_API_RATE_LIMIT,
                error_message=ERROR_TYPE_API_RATE_LIMIT,
                error_description=ERROR_TYPE_API_RATE_LIMIT,
            )

    def _raise_from_response(self, response):
        if response.is_success:
            return
        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            self._raise_rate_limit_exception(response)
        raise AuthException(
            response.status_code,
            ERROR_TYPE_SERVER_ERROR,
            response.text,
        )

    def _get_default_headers(self, pswd: str | None = None):
        headers = _default_headers.copy()
        headers["x-descope-project-id"] = self.project_id
        bearer = self.project_id
        if pswd:
            bearer = f"{self.project_id}:{pswd}"
        if self.management_key:
            bearer = f"{bearer}:{self.management_key}"
        headers["Authorization"] = f"Bearer {bearer}"
        if self.rate_limit_tier:
            headers["x-descope-license"] = self.rate_limit_tier
        return headers
