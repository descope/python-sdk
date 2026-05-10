from __future__ import annotations

import asyncio
import contextvars
import os
import platform
import ssl
import threading
import time
from http import HTTPStatus
from importlib.metadata import version
from typing import Awaitable, cast

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


# HTTP status codes that should trigger automatic retries
_RETRY_STATUS_CODES = {503, 521, 522, 524, 530}
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
    """

    def __init__(self, response: httpx.Response):
        self.raw = response
        self._json_data = None

    def json(self):
        """Get the parsed JSON response, cached after first access."""
        if self._json_data is None:
            self._json_data = self.raw.json()
        return self._json_data

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

    def __str__(self):
        return str(self.json())

    def __repr__(self):
        return f"DescopeResponse({repr(self.json())})"

    def __bool__(self):
        return bool(self.json())

    def __len__(self):
        return len(self.json())

    def __eq__(self, other):
        if isinstance(other, DescopeResponse):
            return self.json() == other.json()
        return self.json() == other

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


class HTTPClient:
    def __init__(
        self,
        project_id: str,
        base_url: str | None = None,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        secure: bool = True,
        management_key: str | None = None,
        verbose: bool = False,
        async_mode_experimental: bool = False,
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

        # Prefer explicitly provided base_url, then env var, then computed default
        env_base = os.getenv("DESCOPE_BASE_URI")
        self.base_url = base_url or env_base or self.base_url_for_project_id(project_id)

        self.project_id = project_id
        self.timeout_seconds = timeout_seconds
        self.secure = secure
        self.management_key = management_key
        self.verbose = verbose
        # Reserved for the future global async rollout (see big-plan.md "Final stage")
        self.async_mode_experimental = async_mode_experimental
        self._thread_local = threading.local()
        self._async_last_response: contextvars.ContextVar[DescopeResponse | None] = contextvars.ContextVar(
            "last_response", default=None
        )

        # Setup SSL verification for httpx (backwards compatibility with requests)
        self.client_verify: bool | ssl.SSLContext = False
        if secure:
            ssl_ctx = ssl.create_default_context(
                cafile=os.environ.get("SSL_CERT_FILE", certifi.where()),
                capath=os.environ.get("SSL_CERT_DIR"),
            )
            if os.environ.get("REQUESTS_CA_BUNDLE"):
                ssl_ctx.load_verify_locations(cafile=os.environ.get("REQUESTS_CA_BUNDLE"))
            self.client_verify = ssl_ctx

        self._async_client: httpx.AsyncClient | None = None
        if async_mode_experimental:
            self._async_client = httpx.AsyncClient(
                verify=self.client_verify,
                timeout=self.timeout_seconds,
            )

    # ------------- public API -------------
    def get(
        self,
        uri: str,
        *,
        params=None,
        allow_redirects: bool | None = True,
        pswd: str | None = None,
        async_mode: bool = False,
    ) -> httpx.Response | Awaitable[httpx.Response]:
        if async_mode:
            if self._async_client is None:
                raise AuthException(
                    400,
                    ERROR_TYPE_INVALID_ARGUMENT,
                    "async_mode requires async_mode_experimental=True at client construction",
                )
            return self._async_get(uri, params=params, allow_redirects=allow_redirects, pswd=pswd)
        response = self._execute_with_retry(
            lambda: httpx.get(
                f"{self.base_url}{uri}",
                headers=self._get_default_headers(pswd),
                params=params,
                follow_redirects=cast(bool, allow_redirects),
                verify=self.client_verify,
                timeout=self.timeout_seconds,
            )
        )
        if self.verbose:
            self._thread_local.last_response = DescopeResponse(response)
        self._raise_from_response(response)
        return response

    def post(
        self,
        uri: str,
        *,
        body: dict | list[dict] | list[str] | None = None,
        params=None,
        pswd: str | None = None,
        base_url: str | None = None,
        async_mode: bool = False,
    ) -> httpx.Response | Awaitable[httpx.Response]:
        if async_mode:
            if self._async_client is None:
                raise AuthException(
                    400,
                    ERROR_TYPE_INVALID_ARGUMENT,
                    "async_mode requires async_mode_experimental=True at client construction",
                )
            return self._async_post(uri, body=body, params=params, pswd=pswd, base_url=base_url)
        response = self._execute_with_retry(
            lambda: httpx.post(
                f"{base_url or self.base_url}{uri}",
                headers=self._get_default_headers(pswd),
                json=body,
                follow_redirects=False,
                verify=self.client_verify,
                params=params,
                timeout=self.timeout_seconds,
            )
        )
        if self.verbose:
            self._thread_local.last_response = DescopeResponse(response)
        self._raise_from_response(response)
        return response

    def put(
        self,
        uri: str,
        *,
        body: dict | list[dict] | list[str] | None = None,
        params=None,
        pswd: str | None = None,
        async_mode: bool = False,
    ) -> httpx.Response | Awaitable[httpx.Response]:
        if async_mode:
            if self._async_client is None:
                raise AuthException(
                    400,
                    ERROR_TYPE_INVALID_ARGUMENT,
                    "async_mode requires async_mode_experimental=True at client construction",
                )
            return self._async_put(uri, body=body, params=params, pswd=pswd)
        response = self._execute_with_retry(
            lambda: httpx.put(
                f"{self.base_url}{uri}",
                headers=self._get_default_headers(pswd),
                json=body,
                follow_redirects=False,
                verify=self.client_verify,
                params=params,
                timeout=self.timeout_seconds,
            )
        )
        self._raise_from_response(response)
        return response

    def patch(
        self,
        uri: str,
        *,
        body: dict | list[dict] | list[str] | None,
        params=None,
        pswd: str | None = None,
        async_mode: bool = False,
    ) -> httpx.Response | Awaitable[httpx.Response]:
        if async_mode:
            if self._async_client is None:
                raise AuthException(
                    400,
                    ERROR_TYPE_INVALID_ARGUMENT,
                    "async_mode requires async_mode_experimental=True at client construction",
                )
            return self._async_patch(uri, body=body, params=params, pswd=pswd)
        response = self._execute_with_retry(
            lambda: httpx.patch(
                f"{self.base_url}{uri}",
                headers=self._get_default_headers(pswd),
                json=body,
                follow_redirects=False,
                verify=self.client_verify,
                params=params,
                timeout=self.timeout_seconds,
            )
        )
        if self.verbose:
            self._thread_local.last_response = DescopeResponse(response)
        self._raise_from_response(response)
        return response

    def delete(
        self,
        uri: str,
        *,
        params=None,
        pswd: str | None = None,
        async_mode: bool = False,
    ) -> httpx.Response | Awaitable[httpx.Response]:
        if async_mode:
            if self._async_client is None:
                raise AuthException(
                    400,
                    ERROR_TYPE_INVALID_ARGUMENT,
                    "async_mode requires async_mode_experimental=True at client construction",
                )
            return self._async_delete(uri, params=params, pswd=pswd)
        response = self._execute_with_retry(
            lambda: httpx.delete(
                f"{self.base_url}{uri}",
                params=params,
                headers=self._get_default_headers(pswd),
                follow_redirects=False,
                verify=self.client_verify,
                timeout=self.timeout_seconds,
            )
        )
        if self.verbose:
            self._thread_local.last_response = DescopeResponse(response)
        self._raise_from_response(response)
        return response

    def get_last_response(self) -> DescopeResponse | None:
        """
        Get the last HTTP response when verbose mode is enabled.

        Useful for accessing HTTP metadata like headers (e.g., cf-ray),
        status codes, and raw response data for debugging.

        This method is thread-safe: each thread will receive its own
        last response when using a shared client instance.

        Returns:
            DescopeResponse: The last response if verbose mode is enabled, None otherwise.

        Example:
            client = DescopeClient(project_id, management_key, verbose=True)
            try:
                client.mgmt.user.create(login_id="u1")
            except AuthException:
                resp = client.get_last_response()
                if resp:
                    logger.error(f"cf-ray: {resp.headers.get('cf-ray')}")
        """
        async_resp = self._async_last_response.get(None)
        if async_resp is not None:
            return async_resp
        return getattr(self._thread_local, "last_response", None)

    def get_default_headers(self, pswd: str | None = None) -> dict:
        return self._get_default_headers(pswd)

    async def aclose(self) -> None:
        if self._async_client is not None:
            await self._async_client.aclose()

    # ------------- helpers -------------
    def _execute_with_retry(self, request_fn) -> httpx.Response:
        """Execute request_fn and retry on retryable status codes.

        Retries up to 3 times: first retry after 100ms, subsequent retries after 5s each.
        The prior response is closed before each retry to release the connection back to
        the pool and avoid connection exhaustion under repeated transient errors.
        """
        response = request_fn()
        for delay in _RETRY_DELAYS_SECONDS:
            if response.status_code not in _RETRY_STATUS_CODES:
                break
            response.close()
            time.sleep(delay)
            response = request_fn()
        return response

    @staticmethod
    def base_url_for_project_id(project_id: str) -> str:
        if len(project_id) >= 32:
            region = project_id[1:5]
            return ".".join([DEFAULT_URL_PREFIX, region, DEFAULT_DOMAIN])
        return DEFAULT_BASE_URL

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
        return headers

    # ------------- async helpers -------------
    async def _async_execute_with_retry(self, request_fn) -> httpx.Response:
        response = await request_fn()
        for delay in _RETRY_DELAYS_SECONDS:
            if response.status_code not in _RETRY_STATUS_CODES:
                break
            await response.aclose()
            await asyncio.sleep(delay)
            response = await request_fn()
        return response

    async def _async_get(
        self,
        uri: str,
        *,
        params=None,
        allow_redirects: bool | None = True,
        pswd: str | None = None,
    ) -> httpx.Response:
        response = await self._async_execute_with_retry(
            lambda: self._async_client.get(
                f"{self.base_url}{uri}",
                headers=self._get_default_headers(pswd),
                params=params,
                follow_redirects=cast(bool, allow_redirects),
            )
        )
        if self.verbose:
            self._async_last_response.set(DescopeResponse(response))
        self._raise_from_response(response)
        return response

    async def _async_post(
        self,
        uri: str,
        *,
        body: dict | list[dict] | list[str] | None = None,
        params=None,
        pswd: str | None = None,
        base_url: str | None = None,
    ) -> httpx.Response:
        response = await self._async_execute_with_retry(
            lambda: self._async_client.post(
                f"{base_url or self.base_url}{uri}",
                headers=self._get_default_headers(pswd),
                json=body,
                follow_redirects=False,
                params=params,
            )
        )
        if self.verbose:
            self._async_last_response.set(DescopeResponse(response))
        self._raise_from_response(response)
        return response

    async def _async_put(
        self,
        uri: str,
        *,
        body: dict | list[dict] | list[str] | None = None,
        params=None,
        pswd: str | None = None,
    ) -> httpx.Response:
        response = await self._async_execute_with_retry(
            lambda: self._async_client.put(
                f"{self.base_url}{uri}",
                headers=self._get_default_headers(pswd),
                json=body,
                follow_redirects=False,
                params=params,
            )
        )
        self._raise_from_response(response)
        return response

    async def _async_patch(
        self,
        uri: str,
        *,
        body: dict | list[dict] | list[str] | None,
        params=None,
        pswd: str | None = None,
    ) -> httpx.Response:
        response = await self._async_execute_with_retry(
            lambda: self._async_client.patch(
                f"{self.base_url}{uri}",
                headers=self._get_default_headers(pswd),
                json=body,
                follow_redirects=False,
                params=params,
            )
        )
        if self.verbose:
            self._async_last_response.set(DescopeResponse(response))
        self._raise_from_response(response)
        return response

    async def _async_delete(
        self,
        uri: str,
        *,
        params=None,
        pswd: str | None = None,
    ) -> httpx.Response:
        response = await self._async_execute_with_retry(
            lambda: self._async_client.delete(
                f"{self.base_url}{uri}",
                params=params,
                headers=self._get_default_headers(pswd),
                follow_redirects=False,
            )
        )
        if self.verbose:
            self._async_last_response.set(DescopeResponse(response))
        self._raise_from_response(response)
        return response
