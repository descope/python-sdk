from __future__ import annotations

import threading
import time
from typing import cast

import httpx

from descope._http_client_base import (
    _RETRY_DELAYS_SECONDS,
    _RETRY_STATUS_CODES,
    DEFAULT_TIMEOUT_SECONDS,
    DescopeResponse,
    HTTPClientBase,
)


class HTTPClient(HTTPClientBase):
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
        super().__init__(
            project_id,
            base_url,
            timeout_seconds=timeout_seconds,
            secure=secure,
            management_key=management_key,
            verbose=verbose,
        )
        self._thread_local = threading.local()

    # ------------- public API -------------
    def get(
        self,
        uri: str,
        *,
        params=None,
        allow_redirects: bool | None = True,
        pswd: str | None = None,
    ) -> httpx.Response:
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
    ) -> httpx.Response:
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
    ) -> httpx.Response:
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
    ) -> httpx.Response:
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
    ) -> httpx.Response:
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
        return getattr(self._thread_local, "last_response", None)

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
