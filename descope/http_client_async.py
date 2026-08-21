from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, cast

import httpx

from descope._http_client_base import (
    _RETRY_DELAYS_SECONDS,
    _RETRY_STATUS_CODES,
    DEFAULT_TIMEOUT_SECONDS,
    ContextVarLastResponseStore,
    DescopeResponse,
    HTTPClientBase,
)


class HTTPClientAsync(HTTPClientBase):
    def __init__(
        self,
        project_id: str,
        base_url: str | None = None,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        secure: bool = True,
        management_key: str | None = None,
        verbose: bool = False,
        last_response_store: ContextVarLastResponseStore | None = None,
    ) -> None:
        super().__init__(
            project_id,
            base_url,
            timeout_seconds=timeout_seconds,
            secure=secure,
            management_key=management_key,
            verbose=verbose,
        )
        self._async_client = httpx.AsyncClient(
            verify=self.client_verify,
            timeout=self.timeout_seconds,
        )
        self.last_response_store = last_response_store or ContextVarLastResponseStore()
        # Optional one-shot async hook invoked before the first request goes
        # out. Used by ``DescopeClientAsync`` to lazily run the license
        # handshake on ``_mgmt_http`` without blocking the event loop in
        # ``__init__``. The hook is expected to be idempotent — it will be
        # awaited on every request, but should fast-path after the first run.
        self._pre_request_hook: Callable[[], Awaitable[None]] | None = None

    async def get(
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
            self.last_response_store.set(DescopeResponse(response))
        self._raise_from_response(response)
        return response

    async def post(
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
            self.last_response_store.set(DescopeResponse(response))
        self._raise_from_response(response)
        return response

    async def put(
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
        if self.verbose:
            self.last_response_store.set(DescopeResponse(response))
        self._raise_from_response(response)
        return response

    async def patch(
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
            self.last_response_store.set(DescopeResponse(response))
        self._raise_from_response(response)
        return response

    async def delete(
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
            self.last_response_store.set(DescopeResponse(response))
        self._raise_from_response(response)
        return response

    def get_last_response(self) -> DescopeResponse | None:
        """
        Get the last HTTP response for the current async task when verbose mode is enabled.

        Uses a ContextVar (not threading.local) so each concurrent async task sees its
        own last response, even though all tasks share one event-loop thread.
        """
        return self.last_response_store.get()

    async def _async_execute_with_retry(self, request_fn) -> httpx.Response:
        if self._pre_request_hook is not None:
            await self._pre_request_hook()
        response = await request_fn()
        for delay in _RETRY_DELAYS_SECONDS:
            if response.status_code not in _RETRY_STATUS_CODES:
                break
            await response.aclose()
            await asyncio.sleep(delay)
            response = await request_fn()
        return response

    async def aclose(self) -> None:
        await self._async_client.aclose()

    async def __aenter__(self) -> HTTPClientAsync:
        return self

    async def __aexit__(self, *args) -> None:
        await self.aclose()
