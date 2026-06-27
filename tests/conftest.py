from __future__ import annotations

import asyncio
import os
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.descope_client import DescopeClient
from descope.descope_client_async import DescopeClientAsync
from tests.common import DEFAULT_BASE_URL
from tests.testutils import PUBLIC_KEY_DICT, SSLMatcher

# ---------------------------------------------------------------------------
# Claude Code sandbox workaround — DO NOT COMMIT uncommented
#
# Claude Code's sandbox routes traffic through a local SOCKS5 proxy. httpx
# picks it up automatically (trust_env=True) but socksio isn't installed, so
# async fixture construction fails with:
#   ImportError: Using SOCKS proxy, but the 'socksio' package is not installed.
#
# Uncomment the fixture below to suppress proxy pickup during the test session.
#
# @pytest.fixture(autouse=True)
# def _disable_httpx_proxy():
#     import httpx
#     _orig = httpx.AsyncClient.__init__
#     def _patched(self, *args, **kwargs):
#         kwargs.setdefault("trust_env", False)
#         _orig(self, *args, **kwargs)
#     with patch.object(httpx.AsyncClient, "__init__", _patched):
#         yield
# ---------------------------------------------------------------------------


PROJECT_ID = "dummy"


def assert_http_called(mock_http, mode, url, **kwargs):
    """Assert the patched HTTP mock was called with the given arguments.

    In sync mode, ``verify`` and ``timeout`` are passed per-call; in async mode
    they are set on the ``httpx.AsyncClient`` constructor and absent from each call.
    This helper injects them automatically for sync so test bodies stay identical.
    """
    if mode == "sync":
        kwargs.setdefault("verify", SSLMatcher())
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT_SECONDS)
    mock_http.assert_called_with(url, **kwargs)


def make_response(json_data=None, *, status=200, cookies=None):
    """Build a mock httpx.Response usable as the return value of a mocked HTTP call."""
    m = MagicMock()
    m.is_success = status < 400
    m.status_code = status
    m.json.return_value = json_data or {}
    cm = MagicMock()
    cm.get = MagicMock(side_effect=lambda k, d=None: (cookies or {}).get(k, d))
    m.cookies = cm
    m.headers = {}
    m.text = str(json_data or "")
    return m


class UnifiedClient:
    """
    Wraps DescopeClient or DescopeClientAsync with a uniform interface so test
    bodies can run unchanged against both variants.

    - ``invoke(maybe_coro)`` — awaits async calls, passes through sync values.
    - ``mock_get/mock_post(response)`` — patches the right HTTP layer per mode.
    """

    def __init__(self, mode: str, raw):
        self.mode = mode  # "sync" | "async"
        self._raw = raw

    def __getattr__(self, name):
        return getattr(self._raw, name)

    async def invoke(self, maybe_coro):
        """Uniformly run a sync return value or an async coroutine."""
        if asyncio.iscoroutine(maybe_coro):
            return await maybe_coro
        return maybe_coro

    @contextmanager
    def mock_get(self, response):
        with self._patch_ctx("get", response) as m:
            yield m

    @contextmanager
    def mock_post(self, response):
        with self._patch_ctx("post", response) as m:
            yield m

    @contextmanager
    def mock_mgmt_post(self, response):
        with self._patch_ctx("post", response, mgmt=True) as m:
            yield m

    @contextmanager
    def mock_mgmt_get(self, response):
        with self._patch_ctx("get", response, mgmt=True) as m:
            yield m

    @contextmanager
    def mock_mgmt_put(self, response):
        with self._patch_ctx("put", response, mgmt=True) as m:
            yield m

    @contextmanager
    def mock_mgmt_delete(self, response):
        with self._patch_ctx("delete", response, mgmt=True) as m:
            yield m

    @contextmanager
    def mock_mgmt_patch(self, response):
        with self._patch_ctx("patch", response, mgmt=True) as m:
            yield m

    @contextmanager
    def mock_mgmt_by_token_post(self, response):
        with self._patch_ctx("post", response, mgmt_by_token=True) as m:
            yield m

    def _patch_ctx(self, method: str, response, *, mgmt: bool = False, mgmt_by_token: bool = False):
        """
        Patch the right layer per mode:

        - sync  → ``httpx.<method>`` (the module-level function HTTPClient calls).
        - async → ``_async_client.<method>`` on the AsyncHTTPClient instance.
        """
        if self.mode == "sync":
            return patch(f"httpx.{method}", return_value=response)
        if mgmt_by_token:
            target = self._raw._mgmt._outbound_application_by_token._http
        elif mgmt:
            target = self._raw._mgmt._http
        else:
            target = self._raw._auth_http
        return patch.object(target._async_client, method, AsyncMock(return_value=response))


class ClientFactory:
    """
    Use via the ``client_factory`` fixture when a test must control construction
    arguments directly (bad project_id, jwt_validation_leeway, auth_management_key…).

    ``make(*args, **kwargs)`` returns a UnifiedClient on success or propagates
    the construction exception — so tests that expect failure just wrap the call
    in ``pytest.raises``.
    """

    def __init__(self, mode: str):
        self.mode = mode
        self._async_clients: list = []  # tracked so teardown can aclose them

    def make(self, *args, **kwargs) -> UnifiedClient:
        """Construct a (Async)DescopeClient and wrap it in UnifiedClient."""
        if self.mode == "sync":
            return UnifiedClient("sync", DescopeClient(*args, **kwargs))
        client = DescopeClientAsync(*args, **kwargs)
        self._async_clients.append(client)
        return UnifiedClient("async", client)


@pytest.fixture(params=["sync", "async"])
async def descope_client(request):
    """
    Parametrized fixture — yields a UnifiedClient wrapping DescopeClient (sync)
    or DescopeClientAsync (async).  Each consuming test runs twice.
    """
    # Save and restore DESCOPE_BASE_URI so it doesn't leak into other tests.
    _prev = os.environ.get("DESCOPE_BASE_URI")
    os.environ["DESCOPE_BASE_URI"] = DEFAULT_BASE_URL
    try:
        if request.param == "sync":
            yield UnifiedClient("sync", DescopeClient(PROJECT_ID, PUBLIC_KEY_DICT))
        else:
            raw = DescopeClientAsync(PROJECT_ID, PUBLIC_KEY_DICT)
            yield UnifiedClient("async", raw)
            await raw.aclose()  # release the underlying httpx.AsyncClient cleanly
    finally:
        if _prev is None:
            os.environ.pop("DESCOPE_BASE_URI", None)
        else:
            os.environ["DESCOPE_BASE_URI"] = _prev


@pytest.fixture(params=["sync", "async"])
async def client_factory(request):
    """
    Parametrized factory fixture — yields a ClientFactory so tests can
    construct clients with custom arguments (bad keys, leeway, mgmt key, …).
    Each consuming test runs twice (sync + async).
    """
    _prev = os.environ.get("DESCOPE_BASE_URI")
    os.environ["DESCOPE_BASE_URI"] = DEFAULT_BASE_URL
    factory = ClientFactory(request.param)
    try:
        yield factory
    finally:
        for raw in factory._async_clients:
            await raw.aclose()
        if _prev is None:
            os.environ.pop("DESCOPE_BASE_URI", None)
        else:
            os.environ["DESCOPE_BASE_URI"] = _prev
