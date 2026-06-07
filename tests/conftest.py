from __future__ import annotations

import asyncio
import os
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from descope.async_descope_client import AsyncDescopeClient
from descope.descope_client import DescopeClient
from tests.common import DEFAULT_BASE_URL

# ---------------------------------------------------------------------------
# Shared test constants
# ---------------------------------------------------------------------------

PROJECT_ID = "dummy"

# ES384 key — kid=P2CuC9yv2UGtGI1o84gCZEb9qEQW, used by the JWT test tokens throughout
# test_descope_client.py and test_descope_client_unified.py.
PUBLIC_KEY_DICT = {
    "alg": "ES384",
    "crv": "P-384",
    "kid": "P2CuC9yv2UGtGI1o84gCZEb9qEQW",
    "kty": "EC",
    "use": "sig",
    "x": "DCjjyS7blnEmenLyJVwmH6yMnp7MlEggfk1kLtOv_Khtpps_Mq4K9brqsCwQhGUP",
    "y": "xKy4IQ2FaLEzrrl1KE5mKbioLhj1prYFk1itdTOr6Xpy1fgq86kC7v-Y2F2vpcDc",
}


# ---------------------------------------------------------------------------
# Response factory
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# UnifiedClient — mode-agnostic wrapper for sync / async clients
# ---------------------------------------------------------------------------


class UnifiedClient:
    """
    Wraps DescopeClient or AsyncDescopeClient with a uniform interface so test
    bodies can run unchanged against both variants.

    - ``invoke(maybe_coro)`` — awaits async calls, passes through sync values.
    - ``mock_get/mock_post(response)`` — patches the right HTTP layer per mode.
    """

    def __init__(self, mode: str, raw):
        self.mode = mode  # "sync" | "async"
        self._raw = raw

    def __getattr__(self, name):
        return getattr(self._raw, name)

    # --- Execution ---

    async def invoke(self, maybe_coro):
        """Uniformly run a sync return value or an async coroutine."""
        if asyncio.iscoroutine(maybe_coro):
            return await maybe_coro
        return maybe_coro

    # --- Mock helpers ---

    @contextmanager
    def mock_get(self, response):
        with self._patch_ctx("get", response) as m:
            yield m

    @contextmanager
    def mock_post(self, response):
        with self._patch_ctx("post", response) as m:
            yield m

    # --- Internals ---

    def _patch_ctx(self, method: str, response):
        """
        Patch the right layer per mode:

        - sync  → ``httpx.<method>`` (the module-level function HTTPClient calls).
        - async → ``_async_client.<method>`` on the AsyncHTTPClient instance.
        """
        if self.mode == "sync":
            return patch(f"httpx.{method}", return_value=response)
        return patch.object(
            self._raw._auth_http._async_client,
            method,
            AsyncMock(return_value=response),
        )


# ---------------------------------------------------------------------------
# ClientFactory — for tests that need custom construction arguments
# ---------------------------------------------------------------------------


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

    def make(self, *args, **kwargs) -> "UnifiedClient":
        """Construct a (Async)DescopeClient and wrap it in UnifiedClient."""
        if self.mode == "sync":
            return UnifiedClient("sync", DescopeClient(*args, **kwargs))
        client = AsyncDescopeClient(*args, **kwargs)
        self._async_clients.append(client)
        return UnifiedClient("async", client)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(params=["sync", "async"])
async def descope_client(request):
    """
    Parametrized fixture — yields a UnifiedClient wrapping DescopeClient (sync)
    or AsyncDescopeClient (async).  Each consuming test runs twice.
    """
    # Save and restore DESCOPE_BASE_URI so it doesn't leak into other tests.
    _prev = os.environ.get("DESCOPE_BASE_URI")
    os.environ["DESCOPE_BASE_URI"] = DEFAULT_BASE_URL
    try:
        if request.param == "sync":
            yield UnifiedClient("sync", DescopeClient(PROJECT_ID, PUBLIC_KEY_DICT))
        else:
            raw = AsyncDescopeClient(PROJECT_ID, PUBLIC_KEY_DICT)
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
