"""Tests for AuthAsync — the async sibling of Auth.

Covers the parts that differ from sync ``Auth``: async fetch, ``ensure_keys``
idempotency + lock serialization, and that the async I/O paths never call
module-level sync ``httpx`` functions.

Behavior parity with sync ``Auth`` (validation logic, audience handling, etc.)
is covered indirectly by the sync+async parametrized suite under
``tests/test_auth.py`` and ``tests/test_descope_client.py`` once
``DescopeClientAsync`` is wired to ``AuthAsync`` in step 5.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from descope.auth_async import AuthAsync
from descope.common import EndpointsV1, EndpointsV2
from descope.exceptions import AuthException
from descope.http_client_async import HTTPClientAsync
from tests.testutils import PUBLIC_KEY_DICT, VALID_REFRESH_TOKEN, VALID_SESSION_TOKEN

PROJECT_ID = "P2CuC9yv2UGtGI1o84gCZEb9qEQW"
JWKS_BODY = json.dumps({"keys": [PUBLIC_KEY_DICT]})


def _make_http_client() -> HTTPClientAsync:
    """Construct an HTTPClientAsync without a running loop (mirrors production usage)."""
    return HTTPClientAsync(PROJECT_ID, base_url="https://example.com", secure=False)


def _jwks_response() -> MagicMock:
    resp = MagicMock()
    resp.text = JWKS_BODY
    resp.status_code = 200
    resp.is_success = True
    resp.headers = {}
    return resp


class TestAuthAsyncEnsureKeys:
    @pytest.mark.asyncio
    async def test_ensure_keys_fetches_when_cache_empty(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, http_client=http)
        try:
            with patch.object(http._async_client, "get", AsyncMock(return_value=_jwks_response())) as mock_get:
                await auth.ensure_keys()
                assert mock_get.call_count == 1
                assert PUBLIC_KEY_DICT["kid"] in auth.public_keys
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_ensure_keys_no_op_when_kid_present(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, public_key=PUBLIC_KEY_DICT, http_client=http)
        try:
            with patch.object(http._async_client, "get", AsyncMock(return_value=_jwks_response())) as mock_get:
                await auth.ensure_keys(PUBLIC_KEY_DICT["kid"])
                assert mock_get.call_count == 0
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_ensure_keys_refetches_on_unknown_kid(self):
        """Mirrors sync Auth behavior: cache miss for a kid triggers a refetch."""
        http = _make_http_client()
        # Seed cache with a key whose kid won't match what we ask for.
        stale_key = dict(PUBLIC_KEY_DICT, kid="STALE")
        auth = AuthAsync(PROJECT_ID, public_key=stale_key, http_client=http)
        try:
            with patch.object(http._async_client, "get", AsyncMock(return_value=_jwks_response())) as mock_get:
                await auth.ensure_keys(PUBLIC_KEY_DICT["kid"])
                assert mock_get.call_count == 1
                assert PUBLIC_KEY_DICT["kid"] in auth.public_keys
                # Stale kid is replaced by the fresh JWKS payload.
                assert "STALE" not in auth.public_keys
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_ensure_keys_serializes_concurrent_callers(self):
        """N concurrent ensure_keys() calls on an empty cache must fetch exactly once."""
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, http_client=http)
        try:
            # Slow the fetch so concurrent tasks pile up at the lock.
            async def _slow_get(*args, **kwargs):
                await asyncio.sleep(0.05)
                return _jwks_response()

            with patch.object(http._async_client, "get", AsyncMock(side_effect=_slow_get)) as mock_get:
                await asyncio.gather(*(auth.ensure_keys() for _ in range(10)))
                assert mock_get.call_count == 1
        finally:
            await http.aclose()


class TestAuthAsyncFetch:
    @pytest.mark.asyncio
    async def test_fetch_public_keys_uses_async_http_not_module_httpx(self):
        """Regression guard: AuthAsync must not call module-level httpx.get."""
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, http_client=http)
        try:
            with patch.object(http._async_client, "get", AsyncMock(return_value=_jwks_response())):
                with patch("httpx.get", side_effect=AssertionError("sync httpx.get must not be called")):
                    await auth._fetch_public_keys()
            assert PUBLIC_KEY_DICT["kid"] in auth.public_keys
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_fetch_public_keys_invalid_jwks_raises(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, http_client=http)
        try:
            bad = MagicMock()
            bad.text = "not json"
            bad.status_code = 200
            bad.is_success = True
            bad.headers = {}
            with patch.object(http._async_client, "get", AsyncMock(return_value=bad)):
                with pytest.raises(AuthException):
                    await auth._fetch_public_keys()
        finally:
            await http.aclose()


class TestAuthAsyncValidate:
    @pytest.mark.asyncio
    async def test_validate_token_sync_raises_when_keys_not_warm(self):
        """The sync _validate_token must NOT fetch — that's ensure_keys's job."""
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, http_client=http)
        try:
            with pytest.raises(AuthException):
                auth._validate_token(VALID_SESSION_TOKEN)
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_validate_token_async_warms_then_validates(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, http_client=http)
        try:
            with patch.object(http._async_client, "get", AsyncMock(return_value=_jwks_response())) as mock_get:
                claims = await auth.validate_token(VALID_SESSION_TOKEN)
                assert mock_get.call_count == 1
                assert claims["jwt"] == VALID_SESSION_TOKEN
                assert claims["iss"] == PROJECT_ID
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_validate_token_empty_raises(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, http_client=http)
        try:
            with pytest.raises(AuthException):
                await auth.validate_token("")
        finally:
            await http.aclose()


class TestAuthAsyncSessionFlows:
    @pytest.mark.asyncio
    async def test_validate_session_returns_jwt_response(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, public_key=PUBLIC_KEY_DICT, http_client=http)
        try:
            result = await auth.validate_session(VALID_SESSION_TOKEN)
            assert result["projectId"] == PROJECT_ID
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_refresh_session_no_blocking_httpx_call(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, public_key=PUBLIC_KEY_DICT, http_client=http)
        try:
            refresh_response = MagicMock()
            refresh_response.json.return_value = {
                "sessionJwt": VALID_SESSION_TOKEN,
                "refreshJwt": VALID_REFRESH_TOKEN,
            }
            refresh_response.cookies = MagicMock()
            refresh_response.cookies.get = MagicMock(return_value=None)
            refresh_response.status_code = 200
            refresh_response.is_success = True
            refresh_response.headers = {}

            with (
                patch.object(http._async_client, "post", AsyncMock(return_value=refresh_response)) as mock_post,
                patch("httpx.get", side_effect=AssertionError("sync httpx.get must not be called")),
                patch("httpx.post", side_effect=AssertionError("sync httpx.post must not be called")),
            ):
                result = await auth.refresh_session(VALID_REFRESH_TOKEN)
                assert result["projectId"] == PROJECT_ID
                # Confirm we hit the refresh endpoint via the async client.
                args, kwargs = mock_post.call_args
                assert args[0].endswith(EndpointsV1.refresh_token_path)
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_select_tenant_requires_refresh_token(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, public_key=PUBLIC_KEY_DICT, http_client=http)
        try:
            with pytest.raises(AuthException):
                await auth.select_tenant("t1", "")
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_refresh_session_requires_token(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, public_key=PUBLIC_KEY_DICT, http_client=http)
        try:
            with pytest.raises(AuthException):
                await auth.refresh_session("")
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_validate_and_refresh_session_returns_when_session_valid(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, public_key=PUBLIC_KEY_DICT, http_client=http)
        try:
            result = await auth.validate_and_refresh_session(VALID_SESSION_TOKEN, VALID_REFRESH_TOKEN)
            assert result["projectId"] == PROJECT_ID
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_validate_and_refresh_session_falls_back_to_refresh(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, public_key=PUBLIC_KEY_DICT, http_client=http)
        try:
            refresh_response = MagicMock()
            refresh_response.json.return_value = {
                "sessionJwt": VALID_SESSION_TOKEN,
                "refreshJwt": VALID_REFRESH_TOKEN,
            }
            refresh_response.cookies = MagicMock()
            refresh_response.cookies.get = MagicMock(return_value=None)
            refresh_response.status_code = 200
            refresh_response.is_success = True
            refresh_response.headers = {}

            with patch.object(http._async_client, "post", AsyncMock(return_value=refresh_response)):
                # Use an obviously-invalid session token to force the refresh path.
                result = await auth.validate_and_refresh_session("not.a.jwt", VALID_REFRESH_TOKEN)
                assert result["projectId"] == PROJECT_ID
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_validate_and_refresh_session_requires_session(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, public_key=PUBLIC_KEY_DICT, http_client=http)
        try:
            with pytest.raises(AuthException):
                await auth.validate_and_refresh_session("", VALID_REFRESH_TOKEN)
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_validate_and_refresh_session_requires_refresh_when_session_invalid(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, public_key=PUBLIC_KEY_DICT, http_client=http)
        try:
            with pytest.raises(AuthException):
                await auth.validate_and_refresh_session("not.a.jwt", "")
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_exchange_token_requires_code(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, public_key=PUBLIC_KEY_DICT, http_client=http)
        try:
            with pytest.raises(AuthException):
                await auth.exchange_token(EndpointsV1.refresh_token_path, "")
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_exchange_token_posts_and_returns_jwt_response(self):
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, public_key=PUBLIC_KEY_DICT, http_client=http)
        try:
            exchange_response = MagicMock()
            exchange_response.json.return_value = {
                "sessionJwt": VALID_SESSION_TOKEN,
                "refreshJwt": VALID_REFRESH_TOKEN,
            }
            exchange_response.cookies = MagicMock()
            exchange_response.cookies.get = MagicMock(return_value=None)
            exchange_response.status_code = 200
            exchange_response.is_success = True
            exchange_response.headers = {}

            with patch.object(http._async_client, "post", AsyncMock(return_value=exchange_response)) as mock_post:
                result = await auth.exchange_token("/v1/oauth/exchange", "code-xyz")
                assert result["projectId"] == PROJECT_ID
                args, _ = mock_post.call_args
                assert args[0].endswith("/v1/oauth/exchange")
        finally:
            await http.aclose()

    @pytest.mark.asyncio
    async def test_ensure_keys_for_jwt_response_skips_unparseable_tokens(self):
        """Unparseable sessionJwt / refreshJwt / refresh_token must not crash key-prewarming."""
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, public_key=PUBLIC_KEY_DICT, http_client=http)
        try:
            # All tokens malformed → both try blocks must hit their except paths.
            body = {"sessionJwt": "not-a-jwt", "refreshJwt": "still-not-a-jwt"}
            await auth._ensure_keys_for_jwt_response(body, refresh_token="also-bad")

            # refreshJwt absent + refresh_token malformed → return-on-except path.
            await auth._ensure_keys_for_jwt_response({"sessionJwt": "x.y.z"}, refresh_token="bad")
        finally:
            await http.aclose()


class TestAuthAsyncJWKSLoading:
    @pytest.mark.asyncio
    async def test_fetch_public_keys_skips_invalid_entries(self):
        """JWKS entries that fail to load must be skipped; valid ones still cached."""
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, http_client=http)
        try:
            jwks_with_invalid = json.dumps({"keys": [{"kid": "broken"}, PUBLIC_KEY_DICT]})
            resp = MagicMock()
            resp.text = jwks_with_invalid
            resp.status_code = 200
            resp.is_success = True
            resp.headers = {}
            with patch.object(http._async_client, "get", AsyncMock(return_value=resp)):
                await auth._fetch_public_keys()
            assert PUBLIC_KEY_DICT["kid"] in auth.public_keys
            assert "broken" not in auth.public_keys
        finally:
            await http.aclose()


class TestAuthAsyncConstruction:
    def test_constructor_requires_project_id(self):
        http = _make_http_client()
        try:
            with pytest.raises(AuthException):
                AuthAsync("", http_client=http)
        finally:
            # Can't await aclose() outside an event loop; httpx.AsyncClient
            # is fine being garbage-collected here in a sync test.
            pass

    @pytest.mark.asyncio
    async def test_jwks_url_matches_endpoint(self):
        """Verify the fetch path hits the v2 public-key URL."""
        http = _make_http_client()
        auth = AuthAsync(PROJECT_ID, http_client=http)
        try:
            with patch.object(http._async_client, "get", AsyncMock(return_value=_jwks_response())) as mock_get:
                await auth._fetch_public_keys()
            args, _ = mock_get.call_args
            assert args[0].endswith(f"{EndpointsV2.public_key_path}/{PROJECT_ID}")
        finally:
            await http.aclose()


@pytest.mark.asyncio
async def test_async_client_constructed_outside_loop_does_not_break():
    """AsyncClient + AuthAsync construction must not require a running loop."""
    http = HTTPClientAsync(PROJECT_ID, base_url="https://example.com", secure=False)
    auth_built = AuthAsync(PROJECT_ID, http_client=http)
    # Ensure no fetch on construction.
    assert auth_built.public_keys == {}
    assert isinstance(http, HTTPClientAsync)
    assert isinstance(http._async_client, httpx.AsyncClient)
    await http.aclose()


class TestDescopeClientAsyncLicenseHandshake:
    """Step 6 guard: the license handshake must happen via ``aopen`` / ``__aenter__``,
    not in ``DescopeClientAsync.__init__``.
    """

    @pytest.mark.asyncio
    async def test_no_sync_httpx_during_construction(self):
        """The async client constructor must not call sync ``httpx.get`` even when a
        ``management_key`` is configured. This guards against re-introducing the
        blocking license handshake on the event loop."""
        from descope.descope_client_async import DescopeClientAsync

        with patch("httpx.get", side_effect=AssertionError("sync httpx.get must not be called from __init__")):
            client = DescopeClientAsync(
                PROJECT_ID,
                public_key=PUBLIC_KEY_DICT,
                management_key="dummy-mgmt-key",
                base_url="https://example.com",
            )
        # ``rate_limit_tier`` is not populated yet — handshake is deferred.
        assert client._mgmt_http.rate_limit_tier is None
        await client.aclose()

    @pytest.mark.asyncio
    async def test_aopen_calls_license_endpoint_once(self):
        """``async with`` must run the license handshake exactly once via ``httpx.AsyncClient``."""
        from descope.descope_client_async import DescopeClientAsync
        from descope.management.common import MgmtV1

        license_resp = MagicMock()
        license_resp.is_success = True
        license_resp.status_code = 200
        license_resp.json.return_value = {"rateLimitTier": "free"}

        async_get = AsyncMock(return_value=license_resp)

        # Patch the AsyncClient.get *method* on the class. The handshake builds a
        # one-shot AsyncClient inside ``_fetch_rate_limit_tier_async``.
        with patch.object(httpx.AsyncClient, "get", async_get):
            async with DescopeClientAsync(
                PROJECT_ID,
                public_key=PUBLIC_KEY_DICT,
                management_key="dummy-mgmt-key",
                base_url="https://example.com",
            ) as client:
                assert client._mgmt_http.rate_limit_tier == "free"

        assert async_get.call_count == 1
        called_url = async_get.call_args.args[0]
        assert called_url.endswith(MgmtV1.license_get_path)

    @pytest.mark.asyncio
    async def test_aopen_skipped_without_management_key(self):
        """No license handshake when management_key is not set."""
        from descope.descope_client_async import DescopeClientAsync

        async_get = AsyncMock()
        with patch.object(httpx.AsyncClient, "get", async_get):
            async with DescopeClientAsync(
                PROJECT_ID,
                public_key=PUBLIC_KEY_DICT,
                base_url="https://example.com",
            ) as client:
                assert client._mgmt_http.rate_limit_tier is None

        assert async_get.call_count == 0

    @pytest.mark.asyncio
    async def test_aopen_is_idempotent(self):
        """Calling ``aopen`` twice should only hit the license endpoint once."""
        from descope.descope_client_async import DescopeClientAsync

        license_resp = MagicMock()
        license_resp.is_success = True
        license_resp.status_code = 200
        license_resp.json.return_value = {"rateLimitTier": "free"}
        async_get = AsyncMock(return_value=license_resp)

        client = DescopeClientAsync(
            PROJECT_ID,
            public_key=PUBLIC_KEY_DICT,
            management_key="dummy-mgmt-key",
            base_url="https://example.com",
        )
        try:
            with patch.object(httpx.AsyncClient, "get", async_get):
                await client.aopen()
                await client.aopen()
            assert async_get.call_count == 1
        finally:
            await client.aclose()


class TestDescopeClientAsyncLazyLicenseHandshake:
    """The license handshake must also fire lazily on the first mgmt-side
    request when the caller skips ``aopen`` / ``async with``. Guards against
    silent rate-limit-tier degradation for users that hold a long-lived
    client without explicit lifecycle management.
    """

    def _license_get_mock(self, tier: str = "free") -> AsyncMock:
        resp = MagicMock()
        resp.is_success = True
        resp.status_code = 200
        resp.json.return_value = {"rateLimitTier": tier}
        return AsyncMock(return_value=resp)

    @pytest.mark.asyncio
    async def test_pre_request_hook_wired_on_mgmt_http_only(self):
        """Auth requests must not pay any handshake cost."""
        from descope.descope_client_async import DescopeClientAsync

        client = DescopeClientAsync(
            PROJECT_ID,
            public_key=PUBLIC_KEY_DICT,
            management_key="dummy-mgmt-key",
            base_url="https://example.com",
        )
        try:
            assert client._mgmt_http._pre_request_hook is not None
            assert client._auth_http._pre_request_hook is None
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_mgmt_request_triggers_handshake_lazily(self):
        """A request through ``_mgmt_http`` without ``aopen`` must run the handshake first."""
        from descope.descope_client_async import DescopeClientAsync

        license_get = self._license_get_mock()
        mgmt_resp = MagicMock()
        mgmt_resp.status_code = 200
        mgmt_resp.is_success = True
        mgmt_resp.headers = {}

        client = DescopeClientAsync(
            PROJECT_ID,
            public_key=PUBLIC_KEY_DICT,
            management_key="dummy-mgmt-key",
            base_url="https://example.com",
        )
        try:
            with patch.object(httpx.AsyncClient, "get", license_get):
                with patch.object(client._mgmt_http._async_client, "post", AsyncMock(return_value=mgmt_resp)):
                    await client._mgmt_http.post("/some/mgmt/path", body={})
            assert license_get.call_count == 1
            assert client._mgmt_http.rate_limit_tier == "free"
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_subsequent_mgmt_requests_do_not_retrigger_handshake(self):
        """Once the handshake has run, further mgmt requests must not retrigger it."""
        from descope.descope_client_async import DescopeClientAsync

        license_get = self._license_get_mock()
        mgmt_resp = MagicMock()
        mgmt_resp.status_code = 200
        mgmt_resp.is_success = True
        mgmt_resp.headers = {}

        client = DescopeClientAsync(
            PROJECT_ID,
            public_key=PUBLIC_KEY_DICT,
            management_key="dummy-mgmt-key",
            base_url="https://example.com",
        )
        try:
            with patch.object(httpx.AsyncClient, "get", license_get):
                with patch.object(client._mgmt_http._async_client, "post", AsyncMock(return_value=mgmt_resp)):
                    await client._mgmt_http.post("/p1", body={})
                    await client._mgmt_http.post("/p2", body={})
                    await client._mgmt_http.post("/p3", body={})
            assert license_get.call_count == 1
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_concurrent_first_requests_handshake_exactly_once(self):
        """N concurrent first-mgmt requests must serialize behind the lock and run handshake exactly once."""
        from descope.descope_client_async import DescopeClientAsync

        license_get = self._license_get_mock()
        mgmt_resp = MagicMock()
        mgmt_resp.status_code = 200
        mgmt_resp.is_success = True
        mgmt_resp.headers = {}

        client = DescopeClientAsync(
            PROJECT_ID,
            public_key=PUBLIC_KEY_DICT,
            management_key="dummy-mgmt-key",
            base_url="https://example.com",
        )
        try:
            with patch.object(httpx.AsyncClient, "get", license_get):
                with patch.object(client._mgmt_http._async_client, "post", AsyncMock(return_value=mgmt_resp)):
                    await asyncio.gather(*(client._mgmt_http.post(f"/p{i}", body={}) for i in range(10)))
            assert license_get.call_count == 1
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_auth_request_does_not_trigger_handshake(self):
        """Auth-side requests must not pay any handshake cost — the hook is only on _mgmt_http."""
        from descope.descope_client_async import DescopeClientAsync

        license_get = self._license_get_mock()
        auth_resp = MagicMock()
        auth_resp.status_code = 200
        auth_resp.is_success = True
        auth_resp.headers = {}

        client = DescopeClientAsync(
            PROJECT_ID,
            public_key=PUBLIC_KEY_DICT,
            management_key="dummy-mgmt-key",
            base_url="https://example.com",
        )
        try:
            with patch.object(httpx.AsyncClient, "get", license_get):
                with patch.object(client._auth_http._async_client, "post", AsyncMock(return_value=auth_resp)):
                    await client._auth_http.post("/some/auth/path", body={})
            assert license_get.call_count == 0
            assert client._mgmt_http.rate_limit_tier is None
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_aopen_then_mgmt_request_runs_handshake_once(self):
        """Eager + lazy paths must not double-fire: aopen followed by mgmt calls = 1 handshake."""
        from descope.descope_client_async import DescopeClientAsync

        license_get = self._license_get_mock()
        mgmt_resp = MagicMock()
        mgmt_resp.status_code = 200
        mgmt_resp.is_success = True
        mgmt_resp.headers = {}

        client = DescopeClientAsync(
            PROJECT_ID,
            public_key=PUBLIC_KEY_DICT,
            management_key="dummy-mgmt-key",
            base_url="https://example.com",
        )
        try:
            with patch.object(httpx.AsyncClient, "get", license_get):
                await client.aopen()
                with patch.object(client._mgmt_http._async_client, "post", AsyncMock(return_value=mgmt_resp)):
                    await client._mgmt_http.post("/some/mgmt/path", body={})
            assert license_get.call_count == 1
        finally:
            await client.aclose()
