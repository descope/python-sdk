from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from descope.async_http_client import AsyncHTTPClient
from descope.exceptions import AuthException, RateLimitException
from descope.http_client import _RETRY_DELAYS_SECONDS, _RETRY_STATUS_CODES
from tests.testutils import SSLMatcher


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_DEFAULT_BASE_URL = "https://api.descope.com"


def make_async_client(*, secure=True, verbose=False, project_id="test123", base_url=_DEFAULT_BASE_URL):
    """Build an AsyncHTTPClient with a mocked _async_client (no real socket).

    base_url is passed explicitly so tests are never affected by the
    DESCOPE_BASE_URI env var that unittest-based tests leave set.
    """
    with patch("descope.async_http_client.httpx.AsyncClient"):
        return AsyncHTTPClient(
            project_id=project_id,
            base_url=base_url,
            timeout_seconds=60,
            secure=secure,
            verbose=verbose,
        )


def make_resp(*, status=200, json_data=None, headers=None, text=""):
    """Build a mock httpx.Response for async tests."""
    r = MagicMock()
    r.is_success = status < 400
    r.status_code = status
    r.json.return_value = json_data or {}
    r.headers = headers or {}
    r.text = text
    r.aclose = AsyncMock()  # awaited by the retry loop on retryable failures
    return r


# ---------------------------------------------------------------------------
# 1. Init — AsyncClient is constructed with right verify/timeout
# ---------------------------------------------------------------------------


class TestAsyncHTTPClientInit:
    def test_secure_passes_ssl_context(self):
        with patch("descope.async_http_client.httpx.AsyncClient") as mock_cls:
            AsyncHTTPClient(project_id="test123", timeout_seconds=30, secure=True)
            _, kwargs = mock_cls.call_args
            assert kwargs["verify"] == SSLMatcher()
            assert kwargs["timeout"] == 30

    def test_insecure_passes_false(self):
        with patch("descope.async_http_client.httpx.AsyncClient") as mock_cls:
            AsyncHTTPClient(project_id="test123", timeout_seconds=10, secure=False)
            _, kwargs = mock_cls.call_args
            assert kwargs["verify"] == SSLMatcher(insecure=True)

    def test_empty_project_id_raises(self):
        with patch("descope.async_http_client.httpx.AsyncClient"):
            with pytest.raises(AuthException) as exc_info:
                AsyncHTTPClient(project_id="", timeout_seconds=30, secure=True)
        assert exc_info.value.status_code == 400


# ---------------------------------------------------------------------------
# 2. Verbs — each verb forwards the right URL, headers, body, params
# ---------------------------------------------------------------------------


class TestAsyncHTTPClientVerbs:
    async def test_get(self):
        client = make_async_client(project_id="test123")
        client._async_client.get = AsyncMock(return_value=make_resp(json_data={"ok": 1}))

        await client.get("/path", params={"q": "1"}, allow_redirects=False, pswd="tok")

        call = client._async_client.get.await_args
        assert call.args[0] == "https://api.descope.com/path"
        assert call.kwargs["params"] == {"q": "1"}
        assert call.kwargs["follow_redirects"] is False
        assert "Bearer test123:tok" in call.kwargs["headers"]["Authorization"]

    async def test_get_default_allow_redirects(self):
        client = make_async_client()
        client._async_client.get = AsyncMock(return_value=make_resp())

        await client.get("/path")

        call = client._async_client.get.await_args
        assert call.kwargs["follow_redirects"] is True  # default allow_redirects=True

    async def test_post(self):
        client = make_async_client(project_id="test123")
        client._async_client.post = AsyncMock(return_value=make_resp())

        await client.post("/create", body={"name": "x"}, params={"a": "b"}, pswd="tok")

        call = client._async_client.post.await_args
        assert call.args[0] == "https://api.descope.com/create"
        assert call.kwargs["json"] == {"name": "x"}
        assert call.kwargs["params"] == {"a": "b"}
        assert call.kwargs["follow_redirects"] is False
        assert "Bearer test123:tok" in call.kwargs["headers"]["Authorization"]

    async def test_post_base_url_override(self):
        client = make_async_client()
        client._async_client.post = AsyncMock(return_value=make_resp())

        await client.post("/ep", body={}, base_url="https://custom.example.com")

        url = client._async_client.post.await_args.args[0]
        assert url == "https://custom.example.com/ep"

    async def test_put(self):
        client = make_async_client(project_id="test123")
        client._async_client.put = AsyncMock(return_value=make_resp())

        await client.put("/update", body={"val": 1}, params={"k": "v"}, pswd="tok")

        call = client._async_client.put.await_args
        assert call.args[0] == "https://api.descope.com/update"
        assert call.kwargs["json"] == {"val": 1}
        assert call.kwargs["follow_redirects"] is False

    async def test_patch(self):
        client = make_async_client(project_id="test123")
        client._async_client.patch = AsyncMock(return_value=make_resp())

        await client.patch("/edit", body={"x": 2}, pswd="tok")

        call = client._async_client.patch.await_args
        assert call.args[0] == "https://api.descope.com/edit"
        assert call.kwargs["json"] == {"x": 2}
        assert call.kwargs["follow_redirects"] is False

    async def test_delete(self):
        client = make_async_client(project_id="test123")
        client._async_client.delete = AsyncMock(return_value=make_resp())

        await client.delete("/remove", params={"id": "1"}, pswd="tok")

        call = client._async_client.delete.await_args
        assert call.args[0] == "https://api.descope.com/remove"
        assert call.kwargs["params"] == {"id": "1"}
        assert call.kwargs["follow_redirects"] is False


# ---------------------------------------------------------------------------
# 3. Retry — mirrors TestRetryMechanism from test_http_client.py
# ---------------------------------------------------------------------------


class TestAsyncRetry:
    async def test_retries_on_retryable_codes(self):
        for status_code in _RETRY_STATUS_CODES:
            client = make_async_client()
            err = make_resp(status=status_code)
            ok = make_resp(status=200)

            with patch("descope.async_http_client.asyncio.sleep", AsyncMock()) as mock_sleep:
                client._async_client.get = AsyncMock(side_effect=[err, ok])
                resp = await client.get("/x")

            assert client._async_client.get.await_count == 2, f"Should retry once on {status_code}"
            assert resp.status_code == 200
            mock_sleep.assert_awaited_once_with(0.1)
            err.aclose.assert_awaited_once()

    async def test_retries_to_exhaustion_raises(self):
        client = make_async_client()
        err = make_resp(status=503, text="Unavailable")

        with patch("descope.async_http_client.asyncio.sleep", AsyncMock()) as mock_sleep:
            client._async_client.get = AsyncMock(return_value=err)
            with pytest.raises(AuthException):
                await client.get("/x")

        # original + 3 retries = 4 total calls
        assert client._async_client.get.await_count == 4
        assert mock_sleep.await_count == 3

    async def test_retry_delay_sequence(self):
        client = make_async_client()
        err = make_resp(status=503, text="Unavailable")
        sleep_calls = []

        async def fake_sleep(delay):
            sleep_calls.append(delay)

        with patch("descope.async_http_client.asyncio.sleep", fake_sleep):
            client._async_client.get = AsyncMock(return_value=err)
            with pytest.raises(AuthException):
                await client.get("/x")

        assert sleep_calls == list(_RETRY_DELAYS_SECONDS)

    async def test_no_retry_on_non_retryable_codes(self):
        for status_code in [400, 401, 403, 404, 500, 502]:
            client = make_async_client()
            err = make_resp(status=status_code, text=f"Error {status_code}")

            with patch("descope.async_http_client.asyncio.sleep", AsyncMock()) as mock_sleep:
                client._async_client.get = AsyncMock(return_value=err)
                with pytest.raises(AuthException):
                    await client.get("/x")

            assert client._async_client.get.await_count == 1, f"Should not retry on {status_code}"
            mock_sleep.assert_not_awaited()

    async def test_prior_response_closed_before_retry(self):
        client = make_async_client()
        err1 = make_resp(status=503)
        err2 = make_resp(status=503)
        ok = make_resp(status=200)

        with patch("descope.async_http_client.asyncio.sleep", AsyncMock()):
            client._async_client.get = AsyncMock(side_effect=[err1, err2, ok])
            await client.get("/x")

        err1.aclose.assert_awaited_once()
        err2.aclose.assert_awaited_once()
        ok.aclose.assert_not_awaited()

    async def test_success_on_first_attempt_no_retry(self):
        client = make_async_client()
        ok = make_resp(status=200)
        with patch("descope.async_http_client.asyncio.sleep", AsyncMock()) as mock_sleep:
            client._async_client.get = AsyncMock(return_value=ok)
            await client.get("/x")
        assert client._async_client.get.await_count == 1
        mock_sleep.assert_not_awaited()

    async def test_retry_succeeds_on_third_attempt(self):
        client = make_async_client()
        err1 = make_resp(status=503)
        err2 = make_resp(status=503)
        ok = make_resp(status=200)
        with patch("descope.async_http_client.asyncio.sleep", AsyncMock()):
            client._async_client.get = AsyncMock(side_effect=[err1, err2, ok])
            resp = await client.get("/x")
        assert resp.status_code == 200
        assert client._async_client.get.await_count == 3

    async def test_retry_works_for_post(self):
        client = make_async_client()
        err = make_resp(status=503)
        ok = make_resp(status=200)
        with patch("descope.async_http_client.asyncio.sleep", AsyncMock()):
            client._async_client.post = AsyncMock(side_effect=[err, ok])
            resp = await client.post("/x", body={})
        assert resp.status_code == 200
        assert client._async_client.post.await_count == 2

    async def test_retry_works_for_put(self):
        client = make_async_client()
        err = make_resp(status=503)
        ok = make_resp(status=200)
        with patch("descope.async_http_client.asyncio.sleep", AsyncMock()):
            client._async_client.put = AsyncMock(side_effect=[err, ok])
            resp = await client.put("/x", body={})
        assert resp.status_code == 200
        assert client._async_client.put.await_count == 2

    async def test_retry_works_for_patch(self):
        client = make_async_client()
        err = make_resp(status=503)
        ok = make_resp(status=200)
        with patch("descope.async_http_client.asyncio.sleep", AsyncMock()):
            client._async_client.patch = AsyncMock(side_effect=[err, ok])
            resp = await client.patch("/x", body={})
        assert resp.status_code == 200
        assert client._async_client.patch.await_count == 2

    async def test_retry_works_for_delete(self):
        client = make_async_client()
        err = make_resp(status=503)
        ok = make_resp(status=200)
        with patch("descope.async_http_client.asyncio.sleep", AsyncMock()):
            client._async_client.delete = AsyncMock(side_effect=[err, ok])
            resp = await client.delete("/x")
        assert resp.status_code == 200
        assert client._async_client.delete.await_count == 2


# ---------------------------------------------------------------------------
# 4. Verbose mode
# ---------------------------------------------------------------------------


class TestAsyncVerbose:
    async def test_get_captures_response_when_verbose(self):
        client = make_async_client(verbose=True)
        client._async_client.get = AsyncMock(
            return_value=make_resp(status=200, json_data={"d": 1}, headers={"cf-ray": "r1"})
        )

        await client.get("/x")

        last = client.get_last_response()
        assert last is not None
        assert last.status_code == 200
        assert last.headers.get("cf-ray") == "r1"

    async def test_get_does_not_capture_when_not_verbose(self):
        client = make_async_client(verbose=False)
        client._async_client.get = AsyncMock(return_value=make_resp())

        await client.get("/x")

        assert client.get_last_response() is None

    async def test_post_captures_response_when_verbose(self):
        client = make_async_client(verbose=True)
        client._async_client.post = AsyncMock(
            return_value=make_resp(status=201, json_data={"id": "u1"}, headers={"cf-ray": "r2"})
        )

        await client.post("/x", body={})

        last = client.get_last_response()
        assert last is not None
        assert last.status_code == 201

    async def test_patch_captures_response_when_verbose(self):
        client = make_async_client(verbose=True)
        client._async_client.patch = AsyncMock(
            return_value=make_resp(status=200, json_data={"ok": 1}, headers={"cf-ray": "r3"})
        )

        await client.patch("/x", body={})

        last = client.get_last_response()
        assert last is not None
        assert last.status_code == 200

    async def test_delete_captures_response_when_verbose(self):
        client = make_async_client(verbose=True)
        client._async_client.delete = AsyncMock(
            return_value=make_resp(status=200, json_data={"gone": 1}, headers={"cf-ray": "r4"})
        )

        await client.delete("/x")

        last = client.get_last_response()
        assert last is not None
        assert last.status_code == 200


# ---------------------------------------------------------------------------
# 5. Error raising — inherited _raise_from_response fires after await
# ---------------------------------------------------------------------------


class TestAsyncErrors:
    async def test_raises_auth_exception_on_500(self):
        client = make_async_client()
        client._async_client.get = AsyncMock(return_value=make_resp(status=500, text="Error"))

        with pytest.raises(AuthException) as exc_info:
            await client.get("/x")

        assert exc_info.value.status_code == 500

    async def test_raises_rate_limit_exception_on_429(self):
        client = make_async_client()
        client._async_client.get = AsyncMock(
            return_value=make_resp(
                status=429,
                json_data={"errorCode": "E010", "errorDescription": "Rate limit exceeded"},
                headers={"Retry-After": "60"},
            )
        )

        with pytest.raises(RateLimitException) as exc_info:
            await client.get("/x")

        assert exc_info.value.error_type == "API rate limit exceeded"

    async def test_raises_rate_limit_when_json_fails(self):
        client = make_async_client()
        bad = make_resp(status=429, headers={"Retry-After": "30"})
        bad.json.side_effect = ValueError("bad json")
        client._async_client.get = AsyncMock(return_value=bad)

        with pytest.raises(RateLimitException):
            await client.get("/x")


# ---------------------------------------------------------------------------
# 6. Lifecycle — aclose and context manager
# ---------------------------------------------------------------------------


class TestAsyncLifecycle:
    async def test_aclose_delegates_to_async_client(self):
        client = make_async_client()
        client._async_client.aclose = AsyncMock()

        await client.aclose()

        client._async_client.aclose.assert_awaited_once()

    async def test_context_manager_yields_client_and_closes(self):
        with patch("descope.async_http_client.httpx.AsyncClient"):
            async with AsyncHTTPClient(project_id="test123", timeout_seconds=60, secure=True) as c:
                assert isinstance(c, AsyncHTTPClient)
                c._async_client.aclose = AsyncMock()

        c._async_client.aclose.assert_awaited_once()


# ---------------------------------------------------------------------------
# 7. Headers — management key propagation
# ---------------------------------------------------------------------------


class TestAsyncHTTPClientHeaders:
    async def test_management_key_in_authorization_header(self):
        """auth_management_key is baked into the Authorization header on every verb call."""
        with patch("descope.async_http_client.httpx.AsyncClient"):
            client = AsyncHTTPClient(
                project_id="proj123",
                timeout_seconds=60,
                secure=True,
                management_key="mgmt-key",
            )
        client._async_client.get = AsyncMock(return_value=make_resp(json_data={"ok": 1}))
        await client.get("/path")
        call = client._async_client.get.await_args
        assert call.kwargs["headers"]["Authorization"] == "Bearer proj123:mgmt-key"
