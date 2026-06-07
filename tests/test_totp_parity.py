"""
Parity port of test_totp.py using the unified sync/async fixture infrastructure.

Structure mirrors the original: one class, one test method per operation.
Each method runs twice — once for sync DescopeClient and once for AsyncDescopeClient —
via pytest's parametrised ``client_factory`` fixture from conftest.

Payload assertions (assert_http_called) are included where the original had them:
  - test_sign_in:   refresh-token call body + headers
  - test_update_user: call body + headers
  - test_sign_up:   asserts result is not None (original had no payload assertion)
"""

from __future__ import annotations

import pytest

from descope import AuthException
from descope.common import (
    DEFAULT_TIMEOUT_SECONDS,
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
)
from tests.conftest import PROJECT_ID, PUBLIC_KEY_DICT, make_response
from tests.testutils import SSLMatcher

from . import common

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# drn=DSR, exp=2264443061 (far future) — signed with PUBLIC_KEY_DICT (P2Cu kid)
VALID_REFRESH_TOKEN = (
    "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ"
    ".eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0NDMwNjEsImlhdCI6MTY1OTY0MzA2MSwiaXNzIjoiUDJDdUM5eXYy"
    "VUd0R0kxbzg0Z0NaRWI5cUVRVyIsInN1YiI6IlUyQ3VDUHVKZ1BXSEdCNVA0R21mYnVQR2hHVm0ifQ"
    ".mRo9FihYMR3qnQT06Mj3CJ5X0uTCEcXASZqfLLUv0cPCLBtBqYTbuK-ZRDnV4e4N6zGCNX2a3jjpbyqbViOx"
    "ICCNSxJsVb-sdsSujtEXwVMsTTLnpWmNsMbOUiKmoME0"
)

# drn=DS, exp=2493061415 (far future) — signed with PUBLIC_KEY_DICT (P2Cu kid)
VALID_SESSION_TOKEN = (
    "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ"
    ".eyJkcm4iOiJEUyIsImV4cCI6MjQ5MzA2MTQxNSwiaWF0IjoxNjU5NjQzMDYxLCJpc3MiOiJQMkN1Qzl5djJVR3"
    "RHSTFvODRnQ1pFYjlxRVFXIiwic3ViIjoiVTJDdUNQdUpnUFdIR0I1UDRHbWZidVBHaEdWbSJ9"
    ".gMalOv1GhqYVsfITcOc7Jv_fibX1Iof6AFy2KCVmyHmU2KwATT6XYXsHjBFFLq262Pg-LS1IX9f_DV3ppzvb1p"
    "SY4ccsP6WDGd1vJpjp3wFBP9Sji6WXL0SCCJUFIyJR"
)


# ---------------------------------------------------------------------------
# Helper: mode-aware HTTP call assertion (same as test_descope_client_parity.py)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestTOTP:
    # ------------------------------------------------------------------
    # sign_up
    # ------------------------------------------------------------------

    async def test_sign_up(self, client_factory):
        signup_user_details = {
            "username": "jhon",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors — no HTTP call made
        with pytest.raises(AuthException):
            await client.invoke(client.totp.sign_up("", signup_user_details))
        with pytest.raises(AuthException):
            await client.invoke(client.totp.sign_up(None, signup_user_details))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.totp.sign_up("dummy@dummy.com", signup_user_details))

        # Success
        data = {"provisioningURL": "http://dummy.com", "image": "imagedata", "key": "k01"}
        with client.mock_post(make_response(data)):
            result = await client.invoke(client.totp.sign_up("dummy@dummy.com", signup_user_details))
        assert result is not None

    # ------------------------------------------------------------------
    # sign_in_code
    # ------------------------------------------------------------------

    async def test_sign_in(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        refresh_token = "dummy refresh token"

        # Validation errors — no HTTP call made
        with pytest.raises(AuthException):
            await client.invoke(client.totp.sign_in_code(None, "1234"))
        with pytest.raises(AuthException):
            await client.invoke(client.totp.sign_in_code("", "1234"))
        with pytest.raises(AuthException):
            await client.invoke(client.totp.sign_in_code("dummy@dummy.com", None))
        with pytest.raises(AuthException):
            await client.invoke(client.totp.sign_in_code("dummy@dummy.com", ""))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.totp.sign_in_code("dummy@dummy.com", "1234"))

        # Success + MFA-without-refresh check
        success_resp = make_response(
            {"sessionJwt": VALID_SESSION_TOKEN},
            cookies={REFRESH_SESSION_COOKIE_NAME: VALID_REFRESH_TOKEN},
        )
        with client.mock_post(success_resp):
            result = await client.invoke(client.totp.sign_in_code("dummy@dummy.com", "1234"))
            assert result is not None
            # MFA stepup requires a refresh token — omitting it must raise
            with pytest.raises(AuthException):
                await client.invoke(client.totp.sign_in_code("dummy@dummy.com", "code", LoginOptions(mfa=True)))

        # Verify refresh token propagates correctly into the request
        with client.mock_post(success_resp) as mock_post:
            await client.invoke(
                client.totp.sign_in_code(
                    "dummy@dummy.com",
                    "1234",
                    LoginOptions(stepup=True),
                    refresh_token=refresh_token,
                )
            )
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.verify_totp_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}:{refresh_token}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={
                "loginId": "dummy@dummy.com",
                "code": "1234",
                "loginOptions": {
                    "stepup": True,
                    "customClaims": None,
                    "mfa": False,
                },
            },
            follow_redirects=False,
        )

    # ------------------------------------------------------------------
    # update_user
    # ------------------------------------------------------------------

    async def test_update_user(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        valid_refresh_token = VALID_REFRESH_TOKEN
        valid_response = {
            "provisioningURL": "http://dummy.com",
            "image": "imagedata",
            "key": "k01",
            "error": "",
        }

        # Validation errors — no HTTP call made
        with pytest.raises(AuthException):
            await client.invoke(client.totp.update_user(None, ""))
        with pytest.raises(AuthException):
            await client.invoke(client.totp.update_user("", ""))
        with pytest.raises(AuthException):
            await client.invoke(client.totp.update_user("dummy@dummy.com", None))
        with pytest.raises(AuthException):
            await client.invoke(client.totp.update_user("dummy@dummy.com", ""))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.totp.update_user("dummy@dummy.com", "dummy refresh token"))

        # Success + payload assertion
        with client.mock_post(make_response(valid_response)) as mock_post:
            res = await client.invoke(client.totp.update_user("dummy@dummy.com", valid_refresh_token))
        assert res == valid_response
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_totp_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}:{valid_refresh_token}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "dummy@dummy.com"},
            follow_redirects=False,
        )
