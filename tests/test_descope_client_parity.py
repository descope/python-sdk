"""
Parity port of test_descope_client.py using the unified sync/async fixture infrastructure.

Structure mirrors the original: one class, one test method per feature.  Each method
runs twice — once for the sync DescopeClient and once for AsyncDescopeClient — via
pytest's parametrised ``descope_client`` / ``client_factory`` fixtures from conftest.

Tests that exercise surfaces not yet ported to AsyncDescopeClient (mgmt, otp, oauth…)
call ``pytest.skip()`` in async mode so the original assertions are preserved verbatim.
"""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from unittest import mock
from unittest.mock import patch

import pytest

from descope import (
    API_RATE_LIMIT_RETRY_AFTER_HEADER,
    ERROR_TYPE_API_RATE_LIMIT,
    SESSION_COOKIE_NAME,
    AccessKeyLoginOptions,
    AuthException,
    RateLimitException,
)
from descope.common import (
    DEFAULT_TIMEOUT_SECONDS,
    SESSION_TOKEN_NAME,
    DeliveryMethod,
    EndpointsV1,
)
from tests.conftest import PROJECT_ID, PUBLIC_KEY_DICT, make_response
from tests.testutils import SSLMatcher

from . import common

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

PUBLIC_KEY_STR = json.dumps(PUBLIC_KEY_DICT)

# The original setUp public_key_dict (kid=2Bt5…) used by a handful of tests
DUMMY_PUBLIC_KEY_DICT = {
    "alg": "ES384",
    "crv": "P-384",
    "kid": "2Bt5WLccLUey1Dp7utptZb3Fx9K",
    "kty": "EC",
    "use": "sig",
    "x": "8SMbQQpCQAGAxCdoIz8y9gDw-wXoyoN5ILWpAlBKOcEM1Y7WmRKc1O2cnHggyEVi",
    "y": "N5n5jKZA5Wu7_b4B36KKjJf-VRfJ-XqczfCSYy9GeQLqF-b63idfE0SYaYk9cFqg",
}

# JWT tokens (all signed with kid=P2CuC9yv2UGtGI1o84gCZEb9qEQW)
VALID_REFRESH_TOKEN = (
    "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ"
    ".eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0NDMwNjEsImlhdCI6MTY1OTY0MzA2MSwiaXNzIjoiUDJDdUM5eXYy"
    "VUd0R0kxbzg0Z0NaRWI5cUVRVyIsInN1YiI6IlUyQ3VDUHVKZ1BXSEdCNVA0R21mYnVQR2hHVm0ifQ"
    ".mRo9FihYMR3qnQT06Mj3CJ5X0uTCEcXASZqfLLUv0cPCLBtBqYTbuK-ZRDnV4e4N6zGCNX2a3jjpbyqbViOx"
    "ICCNSxJsVb-sdsSujtEXwVMsTTLnpWmNsMbOUiKmoME0"
)

VALID_SESSION_TOKEN = (
    "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ"
    ".eyJkcm4iOiJEUyIsImV4cCI6MjQ5MzA2MTQxNSwiaWF0IjoxNjU5NjQzMDYxLCJpc3MiOiJQMkN1Qzl5djJVR3"
    "RHSTFvODRnQ1pFYjlxRVFXIiwic3ViIjoiVTJDdUNQdUpnUFdIR0I1UDRHbWZidVBHaEdWbSJ9"
    ".gMalOv1GhqYVsfITcOc7Jv_fibX1Iof6AFy2KCVmyHmU2KwATT6XYXsHjBFFLq262Pg-LS1IX9f_DV3ppzvb1p"
    "SY4ccsP6WDGd1vJpjp3wFBP9Sji6WXL0SCCJUFIyJR"
)

# drn=DS, exp=1659644298 (past)
EXPIRED_SESSION_TOKEN = (
    "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ"
    ".eyJkcm4iOiJEUyIsImV4cCI6MTY1OTY0NDI5OCwiaWF0IjoxNjU5NjQ0Mjk3LCJpc3MiOiJQMkN1Qzl5djJVR3"
    "RHSTFvODRnQ1pFYjlxRVFXIiwic3ViIjoiVTJDdUNQdUpnUFdIR0I1UDRHbWZidVBHaEdWbSJ9"
    ".wBuOnIQI_z3SXOszqsWCg8ilOPdE5ruWYHA3jkaeQ3uX9hWgCTd69paFajc-xdMYbqlIF7JHji7T9oVmkCUJvD"
    "NgRZRZO9boMFANPyXitLOK4aX3VZpMJBpFxdrWV3GE"
)

EXPECTED_USER_ID = "U2CuCPuJgPWHGB5P4GmfbuPGhGVm"
EXPECTED_PROJECT_ID = "P2CuC9yv2UGtGI1o84gCZEb9qEQW"

# Tokens ported from test_descope_client.py that must fail validate_session
_INVALID_HEADER_TOKEN = (
    "AyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImR1bW15In0"
    ".Bcz3xSxEcxgBSZOzqrTvKnb9-u45W-RlAbHSBL6E8zo2yJ9SYfODphdZ8tP5ARNTvFSPj2wgyu1SeiZWoGGP"
    "HPNMt4p65tPeVf5W8--d2aKXCc4KvAOOK3B_Cvjy_TO8"
)
_MISSING_KID_TOKEN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImFhYSI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0"
    ".eyJleHAiOjE5ODEzOTgxMTF9"
    ".GQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP"
    "3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh"
)
_INVALID_PAYLOAD_TOKEN = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoxNjU3Nzk2Njc4LCJpYXQiOjE2NTc3OTYwNzgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJCdEVIa2dPdTAybG1NeHpQSWV4ZE10VXcxTSJ9.lTUKMIjkrdsfryREYrgz4jMV7M0-JF-Q-KNlI0xZhamYqnSYtvzdwAoYiyWamx22XrN5SZkcmVZ5bsx-g2C0p5VMbnmmxEaxcnsFJHqVAJUYEv5HGQHumN50DYSlLXXg"


# ---------------------------------------------------------------------------
# Helper: mode-aware HTTP call assertion
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


class TestDescopeClient:
    # ------------------------------------------------------------------
    # Construction validation
    # ------------------------------------------------------------------

    async def test_descope_client(self, client_factory):
        with pytest.raises(AuthException):
            client_factory.make(None, "dummy")
        with pytest.raises(AuthException):
            client_factory.make("", "dummy")

        with patch("os.getenv") as mock_getenv:
            mock_getenv.return_value = ""
            with pytest.raises(AuthException):
                client_factory.make(None, "dummy")

        assert client_factory.make(PROJECT_ID, None) is not None
        assert client_factory.make(PROJECT_ID, "") is not None
        with pytest.raises(AuthException):
            client_factory.make(PROJECT_ID, "not dict object")
        assert client_factory.make(PROJECT_ID, PUBLIC_KEY_STR) is not None

    async def test_project_id_from_env_without_env(self, client_factory):
        with patch.dict("os.environ", {"DESCOPE_PROJECT_ID": ""}):
            with pytest.raises(AuthException):
                client_factory.make("")

    # ------------------------------------------------------------------
    # Management client (sync-only)
    # ------------------------------------------------------------------

    async def test_mgmt(self, descope_client):
        if descope_client.mode != "sync":
            pytest.skip("mgmt not available on AsyncDescopeClient")

        # Validate that any invocation of specific mgmt object raises AuthException as mgmt key was not set
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.tenant
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.sso_application
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.user
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.access_key
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.sso
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.jwt
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.permission
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.role
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.group
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.flow
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.audit
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.authz
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.fga
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.project
        with pytest.raises(AuthException):
            _ = descope_client.mgmt.outbound_application

        # Validate that outbound_application_by_token doesn't require mgmt key
        try:
            _ = descope_client.mgmt.outbound_application_by_token
        except AuthException:
            pytest.fail("failed to initiate outbound_application_by_token without management key")

    # ------------------------------------------------------------------
    # logout / logout_all
    # ------------------------------------------------------------------

    async def test_logout(self, descope_client):
        with pytest.raises(AuthException):
            await descope_client.invoke(descope_client.logout(None))

        with descope_client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await descope_client.invoke(descope_client.logout(""))

        with descope_client.mock_post(make_response(status=200)):
            assert await descope_client.invoke(descope_client.logout("")) is not None

    async def test_logout_all(self, descope_client):
        with pytest.raises(AuthException):
            await descope_client.invoke(descope_client.logout_all(None))

        with descope_client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await descope_client.invoke(descope_client.logout_all(""))

        with descope_client.mock_post(make_response(status=200)):
            assert await descope_client.invoke(descope_client.logout_all("")) is not None

    # ------------------------------------------------------------------
    # me
    # ------------------------------------------------------------------

    async def test_me(self, descope_client):
        with pytest.raises(AuthException):
            await descope_client.invoke(descope_client.me(None))

        with descope_client.mock_get(make_response(status=500)):
            with pytest.raises(AuthException):
                await descope_client.invoke(descope_client.me(""))

        data = json.loads("""{"name": "Testy McTester", "email": "testy@tester.com"}""")
        with descope_client.mock_get(make_response(data)) as mock_get:
            user_response = await descope_client.invoke(descope_client.me(""))
        assert user_response is not None
        assert data["name"] == user_response["name"]
        assert_http_called(
            mock_get,
            descope_client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.me_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            follow_redirects=None,
            params=None,
        )

    # ------------------------------------------------------------------
    # my_tenants
    # ------------------------------------------------------------------

    async def test_my_tenants(self, descope_client):
        with pytest.raises(AuthException):
            await descope_client.invoke(descope_client.my_tenants(None))

        with pytest.raises(AuthException):
            await descope_client.invoke(descope_client.my_tenants(""))

        with pytest.raises(AuthException):
            await descope_client.invoke(descope_client.my_tenants("", True, ["a"]))

        with descope_client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await descope_client.invoke(descope_client.my_tenants("", True))

        data = json.loads("""{"tenants": [{"id": "tenant_id", "name": "tenant_name"}]}""")
        with descope_client.mock_post(make_response(data)) as mock_post:
            tenant_response = await descope_client.invoke(descope_client.my_tenants("", False, ["a"]))
        assert tenant_response is not None
        assert data["tenants"][0]["name"] == tenant_response["tenants"][0]["name"]
        assert_http_called(
            mock_post,
            descope_client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.my_tenants_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            json={"dct": False, "ids": ["a"]},
            follow_redirects=False,
            params=None,
        )

    # ------------------------------------------------------------------
    # history
    # ------------------------------------------------------------------

    async def test_history(self, descope_client):
        with pytest.raises(AuthException):
            await descope_client.invoke(descope_client.history(None))

        with descope_client.mock_get(make_response(status=500)):
            with pytest.raises(AuthException):
                await descope_client.invoke(descope_client.history(""))

        data = json.loads(
            """
            [
                {
                    "userId":    "kuku",
                    "city":      "kefar saba",
                    "country":   "Israel",
                    "ip":        "1.1.1.1",
                    "loginTime": 32
                },
                {
                    "userId":    "nunu",
                    "city":      "eilat",
                    "country":   "Israele",
                    "ip":        "1.1.1.2",
                    "loginTime": 23
                }
            ]
            """
        )
        with descope_client.mock_get(make_response(data)) as mock_get:
            user_response = await descope_client.invoke(descope_client.history(""))
        assert user_response is not None
        assert data == user_response
        assert_http_called(
            mock_get,
            descope_client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.history_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            follow_redirects=None,
            params=None,
        )

    # ------------------------------------------------------------------
    # validate_session — pure-CPU helper (no IO)
    # ------------------------------------------------------------------

    async def test_validate_session(self, client_factory):
        # Client with the 2Bt5 key (matching the kid in _INVALID_PAYLOAD_TOKEN)
        client = client_factory.make(PROJECT_ID, DUMMY_PUBLIC_KEY_DICT)

        with pytest.raises(AuthException):
            client.validate_session(_MISSING_KID_TOKEN)
        with pytest.raises(AuthException):
            client.validate_session(_INVALID_HEADER_TOKEN)
        with pytest.raises(AuthException):
            client.validate_session(_INVALID_PAYLOAD_TOKEN)

        # None key client + None token
        client4 = client_factory.make(PROJECT_ID, None)
        with pytest.raises(AuthException):
            client4.validate_session(None)

    async def test_validate_session_response_structure(self, descope_client):
        result = descope_client.validate_session(VALID_SESSION_TOKEN)
        assert result == {
            "drn": "DS",
            "exp": 2493061415,
            "iat": 1659643061,
            "iss": EXPECTED_PROJECT_ID,
            "sub": EXPECTED_USER_ID,
            "jwt": VALID_SESSION_TOKEN,
            "permissions": [],
            "roles": [],
            "tenants": {},
            "projectId": EXPECTED_PROJECT_ID,
            "userId": EXPECTED_USER_ID,
            "sessionToken": {
                "drn": "DS",
                "exp": 2493061415,
                "iat": 1659643061,
                "iss": EXPECTED_PROJECT_ID,
                "sub": EXPECTED_USER_ID,
                "jwt": VALID_SESSION_TOKEN,
            },
        }

    async def test_validate_session_valid_tokens(self, client_factory):
        # Client with P2Cu key preloaded
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        dummy_refresh_token = "refresh"
        valid_jwt_token = VALID_REFRESH_TOKEN  # far-future DSR token, P2Cu kid

        # Valid token validates locally — no network needed
        client.validate_session(valid_jwt_token)

        assert (
            await client.invoke(client.validate_and_refresh_session(valid_jwt_token, dummy_refresh_token)) is not None
        )

        # Key id cannot be found — key fetch returns wrong kid
        client2 = client_factory.make(PROJECT_ID, None)
        with patch("httpx.get") as mock_request:
            fake_key = deepcopy(DUMMY_PUBLIC_KEY_DICT)
            fake_key["kid"] = "dummy_kid"
            mock_request.return_value.text = json.dumps([fake_key])
            mock_request.return_value.is_success = True
            with pytest.raises(AuthException):
                await client2.invoke(client2.validate_and_refresh_session(valid_jwt_token, dummy_refresh_token))

        # Key fetch returns unparsable key
        client3 = client_factory.make(PROJECT_ID, None)
        with patch("httpx.get") as mock_request:
            mock_request.return_value.text = """[{"kid": "dummy_kid"}]"""
            mock_request.return_value.is_success = True
            with pytest.raises(AuthException):
                await client3.invoke(client3.validate_and_refresh_session(valid_jwt_token, dummy_refresh_token))

        # header_alg != key[alg]
        bad_alg_key = deepcopy(DUMMY_PUBLIC_KEY_DICT)
        bad_alg_key["alg"] = "ES521"
        client4 = client_factory.make(PROJECT_ID, bad_alg_key)
        with patch("httpx.get") as mock_request:
            mock_request.return_value.text = """[{"kid": "dummy_kid"}]"""
            mock_request.return_value.is_success = True
            with pytest.raises(AuthException):
                await client4.invoke(client4.validate_and_refresh_session(valid_jwt_token, dummy_refresh_token))

        # Both session_token and refresh_token are None
        client4b = client_factory.make(PROJECT_ID, None)
        with pytest.raises(AuthException):
            await client4b.invoke(client4b.validate_and_refresh_session(None, None))

        # Expired session triggers refresh; refreshed token is also expired → fails
        expired_jwt_token = EXPIRED_SESSION_TOKEN
        valid_refresh_for_expire_test = valid_jwt_token
        with patch("httpx.get") as mock_request:
            mock_request.return_value.cookies = {SESSION_COOKIE_NAME: expired_jwt_token}
            mock_request.return_value.is_success = True
            with pytest.raises(AuthException):
                await client3.invoke(
                    client3.validate_and_refresh_session(expired_jwt_token, valid_refresh_for_expire_test)
                )

    # ------------------------------------------------------------------
    # Exception object shapes (no client needed)
    # ------------------------------------------------------------------

    def test_exception_object(self):
        ex = AuthException(401, "dummy-type", "dummy error message")
        assert str(ex) is not None
        assert repr(ex) is not None
        assert ex.status_code == 401
        assert ex.error_type == "dummy-type"
        assert ex.error_message == "dummy error message"

    def test_api_rate_limit_exception_object(self):
        ex = RateLimitException(
            429,
            ERROR_TYPE_API_RATE_LIMIT,
            "API rate limit exceeded description",
            "API rate limit exceeded",
            {API_RATE_LIMIT_RETRY_AFTER_HEADER: "9"},
        )
        assert str(ex) is not None
        assert repr(ex) is not None
        assert ex.status_code == 429
        assert ex.error_type == ERROR_TYPE_API_RATE_LIMIT
        assert ex.error_description == "API rate limit exceeded description"
        assert ex.error_message == "API rate limit exceeded"
        assert ex.rate_limit_parameters.get(API_RATE_LIMIT_RETRY_AFTER_HEADER, "") == "9"

    # ------------------------------------------------------------------
    # Expired token + refresh flows
    # ------------------------------------------------------------------

    async def test_expired_token(self, client_factory):
        # expired DS token (kid=P2Cu, exp=1657798328 — past)
        expired_jwt_token = (
            "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9"
            ".eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg5NzI4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoxNjU3Nzk4MzI4LCJpYXQiOjE2NTc3OTc3MjgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJCdEVIa2dPdTAybG1NeHpQSWV4ZE10VXcxTSJ9"
            ".i-JoPoYmXl3jeLTARvYnInBiRdTT4uHZ3X3xu_n1dhUb1Qy_gqK7Ru8ErYXeENdfPOe4mjShc_HsVyb5PjE2LMFmb58WR8wixtn0R-u_MqTpuI_422Dk6hMRjTFEVRWu"
        )
        dummy_refresh_token = "dummy refresh token"

        # Client with P2Cu key (same kid the validate tokens use in refresh path)
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Fail flow: key is preloaded so validate_session raises due to expiration
        with patch("httpx.get") as mock_request:
            mock_request.return_value.is_success = False
            with pytest.raises(AuthException):
                client.validate_session(expired_jwt_token)

        with patch("httpx.get") as mock_request:
            mock_request.return_value.cookies = {"aaa": "aaa"}
            mock_request.return_value.is_success = True
            with pytest.raises(AuthException):
                client.validate_session(expired_jwt_token)

        # Fail flow: jwt.get_unverified_header returns {} (no kid)
        dummy_session_token = "dummy session token"
        # dummy_client has the 2Bt5 key; EXPIRED_SESSION_TOKEN uses P2Cu — key not loaded
        dummy_client = client_factory.make(PROJECT_ID, DUMMY_PUBLIC_KEY_DICT)
        with patch("jwt.get_unverified_header") as mock_jwt_get_unverified_header:
            mock_jwt_get_unverified_header.return_value = {}
            with pytest.raises(AuthException):
                await dummy_client.invoke(
                    dummy_client.validate_and_refresh_session(dummy_session_token, dummy_refresh_token)
                )

        # Success flow: expired token → POST refresh → returns valid new session token
        new_session_token = VALID_SESSION_TOKEN
        valid_refresh_token = VALID_REFRESH_TOKEN
        expired_token = EXPIRED_SESSION_TOKEN
        resp = make_response({"sessionJwt": new_session_token}, cookies={})
        with client.mock_post(resp):
            # Refresh because of expiration
            result = await client.invoke(client.validate_and_refresh_session(expired_token, valid_refresh_token))
            new_session_token_from_request = result[SESSION_TOKEN_NAME]["jwt"]
            assert new_session_token_from_request == new_session_token, "Failed to refresh token"

            # Refresh explicitly
            result = await client.invoke(client.refresh_session(valid_refresh_token))
            new_session_token_from_request = result[SESSION_TOKEN_NAME]["jwt"]
            assert new_session_token_from_request == new_session_token, "Failed to refresh token"

        # Fail flow: refreshed token is also expired → AuthException
        # dummy_client has P2Cu key; expired_jwt_token (kid=2Bt5) is NOT preloaded → triggers
        # JWKS fetch via httpx.get; mock returns garbage JSON → AuthException
        expired_jwt_token2 = EXPIRED_SESSION_TOKEN
        valid_refresh_token2 = VALID_REFRESH_TOKEN
        new_refreshed_token = expired_jwt_token2
        with patch("httpx.get") as mock_request:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"sessionJwt": new_refreshed_token}
            mock_request.return_value = my_mock_response
            mock_request.return_value.cookies = {}
            with pytest.raises(AuthException):
                await dummy_client.invoke(
                    dummy_client.validate_and_refresh_session(expired_jwt_token2, valid_refresh_token2)
                )

    # ------------------------------------------------------------------
    # Public key loading errors
    # ------------------------------------------------------------------

    async def test_public_key_load(self, client_factory):
        # Test key without kty property
        invalid_public_key = deepcopy(PUBLIC_KEY_DICT)
        invalid_public_key.pop("kty")
        with pytest.raises(AuthException) as exc_info:
            client_factory.make(PROJECT_ID, invalid_public_key)
        assert exc_info.value.status_code == 500

        # Test key without kid property
        invalid_public_key = deepcopy(PUBLIC_KEY_DICT)
        invalid_public_key.pop("kid")
        with pytest.raises(AuthException) as exc_info:
            client_factory.make(PROJECT_ID, invalid_public_key)
        assert exc_info.value.status_code == 500

        # Test key with unknown algorithm
        invalid_public_key = deepcopy(PUBLIC_KEY_DICT)
        invalid_public_key["alg"] = "unknown algorithm"
        with pytest.raises(AuthException) as exc_info:
            client_factory.make(PROJECT_ID, invalid_public_key)
        assert exc_info.value.status_code == 500

    # ------------------------------------------------------------------
    # Client property surface
    # ------------------------------------------------------------------

    async def test_client_properties(self, descope_client):
        # totp is available on both sync and async clients
        assert descope_client.totp is not None, "Empty totp object"

        # All other auth-method properties are sync-only
        if descope_client.mode != "sync":
            return
        assert descope_client.magiclink is not None, "Empty Magiclink object"
        assert descope_client.otp is not None, "Empty otp object"
        assert descope_client.oauth is not None, "Empty oauth object"
        assert descope_client.saml is not None, "Empty saml object"
        assert descope_client.sso is not None, "Empty saml object"
        assert descope_client.webauthn is not None, "Empty webauthN object"

    # ------------------------------------------------------------------
    # Permission / role helpers — pure-CPU
    # ------------------------------------------------------------------

    async def test_validate_permissions(self, descope_client):
        jwt_response = {}
        assert descope_client.validate_permissions(jwt_response, ["Perm 1"]) is False

        jwt_response = {"permissions": []}
        assert descope_client.validate_permissions(jwt_response, ["Perm 1"]) is False
        assert descope_client.validate_permissions(jwt_response, []) is True

        jwt_response = {"permissions": ["Perm 1"]}
        assert descope_client.validate_permissions(jwt_response, "Perm 1") is True
        assert descope_client.validate_permissions(jwt_response, ["Perm 1"]) is True
        assert descope_client.validate_permissions(jwt_response, ["Perm 2"]) is False

        # Tenant level
        jwt_response = {"tenants": {}}
        assert descope_client.validate_tenant_permissions(jwt_response, "t1", ["Perm 2"]) is False

        jwt_response = {"tenants": {"t1": {}}}
        assert descope_client.validate_tenant_permissions(jwt_response, "t1", ["Perm 2"]) is False

        jwt_response = {"tenants": {"t1": {"permissions": "Perm 1"}}}
        assert descope_client.validate_tenant_permissions(jwt_response, "t1", []) is True
        assert descope_client.validate_tenant_permissions(jwt_response, "t1", ["Perm 1"]) is True
        assert descope_client.validate_tenant_permissions(jwt_response, "t1", ["Perm 2"]) is False
        assert descope_client.validate_tenant_permissions(jwt_response, "t1", ["Perm 1", "Perm 2"]) is False
        assert descope_client.validate_tenant_permissions(jwt_response, "t2", []) is False

    async def test_get_matched_permissions(self, descope_client):
        jwt_response = {}
        assert descope_client.get_matched_permissions(jwt_response, []) == []

        jwt_response = {"permissions": []}
        assert descope_client.get_matched_permissions(jwt_response, ["Perm 1"]) == []

        jwt_response = {"permissions": ["Perm 1", "Perm 2"]}
        assert descope_client.get_matched_permissions(jwt_response, ["Perm 1"]) == ["Perm 1"]
        assert descope_client.get_matched_permissions(jwt_response, ["Perm 1", "Perm 2"]) == ["Perm 1", "Perm 2"]
        assert descope_client.get_matched_permissions(jwt_response, ["Perm 1", "Perm 2", "Perm 3"]) == [
            "Perm 1",
            "Perm 2",
        ]

        # Tenant level
        jwt_response = {"tenants": {}}
        assert descope_client.get_matched_tenant_permissions(jwt_response, "t1", ["Perm 1"]) == []

        jwt_response = {"tenants": {"t1": {}}}
        assert descope_client.get_matched_tenant_permissions(jwt_response, "t1", ["Perm 1"]) == []

        jwt_response = {"tenants": {"t1": {"permissions": ["Perm 1", "Perm 2"]}}}
        assert descope_client.get_matched_tenant_permissions(jwt_response, "t1", ["Perm 1"]) == ["Perm 1"]
        assert descope_client.get_matched_tenant_permissions(jwt_response, "t1", ["Perm 1", "Perm 2"]) == [
            "Perm 1",
            "Perm 2",
        ]
        assert descope_client.get_matched_tenant_permissions(jwt_response, "t1", ["Perm 1", "Perm 2", "Perm 3"]) == [
            "Perm 1",
            "Perm 2",
        ]

    async def test_validate_roles(self, descope_client):
        jwt_response = {}
        assert descope_client.validate_roles(jwt_response, ["Role 1"]) is False

        jwt_response = {"roles": []}
        assert descope_client.validate_roles(jwt_response, ["Role 1"]) is False
        assert descope_client.validate_roles(jwt_response, []) is True

        jwt_response = {"roles": ["Role 1"]}
        assert descope_client.validate_roles(jwt_response, "Role 1") is True
        assert descope_client.validate_roles(jwt_response, ["Role 1"]) is True
        assert descope_client.validate_roles(jwt_response, ["Role 2"]) is False

        # Tenant level
        jwt_response = {"tenants": {}}
        assert descope_client.validate_tenant_roles(jwt_response, "t1", ["Perm 2"]) is False

        jwt_response = {"tenants": {"t1": {}}}
        assert descope_client.validate_tenant_roles(jwt_response, "t1", ["Perm 2"]) is False

        jwt_response = {"tenants": {"t1": {"roles": "Role 1"}}}
        assert descope_client.validate_tenant_roles(jwt_response, "t1", ["Role 1"]) is True
        assert descope_client.validate_tenant_roles(jwt_response, "t1", []) is True
        assert descope_client.validate_tenant_roles(jwt_response, "t1", ["Role 2"]) is False
        assert descope_client.validate_tenant_roles(jwt_response, "t1", ["Role 1", "Role 2"]) is False
        assert descope_client.validate_tenant_roles(jwt_response, "t1", ["Perm 1", "Perm 2"]) is False

    async def test_get_matched_roles(self, descope_client):
        jwt_response = {}
        assert descope_client.get_matched_roles(jwt_response, []) == []

        jwt_response = {"roles": []}
        assert descope_client.get_matched_roles(jwt_response, ["Role 1"]) == []

        jwt_response = {"roles": ["Role 1", "Role 2"]}
        assert descope_client.get_matched_roles(jwt_response, ["Role 1"]) == ["Role 1"]
        assert descope_client.get_matched_roles(jwt_response, ["Role 1", "Role 2"]) == ["Role 1", "Role 2"]
        assert descope_client.get_matched_roles(jwt_response, ["Role 1", "Role 2", "Role 3"]) == ["Role 1", "Role 2"]

        # Tenant level
        jwt_response = {"tenants": {}}
        assert descope_client.get_matched_tenant_roles(jwt_response, "t1", ["Role 1"]) == []

        jwt_response = {"tenants": {"t1": {}}}
        assert descope_client.get_matched_tenant_roles(jwt_response, "t1", ["Role 1"]) == []

        jwt_response = {"tenants": {"t1": {"roles": ["Role 1", "Role 2"]}}}
        assert descope_client.get_matched_tenant_roles(jwt_response, "t1", ["Role 1"]) == ["Role 1"]
        assert descope_client.get_matched_tenant_roles(jwt_response, "t1", ["Role 1", "Role 2"]) == ["Role 1", "Role 2"]
        assert descope_client.get_matched_tenant_roles(jwt_response, "t1", ["Role 1", "Role 2", "Role 3"]) == [
            "Role 1",
            "Role 2",
        ]

    # ------------------------------------------------------------------
    # exchange_access_key
    # ------------------------------------------------------------------

    async def test_exchange_access_key_empty_param(self, descope_client):
        with pytest.raises(AuthException) as exc_info:
            await descope_client.invoke(descope_client.exchange_access_key(""))
        assert exc_info.value.status_code == 400

    async def test_exchange_access_key(self, descope_client):
        dummy_access_key = "dummy access key"
        resp = make_response({"sessionJwt": VALID_REFRESH_TOKEN})
        with descope_client.mock_post(resp) as mock_post:
            jwt_response = await descope_client.invoke(
                descope_client.exchange_access_key(
                    access_key=dummy_access_key,
                    login_options=AccessKeyLoginOptions(custom_claims={"k1": "v1"}),
                )
            )
        assert jwt_response["keyId"] == EXPECTED_USER_ID
        assert jwt_response["projectId"] == EXPECTED_PROJECT_ID
        assert_http_called(
            mock_post,
            descope_client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.exchange_auth_access_key_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}:dummy access key",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginOptions": {"customClaims": {"k1": "v1"}}},
            follow_redirects=False,
        )

    # ------------------------------------------------------------------
    # JWT validation leeway
    # ------------------------------------------------------------------

    async def test_jwt_validation_leeway(self, client_factory):
        # Negative leeway forces even far-future tokens to appear expired
        min_int = -sys.maxsize - 1
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, jwt_validation_leeway=min_int)

        with pytest.raises(AuthException) as exc_info:
            client.validate_session(VALID_REFRESH_TOKEN)
        assert exc_info.value.status_code == 400
        assert "nbf in future" in exc_info.value.error_message

    # ------------------------------------------------------------------
    # select_tenant
    # ------------------------------------------------------------------

    async def test_select_tenant(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        data = json.loads(
            """{"jwts": ["eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"], "user": {"loginIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
        )
        resp = make_response(data)
        with client.mock_post(resp) as mock_post:
            await client.invoke(client.select_tenant("t1", VALID_REFRESH_TOKEN))
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.select_tenant_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}:{VALID_REFRESH_TOKEN}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"tenant": "t1"},
            follow_redirects=False,
        )

    # ------------------------------------------------------------------
    # auth_management_key header propagation (sync-only: uses otp)
    # ------------------------------------------------------------------

    async def test_auth_management_key_with_functions(self, client_factory):
        if client_factory.mode != "sync":
            pytest.skip("otp not available on AsyncDescopeClient")

        auth_mgmt_key = "test-auth-mgmt-key"

        # Test 1: Direct auth_management_key setting (without refresh token)
        client = client_factory.make(PROJECT_ID, DUMMY_PUBLIC_KEY_DICT, auth_management_key=auth_mgmt_key)

        with patch("httpx.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response

            client.otp.sign_up(DeliveryMethod.EMAIL, "test@example.com")

            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_otp_path}/email",
                headers={
                    **common.default_headers,
                    "x-descope-project-id": PROJECT_ID,
                    "Authorization": f"Bearer {PROJECT_ID}:{auth_mgmt_key}",
                },
                json={
                    "loginId": "test@example.com",
                    "user": {"email": "test@example.com"},
                    "email": "test@example.com",
                },
                params=None,
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test 2: Environment variable auth_management_key setting
        env_auth_mgmt_key = "env-auth-mgmt-key"
        with patch.dict("os.environ", {"DESCOPE_AUTH_MANAGEMENT_KEY": env_auth_mgmt_key}):
            client_env = client_factory.make(PROJECT_ID, DUMMY_PUBLIC_KEY_DICT)

            with patch("httpx.post") as mock_post:
                my_mock_response = mock.Mock()
                my_mock_response.is_success = True
                my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
                mock_post.return_value = my_mock_response

                client_env.otp.sign_up(DeliveryMethod.EMAIL, "test@example.com")

                mock_post.assert_called_with(
                    f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_otp_path}/email",
                    headers={
                        **common.default_headers,
                        "x-descope-project-id": PROJECT_ID,
                        "Authorization": f"Bearer {PROJECT_ID}:{env_auth_mgmt_key}",
                    },
                    json={
                        "loginId": "test@example.com",
                        "user": {"email": "test@example.com"},
                        "email": "test@example.com",
                    },
                    follow_redirects=False,
                    params=None,
                    verify=SSLMatcher(),
                    timeout=DEFAULT_TIMEOUT_SECONDS,
                )

        # Test 3: Direct parameter takes priority over environment variable
        direct_auth_mgmt_key = "direct-auth-mgmt-key"
        with patch.dict("os.environ", {"DESCOPE_AUTH_MANAGEMENT_KEY": env_auth_mgmt_key}):
            client_priority = client_factory.make(
                PROJECT_ID, DUMMY_PUBLIC_KEY_DICT, auth_management_key=direct_auth_mgmt_key
            )

            with patch("httpx.post") as mock_post:
                my_mock_response = mock.Mock()
                my_mock_response.is_success = True
                my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
                mock_post.return_value = my_mock_response

                client_priority.otp.sign_up(DeliveryMethod.EMAIL, "test@example.com")

                mock_post.assert_called_with(
                    f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_otp_path}/email",
                    headers={
                        **common.default_headers,
                        "x-descope-project-id": PROJECT_ID,
                        "Authorization": f"Bearer {PROJECT_ID}:{direct_auth_mgmt_key}",
                    },
                    json={
                        "loginId": "test@example.com",
                        "user": {"email": "test@example.com"},
                        "email": "test@example.com",
                    },
                    params=None,
                    follow_redirects=False,
                    verify=SSLMatcher(),
                    timeout=DEFAULT_TIMEOUT_SECONDS,
                )

    async def test_auth_management_key_with_refresh_token(self, client_factory):
        if client_factory.mode != "sync":
            pytest.skip("otp not available on AsyncDescopeClient")

        auth_mgmt_key = "test-auth-mgmt-key"
        client = client_factory.make(PROJECT_ID, DUMMY_PUBLIC_KEY_DICT, auth_management_key=auth_mgmt_key)

        # Test with refresh token function
        refresh_token = "test_refresh_token"
        with patch("httpx.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "n***@example.com"}
            mock_post.return_value = my_mock_response

            client.otp.update_user_email("old@example.com", "new@example.com", refresh_token)

            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_email_otp_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:{refresh_token}:{auth_mgmt_key}",
                    "x-descope-project-id": PROJECT_ID,
                },
                json={
                    "loginId": "old@example.com",
                    "email": "new@example.com",
                    "addToLoginIDs": False,
                    "onMergeUseExisting": False,
                },
                follow_redirects=False,
                params=None,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Without auth_management_key — refresh token only in Authorization
        client_no_auth = client_factory.make(PROJECT_ID, DUMMY_PUBLIC_KEY_DICT)
        with patch("httpx.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "n***@example.com"}
            mock_post.return_value = my_mock_response

            client_no_auth.otp.update_user_email("old@example.com", "new@example.com", refresh_token)

            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_email_otp_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:{refresh_token}",
                    "x-descope-project-id": PROJECT_ID,
                },
                json={
                    "loginId": "old@example.com",
                    "email": "new@example.com",
                    "addToLoginIDs": False,
                    "onMergeUseExisting": False,
                },
                follow_redirects=False,
                params=None,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    # ------------------------------------------------------------------
    # base_url parameter
    # ------------------------------------------------------------------

    async def test_base_url_setting(self, client_factory):
        custom_base_url = "https://api.use1.descope.com"
        client = client_factory.make(PROJECT_ID, base_url=custom_base_url, public_key=PUBLIC_KEY_DICT)

        # Auth HTTP client base_url is available on both sync and async
        assert client._auth.http_client.base_url == custom_base_url

        # Management HTTP client is sync-only
        if client_factory.mode == "sync":
            assert client._mgmt._http.base_url == custom_base_url

    async def test_base_url_none(self, client_factory):
        client = client_factory.make(PROJECT_ID, base_url=None, public_key=PUBLIC_KEY_DICT)

        expected_base_url = common.DEFAULT_BASE_URL
        assert client._auth.http_client.base_url == expected_base_url

        if client_factory.mode == "sync":
            assert client._mgmt._http.base_url == expected_base_url

    # ------------------------------------------------------------------
    # Verbose mode
    # ------------------------------------------------------------------

    async def test_verbose_mode_disabled_by_default(self, client_factory):
        client = client_factory.make(PROJECT_ID, public_key=PUBLIC_KEY_DICT)
        assert client.get_last_response() is None

    async def test_verbose_mode_enabled(self, client_factory):
        client = client_factory.make(PROJECT_ID, public_key=PUBLIC_KEY_DICT, verbose=True)
        # Just verify it doesn't error when enabled
        assert client.get_last_response() is None  # No requests made yet

    async def test_verbose_mode_captures_mgmt_response(self, client_factory):
        if client_factory.mode != "sync":
            pytest.skip("mgmt not available on AsyncDescopeClient")

        mock_response = mock.Mock()
        mock_response.is_success = True
        mock_response.json.return_value = {"user": {"id": "u1", "loginIds": ["test@example.com"]}}
        mock_response.headers = {"cf-ray": "mgmt-ray-123", "x-request-id": "req-456"}
        mock_response.status_code = 200

        with patch("httpx.post", return_value=mock_response):
            client = client_factory.make(
                PROJECT_ID,
                public_key=PUBLIC_KEY_DICT,
                management_key="test-mgmt-key",
                verbose=True,
            )
            client.mgmt.user.create(login_id="test@example.com")

        last_resp = client.get_last_response()
        assert last_resp is not None
        assert last_resp["user"]["id"] == "u1"
        assert last_resp.headers.get("cf-ray") == "mgmt-ray-123"
        assert last_resp.status_code == 200
