import pytest

from descope import AuthException
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
)
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT, VALID_REFRESH_TOKEN, VALID_SESSION_TOKEN

from . import common


class TestOAuth:
    def test_compose_start_params(self):
        from descope.authmethod.oauth import OAuth

        assert OAuth._compose_start_params("google", "http://example.com") == {
            "provider": "google",
            "redirectURL": "http://example.com",
        }
        assert OAuth._compose_start_params("google") == {"provider": "google"}

    def test_verify_provider(self):
        from descope.authmethod.oauth import OAuth

        assert OAuth._verify_provider("") is False
        assert OAuth._verify_provider(None) is False
        assert OAuth._verify_provider("google") is True

    async def test_start(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors — no HTTP call made
        with pytest.raises(AuthException):
            await client.invoke(client.oauth.start(""))
        with pytest.raises(AuthException):
            await client.invoke(client.oauth.start(None))
        with pytest.raises(AuthException):
            await client.invoke(client.oauth.start("facebook", login_options=LoginOptions(mfa=True)))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.oauth.start("google"))

        # Success
        with client.mock_post(make_response({"url": "http://auth.example.com"})):
            result = await client.invoke(client.oauth.start("google"))
        assert result is not None

        # Verify payload with params
        with client.mock_post(make_response({"url": "http://auth.example.com"})) as mock_post:
            await client.invoke(client.oauth.start("facebook"))
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.oauth_start_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params={"provider": "facebook"},
            json={},
            follow_redirects=False,
        )

    async def test_start_with_login_options(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        refresh_token = "dummy-refresh"

        lo = LoginOptions(stepup=True, custom_claims={"k1": "v1"})
        with client.mock_post(make_response({})) as mock_post:
            await client.invoke(client.oauth.start("facebook", login_options=lo, refresh_token=refresh_token))
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.oauth_start_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}:{refresh_token}",
                "x-descope-project-id": PROJECT_ID,
            },
            params={"provider": "facebook"},
            json={"stepup": True, "customClaims": {"k1": "v1"}, "mfa": False},
            follow_redirects=False,
        )

    async def test_exchange_token(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.oauth.exchange_token(""))
        with pytest.raises(AuthException):
            await client.invoke(client.oauth.exchange_token(None))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.oauth.exchange_token("c1"))

        # Success
        success_resp = make_response(
            {"sessionJwt": VALID_SESSION_TOKEN},
            cookies={REFRESH_SESSION_COOKIE_NAME: VALID_REFRESH_TOKEN},
        )
        with client.mock_post(success_resp) as mock_post:
            result = await client.invoke(client.oauth.exchange_token("c1"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.oauth_exchange_token_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"code": "c1"},
            follow_redirects=False,
        )
