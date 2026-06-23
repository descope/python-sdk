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


class TestSSO:
    def test_compose_start_params(self):
        from descope.authmethod.sso import SSO

        assert SSO._compose_start_params("tenant1", "http://dummy.com", "", "", "", None) == {
            "tenant": "tenant1",
            "redirectURL": "http://dummy.com",
        }
        assert SSO._compose_start_params("tenant1", "http://dummy.com", "bla", "blue", "", None) == {
            "tenant": "tenant1",
            "redirectURL": "http://dummy.com",
            "prompt": "bla",
            "ssoId": "blue",
        }
        assert SSO._compose_start_params("t1", "http://x.com", "consent", "sid", "user@d.com", True) == {
            "tenant": "t1",
            "redirectURL": "http://x.com",
            "prompt": "consent",
            "ssoId": "sid",
            "loginHint": "user@d.com",
            "forceAuthn": True,
        }
        # forceAuthn=False must be included (not skipped as falsy)
        assert SSO._compose_start_params("t1", "http://x.com", "", "", "", False) == {
            "tenant": "t1",
            "redirectURL": "http://x.com",
            "forceAuthn": False,
        }

    async def test_start(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.sso.start("", "http://dummy.com"))
        with pytest.raises(AuthException):
            await client.invoke(client.sso.start(None, "http://dummy.com"))
        with pytest.raises(AuthException):
            await client.invoke(client.sso.start("tenant", "http://dummy.com", LoginOptions(mfa=True)))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.sso.start("tenant1", "http://dummy.com"))

        # Success
        with client.mock_post(make_response({"url": "http://auth.example.com"})):
            result = await client.invoke(client.sso.start("tenant1", "http://dummy.com"))
        assert result is not None

        # Verify payload
        with client.mock_post(make_response({})) as mock_post:
            await client.invoke(client.sso.start("tenant1", "http://dummy.com", sso_id="some-sso-id"))
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.auth_sso_start_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params={
                "tenant": "tenant1",
                "redirectURL": "http://dummy.com",
                "ssoId": "some-sso-id",
            },
            json={},
            follow_redirects=False,
        )

    async def test_start_with_login_options(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        lo = LoginOptions(stepup=True, custom_claims={"k1": "v1"})

        with client.mock_post(make_response({})) as mock_post:
            await client.invoke(client.sso.start("tenant1", "http://dummy.com", lo, "refresh"))
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.auth_sso_start_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}:refresh",
                "x-descope-project-id": PROJECT_ID,
            },
            params={"tenant": "tenant1", "redirectURL": "http://dummy.com"},
            json={"stepup": True, "customClaims": {"k1": "v1"}, "mfa": False},
            follow_redirects=False,
        )

    async def test_exchange_token(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.sso.exchange_token(""))
        with pytest.raises(AuthException):
            await client.invoke(client.sso.exchange_token(None))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.sso.exchange_token("c1"))

        # Success
        success_resp = make_response(
            {"sessionJwt": VALID_SESSION_TOKEN},
            cookies={REFRESH_SESSION_COOKIE_NAME: VALID_REFRESH_TOKEN},
        )
        with client.mock_post(success_resp) as mock_post:
            result = await client.invoke(client.sso.exchange_token("c1"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sso_exchange_token_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"code": "c1"},
            follow_redirects=False,
        )
