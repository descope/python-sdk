import pytest

from descope import AuthException
from descope.authmethod.enchantedlink import EnchantedLink
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
)
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT, VALID_REFRESH_TOKEN, VALID_SESSION_TOKEN

from . import common


class TestEnchantedLink:
    def test_compose_urls(self):
        assert EnchantedLink._compose_signin_url() == "/v1/auth/enchantedlink/signin/email"
        assert EnchantedLink._compose_signup_url() == "/v1/auth/enchantedlink/signup/email"
        assert EnchantedLink._compose_sign_up_or_in_url() == "/v1/auth/enchantedlink/signup-in/email"

    def test_compose_body(self):
        assert EnchantedLink._compose_signin_body("id1", "uri1") == {
            "loginId": "id1",
            "URI": "uri1",
            "loginOptions": {},
        }
        assert EnchantedLink._compose_verify_body("t1") == {"token": "t1"}
        assert EnchantedLink._compose_get_session_body("ref1") == {"pendingRef": "ref1"}

    async def test_sign_in(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.enchantedlink.sign_in("", "http://r.me"))
        with pytest.raises(AuthException):
            await client.invoke(client.enchantedlink.sign_in(None, "http://r.me"))
        with pytest.raises(AuthException):
            await client.invoke(client.enchantedlink.sign_in("id", "http://r.me", LoginOptions(mfa=True)))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.enchantedlink.sign_in("dummy@dummy.com", "http://r.me"))

        # Success + payload
        with client.mock_post(make_response({"pendingRef": "ref123", "linkId": "lnk1"})) as mock_post:
            result = await client.invoke(client.enchantedlink.sign_in("dummy@dummy.com", "http://r.me"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_enchantedlink_path}/email",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "dummy@dummy.com", "URI": "http://r.me", "loginOptions": {}},
            follow_redirects=False,
        )

    async def test_sign_in_with_login_options(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        lo = LoginOptions(stepup=True, custom_claims={"k1": "v1"})

        with client.mock_post(make_response({"pendingRef": "ref1", "linkId": "24"})) as mock_post:
            await client.invoke(client.enchantedlink.sign_in("dummy@dummy.com", "http://r.me", lo, "refresh"))
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_enchantedlink_path}/email",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}:refresh",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={
                "loginId": "dummy@dummy.com",
                "URI": "http://r.me",
                "loginOptions": {"stepup": True, "customClaims": {"k1": "v1"}, "mfa": False},
            },
            follow_redirects=False,
        )

    async def test_sign_up(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        user = {"name": "John", "email": "dummy@dummy.com"}

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.enchantedlink.sign_up(None, "http://r.me", user))
        with pytest.raises(AuthException):
            await client.invoke(client.enchantedlink.sign_up("", "http://r.me", user))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.enchantedlink.sign_up("dummy@dummy.com", "http://r.me", user))

        # Success
        with client.mock_post(make_response({"pendingRef": "ref123", "linkId": "lnk1"})):
            result = await client.invoke(client.enchantedlink.sign_up("dummy@dummy.com", "http://r.me", user))
        assert result is not None

    async def test_sign_up_or_in(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.enchantedlink.sign_up_or_in("dummy@dummy.com", "http://r.me"))

        # Success + payload
        with client.mock_post(make_response({"pendingRef": "ref123"})) as mock_post:
            result = await client.invoke(client.enchantedlink.sign_up_or_in("dummy@dummy.com", "http://r.me"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_or_in_auth_enchantedlink_path}/email",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "dummy@dummy.com", "URI": "http://r.me", "loginOptions": {}},
            follow_redirects=False,
        )

    async def test_get_session(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.enchantedlink.get_session("pending-ref"))

        # Success
        success_resp = make_response(
            {"sessionJwt": VALID_SESSION_TOKEN},
            cookies={REFRESH_SESSION_COOKIE_NAME: VALID_REFRESH_TOKEN},
        )
        with client.mock_post(success_resp) as mock_post:
            result = await client.invoke(client.enchantedlink.get_session("pending-ref"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.get_session_enchantedlink_auth_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"pendingRef": "pending-ref"},
            follow_redirects=False,
        )

    async def test_verify(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.enchantedlink.verify("some-token"))

        # Success (returns None)
        with client.mock_post(make_response({})) as mock_post:
            result = await client.invoke(client.enchantedlink.verify("some-token"))
        assert result is None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.verify_enchantedlink_auth_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"token": "some-token"},
            follow_redirects=False,
        )

    async def test_update_user_email(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        refresh_token = VALID_REFRESH_TOKEN

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.enchantedlink.update_user_email("", "new@example.com", refresh_token))
        with pytest.raises(AuthException):
            await client.invoke(client.enchantedlink.update_user_email(None, "new@example.com", refresh_token))
        with pytest.raises(AuthException):
            await client.invoke(client.enchantedlink.update_user_email("id", "bad-email", refresh_token))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.enchantedlink.update_user_email("id", "new@example.com", refresh_token))

        # Success + payload
        with client.mock_post(make_response({"pendingRef": "ref123"})) as mock_post:
            result = await client.invoke(
                client.enchantedlink.update_user_email("dummy@dummy.com", "new@example.com", refresh_token)
            )
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_email_enchantedlink_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}:{refresh_token}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={
                "loginId": "dummy@dummy.com",
                "email": "new@example.com",
                "addToLoginIDs": False,
                "onMergeUseExisting": False,
            },
            follow_redirects=False,
        )
