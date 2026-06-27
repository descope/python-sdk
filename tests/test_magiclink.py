import pytest

from descope import AuthException, DeliveryMethod
from descope.authmethod.magiclink import MagicLink
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
)
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT, VALID_REFRESH_TOKEN, VALID_SESSION_TOKEN

from . import common


class TestMagicLink:
    def test_compose_urls(self):
        assert MagicLink._compose_signin_url(DeliveryMethod.SMS) == "/v1/auth/magiclink/signin/sms"
        assert MagicLink._compose_signup_url(DeliveryMethod.WHATSAPP) == "/v1/auth/magiclink/signup/whatsapp"
        assert MagicLink._compose_sign_up_or_in_url(DeliveryMethod.EMAIL) == "/v1/auth/magiclink/signup-in/email"
        assert MagicLink._compose_update_phone_url(DeliveryMethod.SMS) == "/v1/auth/magiclink/update/phone/sms"

    def test_compose_body(self):
        assert MagicLink._compose_signin_body("id1", "uri1") == {
            "loginId": "id1",
            "URI": "uri1",
            "loginOptions": {},
        }
        assert MagicLink._compose_verify_body("t1") == {"token": "t1"}
        assert MagicLink._compose_update_user_email_body("id1", "email1", True, False) == {
            "loginId": "id1",
            "email": "email1",
            "addToLoginIDs": True,
            "onMergeUseExisting": False,
        }

    async def test_sign_in(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.magiclink.sign_in(DeliveryMethod.EMAIL, "", "http://r.me"))
        with pytest.raises(AuthException):
            await client.invoke(client.magiclink.sign_in(DeliveryMethod.EMAIL, None, "http://r.me"))
        with pytest.raises(AuthException):
            await client.invoke(
                client.magiclink.sign_in(DeliveryMethod.EMAIL, "dummy@dummy.com", "http://r.me", LoginOptions(mfa=True))
            )

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.magiclink.sign_in(DeliveryMethod.EMAIL, "dummy@dummy.com", "http://r.me"))

        # Success + payload
        with client.mock_post(make_response({"maskedEmail": "du***@***my.com"})) as mock_post:
            result = await client.invoke(
                client.magiclink.sign_in(DeliveryMethod.EMAIL, "dummy@dummy.com", "http://r.me")
            )
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_magiclink_path}/email",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "dummy@dummy.com", "URI": "http://r.me", "loginOptions": {}},
            follow_redirects=False,
        )

    async def test_sign_up(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        user = {"name": "John", "email": "dummy@dummy.com"}

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.magiclink.sign_up(DeliveryMethod.EMAIL, None, "http://r.me", user))
        with pytest.raises(AuthException):
            await client.invoke(client.magiclink.sign_up(DeliveryMethod.EMAIL, "", "http://r.me", user))
        with pytest.raises(AuthException):
            await client.invoke(
                client.magiclink.sign_up(DeliveryMethod.EMAIL, "id", "http://r.me", {"email": "not-valid"})
            )

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.magiclink.sign_up(DeliveryMethod.EMAIL, "dummy@dummy.com", "http://r.me", user)
                )

        # Success
        with client.mock_post(make_response({"maskedEmail": "du***@***my.com"})):
            result = await client.invoke(
                client.magiclink.sign_up(DeliveryMethod.EMAIL, "dummy@dummy.com", "http://r.me", user)
            )
        assert result is not None

    async def test_sign_up_or_in(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.magiclink.sign_up_or_in(DeliveryMethod.EMAIL, "dummy@dummy.com", "http://r.me")
                )

        # Success + payload
        with client.mock_post(make_response({"maskedEmail": "du***@***my.com"})) as mock_post:
            result = await client.invoke(
                client.magiclink.sign_up_or_in(DeliveryMethod.EMAIL, "dummy@dummy.com", "http://r.me")
            )
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_or_in_auth_magiclink_path}/email",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "dummy@dummy.com", "URI": "http://r.me", "loginOptions": {}},
            follow_redirects=False,
        )

    async def test_verify(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.magiclink.verify("some-token"))

        # Success
        success_resp = make_response(
            {"sessionJwt": VALID_SESSION_TOKEN},
            cookies={REFRESH_SESSION_COOKIE_NAME: VALID_REFRESH_TOKEN},
        )
        with client.mock_post(success_resp) as mock_post:
            result = await client.invoke(client.magiclink.verify("some-token"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.verify_magiclink_auth_path}",
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
            await client.invoke(client.magiclink.update_user_email("", "new@example.com", refresh_token))
        with pytest.raises(AuthException):
            await client.invoke(client.magiclink.update_user_email(None, "new@example.com", refresh_token))
        with pytest.raises(AuthException):
            await client.invoke(client.magiclink.update_user_email("id", "bad-email", refresh_token))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.magiclink.update_user_email("id", "new@example.com", refresh_token))

        # Success + payload
        with client.mock_post(make_response({"maskedEmail": "ne***@***le.com"})) as mock_post:
            result = await client.invoke(
                client.magiclink.update_user_email("dummy@dummy.com", "new@example.com", refresh_token)
            )
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_email_magiclink_path}",
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

    async def test_update_user_phone(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        refresh_token = VALID_REFRESH_TOKEN

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(
                client.magiclink.update_user_phone(DeliveryMethod.SMS, "", "+11234567890", refresh_token)
            )
        with pytest.raises(AuthException):
            await client.invoke(
                client.magiclink.update_user_phone(DeliveryMethod.SMS, "id", "bad-phone", refresh_token)
            )

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.magiclink.update_user_phone(DeliveryMethod.SMS, "dummy", "+11234567890", refresh_token)
                )

        # Success + payload
        with client.mock_post(make_response({"maskedPhone": "+1***890"})) as mock_post:
            result = await client.invoke(
                client.magiclink.update_user_phone(DeliveryMethod.SMS, "dummy", "+11234567890", refresh_token)
            )
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_phone_magiclink_path}",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}:{refresh_token}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={
                "loginId": "dummy",
                "phone": "+11234567890",
                "addToLoginIDs": False,
                "onMergeUseExisting": False,
            },
            follow_redirects=False,
        )
