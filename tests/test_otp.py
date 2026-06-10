import pytest

from descope import AuthException, DeliveryMethod
from descope.authmethod.otp import OTP
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
)
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT, VALID_REFRESH_TOKEN, VALID_SESSION_TOKEN

from . import common


class TestOTP:
    def test_compose_signin_url(self):
        assert OTP._compose_signin_url(DeliveryMethod.EMAIL) == "/v1/auth/otp/signin/email"
        assert OTP._compose_signin_url(DeliveryMethod.SMS) == "/v1/auth/otp/signin/sms"
        assert OTP._compose_signin_url(DeliveryMethod.VOICE) == "/v1/auth/otp/signin/voice"
        assert OTP._compose_signin_url(DeliveryMethod.WHATSAPP) == "/v1/auth/otp/signin/whatsapp"

    def test_compose_verify_code_url(self):
        assert OTP._compose_verify_code_url(DeliveryMethod.EMAIL) == "/v1/auth/otp/verify/email"
        assert OTP._compose_verify_code_url(DeliveryMethod.SMS) == "/v1/auth/otp/verify/sms"

    def test_compose_sign_up_or_in_url(self):
        assert OTP._compose_sign_up_or_in_url(DeliveryMethod.EMAIL) == "/v1/auth/otp/signup-in/email"
        assert OTP._compose_sign_up_or_in_url(DeliveryMethod.SMS) == "/v1/auth/otp/signup-in/sms"

    def test_compose_update_phone_url(self):
        assert OTP._compose_update_phone_url(DeliveryMethod.SMS) == "/v1/auth/otp/update/phone/sms"
        assert OTP._compose_update_phone_url(DeliveryMethod.WHATSAPP) == "/v1/auth/otp/update/phone/whatsapp"

    async def test_sign_in(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.otp.sign_in(DeliveryMethod.EMAIL, ""))
        with pytest.raises(AuthException):
            await client.invoke(client.otp.sign_in(DeliveryMethod.EMAIL, None))
        with pytest.raises(AuthException):
            await client.invoke(client.otp.sign_in(DeliveryMethod.EMAIL, "id", LoginOptions(mfa=True)))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.otp.sign_in(DeliveryMethod.EMAIL, "dummy@dummy.com"))

        # Success
        with client.mock_post(make_response({"maskedEmail": "du***@***my.com"})):
            result = await client.invoke(client.otp.sign_in(DeliveryMethod.EMAIL, "dummy@dummy.com"))
        assert result is not None

        # Verify payload
        with client.mock_post(make_response({"maskedEmail": "du***@***my.com"})) as mock_post:
            await client.invoke(client.otp.sign_in(DeliveryMethod.EMAIL, "dummy@dummy.com"))
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_otp_path}/email",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "dummy@dummy.com", "loginOptions": {}},
            follow_redirects=False,
        )

    async def test_sign_up(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        user = {"name": "John", "email": "dummy@dummy.com"}

        # Validation errors — empty login_id returns False from adjust_and_verify
        with pytest.raises(AuthException):
            await client.invoke(client.otp.sign_up(DeliveryMethod.EMAIL, None, user))
        with pytest.raises(AuthException):
            await client.invoke(client.otp.sign_up(DeliveryMethod.EMAIL, "", user))
        # Bad email in user dict
        with pytest.raises(AuthException):
            await client.invoke(client.otp.sign_up(DeliveryMethod.EMAIL, "id", {"email": "not-valid"}))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.otp.sign_up(DeliveryMethod.EMAIL, "dummy@dummy.com", user))

        # Success
        with client.mock_post(make_response({"maskedEmail": "du***@***my.com"})):
            result = await client.invoke(client.otp.sign_up(DeliveryMethod.EMAIL, "dummy@dummy.com", user))
        assert result is not None

    async def test_sign_up_or_in(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.otp.sign_up_or_in(DeliveryMethod.EMAIL, ""))
        with pytest.raises(AuthException):
            await client.invoke(client.otp.sign_up_or_in(DeliveryMethod.EMAIL, None))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.otp.sign_up_or_in(DeliveryMethod.EMAIL, "dummy@dummy.com"))

        # Success
        with client.mock_post(make_response({"maskedEmail": "du***@***my.com"})) as mock_post:
            result = await client.invoke(client.otp.sign_up_or_in(DeliveryMethod.EMAIL, "dummy@dummy.com"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_or_in_auth_otp_path}/email",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "dummy@dummy.com", "loginOptions": {}},
            follow_redirects=False,
        )

    async def test_verify_code(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.otp.verify_code(DeliveryMethod.EMAIL, "", "123456"))
        with pytest.raises(AuthException):
            await client.invoke(client.otp.verify_code(DeliveryMethod.EMAIL, None, "123456"))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.otp.verify_code(DeliveryMethod.EMAIL, "dummy@dummy.com", "123456"))

        # Success
        success_resp = make_response(
            {"sessionJwt": VALID_SESSION_TOKEN},
            cookies={REFRESH_SESSION_COOKIE_NAME: VALID_REFRESH_TOKEN},
        )
        with client.mock_post(success_resp) as mock_post:
            result = await client.invoke(client.otp.verify_code(DeliveryMethod.EMAIL, "dummy@dummy.com", "123456"))
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.verify_code_auth_path}/email",
            headers={
                **common.default_headers,
                "Authorization": f"Bearer {PROJECT_ID}",
                "x-descope-project-id": PROJECT_ID,
            },
            params=None,
            json={"loginId": "dummy@dummy.com", "code": "123456"},
            follow_redirects=False,
        )

    async def test_update_user_email(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)
        refresh_token = VALID_REFRESH_TOKEN

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.otp.update_user_email("", "new@example.com", refresh_token))
        with pytest.raises(AuthException):
            await client.invoke(client.otp.update_user_email(None, "new@example.com", refresh_token))
        with pytest.raises(AuthException):
            await client.invoke(client.otp.update_user_email("id", "not-valid-email", refresh_token))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.otp.update_user_email("dummy@dummy.com", "new@example.com", refresh_token))

        # Success
        with client.mock_post(make_response({"maskedEmail": "ne***@***le.com"})) as mock_post:
            result = await client.invoke(
                client.otp.update_user_email("dummy@dummy.com", "new@example.com", refresh_token)
            )
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_email_otp_path}",
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
            await client.invoke(client.otp.update_user_phone(DeliveryMethod.SMS, "", "+11234567890", refresh_token))
        with pytest.raises(AuthException):
            await client.invoke(client.otp.update_user_phone(DeliveryMethod.SMS, "id", "not-a-phone", refresh_token))

        # HTTP error
        with client.mock_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.otp.update_user_phone(DeliveryMethod.SMS, "dummy", "+11234567890", refresh_token)
                )

        # Success
        with client.mock_post(make_response({"maskedPhone": "+1***890"})) as mock_post:
            result = await client.invoke(
                client.otp.update_user_phone(DeliveryMethod.SMS, "dummy", "+11234567890", refresh_token)
            )
        assert result is not None
        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_phone_otp_path}/sms",
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
