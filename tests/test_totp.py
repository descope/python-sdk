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


class TestTOTP:
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
