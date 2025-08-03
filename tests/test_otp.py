from enum import Enum
from unittest import mock
from unittest.mock import patch
import asyncio

import pytest
from descope import SESSION_COOKIE_NAME, AuthException, DeliveryMethod, DescopeClient
from descope.authmethod.otp import OTP  # noqa: F401
from descope.common import (
    DEFAULT_TIMEOUT_SECONDS,
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
    SignUpOptions,
)

from . import common
from .common import DEFAULT_BASE_URL, default_headers
from .utils import HTTPMockHelper, safe_await


class TestOTP(common.DescopeTest):
    def setUp(self) -> None:
        super().setUp()
        self.dummy_project_id = "dummy"
        self.public_key_dict = {
            "alg": "ES384",
            "crv": "P-384",
            "kid": "P2CtzUhdqpIF2ys9gg7ms06UvtC4",
            "kty": "EC",
            "use": "sig",
            "x": "pX1l7nT2turcK5_Cdzos8SKIhpLh1Wy9jmKAVyMFiOCURoj-WQX1J0OUQqMsQO0s",
            "y": "B0_nWAv2pmG_PzoH3-bSYZZzLNKUA0RoE2SH7DaS0KV4rtfWZhYd0MEr0xfdGKx0",
        }

    async def test_compose_signin_url(self):
        self.assertEqual(
            OTP._compose_signin_url(DeliveryMethod.EMAIL),
            "/v1/auth/otp/signin/email",
        )
        self.assertEqual(
            OTP._compose_signin_url(DeliveryMethod.SMS),
            "/v1/auth/otp/signin/sms",
        )
        self.assertEqual(
            OTP._compose_signin_url(DeliveryMethod.VOICE),
            "/v1/auth/otp/signin/voice",
        )
        self.assertEqual(
            OTP._compose_signin_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/otp/signin/whatsapp",
        )

    async def test_compose_verify_code_url(self):
        self.assertEqual(
            OTP._compose_verify_code_url(DeliveryMethod.EMAIL),
            "/v1/auth/otp/verify/email",
        )
        self.assertEqual(
            OTP._compose_verify_code_url(DeliveryMethod.SMS),
            "/v1/auth/otp/verify/sms",
        )
        self.assertEqual(
            OTP._compose_verify_code_url(DeliveryMethod.VOICE),
            "/v1/auth/otp/verify/voice",
        )
        self.assertEqual(
            OTP._compose_verify_code_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/otp/verify/whatsapp",
        )

    async def test_compose_update_phone_url(self):
        self.assertEqual(
            OTP._compose_update_phone_url(DeliveryMethod.EMAIL),
            "/v1/auth/otp/update/phone/email",
        )
        self.assertEqual(
            OTP._compose_update_phone_url(DeliveryMethod.SMS),
            "/v1/auth/otp/update/phone/sms",
        )
        self.assertEqual(
            OTP._compose_update_phone_url(DeliveryMethod.VOICE),
            "/v1/auth/otp/update/phone/voice",
        )
        self.assertEqual(
            OTP._compose_update_phone_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/otp/update/phone/whatsapp",
        )

    async def test_compose_sign_up_or_in_url(self):
        self.assertEqual(
            OTP._compose_sign_up_or_in_url(DeliveryMethod.EMAIL),
            "/v1/auth/otp/signup-in/email",
        )
        self.assertEqual(
            OTP._compose_sign_up_or_in_url(DeliveryMethod.SMS),
            "/v1/auth/otp/signup-in/sms",
        )
        self.assertEqual(
            OTP._compose_sign_up_or_in_url(DeliveryMethod.VOICE),
            "/v1/auth/otp/signup-in/voice",
        )
        self.assertEqual(
            OTP._compose_sign_up_or_in_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/otp/signup-in/whatsapp",
        )

    async def test_compose_update_user_phone_body(self):
        self.assertEqual(
            OTP._compose_update_user_phone_body(
                "dummy@dummy.com", "+11111111", False, True
            ),
            {
                "loginId": "dummy@dummy.com",
                "phone": "+11111111",
                "addToLoginIDs": False,
                "onMergeUseExisting": True,
            },
        )

    async def test_compose_update_user_email_body(self):
        self.assertEqual(
            OTP._compose_update_user_email_body(
                "dummy@dummy.com", "dummy@dummy.com", False, True
            ),
            {
                "loginId": "dummy@dummy.com",
                "email": "dummy@dummy.com",
                "addToLoginIDs": False,
                "onMergeUseExisting": True,
            },
        )

    async def test_sign_up(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict, async_mode=self.async_mode)
        invalid_signup_user_details = {
            "username": "jhon",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy",
        }
        signup_user_details = {
            "username": "jhon",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }

        client = DescopeClient(self.dummy_project_id, self.public_key_dict, async_mode=self.async_mode)

        # Test failed flows
        with self.assertRaises(AuthException):
            await safe_await(client.otp.sign_up(
                DeliveryMethod.EMAIL,
                "dummy@dummy",
                invalid_signup_user_details,
            ))
        invalid_signup_user_details["email"] = "dummy@dummy.com"  # set valid mail
        invalid_signup_user_details["phone"] = "aaaaaaaa"  # set invalid phone
        with self.assertRaises(AuthException):
            await safe_await(client.otp.sign_up(
                DeliveryMethod.EMAIL,
                "",
                invalid_signup_user_details,
            ))
        with self.assertRaises(AuthException):
            await safe_await(client.otp.sign_up(
                DeliveryMethod.SMS,
                "dummy@dummy.com",
                invalid_signup_user_details,
            ))
        with self.assertRaises(AuthException):
            await safe_await(client.otp.sign_up(
                DeliveryMethod.VOICE,
                "dummy@dummy.com",
                invalid_signup_user_details,
            ))
        with self.assertRaises(AuthException):
            await safe_await(client.otp.sign_up(
                DeliveryMethod.WHATSAPP,
                "dummy@dummy.com",
                invalid_signup_user_details,
            ))

        with HTTPMockHelper.mock_http_call(self.async_mode, "post", ok=False) as mock_http:
            with self.assertRaises(AuthException):
                await safe_await(client.otp.sign_up(
                    DeliveryMethod.EMAIL,
                    "dummy@dummy.com",
                    signup_user_details,
                ))

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            self.async_mode, "post", ok=True, json=lambda: {"maskedEmail": "t***@example.com"}
        ) as mock_http:
            result = await safe_await(client.otp.sign_up(
                DeliveryMethod.EMAIL, "dummy@dummy.com", signup_user_details
            ))
            self.assertEqual("t***@example.com", result)

        # Test flow where username set as empty and we used the login_id as default
        signup_user_details = {
            "username": "",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }

        with HTTPMockHelper.mock_http_call(
            self.async_mode, "post", ok=True, json=lambda: {"maskedEmail": "t***@example.com"}
        ) as mock_http:
            result = await safe_await(client.otp.sign_up(
                DeliveryMethod.EMAIL, "dummy@dummy.com", signup_user_details
            ))
            self.assertEqual("t***@example.com", result)
            HTTPMockHelper.assert_http_call(
                mock_http,
                self.async_mode,
                f"{DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_otp_path}/email",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "user": {
                        "username": "",
                        "name": "john",
                        "phone": "972525555555",
                        "email": "dummy@dummy.com",
                    },
                    "email": "dummy@dummy.com",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with sign up options
        with HTTPMockHelper.mock_http_call(
            self.async_mode, "post", ok=True, json=lambda: {"maskedEmail": "t***@example.com"}
        ) as mock_http:
            result = await safe_await(client.otp.sign_up(
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                signup_user_details,
                SignUpOptions(template_options={"bla": "blue"}, template_id="foo"),
            ))
            self.assertEqual("t***@example.com", result)
            HTTPMockHelper.assert_http_call(
                mock_http,
                self.async_mode,
                f"{DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_otp_path}/email",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "user": {
                        "username": "",
                        "name": "john",
                        "phone": "972525555555",
                        "email": "dummy@dummy.com",
                    },
                    "email": "dummy@dummy.com",
                    "loginOptions": {
                        "templateOptions": {"bla": "blue"},
                        "templateId": "foo",
                    },
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test user is None so using the login_id as default
        with HTTPMockHelper.mock_http_call(
            self.async_mode, "post", ok=True, json=lambda: {"maskedEmail": "t***@example.com"}
        ) as mock_http:
            result = await safe_await(client.otp.sign_up(DeliveryMethod.EMAIL, "dummy@dummy.com", None))
            self.assertEqual("t***@example.com", result)
            HTTPMockHelper.assert_http_call(
                mock_http,
                self.async_mode,
                f"{DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_otp_path}/email",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "user": {"email": "dummy@dummy.com"},
                    "email": "dummy@dummy.com",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # test undefined enum value
        class Dummy(Enum):
            DUMMY = 7

        with self.assertRaises(AuthException):
            await safe_await(OTP._compose_signin_url(Dummy.DUMMY))
        
    async def test_sign_in(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict, async_mode=self.async_mode)

        # Test failed flows
        with self.assertRaises(AuthException):
            await safe_await(client.otp.sign_in(DeliveryMethod.EMAIL, ""))
        
        with self.assertRaises(AuthException):
            await safe_await(client.otp.sign_in(DeliveryMethod.EMAIL, None))

        with HTTPMockHelper.mock_http_call(self.async_mode, "post", ok=False) as mock_http:
            with self.assertRaises(AuthException):
                await safe_await(client.otp.sign_in(DeliveryMethod.EMAIL, "dummy@dummy.com"))

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            self.async_mode, "post", ok=True, json=lambda: {"maskedEmail": "t***@example.com"}
        ) as mock_http:
            result = await safe_await(client.otp.sign_in(DeliveryMethod.EMAIL, "dummy@dummy.com"))
            self.assertEqual("t***@example.com", result)
            
            with self.assertRaises(AuthException):
                await safe_await(client.otp.sign_in(
                    DeliveryMethod.EMAIL,
                    "exid",
                    LoginOptions(mfa=True),
                ))

        # Validate refresh token used while provided
        with HTTPMockHelper.mock_http_call(self.async_mode, "post", json=lambda: {"maskedEmail": "t***@example.com"}) as mock_http:
            refresh_token = "dummy refresh token"
            await safe_await(client.otp.sign_in(
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                LoginOptions(stepup=True),
                refresh_token=refresh_token,
            ))
            HTTPMockHelper.assert_http_call(
                mock_http,
                self.async_mode,
                f"{DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_otp_path}/email",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{refresh_token}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "loginOptions": {
                        "stepup": True,
                        "customClaims": None,
                        "mfa": False,
                    },
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
        return
        # With template options
        with HTTPMockHelper.mock_http_call(self.async_mode, "post") as mock_http:
            refresh_token = "dummy refresh token"
            await safe_await(client.otp.sign_in(
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                LoginOptions(
                    stepup=True, template_options={"blue": "bla"}, template_id="foo"
                ),
                refresh_token=refresh_token,
            ))
            HTTPMockHelper.assert_http_call(
                mock_http,
                self.async_mode,
                f"{DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_otp_path}/email",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{refresh_token}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "loginOptions": {
                        "stepup": True,
                        "customClaims": None,
                        "templateOptions": {"blue": "bla"},
                        "templateId": "foo",
                        "mfa": False,
                    },
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_sign_up_or_in(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict, async_mode=self.async_mode)

        # Test failed flows
        with self.assertRaises(AuthException):
            await safe_await(client.otp.sign_up_or_in(DeliveryMethod.EMAIL, ""))

        with HTTPMockHelper.mock_http_call(self.async_mode, "post", ok=False) as mock_http:
            with self.assertRaises(AuthException):
                await safe_await(client.otp.sign_up_or_in(
                    DeliveryMethod.EMAIL,
                    "dummy@dummy.com",
                ))

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            self.async_mode, "post", ok=True, json=lambda: {"maskedEmail": "t***@example.com"}
        ) as mock_http:
            result = await safe_await(client.otp.sign_up_or_in(DeliveryMethod.EMAIL, "dummy@dummy.com"))
            self.assertEqual("t***@example.com", result)

        # Test success flow with sign up options
        with HTTPMockHelper.mock_http_call(
            self.async_mode, "post", ok=True, json=lambda: {"maskedEmail": "t***@example.com"}
        ) as mock_http:
            result = await safe_await(client.otp.sign_up_or_in(
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                SignUpOptions(template_options={"bla": "blue"}, template_id="foo"),
            ))
            self.assertEqual("t***@example.com", result)
            HTTPMockHelper.assert_http_call(
                mock_http,
                self.async_mode,
                f"{DEFAULT_BASE_URL}{EndpointsV1.sign_up_or_in_auth_otp_path}/email",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "dummy@dummy.com",
                    "loginOptions": {
                        "stepup": False,
                        "customClaims": None,
                        "mfa": False,
                        "templateOptions": {"bla": "blue"},
                        "templateId": "foo",
                    },
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )

    async def test_verify_code(self):
        code = "1234"

        client = DescopeClient(self.dummy_project_id, self.public_key_dict, async_mode=self.async_mode)

        with self.assertRaises(AuthException):
            await safe_await(client.otp.verify_code(DeliveryMethod.EMAIL, "", code))
        
        with self.assertRaises(AuthException):
            await safe_await(client.otp.verify_code(DeliveryMethod.EMAIL, None, code))

        with HTTPMockHelper.mock_http_call(self.async_mode, "post", ok=False) as mock_http:
            with self.assertRaises(AuthException):
                await safe_await(client.otp.verify_code(
                    DeliveryMethod.EMAIL,
                    "dummy@dummy.com",
                    code,
                ))

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL"
        
        cookies = {
            SESSION_COOKIE_NAME: "dummy session token",
            REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
        }
        
        with HTTPMockHelper.mock_http_call(
            self.async_mode, "post", ok=True, json=lambda: {}, cookies=cookies
        ) as mock_http:
            result = await safe_await(client.otp.verify_code(DeliveryMethod.EMAIL, "dummy@dummy.com", code))
            self.assertIsNotNone(result)

    async def test_update_user_email(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict, async_mode=self.async_mode)

        # Test failed flows
        with self.assertRaises(AuthException):
            await safe_await(client.otp.update_user_email(
                "",
                "dummy@dummy.com",
                "refresh_token1",
            ))

        with self.assertRaises(AuthException):
            await safe_await(client.otp.update_user_email(
                "id1",
                "dummy@dummy",
                "refresh_token1",
            ))

        with HTTPMockHelper.mock_http_call(self.async_mode, "post", ok=False) as mock_http:
            with self.assertRaises(AuthException):
                await safe_await(client.otp.update_user_email(
                    "id1",
                    "dummy@dummy.com",
                    "refresh_token1",
                ))

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            self.async_mode, "post", ok=True, json=lambda: {"maskedEmail": "t***@example.com"}
        ) as mock_http:
            result = await safe_await(client.otp.update_user_email(
                "id1", "dummy@dummy.com", "refresh_token1"
            ))
            self.assertEqual("t***@example.com", result)
            HTTPMockHelper.assert_http_call(
                mock_http,
                self.async_mode,
                f"{DEFAULT_BASE_URL}{EndpointsV1.update_user_email_otp_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:refresh_token1",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "id1",
                    "email": "dummy@dummy.com",
                    "addToLoginIDs": False,
                    "onMergeUseExisting": False,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )

        # Test success flow with template options
        with HTTPMockHelper.mock_http_call(
            self.async_mode, "post", ok=True, json=lambda: {"maskedEmail": "t***@example.com"}
        ) as mock_http:
            result = await safe_await(client.otp.update_user_email(
                "id1",
                "dummy@dummy.com",
                "refresh_token1",
                template_options={"bla": "blue"},
            ))
            self.assertEqual("t***@example.com", result)
            HTTPMockHelper.assert_http_call(
                mock_http,
                self.async_mode,
                f"{DEFAULT_BASE_URL}{EndpointsV1.update_user_email_otp_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:refresh_token1",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "id1",
                    "email": "dummy@dummy.com",
                    "addToLoginIDs": False,
                    "onMergeUseExisting": False,
                    "templateOptions": {"bla": "blue"},
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )

    async def test_update_user_phone(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict, async_mode=self.async_mode)

        # Test failed flows
        with self.assertRaises(AuthException):
            await safe_await(client.otp.update_user_phone(
                DeliveryMethod.SMS,
                "",
                "+1111111",
                "refresh_token1",
            ))
        
        with self.assertRaises(AuthException):
            await safe_await(client.otp.update_user_phone(
                DeliveryMethod.SMS,
                "id1",
                "not_a_phone",
                "refresh_token1",
            ))
        
        with self.assertRaises(AuthException):
            await safe_await(client.otp.update_user_phone(
                DeliveryMethod.EMAIL,
                "id1",
                "+1111111",
                "refresh_token1",
            ))

        with HTTPMockHelper.mock_http_call(self.async_mode, "post", ok=False) as mock_http:
            with self.assertRaises(AuthException):
                await safe_await(client.otp.update_user_phone(
                    DeliveryMethod.SMS,
                    "id1",
                    "+1111111",
                    "refresh_token1",
                ))

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            self.async_mode, "post", ok=True, json=lambda: {"maskedPhone": "*****111"}
        ) as mock_http:
            result = await safe_await(client.otp.update_user_phone(
                DeliveryMethod.SMS, "id1", "+1111111", "refresh_token1"
            ))
            self.assertEqual("*****111", result)
            HTTPMockHelper.assert_http_call(
                mock_http,
                self.async_mode,
                f"{DEFAULT_BASE_URL}{EndpointsV1.update_user_phone_otp_path}/sms",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:refresh_token1",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "id1",
                    "phone": "+1111111",
                    "addToLoginIDs": False,
                    "onMergeUseExisting": False,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )

        with HTTPMockHelper.mock_http_call(
            self.async_mode, "post", ok=True, json=lambda: {"maskedPhone": "*****111"}
        ) as mock_http:
            result = await safe_await(client.otp.update_user_phone(
                DeliveryMethod.VOICE, "id1", "+1111111", "refresh_token1"
            ))
            self.assertEqual("*****111", result)
            HTTPMockHelper.assert_http_call(
                mock_http,
                self.async_mode,
                f"{DEFAULT_BASE_URL}{EndpointsV1.update_user_phone_otp_path}/voice",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:refresh_token1",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "id1",
                    "phone": "+1111111",
                    "addToLoginIDs": False,
                    "onMergeUseExisting": False,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )

        with HTTPMockHelper.mock_http_call(
            self.async_mode, "post", ok=True, json=lambda: {"maskedPhone": "*****111"}
        ) as mock_http:
            result = await safe_await(client.otp.update_user_phone(
                DeliveryMethod.WHATSAPP, "id1", "+1111111", "refresh_token1"
            ))
            self.assertEqual("*****111", result)
            HTTPMockHelper.assert_http_call(
                mock_http,
                self.async_mode,
                f"{DEFAULT_BASE_URL}{EndpointsV1.update_user_phone_otp_path}/whatsapp",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:refresh_token1",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "id1",
                    "phone": "+1111111",
                    "addToLoginIDs": False,
                    "onMergeUseExisting": False,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )

        # Test success flow with template options
        with HTTPMockHelper.mock_http_call(
            self.async_mode, "post", ok=True, json=lambda: {"maskedPhone": "*****111"}
        ) as mock_http:
            result = await safe_await(client.otp.update_user_phone(
                DeliveryMethod.SMS,
                "id1",
                "+1111111",
                "refresh_token1",
                template_options={"bla": "blue"},
            ))
            self.assertEqual("*****111", result)
            HTTPMockHelper.assert_http_call(
                mock_http,
                self.async_mode,
                f"{DEFAULT_BASE_URL}{EndpointsV1.update_user_phone_otp_path}/sms",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:refresh_token1",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "id1",
                    "phone": "+1111111",
                    "addToLoginIDs": False,
                    "onMergeUseExisting": False,
                    "templateOptions": {"bla": "blue"},
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )
