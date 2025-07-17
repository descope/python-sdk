from enum import Enum
from unittest import mock
from unittest.mock import patch

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
from .async_test_base import (
    parameterized_sync_async_subcase,
    HTTPMockHelper,
    MethodTestHelper,
)


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

    def test_compose_signin_url(self):
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

    def test_compose_verify_code_url(self):
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

    def test_compose_update_phone_url(self):
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

    def test_compose_sign_up_or_in_url(self):
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

    def test_compose_update_user_phone_body(self):
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

    def test_compose_update_user_email_body(self):
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

    @parameterized_sync_async_subcase("sign_up", "sign_up_async")
    def test_sign_up(self, method_name, is_async):
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

        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            DeliveryMethod.EMAIL,
            "dummy@dummy",
            invalid_signup_user_details,
        )
        invalid_signup_user_details["email"] = "dummy@dummy.com"  # set valid mail
        invalid_signup_user_details["phone"] = "aaaaaaaa"  # set invalid phone
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            DeliveryMethod.EMAIL,
            "",
            invalid_signup_user_details,
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            DeliveryMethod.SMS,
            "dummy@dummy.com",
            invalid_signup_user_details,
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            DeliveryMethod.VOICE,
            "dummy@dummy.com",
            invalid_signup_user_details,
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            DeliveryMethod.WHATSAPP,
            "dummy@dummy.com",
            invalid_signup_user_details,
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.otp,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                signup_user_details,
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.otp,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                signup_user_details,
            )
            self.assertEqual("t***@example.com", result)

        # Test flow where username set as empty and we used the login_id as default
        signup_user_details = {
            "username": "",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }

        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.otp,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                signup_user_details,
            )
            self.assertEqual("t***@example.com", result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_otp_path}/email",
                headers={
                    **common.default_headers,
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
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.otp,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                signup_user_details,
                SignUpOptions(template_options={"bla": "blue"}, template_id="foo"),
            )
            self.assertEqual("t***@example.com", result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_otp_path}/email",
                headers={
                    **common.default_headers,
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
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.otp,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                None,
            )
            self.assertEqual("t***@example.com", result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_otp_path}/email",
                headers={
                    **common.default_headers,
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

        self.assertRaises(AuthException, OTP._compose_signin_url, Dummy.DUMMY)

    @parameterized_sync_async_subcase("sign_in", "sign_in_async")
    def test_sign_in(self, method_name, is_async):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            DeliveryMethod.EMAIL,
            "",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            DeliveryMethod.EMAIL,
            None,
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.otp,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.otp,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
            )
            self.assertEqual("t***@example.com", result)

        # Test MFA exception - should throw before HTTP call
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            DeliveryMethod.EMAIL,
            "exid",
            LoginOptions(mfa=True),
        )

        # Validate refresh token used while provided
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ) as mock_post:
            refresh_token = "dummy refresh token"
            MethodTestHelper.call_method(
                client.otp,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                LoginOptions(stepup=True),
                refresh_token=refresh_token,
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_otp_path}/email",
                headers={
                    **common.default_headers,
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

        # With template options
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ) as mock_post:
            refresh_token = "dummy refresh token"
            MethodTestHelper.call_method(
                client.otp,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                LoginOptions(
                    stepup=True, template_options={"blue": "bla"}, template_id="foo"
                ),
                refresh_token=refresh_token,
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_otp_path}/email",
                headers={
                    **common.default_headers,
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

    @parameterized_sync_async_subcase("sign_up_or_in", "sign_up_or_in_async")
    def test_sign_up_or_in(self, method_name, is_async):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            DeliveryMethod.EMAIL,
            "",
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.otp,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.otp,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
            )
            self.assertEqual("t***@example.com", result)

        # Test success flow with sign up options
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.otp,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                SignUpOptions(template_options={"bla": "blue"}, template_id="foo"),
            )
            self.assertEqual("t***@example.com", result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_or_in_auth_otp_path}/email",
                headers={
                    **common.default_headers,
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

    @parameterized_sync_async_subcase("verify_code", "verify_code_async")
    def test_verify_code(self, method_name, is_async):
        code = "1234"

        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            DeliveryMethod.EMAIL,
            "",
            code,
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            DeliveryMethod.EMAIL,
            None,
            code,
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.otp,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                code,
            )

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL"
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {},
            cookies={
                SESSION_COOKIE_NAME: "dummy session token",
                REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
            },
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.otp,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                code,
            )
            self.assertIsNotNone(result)

    @parameterized_sync_async_subcase("update_user_email", "update_user_email_async")
    def test_update_user_email(self, method_name, is_async):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            "",
            "dummy@dummy.com",
            "refresh_token1",
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            "id1",
            "dummy@dummy",
            "refresh_token1",
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.otp,
                method_name,
                "id1",
                "dummy@dummy.com",
                "refresh_token1",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.otp,
                method_name,
                "id1",
                "dummy@dummy.com",
                "refresh_token1",
            )
            self.assertEqual("t***@example.com", result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_email_otp_path}",
                headers={
                    **common.default_headers,
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
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.otp,
                method_name,
                "id1",
                "dummy@dummy.com",
                "refresh_token1",
                template_options={"bla": "blue"},
            )
            self.assertEqual("t***@example.com", result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_email_otp_path}",
                headers={
                    **common.default_headers,
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

    @parameterized_sync_async_subcase("update_user_phone", "update_user_phone_async")
    def test_update_user_phone(self, method_name, is_async):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            DeliveryMethod.SMS,
            "",
            "+1111111",
            "refresh_token1",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            DeliveryMethod.SMS,
            "id1",
            "not_a_phone",
            "refresh_token1",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.otp,
            method_name,
            DeliveryMethod.EMAIL,
            "id1",
            "+1111111",
            "refresh_token1",
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.otp,
                method_name,
                DeliveryMethod.SMS,
                "id1",
                "+1111111",
                "refresh_token1",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"maskedPhone": "*****111"}
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.otp,
                method_name,
                DeliveryMethod.SMS,
                "id1",
                "+1111111",
                "refresh_token1",
            )
            self.assertEqual("*****111", result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_phone_otp_path}/sms",
                headers={
                    **common.default_headers,
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
            is_async, method="post", ok=True, json=lambda: {"maskedPhone": "*****111"}
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.otp,
                method_name,
                DeliveryMethod.VOICE,
                "id1",
                "+1111111",
                "refresh_token1",
            )
            self.assertEqual("*****111", result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_phone_otp_path}/voice",
                headers={
                    **common.default_headers,
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
            is_async, method="post", ok=True, json=lambda: {"maskedPhone": "*****111"}
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.otp,
                method_name,
                DeliveryMethod.WHATSAPP,
                "id1",
                "+1111111",
                "refresh_token1",
            )
            self.assertEqual("*****111", result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_phone_otp_path}/whatsapp",
                headers={
                    **common.default_headers,
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
            is_async, method="post", ok=True, json=lambda: {"maskedPhone": "*****111"}
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.otp,
                method_name,
                DeliveryMethod.SMS,
                "id1",
                "+1111111",
                "refresh_token1",
                template_options={"bla": "blue"},
            )
            self.assertEqual("*****111", result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_phone_otp_path}/sms",
                headers={
                    **common.default_headers,
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
