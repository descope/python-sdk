import json
import unittest
from unittest import mock
from unittest.mock import patch

from descope import SESSION_COOKIE_NAME, AuthException, DeliveryMethod
from descope.auth import Auth
from descope.authmethod.magiclink import MagicLink  # noqa: F401
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


class TestMagicLink(common.DescopeTest):
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

    def test_compose_urls(self):
        self.assertEqual(
            MagicLink._compose_signin_url(DeliveryMethod.SMS),
            "/v1/auth/magiclink/signin/sms",
        )
        self.assertEqual(
            MagicLink._compose_signup_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/magiclink/signup/whatsapp",
        )
        self.assertEqual(
            MagicLink._compose_sign_up_or_in_url(DeliveryMethod.EMAIL),
            "/v1/auth/magiclink/signup-in/email",
        )

        self.assertEqual(
            MagicLink._compose_update_phone_url(DeliveryMethod.SMS),
            "/v1/auth/magiclink/update/phone/sms",
        )

    def test_compose_body(self):
        self.assertEqual(
            MagicLink._compose_signin_body("id1", "uri1"),
            {
                "loginId": "id1",
                "URI": "uri1",
                "loginOptions": {},
            },
        )

        lo = LoginOptions(stepup=True, custom_claims={"k1": "v1"}, template_id="foo")
        self.assertEqual(
            MagicLink._compose_signin_body("id1", "uri1", lo),
            {
                "loginId": "id1",
                "URI": "uri1",
                "loginOptions": {
                    "stepup": True,
                    "mfa": False,
                    "customClaims": {"k1": "v1"},
                    "templateId": "foo",
                },
            },
        )

        self.assertEqual(
            MagicLink._compose_signup_body(
                DeliveryMethod.EMAIL, "id1", "uri1", {"email": "email1"}
            ),
            {
                "loginId": "id1",
                "URI": "uri1",
                "user": {"email": "email1"},
                "email": "email1",
            },
        )
        self.assertEqual(
            MagicLink._compose_verify_body("t1"),
            {"token": "t1"},
        )

        self.assertEqual(
            MagicLink._compose_update_user_email_body("id1", "email1", True, False),
            {
                "loginId": "id1",
                "email": "email1",
                "addToLoginIDs": True,
                "onMergeUseExisting": False,
            },
        )

        self.assertEqual(
            MagicLink._compose_update_user_phone_body("id1", "+11111111", False, True),
            {
                "loginId": "id1",
                "phone": "+11111111",
                "addToLoginIDs": False,
                "onMergeUseExisting": True,
            },
        )

    @parameterized_sync_async_subcase("sign_in", "sign_in_async")
    def test_sign_in(self, method_name, is_async):
        magiclink = MagicLink(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            magiclink,
            method_name,
            DeliveryMethod.EMAIL,
            None,
            "http://test.me",
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                magiclink,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ) as mock_post:
            result = MethodTestHelper.call_method(
                magiclink,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
            )
            self.assertEqual("t***@example.com", result)

            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                magiclink,
                method_name,
                DeliveryMethod.EMAIL,
                "exid",
                "http://test.me",
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
                magiclink,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
                LoginOptions(stepup=True),
                refresh_token=refresh_token,
            )

            # Use the new assert helper
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_magiclink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{refresh_token}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "dummy@dummy.com",
                    "URI": "http://test.me",
                    "loginOptions": {
                        "stepup": True,
                        "customClaims": None,
                        "mfa": False,
                    },
                },
                params=None,
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
                magiclink,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
                LoginOptions(
                    stepup=True, template_options={"blue": "bla"}, template_id=None
                ),
                refresh_token=refresh_token,
            )

            # Use the new assert helper
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_magiclink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{refresh_token}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "dummy@dummy.com",
                    "URI": "http://test.me",
                    "loginOptions": {
                        "stepup": True,
                        "customClaims": None,
                        "templateOptions": {"blue": "bla"},
                        "mfa": False,
                    },
                },
                params=None,
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("sign_up", "sign_up_async")
    def test_sign_up(self, method_name, is_async):
        signup_user_details = {
            "username": "jhon",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }

        magiclink = MagicLink(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            magiclink,
            method_name,
            DeliveryMethod.EMAIL,
            None,
            "http://test.me",
            signup_user_details,
        )

        with HTTPMockHelper.mock_http_call(is_async, method="post", ok=False):
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                magiclink,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
                signup_user_details,
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ):
            resp = MethodTestHelper.call_method(
                magiclink,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
                signup_user_details,
            )
            self.assertEqual("t***@example.com", resp)

        # Test success flow with sign up options
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                magiclink,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
                signup_user_details,
                SignUpOptions(template_options={"bla": "blue"}, template_id="foo"),
            )
            self.assertEqual("t***@example.com", resp)

            # Verify the HTTP call was made with correct parameters
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_magiclink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "dummy@dummy.com",
                    "URI": "http://test.me",
                    "user": {
                        "username": "jhon",
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
                params=None,
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test flow where username not set and we used the login_id as default
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
        ):
            resp = MethodTestHelper.call_method(
                magiclink,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
                signup_user_details,
            )
            self.assertEqual("t***@example.com", resp)

        # Test user is None so using the login_id as default
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ):
            resp = MethodTestHelper.call_method(
                magiclink,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
                None,
            )
            self.assertEqual("t***@example.com", resp)

    @parameterized_sync_async_subcase("sign_up_or_in", "sign_up_or_in_async")
    def test_sign_up_or_in(self, method_name, is_async):
        magiclink = MagicLink(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        with HTTPMockHelper.mock_http_call(is_async, method="post", ok=False):
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                magiclink,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ):
            result = MethodTestHelper.call_method(
                magiclink,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
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
                magiclink,
                method_name,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
                SignUpOptions(template_options={"bla": "blue"}, template_id="foo"),
            )
            self.assertEqual("t***@example.com", result)

            # Verify the HTTP call was made with correct parameters
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_or_in_auth_magiclink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "dummy@dummy.com",
                    "URI": "http://test.me",
                    "loginOptions": {
                        "stepup": False,
                        "customClaims": None,
                        "mfa": False,
                        "templateOptions": {"bla": "blue"},
                        "templateId": "foo",
                    },
                },
                params=None,
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("verify", "verify_async")
    def test_verify(self, method_name, is_async):
        token = "1234"

        magiclink = MagicLink(Auth(self.dummy_project_id, self.public_key_dict))

        with HTTPMockHelper.mock_http_call(is_async, method="post", ok=False):
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                magiclink,
                method_name,
                token,
            )

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL"

        # Create a mock response with cookies attribute
        mock_response = mock.Mock()
        mock_response.ok = True
        mock_response.json.return_value = {}
        mock_response.cookies = {
            SESSION_COOKIE_NAME: "dummy session token",
            REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
        }

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
            # Need to manually set the cookies on the mock response
            mock_post.return_value.cookies = mock_response.cookies
            result = MethodTestHelper.call_method(magiclink, method_name, token)
            self.assertIsNotNone(result)

    def test_verify_with_get_keys_mock(self):
        token = "1234"
        magiclink = MagicLink(
            Auth(self.dummy_project_id, None)
        )  # public key will be "fetched" by Get mock

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL"
        with patch("httpx.get") as mock_get:
            mock_get.return_value.text = json.dumps({"keys": [self.public_key_dict]})
            mock_get.return_value.ok = True

            with patch("httpx.post") as mock_post:
                my_mock_response = mock.Mock()
                my_mock_response.ok = True
                my_mock_response.json.return_value = {}
                mock_post.return_value = my_mock_response
                mock_post.return_value.cookies = {
                    SESSION_COOKIE_NAME: "dummy session token",
                    REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
                }
                self.assertIsNotNone(magiclink.verify(token))

    @parameterized_sync_async_subcase("update_user_email", "update_user_email_async")
    def test_update_user_email(self, method_name, is_async):
        magiclink = MagicLink(Auth(self.dummy_project_id, self.public_key_dict))

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            magiclink,
            method_name,
            "",
            "dummy@dummy.com",
            "refresh_token1",
        )

        with HTTPMockHelper.mock_http_call(is_async, method="post", ok=False):
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                magiclink,
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
        ):
            result = MethodTestHelper.call_method(
                magiclink,
                method_name,
                "id1",
                "dummy@dummy.com",
                "refresh_token1",
            )
            self.assertEqual("t***@example.com", result)

        # Test success flow with template options
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"maskedEmail": "t***@example.com"},
        ):
            result = MethodTestHelper.call_method(
                magiclink,
                method_name,
                "id1",
                "dummy@dummy.com",
                "refresh_token1",
                template_options={"bla": "blue"},
            )
            self.assertEqual("t***@example.com", result)

    @parameterized_sync_async_subcase("update_user_phone", "update_user_phone_async")
    def test_update_user_phone(self, method_name, is_async):
        magiclink = MagicLink(Auth(self.dummy_project_id, self.public_key_dict))

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            magiclink,
            method_name,
            DeliveryMethod.EMAIL,
            "",
            "+11111111",
            "refresh_token1",
        )

        with HTTPMockHelper.mock_http_call(is_async, method="post", ok=False):
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                magiclink,
                method_name,
                DeliveryMethod.EMAIL,
                "id1",
                "+11111111",
                "refresh_token1",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"maskedPhone": "*****1111"}
        ):
            result = MethodTestHelper.call_method(
                magiclink,
                method_name,
                DeliveryMethod.SMS,
                "id1",
                "+11111111",
                "refresh_token1",
            )
            self.assertEqual("*****1111", result)

        # Test success flow with template options
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"maskedPhone": "*****1111"}
        ):
            result = MethodTestHelper.call_method(
                magiclink,
                method_name,
                DeliveryMethod.SMS,
                "id1",
                "+11111111",
                "refresh_token1",
                template_options={"bla": "blue"},
            )
            self.assertEqual("*****1111", result)


if __name__ == "__main__":
    unittest.main()
