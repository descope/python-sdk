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

from descope.future_utils import futu_await
from tests.testutils import SSLMatcher, mock_http_call
from . import common


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

    async def test_compose_urls(self):
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

    async def test_compose_body(self):
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

    async def test_sign_in(self):
        magiclink = MagicLink(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )

        # Test failed flows
        with self.assertRaises(AuthException):
            await futu_await(
                magiclink.sign_in(
                    DeliveryMethod.EMAIL,
                    None,
                    "http://test.me",
                )
            )

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    magiclink.sign_in(
                        DeliveryMethod.EMAIL,
                        "dummy@dummy.com",
                        "http://test.me",
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}

            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                await futu_await(
                    magiclink.sign_in(
                        DeliveryMethod.EMAIL, "dummy@dummy.com", "http://test.me"
                    )
                ),
            )

            with self.assertRaises(AuthException):

                await futu_await(
                    magiclink.sign_in(
                        DeliveryMethod.EMAIL,
                        "exid",
                        "http://test.me",
                        LoginOptions(mfa=True),
                    ),
                )

        # Validate refresh token used while provided
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response

            refresh_token = "dummy refresh token"
            await futu_await(
                magiclink.sign_in(
                    DeliveryMethod.EMAIL,
                    "dummy@dummy.com",
                    "http://test.me",
                    LoginOptions(stepup=True),
                    refresh_token=refresh_token,
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_magiclink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{refresh_token}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "URI": "http://test.me",
                    "loginOptions": {
                        "stepup": True,
                        "customClaims": None,
                        "mfa": False,
                    },
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # With template options
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response

            refresh_token = "dummy refresh token"
            await futu_await(
                magiclink.sign_in(
                    DeliveryMethod.EMAIL,
                    "dummy@dummy.com",
                    "http://test.me",
                    LoginOptions(
                        stepup=True, template_options={"blue": "bla"}, template_id=None
                    ),
                    refresh_token=refresh_token,
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_magiclink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{refresh_token}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
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
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_sign_up(self):
        signup_user_details = {
            "username": "jhon",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }

        magiclink = MagicLink(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )

        # Test failed flows
        with self.assertRaises(AuthException):
            await futu_await(
                magiclink.sign_up(
                    DeliveryMethod.EMAIL,
                    None,
                    "http://test.me",
                    signup_user_details,
                )
            )

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    magiclink.sign_up(
                        DeliveryMethod.EMAIL,
                        "dummy@dummy.com",
                        "http://test.me",
                        signup_user_details,
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            resp = await futu_await(
                magiclink.sign_up(
                    DeliveryMethod.EMAIL,
                    "dummy@dummy.com",
                    "http://test.me",
                    signup_user_details,
                )
            )
            self.assertEqual("t***@example.com", resp)

        # Test success flow with sign up options
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            resp = await futu_await(
                magiclink.sign_up(
                    DeliveryMethod.EMAIL,
                    "dummy@dummy.com",
                    "http://test.me",
                    signup_user_details,
                    SignUpOptions(template_options={"bla": "blue"}, template_id="foo"),
                )
            )
            self.assertEqual("t***@example.com", resp)

            mock_post.assert_called_with(
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
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )

        # Test flow where username not set and we used the login_id as default
        signup_user_details = {
            "username": "",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }

        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                await futu_await(
                    magiclink.sign_up(
                        DeliveryMethod.EMAIL,
                        "dummy@dummy.com",
                        "http://test.me",
                        signup_user_details,
                    )
                ),
            )
            mock_post.assert_called_with(
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
                        "username": "",
                        "name": "john",
                        "phone": "972525555555",
                        "email": "dummy@dummy.com",
                    },
                    "email": "dummy@dummy.com",
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )

        # Test user is None so using the login_id as default
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                await futu_await(
                    magiclink.sign_up(
                        DeliveryMethod.EMAIL,
                        "dummy@dummy.com",
                        "http://test.me",
                        None,
                    )
                ),
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_magiclink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "dummy@dummy.com",
                    "URI": "http://test.me",
                    "user": {"email": "dummy@dummy.com"},
                    "email": "dummy@dummy.com",
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )

    async def test_sign_up_or_in(self):
        magiclink = MagicLink(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )

        # Test failed flows

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    magiclink.sign_up_or_in(
                        DeliveryMethod.EMAIL,
                        "dummy@dummy.com",
                        "http://test.me",
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                await futu_await(
                    magiclink.sign_up_or_in(
                        DeliveryMethod.EMAIL, "dummy@dummy.com", "http://test.me"
                    )
                ),
            )

        # Test success flow with sign up options
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                await futu_await(
                    magiclink.sign_up_or_in(
                        DeliveryMethod.EMAIL,
                        "dummy@dummy.com",
                        "http://test.me",
                        SignUpOptions(
                            template_options={"bla": "blue"}, template_id="foo"
                        ),
                    )
                ),
            )
            mock_post.assert_called_with(
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
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )

    async def test_verify(self):
        token = "1234"

        magiclink = MagicLink(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    magiclink.verify(
                        token,
                    )
                )

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL"
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {}
            mock_post.return_value = my_mock_response
            mock_post.return_value.cookies = {
                SESSION_COOKIE_NAME: "dummy session token",
                REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
            }
            self.assertIsNotNone(await futu_await(magiclink.verify(token)))

    async def test_verify_with_get_keys_mock(self):
        token = "1234"
        magiclink = MagicLink(
            Auth(self.dummy_project_id, None, async_mode=self.async_test)
        )  # public key will be "fetched" by Get mock

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL"
        # _fetch_public_keys is always sync
        with mock_http_call(False, "get") as mock_get:
            mock_get.return_value.text = json.dumps({"keys": [self.public_key_dict]})
            mock_get.return_value.is_success = True

            with mock_http_call(self.async_test, "post") as mock_post:
                my_mock_response = mock.Mock()
                my_mock_response.is_success = True
                my_mock_response.json.return_value = {}
                mock_post.return_value = my_mock_response
                mock_post.return_value.cookies = {
                    SESSION_COOKIE_NAME: "dummy session token",
                    REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
                }
                self.assertIsNotNone(await futu_await(magiclink.verify(token)))

    async def test_update_user_email(self):
        magiclink = MagicLink(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )

        with self.assertRaises(AuthException):

            await futu_await(
                magiclink.update_user_email(
                    "",
                    "dummy@dummy.com",
                    "refresh_token1",
                )
            )

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    magiclink.update_user_email(
                        "id1",
                        "dummy@dummy.com",
                        "refresh_token1",
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                await futu_await(
                    magiclink.update_user_email(
                        "id1", "dummy@dummy.com", "refresh_token1"
                    )
                ),
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_email_magiclink_path}",
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )

        # Test success flow with template options
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                await futu_await(
                    magiclink.update_user_email(
                        "id1",
                        "dummy@dummy.com",
                        "refresh_token1",
                        template_options={"bla": "blue"},
                    )
                ),
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_email_magiclink_path}",
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )

    async def test_update_user_phone(self):
        magiclink = MagicLink(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )

        with self.assertRaises(AuthException):

            await futu_await(
                magiclink.update_user_phone(
                    DeliveryMethod.EMAIL,
                    "",
                    "+11111111",
                    "refresh_token1",
                )
            )

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    magiclink.update_user_phone(
                        DeliveryMethod.EMAIL,
                        "id1",
                        "+11111111",
                        "refresh_token1",
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedPhone": "*****1111"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "*****1111",
                await futu_await(
                    magiclink.update_user_phone(
                        DeliveryMethod.SMS, "id1", "+11111111", "refresh_token1"
                    )
                ),
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_phone_magiclink_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:refresh_token1",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "id1",
                    "phone": "+11111111",
                    "addToLoginIDs": False,
                    "onMergeUseExisting": False,
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )

        # Test success flow with template options
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedPhone": "*****1111"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "*****1111",
                await futu_await(
                    magiclink.update_user_phone(
                        DeliveryMethod.SMS,
                        "id1",
                        "+11111111",
                        "refresh_token1",
                        template_options={"bla": "blue"},
                    )
                ),
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_phone_magiclink_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:refresh_token1",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "id1",
                    "phone": "+11111111",
                    "addToLoginIDs": False,
                    "onMergeUseExisting": False,
                    "templateOptions": {"bla": "blue"},
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )


if __name__ == "__main__":
    unittest.main()
