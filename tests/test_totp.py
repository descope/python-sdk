import json
from unittest import mock
from unittest.mock import patch

from descope import AuthException
from descope.auth import Auth
from descope.authmethod.totp import TOTP  # noqa: F401
from descope.common import DEFAULT_TIMEOUT_SECONDS, EndpointsV1, LoginOptions

from descope.future_utils import futu_await
from tests.testutils import SSLMatcher, mock_http_call
from . import common


class TestTOTP(common.DescopeTest):
    def setUp(self) -> None:
        super().setUp()
        self.dummy_project_id = "dummy"
        self.public_key_dict = {
            "alg": "ES384",
            "crv": "P-384",
            "kid": "2Bt5WLccLUey1Dp7utptZb3Fx9K",
            "kty": "EC",
            "use": "sig",
            "x": "8SMbQQpCQAGAxCdoIz8y9gDw-wXoyoN5ILWpAlBKOcEM1Y7WmRKc1O2cnHggyEVi",
            "y": "N5n5jKZA5Wu7_b4B36KKjJf-VRfJ-XqczfCSYy9GeQLqF-b63idfE0SYaYk9cFqg",
        }

    async def test_sign_up(self):
        signup_user_details = {
            "username": "jhon",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }

        totp = TOTP(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )

        # Test failed flows
        with self.assertRaises(AuthException):
            await futu_await(
                totp.sign_up(
                    "",
                    signup_user_details,
                )
            )

        with self.assertRaises(AuthException):

            await futu_await(
                totp.sign_up(
                    None,
                    signup_user_details,
                )
            )

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    totp.sign_up(
                        "dummy@dummy.com",
                        signup_user_details,
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNotNone(
                await futu_await(totp.sign_up("dummy@dummy.com", signup_user_details))
            )

    async def test_sign_in(self):
        totp = TOTP(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )

        # Test failed flows
        with self.assertRaises(AuthException):
            await futu_await(totp.sign_in_code(None, "1234"))
        with self.assertRaises(AuthException):
            await futu_await(totp.sign_in_code("", "1234"))
        with self.assertRaises(AuthException):
            await futu_await(totp.sign_in_code("dummy@dummy.com", None))
        with self.assertRaises(AuthException):
            await futu_await(totp.sign_in_code("dummy@dummy.com", ""))

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(totp.sign_in_code("dummy@dummy.com", "1234"))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.cookies = {}
            data = json.loads(
                """{"jwts": ["eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"], "user": {"loginIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
            )
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            self.assertIsNotNone(
                await futu_await(totp.sign_in_code("dummy@dummy.com", "1234"))
            )
            with self.assertRaises(AuthException):
                await futu_await(
                    totp.sign_in_code(
                        "dummy@dummy.com", "code", LoginOptions(mfa=True)
                    ),
                )

        # Validate refresh token used while provided
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.cookies = {}
            data = json.loads(
                """{"jwts": ["eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"], "user": {"loginIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
            )
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            refresh_token = "dummy refresh token"
            await futu_await(
                totp.sign_in_code(
                    "dummy@dummy.com",
                    "1234",
                    LoginOptions(stepup=True),
                    refresh_token=refresh_token,
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.verify_totp_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{refresh_token}",
                    "x-descope-project-id": self.dummy_project_id,
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_update_user(self):
        totp = TOTP(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )

        # Test failed flows
        with self.assertRaises(AuthException):
            await futu_await(totp.update_user(None, ""))
        with self.assertRaises(AuthException):
            await futu_await(totp.update_user("", ""))
        with self.assertRaises(AuthException):
            await futu_await(totp.update_user("dummy@dummy.com", None))
        with self.assertRaises(AuthException):
            await futu_await(totp.update_user("dummy@dummy.com", ""))

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    totp.update_user(
                        "dummy@dummy.com",
                        "dummy refresh token",
                    )
                )

            valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkVGVuYW50cyI6eyIiOm51bGx9LCJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwNjc5MjA4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MjA5MDA4NzIwOCwiaWF0IjoxNjU4MDg3MjA4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQzU1dnl4dzBzUkw2RmRNNjhxUnNDRGRST1YifQ.cWP5up4R5xeIl2qoG2NtfLH3Q5nRJVKdz-FDoAXctOQW9g3ceZQi6rZQ-TPBaXMKw68bijN3bLJTqxWW5WHzqRUeopfuzTcMYmC0wP2XGJkrdF6A8D5QW6acSGqglFgu"
            valid_response = json.loads(
                """{ "provisioningURL": "http://dummy.com", "image": "imagedata", "key": "k01", "error": "" }"""
            )
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = valid_response
            mock_post.return_value = my_mock_response
            res = await futu_await(totp.update_user("dummy@dummy.com", valid_jwt_token))
            expected_uri = f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_totp_path}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{valid_jwt_token}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"loginId": "dummy@dummy.com"},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res, valid_response)
