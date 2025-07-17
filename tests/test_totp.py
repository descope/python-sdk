import json
from unittest import mock
from unittest.mock import patch

from descope import AuthException
from descope.auth import Auth
from descope.authmethod.totp import TOTP  # noqa: F401
from descope.common import DEFAULT_TIMEOUT_SECONDS, EndpointsV1, LoginOptions

from . import common
from .async_test_base import (
    parameterized_sync_async_subcase,
    HTTPMockHelper,
    MethodTestHelper,
)


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

    @parameterized_sync_async_subcase("sign_up", "sign_up_async")
    def test_sign_up(self, method_name, is_async):
        signup_user_details = {
            "username": "jhon",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }

        totp = TOTP(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            totp,
            method_name,
            "",
            signup_user_details,
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            totp,
            method_name,
            None,
            signup_user_details,
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                totp,
                method_name,
                "dummy@dummy.com",
                signup_user_details,
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            self.assertIsNotNone(
                MethodTestHelper.call_method(
                    totp, method_name, "dummy@dummy.com", signup_user_details
                )
            )

    @parameterized_sync_async_subcase("sign_in_code", "sign_in_code_async")
    def test_sign_in(self, method_name, is_async):
        totp = TOTP(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                totp,
                method_name,
                None,
                "1234",
            )
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                totp,
                method_name,
                "",
                "1234",
            )
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                totp,
                method_name,
                "dummy@dummy.com",
                None,
            )
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                totp,
                method_name,
                "dummy@dummy.com",
                "",
            )

        # Test HTTP failure
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                totp,
                method_name,
                "dummy@dummy.com",
                "1234",
            )

        # Test success flow
        data = json.loads(
            """{"jwts": ["eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"], "user": {"loginIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data
        ) as mock_post:
            # Mock response with cookies
            if is_async:

                async def mock_response_func(*args, **kwargs):
                    response = mock.Mock()
                    response.ok = True
                    response.json.return_value = data
                    response.cookies = {}
                    return response

                mock_post.side_effect = mock_response_func
            else:
                response = mock.Mock()
                response.ok = True
                response.json.return_value = data
                response.cookies = {}
                mock_post.return_value = response

            result = MethodTestHelper.call_method(
                totp, method_name, "dummy@dummy.com", "1234"
            )
            self.assertIsNotNone(result)

        # Test MFA validation failure
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data
        ) as mock_post:
            if is_async:

                async def mock_response_func(*args, **kwargs):
                    response = mock.Mock()
                    response.ok = True
                    response.json.return_value = data
                    response.cookies = {}
                    return response

                mock_post.side_effect = mock_response_func
            else:
                response = mock.Mock()
                response.ok = True
                response.json.return_value = data
                response.cookies = {}
                mock_post.return_value = response

            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                totp,
                method_name,
                "dummy@dummy.com",
                "code",
                LoginOptions(mfa=True),
            )

        # Test with refresh token
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data
        ) as mock_post:
            if is_async:

                async def mock_response_func(*args, **kwargs):
                    response = mock.Mock()
                    response.ok = True
                    response.json.return_value = data
                    response.cookies = {}
                    return response

                mock_post.side_effect = mock_response_func
            else:
                response = mock.Mock()
                response.ok = True
                response.json.return_value = data
                response.cookies = {}
                mock_post.return_value = response

            refresh_token = "dummy refresh token"
            result = MethodTestHelper.call_method(
                totp,
                method_name,
                "dummy@dummy.com",
                "1234",
                LoginOptions(stepup=True),
                refresh_token=refresh_token,
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("update_user", "update_user_async")
    def test_update_user(self, method_name, is_async):
        totp = TOTP(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                totp,
                method_name,
                None,
                "",
            )
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                totp,
                method_name,
                "",
                "",
            )
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                totp,
                method_name,
                "dummy@dummy.com",
                None,
            )
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                totp,
                method_name,
                "dummy@dummy.com",
                "",
            )

        # Test HTTP failure
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                totp,
                method_name,
                "dummy@dummy.com",
                "dummy refresh token",
            )

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkVGVuYW50cyI6eyIiOm51bGx9LCJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwNjc5MjA4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MjA5MDA4NzIwOCwiaWF0IjoxNjU4MDg3MjA4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQzU1dnl4dzBzUkw2RmRNNjhxUnNDRGRST1YifQ.cWP5up4R5xeIl2qoG2NtfLH3Q5nRJVKdz-FDoAXctOQW9g3ceZQi6rZQ-TPBaXMKw68bijN3bLJTqxWW5WHzqRUeopfuzTcMYmC0wP2XGJkrdF6A8D5QW6acSGqglFgu"
        valid_response = json.loads(
            """{ "provisioningURL": "http://dummy.com", "image": "imagedata", "key": "k01", "error": "" }"""
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: valid_response
        ) as mock_post:
            res = MethodTestHelper.call_method(
                totp, method_name, "dummy@dummy.com", valid_jwt_token
            )
            expected_uri = f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_totp_path}"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{valid_jwt_token}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"loginId": "dummy@dummy.com"},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res, valid_response)
