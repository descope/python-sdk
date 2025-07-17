import json
from unittest import mock
from unittest.mock import patch

from descope import AuthException
from descope.auth import Auth
from descope.authmethod.password import Password  # noqa: F401
from descope.common import DEFAULT_TIMEOUT_SECONDS, EndpointsV1

from . import common
from .async_test_base import (
    parameterized_sync_async_subcase,
    HTTPMockHelper,
    MethodTestHelper,
)


class TestPassword(common.DescopeTest):
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

        password = Password(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "",
            None,
            signup_user_details,
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            None,
            None,
            signup_user_details,
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "login_id",
            "",
            signup_user_details,
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "login_id",
            None,
            signup_user_details,
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                password,
                method_name,
                "dummy@dummy.com",
                "123456",
                signup_user_details,
            )

        # Test success flow
        data = json.loads(
            """{"jwts": ["eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"], "user": {"loginIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data, cookies={}
        ) as mock_post:
            result = MethodTestHelper.call_method(
                password,
                method_name,
                "dummy@dummy.com",
                "123456",
                signup_user_details,
            )
            self.assertIsNotNone(result)

            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "password": "123456",
                    "user": {
                        "username": "jhon",
                        "name": "john",
                        "phone": "972525555555",
                        "email": "dummy@dummy.com",
                    },
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("sign_in", "sign_in_async")
    def test_sign_in(self, method_name, is_async):
        password = Password(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "",
            None,
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            None,
            None,
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "login_id",
            "",
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "login_id",
            None,
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                password,
                method_name,
                "dummy@dummy.com",
                "123456",
            )

        # Test success flow
        data = json.loads(
            """{"jwts": ["eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"], "user": {"loginIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data, cookies={}
        ) as mock_post:
            result = MethodTestHelper.call_method(
                password, method_name, "dummy@dummy.com", "123456"
            )
            self.assertIsNotNone(result)

            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "password": "123456",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("send_reset", "send_reset_async")
    def test_send_reset(self, method_name, is_async):
        password = Password(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "",
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            None,
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                password,
                method_name,
                "dummy@dummy.com",
            )

        # Test success flow
        data = json.loads(
            """{"resetMethod": "magiclink", "maskedEmail": "du***@***my.com"}"""
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data, cookies={}
        ) as mock_post:
            result = MethodTestHelper.call_method(
                password,
                method_name,
                "dummy@dummy.com",
                "https://redirect.here.com",
            )
            self.assertIsNotNone(result)

            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.send_reset_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "redirectUrl": "https://redirect.here.com",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with template options
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data, cookies={}
        ) as mock_post:
            result = MethodTestHelper.call_method(
                password,
                method_name,
                "dummy@dummy.com",
                "https://redirect.here.com",
                {"bla": "blue"},
            )
            self.assertIsNotNone(result)

            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.send_reset_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "redirectUrl": "https://redirect.here.com",
                    "templateOptions": {"bla": "blue"},
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("update", "update_async")
    def test_update(self, method_name, is_async):
        password = Password(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "",
            None,
            None,
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            None,
            None,
            None,
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "login_id",
            "",
            None,
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "login_id",
            None,
            None,
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "login_id",
            "123456",
            "",
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "login_id",
            "123456",
            None,
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                password,
                method_name,
                "dummy@dummy.com",
                "1234567",
                "refresh_token",
            )

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkVGVuYW50cyI6eyIiOm51bGx9LCJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwNjc5MjA4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MjA5MDA4NzIwOCwiaWF0IjoxNjU4MDg3MjA4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQzU1dnl4dzBzUkw2RmRNNjhxUnNDRGRST1YifQ.cWP5up4R5xeIl2qoG2NtfLH3Q5nRJVKdz-FDoAXctOQW9g3ceZQi6rZQ-TPBaXMKw68bijN3bLJTqxWW5WHzqRUeopfuzTcMYmC0wP2XGJkrdF6A8D5QW6acSGqglFgu"

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                password,
                method_name,
                "dummy@dummy.com",
                "123456",
                valid_jwt_token,
            )
            self.assertIsNone(result)

            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{valid_jwt_token}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "newPassword": "123456",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("replace", "replace_async")
    def test_replace(self, method_name, is_async):
        password = Password(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "",
            None,
            None,
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            None,
            None,
            None,
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "login_id",
            "",
            None,
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "login_id",
            None,
            None,
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "login_id",
            "123456",
            "",
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            password,
            method_name,
            "login_id",
            "123456",
            None,
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                password,
                method_name,
                "dummy@dummy.com",
                "123456",
                "1234567",
            )

        # Test success flow
        data = json.loads(
            """{"jwts": ["eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"], "user": {"loginIds": ["test@company.com"], "name": "", "email": "test@company.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data, cookies={}
        ) as mock_post:
            jwt_response = MethodTestHelper.call_method(
                password, method_name, "dummy@dummy.com", "123456", "1234567"
            )
            self.assertIsNotNone(jwt_response)
            self.assertIsNotNone(jwt_response["user"])
            self.assertEqual(jwt_response["user"]["loginIds"], ["test@company.com"])

            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.replace_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "oldPassword": "123456",
                    "newPassword": "1234567",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("get_policy", "get_policy_async")
    def test_policy(self, method_name, is_async):
        password = Password(Auth(self.dummy_project_id, self.public_key_dict))

        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=False
        ) as mock_get:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                password,
                method_name,
            )

        # Test success flow
        data = json.loads("""{"minLength": 8, "lowercase": true}""")

        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=True, json=lambda: data, cookies={}
        ) as mock_get:
            result = MethodTestHelper.call_method(password, method_name)
            self.assertIsNotNone(result)

            HTTPMockHelper.assert_http_call(
                mock_get,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.password_policy_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                follow_redirects=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
