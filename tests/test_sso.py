import json
import unittest
from unittest import mock
from unittest.mock import patch

from descope import AuthException
from descope.auth import Auth
from descope.authmethod.sso import SSO
from descope.common import DEFAULT_TIMEOUT_SECONDS, EndpointsV1, LoginOptions

from . import common
from .async_test_base import (
    parameterized_sync_async_subcase,
    HTTPMockHelper,
    MethodTestHelper,
)


class TestSSO(common.DescopeTest):
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

    def test_compose_start_params(self):
        self.assertEqual(
            SSO._compose_start_params("tenant1", "http://dummy.com", "", ""),
            {"tenant": "tenant1", "redirectURL": "http://dummy.com"},
        )

        self.assertEqual(
            SSO._compose_start_params("tenant1", "http://dummy.com", "bla", "blue"),
            {
                "tenant": "tenant1",
                "redirectURL": "http://dummy.com",
                "prompt": "bla",
                "ssoId": "blue",
            },
        )

    @parameterized_sync_async_subcase("start", "start_async")
    def test_sso_start(self, method_name, is_async):
        sso = SSO(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            sso,
            method_name,
            "",
            "http://dummy.com",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            sso,
            method_name,
            None,
            "http://dummy.com",
        )

        with HTTPMockHelper.mock_http_call(is_async, method="post", ok=False):
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                sso,
                method_name,
                "tenant1",
                "http://dummy.com",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                sso, method_name, "tenant1", "http://dummy.com"
            )
            self.assertIsNotNone(result)

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            MethodTestHelper.call_method(
                sso,
                method_name,
                "tenant1",
                "http://dummy.com",
                sso_id="some-sso-id",
            )
            expected_uri = f"{common.DEFAULT_BASE_URL}{EndpointsV1.auth_sso_start_path}"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={
                    "tenant": "tenant1",
                    "redirectURL": "http://dummy.com",
                    "ssoId": "some-sso-id",
                },
                json={},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                sso,
                method_name,
                "tenant",
                "http://dummy.com",
                LoginOptions(mfa=True),
            )

    @parameterized_sync_async_subcase("start", "start_async")
    def test_sso_start_with_login_options(self, method_name, is_async):
        sso = SSO(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            sso,
            method_name,
            "",
            "http://dummy.com",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            sso,
            method_name,
            None,
            "http://dummy.com",
        )

        with HTTPMockHelper.mock_http_call(is_async, method="post", ok=False):
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                sso,
                method_name,
                "tenant1",
                "http://dummy.com",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                sso, method_name, "tenant1", "http://dummy.com"
            )
            self.assertIsNotNone(result)

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            lo = LoginOptions(stepup=True, custom_claims={"k1": "v1"})
            MethodTestHelper.call_method(
                sso, method_name, "tenant1", "http://dummy.com", lo, "refresh"
            )
            expected_uri = f"{common.DEFAULT_BASE_URL}{EndpointsV1.auth_sso_start_path}"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:refresh",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"tenant": "tenant1", "redirectURL": "http://dummy.com"},
                json={"stepup": True, "customClaims": {"k1": "v1"}, "mfa": False},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_compose_exchange_params(self):
        self.assertEqual(Auth._compose_exchange_body("c1"), {"code": "c1"})

    @parameterized_sync_async_subcase("exchange_token", "exchange_token_async")
    def test_exchange_token(self, method_name, is_async):
        sso = SSO(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException, MethodTestHelper.call_method, sso, method_name, ""
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            sso,
            method_name,
            None,
        )

        with HTTPMockHelper.mock_http_call(is_async, method="post", ok=False):
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                sso,
                method_name,
                "c1",
            )

        # Test success flow
        my_mock_response = mock.Mock()
        my_mock_response.ok = True
        my_mock_response.cookies = {}
        data = json.loads(
            """{"jwts": ["eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"], "user": {"loginIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
        )
        my_mock_response.json.return_value = data

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, cookies={}, json=lambda: data
        ) as mock_post:
            MethodTestHelper.call_method(sso, method_name, "c1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sso_exchange_token_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"code": "c1"},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )


if __name__ == "__main__":
    unittest.main()
