import json
import unittest
from unittest import mock
from unittest.mock import patch

from descope import AuthException
from descope.auth import Auth
from descope.authmethod.oauth import OAuth
from descope.common import DEFAULT_TIMEOUT_SECONDS, EndpointsV1, LoginOptions
from descope.future_utils import futu_await

from . import common
from tests.testutils import SSLMatcher, mock_http_call


class TestOAuth(common.DescopeTest):
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

    async def test_compose_start_params(self):
        self.assertEqual(
            OAuth._compose_start_params("google", "http://example.com"),
            {"provider": "google", "redirectURL": "http://example.com"},
        )

    async def test_verify_oauth_providers(self):
        self.assertEqual(
            OAuth._verify_provider(""),
            False,
        )

        self.assertEqual(
            OAuth._verify_provider(None),
            False,
        )

    async def test_oauth_start(self):
        oauth = OAuth(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )

        # Test failed flows
        with self.assertRaises(AuthException):
            await futu_await(oauth.start(""))

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(oauth.start("google"))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            mock_post.json.return_value = {}
            self.assertIsNotNone(await futu_await(oauth.start("google")))

            with self.assertRaises(AuthException):
                await futu_await(
                    oauth.start("facebook", "http://test.me", LoginOptions(mfa=True)),
                )

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            await futu_await(oauth.start("facebook"))
            expected_uri = f"{common.DEFAULT_BASE_URL}{EndpointsV1.oauth_start_path}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"provider": "facebook"},
                json={},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_oauth_start_with_login_options(self):
        oauth = OAuth(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )

        # Test failed flows
        with self.assertRaises(AuthException):
            await futu_await(oauth.start(""))

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(oauth.start("google"))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNotNone(await futu_await(oauth.start("google")))

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            lo = LoginOptions(stepup=True, custom_claims={"k1": "v1"})
            await futu_await(
                oauth.start("facebook", login_options=lo, refresh_token="refresh")
            )
            expected_uri = f"{common.DEFAULT_BASE_URL}{EndpointsV1.oauth_start_path}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:refresh",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"provider": "facebook"},
                json={"stepup": True, "customClaims": {"k1": "v1"}, "mfa": False},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_compose_exchange_params(self):
        self.assertEqual(Auth._compose_exchange_body("c1"), {"code": "c1"})

    async def test_exchange_token(self):
        oauth = OAuth(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )

        # Test failed flows
        with self.assertRaises(AuthException):
            await futu_await(oauth.exchange_token(""))
        with self.assertRaises(AuthException):
            await futu_await(oauth.exchange_token(None))

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(oauth.exchange_token("c1"))

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
            await futu_await(oauth.exchange_token("c1"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.oauth_exchange_token_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"code": "c1"},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )


if __name__ == "__main__":
    unittest.main()
