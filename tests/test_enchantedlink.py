import json
import unittest
from unittest import mock
from unittest.mock import patch

from descope import SESSION_COOKIE_NAME, AuthException
from descope.auth import Auth
from descope.authmethod.enchantedlink import EnchantedLink  # noqa: F401
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

from . import common


class TestEnchantedLink(common.DescopeTest):
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
            EnchantedLink._compose_signin_url(),
            "/v1/auth/enchantedlink/signin/email",
        )

    def test_compose_body(self):
        self.assertEqual(
            EnchantedLink._compose_signin_body("id1", "uri1"),
            {
                "loginId": "id1",
                "URI": "uri1",
                "loginOptions": {},
            },
        )

        lo = LoginOptions(stepup=True, custom_claims={"k1": "v1"})
        self.assertEqual(
            EnchantedLink._compose_signin_body("id1", "uri1", lo),
            {
                "loginId": "id1",
                "URI": "uri1",
                "loginOptions": {
                    "stepup": True,
                    "mfa": False,
                    "customClaims": {"k1": "v1"},
                },
            },
        )

        self.assertEqual(
            EnchantedLink._compose_signup_body("id1", "uri1", {"email": "email1"}),
            {
                "loginId": "id1",
                "URI": "uri1",
                "user": {"email": "email1"},
                "email": "email1",
            },
        )
        self.assertEqual(
            EnchantedLink._compose_verify_body("t1"),
            {"token": "t1"},
        )

        self.assertEqual(
            EnchantedLink._compose_update_user_email_body("id1", "email1", True, False),
            {
                "loginId": "id1",
                "email": "email1",
                "addToLoginIDs": True,
                "onMergeUseExisting": False,
            },
        )

        self.assertEqual(
            EnchantedLink._compose_get_session_body("pending_ref1"),
            {"pendingRef": "pending_ref1"},
        )

        self.assertEqual(
            EnchantedLink._compose_get_session_body("pending_ref1"),
            {"pendingRef": "pending_ref1"},
        )

    @parameterized_sync_async_subcase("sign_in", "sign_in_async")
    def test_sign_in(self, method_name, is_async):
        enchantedlink = EnchantedLink(Auth(self.dummy_project_id, self.public_key_dict))
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            # Test failed flows
            with self.assertRaises(AuthException):
                MethodTestHelper.call_method(
                    enchantedlink, method_name, "", "http://test.me"
                )
            data = json.loads("""{"pendingRef": "aaaa","linkId":"24"}""")
            with HTTPMockHelper.mock_http_call(
                is_async, method="post", ok=True, json=lambda: data
            ) as mock_post:
                res = MethodTestHelper.call_method(
                    enchantedlink,
                    method_name,
                    "dummy@dummy.com",
                    "http://test.me",
                )
                HTTPMockHelper.assert_http_call(
                    mock_post,
                    is_async,
                    f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_enchantedlink_path}/email",
                    headers={
                        **common.default_headers,
                        "Authorization": f"Bearer {self.dummy_project_id}",
                        "x-descope-project-id": self.dummy_project_id,
                    },
                    params=None,
                    json={
                        "loginId": "dummy@dummy.com",
                        "URI": "http://test.me",
                        "loginOptions": {},
                    },
                    follow_redirects=False,
                    verify=True,
                    timeout=DEFAULT_TIMEOUT_SECONDS,
                )
            self.assertEqual(res["pendingRef"], "aaaa")
            self.assertEqual(res["linkId"], "24")

        # Validate refresh token used while provided
        with patch("httpx.post") as mock_post:
            refresh_token = "dummy refresh token"
            enchantedlink.sign_in(
                "dummy@dummy.com",
                "http://test.me",
                LoginOptions(stepup=True),
                refresh_token=refresh_token,
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_enchantedlink_path}/email",
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
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # With template options
        with patch("httpx.post") as mock_post:
            refresh_token = "dummy refresh token"
            enchantedlink.sign_in(
                "dummy@dummy.com",
                "http://test.me",
                LoginOptions(
                    stepup=True,
                    template_options={"blue": "bla"},
                    template_id="foo",
                    revoke_other_sessions=True,
                ),
                refresh_token=refresh_token,
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_enchantedlink_path}/email",
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
                        "templateId": "foo",
                        "revokeOtherSessions": True,
                        "mfa": False,
                    },
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_sign_in_with_login_options(self):
        enchantedlink = EnchantedLink(Auth(self.dummy_project_id, self.public_key_dict))
        with patch("httpx.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            data = json.loads("""{"pendingRef": "aaaa", "linkId":"24"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            lo = LoginOptions(stepup=True, custom_claims={"k1": "v1"})
            enchantedlink.sign_in("dummy@dummy.com", "http://test.me", lo, "refresh")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_enchantedlink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:refresh",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "URI": "http://test.me",
                    "loginOptions": {
                        "stepup": True,
                        "customClaims": {"k1": "v1"},
                        "mfa": False,
                    },
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("sign_up", "sign_up_async")
    def test_sign_up(self, method_name, is_async):
        enchantedlink = EnchantedLink(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                enchantedlink,
                method_name,
                "",
                "http://test.me",
                {"name": "john"},
            )

        data = json.loads("""{"pendingRef": "aaaa"}""")
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data
        ) as mock_post:
            res = MethodTestHelper.call_method(
                enchantedlink,
                method_name,
                "dummy@dummy.com",
                "http://test.me",
                {"username": "user1", "email": "dummy@dummy.com"},
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_enchantedlink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "URI": "http://test.me",
                    "user": {"username": "user1", "email": "dummy@dummy.com"},
                    "email": "dummy@dummy.com",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res["pendingRef"], "aaaa")

        # Test user is None so using the login_id as default
        data_none = json.loads("""{"pendingRef": "aaaa"}""")
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data_none
        ) as mock_post:
            res = MethodTestHelper.call_method(
                enchantedlink,
                method_name,
                "dummy@dummy.com",
                "http://test.me",
                None,
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_enchantedlink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "URI": "http://test.me",
                    "user": {"email": "dummy@dummy.com"},
                    "email": "dummy@dummy.com",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res["pendingRef"], "aaaa")

        # Test success flow with sign up options
        data_options = json.loads("""{"pendingRef": "aaaa"}""")
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data_options
        ) as mock_post:
            res = MethodTestHelper.call_method(
                enchantedlink,
                method_name,
                "dummy@dummy.com",
                "http://test.me",
                None,
                SignUpOptions(
                    template_options={"bla": "blue"},
                    template_id="foo",
                    revoke_other_sessions=True,
                ),
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_enchantedlink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "URI": "http://test.me",
                    "user": {"email": "dummy@dummy.com"},
                    "email": "dummy@dummy.com",
                    "loginOptions": {
                        "templateOptions": {"bla": "blue"},
                        "templateId": "foo",
                        "revokeOtherSessions": True,
                    },
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res["pendingRef"], "aaaa")

    @parameterized_sync_async_subcase("sign_up_or_in", "sign_up_or_in_async")
    def test_sign_up_or_in(self, method_name, is_async):
        enchantedlink = EnchantedLink(Auth(self.dummy_project_id, self.public_key_dict))

        # Test basic flow
        data = json.loads("""{"pendingRef": "aaaa"}""")
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data
        ) as mock_post:
            res = MethodTestHelper.call_method(
                enchantedlink,
                method_name,
                "dummy@dummy.com",
                "http://test.me",
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_or_in_auth_enchantedlink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "URI": "http://test.me",
                    "loginOptions": {},
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res["pendingRef"], "aaaa")

        # Test success flow with sign up options
        data_options = json.loads("""{"pendingRef": "aaaa"}""")
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data_options
        ) as mock_post:
            res = MethodTestHelper.call_method(
                enchantedlink,
                method_name,
                "dummy@dummy.com",
                "http://test.me",
                SignUpOptions(template_options={"bla": "blue"}),
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_or_in_auth_enchantedlink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "dummy@dummy.com",
                    "URI": "http://test.me",
                    "loginOptions": {
                        "stepup": False,
                        "customClaims": None,
                        "mfa": False,
                        "templateOptions": {"bla": "blue"},
                    },
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res["pendingRef"], "aaaa")

    @parameterized_sync_async_subcase("verify", "verify_async")
    def test_verify(self, method_name, is_async):
        token = "1234"
        enchantedlink = EnchantedLink(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                enchantedlink,
                method_name,
                token,
            )

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL"

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {}
        ) as mock_post:
            # Create a mock response with cookies
            if is_async:
                # For async, we need to set up the mock differently
                async def mock_response_func(*args, **kwargs):
                    response = mock.Mock()
                    response.ok = True
                    response.json.return_value = {}
                    response.cookies = {
                        SESSION_COOKIE_NAME: "dummy session token",
                        REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
                    }
                    return response

                mock_post.side_effect = mock_response_func
            else:
                response = mock.Mock()
                response.ok = True
                response.json.return_value = {}
                response.cookies = {
                    SESSION_COOKIE_NAME: "dummy session token",
                    REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
                }
                mock_post.return_value = response

            result = MethodTestHelper.call_method(enchantedlink, method_name, token)
            self.assertIsNone(result)

    @parameterized_sync_async_subcase("get_session", "get_session_async")
    def test_get_session(self, method_name, is_async):
        enchantedlink = EnchantedLink(Auth(self.dummy_project_id, self.public_key_dict))

        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL"

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {}
        ) as mock_post:
            # Create a mock response with cookies
            if is_async:
                # For async, we need to set up the mock differently
                async def mock_response_func(*args, **kwargs):
                    response = mock.Mock()
                    response.ok = True
                    response.json.return_value = {}
                    response.cookies = {
                        SESSION_COOKIE_NAME: "dummy session token",
                        REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
                    }
                    return response

                mock_post.side_effect = mock_response_func
            else:
                response = mock.Mock()
                response.ok = True
                response.json.return_value = {}
                response.cookies = {
                    SESSION_COOKIE_NAME: "dummy session token",
                    REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
                }
                mock_post.return_value = response

            result = MethodTestHelper.call_method(enchantedlink, method_name, "aaaaaa")
            self.assertIsNotNone(result)

    @parameterized_sync_async_subcase("update_user_email", "update_user_email_async")
    def test_update_user_email(self, method_name, is_async):
        enchantedlink = EnchantedLink(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                enchantedlink,
                method_name,
                "",
                "dummy@dummy.com",
                "refresh_token1",
            )

        # Test success flow
        data = json.loads("""{"pendingRef": "aaaa"}""")
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data
        ) as mock_post:
            res = MethodTestHelper.call_method(
                enchantedlink,
                method_name,
                "id1",
                "dummy@dummy.com",
                "refresh_token1",
            )
            self.assertEqual(res["pendingRef"], "aaaa")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_email_enchantedlink_path}",
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

        # Test with template options
        data_options = json.loads("""{"pendingRef": "aaaa"}""")
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data_options
        ) as mock_post:
            res = MethodTestHelper.call_method(
                enchantedlink,
                method_name,
                "id1",
                "dummy@dummy.com",
                "refresh_token1",
                template_options={"bla": "blue"},
            )
            self.assertEqual(res["pendingRef"], "aaaa")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_user_email_enchantedlink_path}",
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


if __name__ == "__main__":
    unittest.main()
