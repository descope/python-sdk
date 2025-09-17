import json
import unittest
from unittest import mock
from unittest.mock import patch

from descope import SESSION_COOKIE_NAME, AuthException, DescopeClient
from descope.auth import Auth
from descope.authmethod.enchantedlink import EnchantedLink  # noqa: F401
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

    async def test_compose_urls(self):
        self.assertEqual(
            EnchantedLink._compose_signin_url(),
            "/v1/auth/enchantedlink/signin/email",
        )

    async def test_compose_body(self):
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

    async def test_sign_in(self):
        client = DescopeClient(
            self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
        )
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            # Test failed flows
            with self.assertRaises(AuthException):
                await futu_await(client.enchantedlink.sign_in("", "http://test.me"))
            data = json.loads("""{"pendingRef": "aaaa","linkId":"24"}""")
            if self.async_test:
                # In async mode, json() should return the data directly without being a mock call
                my_mock_response.json = mock.Mock(return_value=data)
            else:
                my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            res = await futu_await(
                client.enchantedlink.sign_in("dummy@dummy.com", "http://test.me")
            )
            mock_post.assert_called_with(
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res["pendingRef"], "aaaa")
            self.assertEqual(res["linkId"], "24")

        # Validate refresh token used while provided
        with mock_http_call(self.async_test, "post") as mock_post:
            refresh_token = "dummy refresh token"
            await futu_await(
                client.enchantedlink.sign_in(
                    "dummy@dummy.com",
                    "http://test.me",
                    LoginOptions(stepup=True),
                    refresh_token=refresh_token,
                )
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # With template options
        with mock_http_call(self.async_test, "post") as mock_post:
            refresh_token = "dummy refresh token"
            await futu_await(
                client.enchantedlink.sign_in(
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_sign_in_with_login_options(self):
        enchantedlink = EnchantedLink(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            data = json.loads("""{"pendingRef": "aaaa", "linkId":"24"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            lo = LoginOptions(stepup=True, custom_claims={"k1": "v1"})
            await futu_await(
                enchantedlink.sign_in(
                    "dummy@dummy.com", "http://test.me", lo, "refresh"
                )
            )
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_sign_up(self):
        enchantedlink = EnchantedLink(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True

            # Test failed flows
            with self.assertRaises(AuthException):
                await futu_await(
                    enchantedlink.sign_up(
                        "",
                        "http://test.me",
                        {"name": "john"},
                    )
                )

            data = json.loads("""{"pendingRef": "aaaa"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            res = await futu_await(
                enchantedlink.sign_up(
                    "dummy@dummy.com",
                    "http://test.me",
                    {"username": "user1", "email": "dummy@dummy.com"},
                )
            )
            mock_post.assert_called_with(
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res["pendingRef"], "aaaa")

        # Test user is None so using the login_id as default
        with mock_http_call(self.async_test, "post") as mock_post:
            data = json.loads("""{"pendingRef": "aaaa"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            res = await futu_await(
                enchantedlink.sign_up(
                    "dummy@dummy.com",
                    "http://test.me",
                    None,
                )
            )
            mock_post.assert_called_with(
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res["pendingRef"], "aaaa")

        # Test success flow with sign up options
        with mock_http_call(self.async_test, "post") as mock_post:
            data = json.loads("""{"pendingRef": "aaaa"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            res = await futu_await(
                enchantedlink.sign_up(
                    "dummy@dummy.com",
                    "http://test.me",
                    None,
                    SignUpOptions(
                        template_options={"bla": "blue"},
                        template_id="foo",
                        revoke_other_sessions=True,
                    ),
                )
            )
            mock_post.assert_called_with(
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res["pendingRef"], "aaaa")

    async def test_sign_up_or_in(self):
        enchantedlink = EnchantedLink(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            data = json.loads("""{"pendingRef": "aaaa"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            await futu_await(
                enchantedlink.sign_up_or_in(
                    "dummy@dummy.com",
                    "http://test.me",
                )
            )
            mock_post.assert_called_with(
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with sign up options
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            data = json.loads("""{"pendingRef": "aaaa"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            await futu_await(
                enchantedlink.sign_up_or_in(
                    "dummy@dummy.com",
                    "http://test.me",
                    SignUpOptions(template_options={"bla": "blue"}),
                )
            )
            mock_post.assert_called_with(
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_verify(self):
        token = "1234"

        enchantedlink = EnchantedLink(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    enchantedlink.verify(
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
            self.assertIsNone(await futu_await(enchantedlink.verify(token)))

    async def test_get_session(self):
        enchantedlink = EnchantedLink(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )

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
            self.assertIsNotNone(await futu_await(enchantedlink.get_session("aaaaaa")))

    async def test_update_user_email(self):
        enchantedlink = EnchantedLink(
            Auth(
                self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
            )
        )
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            # Test failed flows
            with self.assertRaises(AuthException):
                await futu_await(
                    enchantedlink.update_user_email(
                        "",
                        "dummy@dummy.com",
                        "refresh_token1",
                    )
                )
            data = json.loads("""{"pendingRef": "aaaa"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            res = await futu_await(
                enchantedlink.update_user_email(
                    "id1", "dummy@dummy.com", "refresh_token1"
                )
            )
            self.assertEqual(res["pendingRef"], "aaaa")
            mock_post.assert_called_with(
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )

        # with template options
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            data = json.loads("""{"pendingRef": "aaaa"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            res = await futu_await(
                enchantedlink.update_user_email(
                    "id1",
                    "dummy@dummy.com",
                    "refresh_token1",
                    template_options={"bla": "blue"},
                )
            )
            self.assertEqual(res["pendingRef"], "aaaa")
            mock_post.assert_called_with(
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
                params=None,
            )


if __name__ == "__main__":
    unittest.main()
