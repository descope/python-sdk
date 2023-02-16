import json
import unittest
from unittest import mock
from unittest.mock import patch

import common

from descope import SESSION_COOKIE_NAME, AuthException
from descope.auth import Auth
from descope.authmethod.enchantedlink import EnchantedLink  # noqa: F401
from descope.common import (
    DEFAULT_BASE_URL,
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
)


class TestEnchantedLink(unittest.TestCase):
    def setUp(self) -> None:
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
            EnchantedLink._compose_update_user_email_body("id1", "email1"),
            {"loginId": "id1", "email": "email1"},
        )

        self.assertEqual(
            EnchantedLink._compose_get_session_body("pending_ref1"),
            {"pendingRef": "pending_ref1"},
        )

        self.assertEqual(
            EnchantedLink._compose_get_session_body("pending_ref1"),
            {"pendingRef": "pending_ref1"},
        )

    def test_sign_in(self):
        enchantedlink = EnchantedLink(Auth(self.dummy_project_id, self.public_key_dict))
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            # Test failed flows
            self.assertRaises(
                AuthException,
                enchantedlink.sign_in,
                "",
                "http://test.me",
            )
            data = json.loads("""{"pendingRef": "aaaa","linkId":"24"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            res = enchantedlink.sign_in("dummy@dummy.com", "http://test.me")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_enchantedlink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
                        "URI": "http://test.me",
                        "loginOptions": {},
                    }
                ),
                allow_redirects=False,
                verify=True,
            )
            self.assertEqual(res["pendingRef"], "aaaa")
            self.assertEqual(res["linkId"], "24")

        # Validate refresh token used while provided
        with patch("requests.post") as mock_post:
            refresh_token = "dummy refresh token"
            enchantedlink.sign_in(
                "dummy@dummy.com",
                "http://test.me",
                LoginOptions(stepup=True),
                refresh_token=refresh_token,
            )
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_enchantedlink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{refresh_token}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
                        "URI": "http://test.me",
                        "loginOptions": {
                            "stepup": True,
                            "customClaims": None,
                            "mfa": False,
                        },
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_sign_in_with_login_options(self):
        enchantedlink = EnchantedLink(Auth(self.dummy_project_id, self.public_key_dict))
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            data = json.loads("""{"pendingRef": "aaaa", "linkId":"24"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            lo = LoginOptions(stepup=True, custom_claims={"k1": "v1"})
            enchantedlink.sign_in("dummy@dummy.com", "http://test.me", lo, "refresh")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_enchantedlink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:refresh",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
                        "URI": "http://test.me",
                        "loginOptions": {
                            "stepup": True,
                            "customClaims": {"k1": "v1"},
                            "mfa": False,
                        },
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_sign_up(self):
        enchantedlink = EnchantedLink(Auth(self.dummy_project_id, self.public_key_dict))
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True

            # Test failed flows
            self.assertRaises(
                AuthException,
                enchantedlink.sign_up,
                "",
                "http://test.me",
                {"name": "john"},
            )

            data = json.loads("""{"pendingRef": "aaaa"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            res = enchantedlink.sign_up(
                "dummy@dummy.com",
                "http://test.me",
                {"username": "user1", "email": "dummy@dummy.com"},
            )
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_enchantedlink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
                        "URI": "http://test.me",
                        "user": {"username": "user1", "email": "dummy@dummy.com"},
                        "email": "dummy@dummy.com",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )
            self.assertEqual(res["pendingRef"], "aaaa")

        # Test user is None so using the login_id as default
        with patch("requests.post") as mock_post:
            data = json.loads("""{"pendingRef": "aaaa"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            res = enchantedlink.sign_up(
                "dummy@dummy.com",
                "http://test.me",
                None,
            )
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_enchantedlink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
                        "URI": "http://test.me",
                        "user": {"email": "dummy@dummy.com"},
                        "email": "dummy@dummy.com",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )
            self.assertEqual(res["pendingRef"], "aaaa")

    def test_sign_up_or_in(self):
        enchantedlink = EnchantedLink(Auth(self.dummy_project_id, self.public_key_dict))
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            data = json.loads("""{"pendingRef": "aaaa"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            enchantedlink.sign_up_or_in(
                "dummy@dummy.com",
                "http://test.me",
            )
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{EndpointsV1.sign_up_or_in_auth_enchantedlink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
                        "URI": "http://test.me",
                        "loginOptions": {},
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_verify(self):
        token = "1234"

        enchantedlink = EnchantedLink(Auth(self.dummy_project_id, self.public_key_dict))

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                enchantedlink.verify,
                token,
            )

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL"
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {}
            mock_post.return_value = my_mock_response
            mock_post.return_value.cookies = {
                SESSION_COOKIE_NAME: "dummy session token",
                REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
            }
            self.assertIsNone(enchantedlink.verify(token))

    def test_get_session(self):
        enchantedlink = EnchantedLink(Auth(self.dummy_project_id, self.public_key_dict))

        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL"
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {}
            mock_post.return_value = my_mock_response
            mock_post.return_value.cookies = {
                SESSION_COOKIE_NAME: "dummy session token",
                REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
            }
            self.assertIsNotNone(enchantedlink.get_session("aaaaaa"))

    def test_update_user_email(self):
        enchantedlink = EnchantedLink(Auth(self.dummy_project_id, self.public_key_dict))
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            # Test failed flows
            self.assertRaises(
                AuthException,
                enchantedlink.update_user_email,
                "",
                "dummy@dummy.com",
                "refresh_token1",
            )
            data = json.loads("""{"pendingRef": "aaaa"}""")
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            res = enchantedlink.update_user_email(
                "id1", "dummy@dummy.com", "refresh_token1"
            )
            self.assertEqual(res["pendingRef"], "aaaa")


if __name__ == "__main__":
    unittest.main()
