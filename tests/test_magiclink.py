import json
import unittest
from unittest import mock
from unittest.mock import patch

from descope import SESSION_COOKIE_NAME, AuthException, DeliveryMethod
from descope.auth import Auth
from descope.authmethod.magiclink import MagicLink  # noqa: F401
from descope.common import REFRESH_SESSION_COOKIE_NAME, EndpointsV1, LoginOptions

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

        lo = LoginOptions(stepup=True, custom_claims={"k1": "v1"})
        self.assertEqual(
            MagicLink._compose_signin_body("id1", "uri1", lo),
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
            MagicLink._compose_update_user_email_body("id1", "email1"),
            {"loginId": "id1", "email": "email1"},
        )

        self.assertEqual(
            MagicLink._compose_update_user_phone_body("id1", "+11111111"),
            {"loginId": "id1", "phone": "+11111111"},
        )

    def test_sign_in(self):
        magiclink = MagicLink(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            magiclink.sign_in,
            DeliveryMethod.EMAIL,
            None,
            "http://test.me",
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                magiclink.sign_in,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}

            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                magiclink.sign_in(
                    DeliveryMethod.EMAIL, "dummy@dummy.com", "http://test.me"
                ),
            )

            self.assertRaises(
                AuthException,
                magiclink.sign_in,
                DeliveryMethod.EMAIL,
                "exid",
                "http://test.me",
                LoginOptions(mfa=True),
            )

        # Validate refresh token used while provided
        with patch("requests.post") as mock_post:
            refresh_token = "dummy refresh token"
            magiclink.sign_in(
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
                LoginOptions(stepup=True),
                refresh_token=refresh_token,
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_magiclink_path}/email",
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

    def test_sign_up(self):
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
            magiclink.sign_up,
            DeliveryMethod.EMAIL,
            None,
            "http://test.me",
            signup_user_details,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                magiclink.sign_up,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
                signup_user_details,
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            resp = magiclink.sign_up(
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
                signup_user_details,
            )
            self.assertEqual("t***@example.com", resp)

        # Test flow where username not set and we used the login_id as default
        signup_user_details = {
            "username": "",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }

        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                magiclink.sign_up(
                    DeliveryMethod.EMAIL,
                    "dummy@dummy.com",
                    "http://test.me",
                    signup_user_details,
                ),
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_magiclink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
                        "URI": "http://test.me",
                        "user": {
                            "username": "",
                            "name": "john",
                            "phone": "972525555555",
                            "email": "dummy@dummy.com",
                        },
                        "email": "dummy@dummy.com",
                    }
                ),
                allow_redirects=False,
                verify=True,
                params=None,
            )

        # Test user is None so using the login_id as default
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                magiclink.sign_up(
                    DeliveryMethod.EMAIL,
                    "dummy@dummy.com",
                    "http://test.me",
                    None,
                ),
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_magiclink_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
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
                params=None,
            )

    def test_sign_up_or_in(self):
        magiclink = MagicLink(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                magiclink.sign_up_or_in,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                magiclink.sign_up_or_in(
                    DeliveryMethod.EMAIL, "dummy@dummy.com", "http://test.me"
                ),
            )

    def test_verify(self):
        token = "1234"

        magiclink = MagicLink(Auth(self.dummy_project_id, self.public_key_dict))

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                magiclink.verify,
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
            self.assertIsNotNone(magiclink.verify(token))

    def test_verify_with_get_keys_mock(self):
        token = "1234"
        magiclink = MagicLink(
            Auth(self.dummy_project_id, None)
        )  # public key will be "fetched" by Get mock

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL"
        with patch("requests.get") as mock_get:
            mock_get.return_value.text = json.dumps({"keys": [self.public_key_dict]})
            mock_get.return_value.ok = True

            with patch("requests.post") as mock_post:
                my_mock_response = mock.Mock()
                my_mock_response.ok = True
                my_mock_response.json.return_value = {}
                mock_post.return_value = my_mock_response
                mock_post.return_value.cookies = {
                    SESSION_COOKIE_NAME: "dummy session token",
                    REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
                }
                self.assertIsNotNone(magiclink.verify(token))

    def test_update_user_email(self):
        magiclink = MagicLink(Auth(self.dummy_project_id, self.public_key_dict))

        self.assertRaises(
            AuthException,
            magiclink.update_user_email,
            "",
            "dummy@dummy.com",
            "refresh_token1",
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                magiclink.update_user_email,
                "id1",
                "dummy@dummy.com",
                "refresh_token1",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                magiclink.update_user_email("id1", "dummy@dummy.com", "refresh_token1"),
            )

    def test_update_user_phone(self):
        magiclink = MagicLink(Auth(self.dummy_project_id, self.public_key_dict))

        self.assertRaises(
            AuthException,
            magiclink.update_user_phone,
            DeliveryMethod.EMAIL,
            "",
            "+11111111",
            "refresh_token1",
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                magiclink.update_user_phone,
                DeliveryMethod.EMAIL,
                "id1",
                "+11111111",
                "refresh_token1",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"maskedPhone": "*****1111"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "*****1111",
                magiclink.update_user_phone(
                    DeliveryMethod.SMS, "id1", "+11111111", "refresh_token1"
                ),
            )


if __name__ == "__main__":
    unittest.main()
