import json
import unittest
from copy import deepcopy
from enum import Enum
from unittest.mock import patch

from descope import SESSION_COOKIE_NAME, AuthClient, AuthException, DeliveryMethod
from descope.authhelper import AuthHelper
from descope.authmethod.oauth import OAuth
from descope.common import DEFAULT_BASE_URI, REFRESH_SESSION_COOKIE_NAME, EndpointsV1

from descope.authmethod.totp import TOTP  # noqa: F401


class TestTOTP(unittest.TestCase):
    def setUp(self) -> None:
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

    def test_sign_up(self):
        signup_user_details = {
            "username": "jhon",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }

        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException,
            client.totp.sign_up,
            "",
            signup_user_details,
        )

        self.assertRaises(
            AuthException,
            client.totp.sign_up,
            None,
            signup_user_details,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.totp.sign_up,
                "dummy@dummy.com",
                signup_user_details,
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(
                client.totp.sign_up(
                    "dummy@dummy.com", signup_user_details
                )
            )

    def test_sign_in(self):
        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(AuthException, client.totp.sign_in_code, None, "1234")
        self.assertRaises(AuthException, client.totp.sign_in_code, "", "1234")
        self.assertRaises(AuthException, client.totp.sign_in_code, "dummy@dummy.com", None)
        self.assertRaises(AuthException, client.totp.sign_in_code, "dummy@dummy.com", "")

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.totp.sign_in_code,
                "dummy@dummy.com",
                "1234"
            )

        #TODO: enable the next text after finding the way to return the value for the ".json()" mock field
        # Test success flow
        # with patch("requests.post") as mock_post:
        #     mock_post.return_value.ok = True
        #     self.assertIsNone(
        #         client.totp.sign_in_code("dummy@dummy.com", "1234")
        #     )

    def test_update_user(self):
        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(AuthException, client.totp.update_user, None, "")
        self.assertRaises(AuthException, client.totp.update_user, "", "")
        self.assertRaises(AuthException, client.totp.update_user, "dummy@dummy.com", None)
        self.assertRaises(AuthException, client.totp.update_user, "dummy@dummy.com", "")

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.totp.update_user,
                "dummy@dummy.com",
                "dummy refresh token"
            )

        #TODO: enable the next text after finding the way to return the value for the ".json()" mock field
        # Test success flow
        # with patch("requests.post") as mock_post:
        #     mock_post.return_value.ok = True
        #     self.assertIsNone(
        #         client.totp.update_user("dummy@dummy.com", "dummy refresh token")
        #     )