import json
import unittest
from copy import deepcopy
from enum import Enum
from unittest.mock import patch

from descope import SESSION_COOKIE_NAME, AuthClient, AuthException, DeliveryMethod
from descope.authhelper import AuthHelper
from descope.common import DEFAULT_BASE_URI, REFRESH_SESSION_COOKIE_NAME, EndpointsV1

from descope.authmethod.magiclink import MagicLink  # noqa: F401


class TestMagicLink(unittest.TestCase):
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
        }  # {"alg": "ES384", "crv": "P-384", "kid": "2Bt5WLccLUey1Dp7utptZb3Fx9K", "kty": "EC", "use": "sig", "x": "8SMbQQpCQAGAxCdoIz8y9gDw-wXoyoN5ILWpAlBKOcEM1Y7WmRKc1O2cnHggyEVi", "y": "N5n5jKZA5Wu7_b4B36KKjJf-VRfJ-XqczfCSYy9GeQLqF-b63idfE0SYaYk9cFqg"}
    
    def test_compose_urls(self):
        self.assertEqual(
            MagicLink._compose_signin_url(DeliveryMethod.PHONE),
            "/v1/auth/signin/magiclink/sms",
        )
        self.assertEqual(
            MagicLink._compose_signup_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/signup/magiclink/whatsapp",
        )
        self.assertEqual(
            MagicLink._compose_sign_up_or_in_url(DeliveryMethod.EMAIL),
            "/v1/auth/sign-up-or-in/magiclink/email",
        )
        
        self.assertEqual(
            MagicLink._compose_update_phone_url(DeliveryMethod.PHONE),
            "/v1/user/update/phone/magiclink/sms",
        )
    

    def test_compose_body(self):
        self.assertEqual(
            MagicLink._compose_signin_body("id1", "uri1", True),
            {
                "externalId": "id1",
                "URI": "uri1",
                "crossDevice": True
            },
        )
        self.assertEqual(
            MagicLink._compose_signup_body(DeliveryMethod.EMAIL, "id1", "uri1", True, { "email": "email1" }),
            {
                "externalId": "id1",
                "URI": "uri1",
                "crossDevice": True,
                "user":  { "email": "email1" },
                "email": "email1"
            },
        )
        self.assertEqual(
            MagicLink._compose_verify_body("t1"),
            {
                "token": "t1",
            },
        )
        
        self.assertEqual(
            MagicLink._compose_update_user_email_body("id1", "email1",  True),
            {
                "externalId": "id1",
                "email": "email1",
                "crossDevice": True
            },
        )
        
        self.assertEqual(
            MagicLink._compose_update_user_phone_body("id1", "+11111111", True),
            {
                "externalId": "id1",
                "phone": "+11111111",
                "crossDevice": True
            },
        )
    
    def test_sign_up_magiclink(self):
        signup_user_details = {
            "username": "jhon",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }

        magiclink = MagicLink(AuthHelper(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            magiclink.sign_up,
            DeliveryMethod.EMAIL,
            "dummy@dummy",
            "http://test.me",
            signup_user_details,
        )
        self.assertRaises(
            AuthException,
            magiclink.sign_up,
            DeliveryMethod.EMAIL,
            "",
            "http://test.me",
            signup_user_details,
        )
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
            mock_post.return_value.ok = True
            self.assertIsNone(
                magiclink.sign_up(
                    DeliveryMethod.EMAIL,
                    "dummy@dummy.com",
                    "http://test.me",
                    signup_user_details,
                )
            )

        # Test flow where username not set and we used the identifier as default
        signup_user_details = {
            "username": "",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                magiclink.sign_up(
                    DeliveryMethod.EMAIL,
                    "dummy@dummy.com",
                    "http://test.me",
                    signup_user_details,
                )
            )

    def test_sign_in_magiclink(self):
        magiclink = MagicLink(AuthHelper(self.dummy_project_id, self.public_key_dict))
        
        # Test failed flows
        self.assertRaises(
            AuthException,
            magiclink.sign_in,
            DeliveryMethod.EMAIL,
            "dummy@dummy",
            "http://test.me",
        )
        self.assertRaises(
            AuthException,
            magiclink.sign_in,
            DeliveryMethod.EMAIL,
            "",
            "http://test.me",
        )
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
            mock_post.return_value.ok = True
            self.assertIsNone(
                magiclink.sign_in(
                    DeliveryMethod.EMAIL, "dummy@dummy.com", "http://test.me"
                )
            )

    def test_verify_magiclink(self):
        token = "1234"

        magiclink = MagicLink(AuthHelper(self.dummy_project_id, self.public_key_dict))

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                magiclink.verify,
                token,
            )

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkVGVuYW50cyI6eyIiOm51bGx9LCJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwNjc5MjA4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MjA5MDA4NzIwOCwiaWF0IjoxNjU4MDg3MjA4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQzU1dnl4dzBzUkw2RmRNNjhxUnNDRGRST1YifQ.cWP5up4R5xeIl2qoG2NtfLH3Q5nRJVKdz-FDoAXctOQW9g3ceZQi6rZQ-TPBaXMKw68bijN3bLJTqxWW5WHzqRUeopfuzTcMYmC0wP2XGJkrdF6A8D5QW6acSGqglFgu"
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.cookies = {
                SESSION_COOKIE_NAME: "dummy session token",
                REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
            }
            self.assertIsNotNone(magiclink.verify(token))
            
    def test_update_user_email_magiclink(self):
        magiclink = MagicLink(AuthHelper(self.dummy_project_id, self.public_key_dict))

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                magiclink.update_user_email,
                "id1",
                "dummy@dummy.com",
                "refresh_token1"
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                magiclink.update_user_email(
                "id1",
                "dummy@dummy.com",
                "refresh_token1"
                )
            )

if __name__ == "__main__":
    unittest.main()
