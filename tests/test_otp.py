import unittest
from enum import Enum
from unittest.mock import patch

from descope import SESSION_COOKIE_NAME, AuthException, DeliveryMethod, DescopeClient
from descope.authmethod.otp import OTP  # noqa: F401
from descope.common import REFRESH_SESSION_COOKIE_NAME


class TestOTP(unittest.TestCase):
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

    def test_compose_signin_url(self):
        self.assertEqual(
            OTP._compose_signin_url(DeliveryMethod.EMAIL),
            "/v1/auth/signin/otp/email",
        )
        self.assertEqual(
            OTP._compose_signin_url(DeliveryMethod.PHONE),
            "/v1/auth/signin/otp/sms",
        )
        self.assertEqual(
            OTP._compose_signin_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/signin/otp/whatsapp",
        )

    def test_compose_verify_code_url(self):
        self.assertEqual(
            OTP._compose_verify_code_url(DeliveryMethod.EMAIL),
            "/v1/auth/code/verify/email",
        )
        self.assertEqual(
            OTP._compose_verify_code_url(DeliveryMethod.PHONE),
            "/v1/auth/code/verify/sms",
        )
        self.assertEqual(
            OTP._compose_verify_code_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/code/verify/whatsapp",
        )

    def test_compose_update_phone_url(self):
        self.assertEqual(
            OTP._compose_update_phone_url(DeliveryMethod.EMAIL),
            "/v1/user/update/phone/otp/email",
        )
        self.assertEqual(
            OTP._compose_update_phone_url(DeliveryMethod.PHONE),
            "/v1/user/update/phone/otp/sms",
        )
        self.assertEqual(
            OTP._compose_update_phone_url(DeliveryMethod.WHATSAPP),
            "/v1/user/update/phone/otp/whatsapp",
        )

    def test_compose_sign_up_or_in_url(self):
        self.assertEqual(
            OTP._compose_sign_up_or_in_url(DeliveryMethod.EMAIL),
            "/v1/auth/sign-up-or-in/otp/email",
        )
        self.assertEqual(
            OTP._compose_sign_up_or_in_url(DeliveryMethod.PHONE),
            "/v1/auth/sign-up-or-in/otp/sms",
        )
        self.assertEqual(
            OTP._compose_sign_up_or_in_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/sign-up-or-in/otp/whatsapp",
        )

    def test_compose_update_user_phone_body(self):
        self.assertEqual(
            OTP._compose_update_user_phone_body("dummy@dummy.com", "+11111111"),
            {"externalId": "dummy@dummy.com", "phone": "+11111111"},
        )

    def test_compose_update_user_email_body(self):
        self.assertEqual(
            OTP._compose_update_user_email_body("dummy@dummy.com", "dummy@dummy.com"),
            {"externalId": "dummy@dummy.com", "email": "dummy@dummy.com"},
        )

    def test_sign_up(self):
        signup_user_details = {
            "username": "jhon",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }

        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException,
            client.otp.sign_up,
            DeliveryMethod.EMAIL,
            "dummy@dummy",
            signup_user_details,
        )
        self.assertRaises(
            AuthException,
            client.otp.sign_up,
            DeliveryMethod.EMAIL,
            "",
            signup_user_details,
        )
        self.assertRaises(
            AuthException,
            client.otp.sign_up,
            DeliveryMethod.EMAIL,
            None,
            signup_user_details,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.otp.sign_up,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                signup_user_details,
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.otp.sign_up(
                    DeliveryMethod.EMAIL, "dummy@dummy.com", signup_user_details
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
                client.otp.sign_up(
                    DeliveryMethod.EMAIL, "dummy@dummy.com", signup_user_details
                )
            )

        # test undefined enum value
        class Dummy(Enum):
            DUMMY = 7

        self.assertRaises(AuthException, OTP._compose_signin_url, Dummy.DUMMY)

    def test_sign_in(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException, client.otp.sign_in, DeliveryMethod.EMAIL, "dummy@dummy"
        )
        self.assertRaises(AuthException, client.otp.sign_in, DeliveryMethod.EMAIL, "")
        self.assertRaises(AuthException, client.otp.sign_in, DeliveryMethod.EMAIL, None)

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.otp.sign_in,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.otp.sign_in(DeliveryMethod.EMAIL, "dummy@dummy.com")
            )

    def test_sign_up_or_in(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException, client.otp.sign_up_or_in, DeliveryMethod.EMAIL, ""
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.otp.sign_up_or_in,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.otp.sign_up_or_in(DeliveryMethod.EMAIL, "dummy@dummy.com")
            )

    def test_verify_code(self):
        code = "1234"

        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        self.assertRaises(
            AuthException,
            client.otp.verify_code,
            DeliveryMethod.EMAIL,
            "dummy@dummy",
            code,
        )
        self.assertRaises(
            AuthException, client.otp.verify_code, DeliveryMethod.EMAIL, "", code
        )
        self.assertRaises(
            AuthException, client.otp.verify_code, DeliveryMethod.EMAIL, None, code
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.otp.verify_code,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                code,
            )

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkVGVuYW50cyI6eyIiOm51bGx9LCJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwNjc5MjA4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MjA5MDA4NzIwOCwiaWF0IjoxNjU4MDg3MjA4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQzU1dnl4dzBzUkw2RmRNNjhxUnNDRGRST1YifQ.cWP5up4R5xeIl2qoG2NtfLH3Q5nRJVKdz-FDoAXctOQW9g3ceZQi6rZQ-TPBaXMKw68bijN3bLJTqxWW5WHzqRUeopfuzTcMYmC0wP2XGJkrdF6A8D5QW6acSGqglFgu"
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.cookies = {
                SESSION_COOKIE_NAME: "dummy session token",
                REFRESH_SESSION_COOKIE_NAME: valid_jwt_token,
            }
            self.assertIsNotNone(
                client.otp.verify_code(DeliveryMethod.EMAIL, "dummy@dummy.com", code)
            )

    def test_update_user_email(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException,
            client.otp.update_user_email,
            "",
            "dummy@dummy.com",
            "refresh_token1",
        )

        self.assertRaises(
            AuthException,
            client.otp.update_user_email,
            "id1",
            "dummy@dummy",
            "refresh_token1",
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.otp.update_user_email,
                "id1",
                "dummy@dummy.com",
                "refresh_token1",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.otp.update_user_email("id1", "dummy@dummy.com", "refresh_token1")
            )

    def test_update_user_phone(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException,
            client.otp.update_user_phone,
            DeliveryMethod.PHONE,
            "",
            "+1111111",
            "refresh_token1",
        )
        self.assertRaises(
            AuthException,
            client.otp.update_user_phone,
            DeliveryMethod.PHONE,
            "id1",
            "not_a_phone",
            "refresh_token1",
        )
        self.assertRaises(
            AuthException,
            client.otp.update_user_phone,
            DeliveryMethod.EMAIL,
            "id1",
            "+1111111",
            "refresh_token1",
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.otp.update_user_phone,
                DeliveryMethod.PHONE,
                "id1",
                "+1111111",
                "refresh_token1",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.otp.update_user_phone(
                    DeliveryMethod.PHONE, "id1", "+1111111", "refresh_token1"
                )
            )
