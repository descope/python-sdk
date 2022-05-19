import json
import unittest
from unittest.mock import patch

from descope import AuthClient, AuthException, DeliveryMethod, User


class TestAuthClient(unittest.TestCase):
    def setUp(self) -> None:
        self.dummy_project_id = "dummy"
        self.public_key_dict = {
            "crv": "P-384",
            "key_ops": ["verify"],
            "kty": "EC",
            "x": "Zd7Unk3ijm3MKXt9vbHR02Y1zX-cpXu6H1_wXRtMl3e39TqeOJ3XnJCxSfE5vjMX",
            "y": "Cv8AgXWpMkMFWvLGhJ_Gsb8LmapAtEurnBsFI4CAG42yUGDfkZ_xjFXPbYssJl7U",
            "alg": "ES384",
            "use": "sig",
            "kid": "32b3da5277b142c7e24fdf0ef09e0919",
        }
        self.public_key_str = json.dumps(self.public_key_dict)

    def test_auth_client(self):
        self.assertRaises(
            AuthException, AuthClient, project_id=None, public_key="dummy"
        )
        self.assertRaises(AuthException, AuthClient, project_id="", public_key="dummy")
        self.assertRaises(
            AuthException, AuthClient, project_id="dummy", public_key=None
        )
        self.assertRaises(AuthException, AuthClient, project_id="dummy", public_key="")
        self.assertRaises(
            AuthException, AuthClient, project_id="dummy", public_key="not dict object"
        )
        self.assertIsNotNone(
            AuthClient(project_id="dummy", public_key=self.public_key_str)
        )

    def test_verify_delivery_method(self):
        self.assertEqual(
            AuthClient._verify_delivery_method(DeliveryMethod.EMAIL, "dummy@dummy.com"),
            True,
        )
        self.assertEqual(
            AuthClient._verify_delivery_method(DeliveryMethod.EMAIL, "dummy@dummy.com"),
            True,
        )
        self.assertEqual(
            AuthClient._verify_delivery_method(DeliveryMethod.EMAIL, "dummy@dummy.com"),
            True,
        )
        self.assertEqual(
            AuthClient._verify_delivery_method(DeliveryMethod.EMAIL, ""), False
        )
        self.assertEqual(
            AuthClient._verify_delivery_method(DeliveryMethod.EMAIL, "dummy@dummy"),
            False,
        )

        self.assertEqual(
            AuthClient._verify_delivery_method(DeliveryMethod.PHONE, "111111111111"),
            True,
        )
        self.assertEqual(
            AuthClient._verify_delivery_method(DeliveryMethod.PHONE, "+111111111111"),
            True,
        )
        self.assertEqual(
            AuthClient._verify_delivery_method(DeliveryMethod.PHONE, "++111111111111"),
            False,
        )
        self.assertEqual(
            AuthClient._verify_delivery_method(DeliveryMethod.PHONE, "asdsad"), False
        )
        self.assertEqual(
            AuthClient._verify_delivery_method(DeliveryMethod.PHONE, ""), False
        )
        self.assertEqual(
            AuthClient._verify_delivery_method(
                DeliveryMethod.PHONE, "unvalid@phone.number"
            ),
            False,
        )

        self.assertEqual(
            AuthClient._verify_delivery_method(DeliveryMethod.WHATSAPP, "111111111111"),
            True,
        )
        self.assertEqual(
            AuthClient._verify_delivery_method(DeliveryMethod.WHATSAPP, ""), False
        )
        self.assertEqual(
            AuthClient._verify_delivery_method(
                DeliveryMethod.WHATSAPP, "unvalid@phone.number"
            ),
            False,
        )

    def test_get_identifier_name_by_method(self):
        self.assertEqual(
            AuthClient._get_identifier_name_by_method(DeliveryMethod.EMAIL), "email"
        )
        self.assertEqual(
            AuthClient._get_identifier_name_by_method(DeliveryMethod.PHONE), "phone"
        )
        self.assertEqual(
            AuthClient._get_identifier_name_by_method(DeliveryMethod.WHATSAPP), "phone"
        )

    def test_compose_verify_code_url(self):
        self.assertEqual(
            AuthClient._compose_signup_url(DeliveryMethod.EMAIL),
            "/v1/auth/signup/otp/email",
        )
        self.assertEqual(
            AuthClient._compose_signup_url(DeliveryMethod.PHONE),
            "/v1/auth/signup/otp/sms",
        )
        self.assertEqual(
            AuthClient._compose_signup_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/signup/otp/whatsapp",
        )
        self.assertEqual(
            AuthClient._compose_signin_url(DeliveryMethod.EMAIL),
            "/v1/auth/signin/otp/email",
        )
        self.assertEqual(
            AuthClient._compose_signin_url(DeliveryMethod.PHONE),
            "/v1/auth/signin/otp/sms",
        )
        self.assertEqual(
            AuthClient._compose_signin_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/signin/otp/whatsapp",
        )
        self.assertEqual(
            AuthClient._compose_verify_code_url(DeliveryMethod.EMAIL),
            "/v1/auth/code/verify/email",
        )
        self.assertEqual(
            AuthClient._compose_verify_code_url(DeliveryMethod.PHONE),
            "/v1/auth/code/verify/sms",
        )
        self.assertEqual(
            AuthClient._compose_verify_code_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/code/verify/whatsapp",
        )

    def test_sign_up_otp(self):
        signup_user_details = User(
            username="jhon", name="john", phone="972525555555", email="dummy@dummy.com"
        )

        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException,
            client.sign_up_otp,
            DeliveryMethod.EMAIL,
            "dummy@dummy",
            signup_user_details,
        )
        self.assertRaises(
            AuthException,
            client.sign_up_otp,
            DeliveryMethod.EMAIL,
            "",
            signup_user_details,
        )
        self.assertRaises(
            AuthException,
            client.sign_up_otp,
            DeliveryMethod.EMAIL,
            None,
            signup_user_details,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.sign_up_otp,
                DeliveryMethod.EMAIL,
                "dummy@dummy",
                signup_user_details,
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.sign_up_otp(
                    DeliveryMethod.EMAIL, "dummy@dummy.com", signup_user_details
                )
            )

    def test_sign_in(self):
        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException, client.sign_in_otp, DeliveryMethod.EMAIL, "dummy@dummy"
        )
        self.assertRaises(AuthException, client.sign_in_otp, DeliveryMethod.EMAIL, "")
        self.assertRaises(AuthException, client.sign_in_otp, DeliveryMethod.EMAIL, None)

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, client.sign_in_otp, DeliveryMethod.EMAIL, "dummy@dummy"
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.sign_in_otp(DeliveryMethod.EMAIL, "dummy@dummy.com")
            )

    def test_verify_code(self):
        code = "1234"

        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        self.assertRaises(
            AuthException, client.verify_code, DeliveryMethod.EMAIL, "dummy@dummy", code
        )
        self.assertRaises(
            AuthException, client.verify_code, DeliveryMethod.EMAIL, "", code
        )
        self.assertRaises(
            AuthException, client.verify_code, DeliveryMethod.EMAIL, None, code
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.verify_code,
                DeliveryMethod.EMAIL,
                "dummy@dummy",
                code,
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(
                client.verify_code(DeliveryMethod.EMAIL, "dummy@dummy.com", code)
            )

    def test_validate_session(self):
        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        invalid_header_jwt_token = "AyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImR1bW15In0.Bcz3xSxEcxgBSZOzqrTvKnb9-u45W-RlAbHSBL6E8zo2yJ9SYfODphdZ8tP5ARNTvFSPj2wgyu1SeiZWoGGPHPNMt4p65tPeVf5W8--d2aKXCc4KvAOOK3B_Cvjy_TO8"
        invalid_payload_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.AyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImR1bW15In0.Bcz3xSxEcxgBSZOzqrTvKnb9-u45W-RlAbHSBL6E8zo2yJ9SYfODphdZ8tP5ARNTvFSPj2wgyu1SeiZWoGGPHPNMt4p65tPeVf5W8--d2aKXCc4KvAOOK3B_Cvjy_TO8"
        expired_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjExODEzOTgxMTF9.EdetpQro-frJV1St1mWGygRSzxf6Bg01NNR_Ipwy_CAQyGDmIQ6ITGQ620hfmjW5HDtZ9-0k7AZnwoLnb709QQgbHMFxlDpIOwtFIAJuU-CqaBDwsNWA1f1RNyPpLxop"
        valid_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjE5ODEzOTgxMTF9.GQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh"

        self.assertRaises(
            AuthException, client.validate_session_request, invalid_header_jwt_token
        )
        self.assertRaises(
            AuthException, client.validate_session_request, invalid_payload_jwt_token
        )
        self.assertRaises(
            AuthException, client.validate_session_request, expired_jwt_token
        )
        self.assertIsNone(client.validate_session_request(valid_jwt_token))


if __name__ == "__main__":
    unittest.main()
