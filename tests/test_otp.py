import json
from enum import Enum
from unittest import mock
from unittest.mock import patch

from descope import SESSION_COOKIE_NAME, AuthException, DeliveryMethod, DescopeClient
from descope.authmethod.otp import OTP  # noqa: F401
from descope.common import REFRESH_SESSION_COOKIE_NAME, EndpointsV1, LoginOptions

from . import common


class TestOTP(common.DescopeTest):
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

    def test_compose_signin_url(self):
        self.assertEqual(
            OTP._compose_signin_url(DeliveryMethod.EMAIL),
            "/v1/auth/otp/signin/email",
        )
        self.assertEqual(
            OTP._compose_signin_url(DeliveryMethod.SMS),
            "/v1/auth/otp/signin/sms",
        )
        self.assertEqual(
            OTP._compose_signin_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/otp/signin/whatsapp",
        )

    def test_compose_verify_code_url(self):
        self.assertEqual(
            OTP._compose_verify_code_url(DeliveryMethod.EMAIL),
            "/v1/auth/otp/verify/email",
        )
        self.assertEqual(
            OTP._compose_verify_code_url(DeliveryMethod.SMS),
            "/v1/auth/otp/verify/sms",
        )
        self.assertEqual(
            OTP._compose_verify_code_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/otp/verify/whatsapp",
        )

    def test_compose_update_phone_url(self):
        self.assertEqual(
            OTP._compose_update_phone_url(DeliveryMethod.EMAIL),
            "/v1/auth/otp/update/phone/email",
        )
        self.assertEqual(
            OTP._compose_update_phone_url(DeliveryMethod.SMS),
            "/v1/auth/otp/update/phone/sms",
        )
        self.assertEqual(
            OTP._compose_update_phone_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/otp/update/phone/whatsapp",
        )

    def test_compose_sign_up_or_in_url(self):
        self.assertEqual(
            OTP._compose_sign_up_or_in_url(DeliveryMethod.EMAIL),
            "/v1/auth/otp/signup-in/email",
        )
        self.assertEqual(
            OTP._compose_sign_up_or_in_url(DeliveryMethod.SMS),
            "/v1/auth/otp/signup-in/sms",
        )
        self.assertEqual(
            OTP._compose_sign_up_or_in_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/otp/signup-in/whatsapp",
        )

    def test_compose_update_user_phone_body(self):
        self.assertEqual(
            OTP._compose_update_user_phone_body("dummy@dummy.com", "+11111111"),
            {"loginId": "dummy@dummy.com", "phone": "+11111111"},
        )

    def test_compose_update_user_email_body(self):
        self.assertEqual(
            OTP._compose_update_user_email_body("dummy@dummy.com", "dummy@dummy.com"),
            {"loginId": "dummy@dummy.com", "email": "dummy@dummy.com"},
        )

    def test_sign_up(self):
        invalid_signup_user_details = {
            "username": "jhon",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy",
        }
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
            invalid_signup_user_details,
        )
        invalid_signup_user_details["email"] = "dummy@dummy.com"  # set valid mail
        invalid_signup_user_details["phone"] = "aaaaaaaa"  # set invalid phone
        self.assertRaises(
            AuthException,
            client.otp.sign_up,
            DeliveryMethod.EMAIL,
            "",
            invalid_signup_user_details,
        )
        self.assertRaises(
            AuthException,
            client.otp.sign_up,
            DeliveryMethod.SMS,
            "dummy@dummy.com",
            invalid_signup_user_details,
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
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                client.otp.sign_up(
                    DeliveryMethod.EMAIL, "dummy@dummy.com", signup_user_details
                ),
            )

        # Test flow where username set as empty and we used the login_id as default
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
                client.otp.sign_up(
                    DeliveryMethod.EMAIL, "dummy@dummy.com", signup_user_details
                ),
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_otp_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
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
            )

        # Test user is None so using the login_id as default
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                client.otp.sign_up(DeliveryMethod.EMAIL, "dummy@dummy.com", None),
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_otp_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
                        "user": {"email": "dummy@dummy.com"},
                        "email": "dummy@dummy.com",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

        # test undefined enum value
        class Dummy(Enum):
            DUMMY = 7

        self.assertRaises(AuthException, OTP._compose_signin_url, Dummy.DUMMY)

    def test_sign_in(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
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
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                client.otp.sign_in(DeliveryMethod.EMAIL, "dummy@dummy.com"),
            )
            self.assertRaises(
                AuthException,
                client.otp.sign_in,
                DeliveryMethod.EMAIL,
                "exid",
                LoginOptions(mfa=True),
            )

        # Validate refresh token used while provided
        with patch("requests.post") as mock_post:
            refresh_token = "dummy refresh token"
            client.otp.sign_in(
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                LoginOptions(stepup=True),
                refresh_token=refresh_token,
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_otp_path}/email",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{refresh_token}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
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
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                client.otp.sign_up_or_in(DeliveryMethod.EMAIL, "dummy@dummy.com"),
            )

    def test_verify_code(self):
        code = "1234"

        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

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
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                client.otp.update_user_email(
                    "id1", "dummy@dummy.com", "refresh_token1"
                ),
            )

    def test_update_user_phone(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException,
            client.otp.update_user_phone,
            DeliveryMethod.SMS,
            "",
            "+1111111",
            "refresh_token1",
        )
        self.assertRaises(
            AuthException,
            client.otp.update_user_phone,
            DeliveryMethod.SMS,
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
                DeliveryMethod.SMS,
                "id1",
                "+1111111",
                "refresh_token1",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"maskedPhone": "*****111"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "*****111",
                client.otp.update_user_phone(
                    DeliveryMethod.SMS, "id1", "+1111111", "refresh_token1"
                ),
            )
