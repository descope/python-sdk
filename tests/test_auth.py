import json
import unittest
from copy import deepcopy
from enum import Enum
from unittest.mock import patch

from descope import SESSION_COOKIE_NAME, AuthClient, AuthException, DeliveryMethod, User
from descope.common import DEFAULT_BASE_URI, REFRESH_SESSION_COOKIE_NAME, EndpointsV1


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

        with patch("os.getenv") as mock_getenv:
            mock_getenv.return_value = ""
            self.assertRaises(
                AuthException, AuthClient, project_id=None, public_key="dummy"
            )

        self.assertIsNotNone(
            AuthException, AuthClient(project_id="dummy", public_key=None)
        )
        self.assertIsNotNone(
            AuthException, AuthClient(project_id="dummy", public_key="")
        )
        self.assertRaises(
            AuthException, AuthClient, project_id="dummy", public_key="not dict object"
        )
        self.assertIsNotNone(
            AuthClient(project_id="dummy", public_key=self.public_key_str)
        )

    def test_validate_and_load_public_key(self):
        # test invalid json
        self.assertRaises(
            AuthException,
            AuthClient._validate_and_load_public_key,
            public_key="invalid json",
        )
        # test public key without kid property
        self.assertRaises(
            AuthException,
            AuthClient._validate_and_load_public_key,
            public_key={"test": "dummy"},
        )

        # test not dict object
        self.assertRaises(
            AuthException, AuthClient._validate_and_load_public_key, public_key=555
        )
        # test invalid dict
        self.assertRaises(
            AuthException,
            AuthClient._validate_and_load_public_key,
            public_key={"kid": "dummy"},
        )

    def test_fetch_public_key(self):
        client = AuthClient(self.dummy_project_id, self.public_key_dict)
        valid_keys_response = """[
    {
        "alg": "ES384",
        "crv": "P-384",
        "kid": "299psneX92K3vpbqPMRCnbZKb27",
        "kty": "EC",
        "use": "sig",
        "x": "435yhcD0tqH6z5M8kNFYEcEYXjzBQWiOvIOZO17rOatpXj-MbA6CKrktiblT4xMb",
        "y": "YMf1EIz68z2_RKBys5byWRUXlqNF_BhO5F0SddkaRtiqZ8M6n7ZnKl65JGN0EEGr"
    }
]
        """

        # Test failed flows
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(AuthException, client._fetch_public_keys)

        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            mock_get.return_value.text = "invalid json"
            self.assertRaises(AuthException, client._fetch_public_keys)

        # test success flow
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            mock_get.return_value.text = valid_keys_response
            self.assertIsNone(client._fetch_public_keys())

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

        class AAA(Enum):
            DUMMY = 4

        self.assertEqual(
            AuthClient._verify_delivery_method(AAA.DUMMY, "unvalid@phone.number"),
            False,
        )

    def test_verify_oauth_providers(self):
        self.assertEqual(
            AuthClient._verify_oauth_provider(""),
            False,
        )

        self.assertEqual(
            AuthClient._verify_oauth_provider(None),
            False,
        )

        self.assertEqual(
            AuthClient._verify_oauth_provider("unknown provider"),
            False,
        )

        self.assertEqual(
            AuthClient._verify_oauth_provider("google"),
            True,
        )

    def test_oauth_start(self):
        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(AuthException, client.oauth_start, "")

        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(AuthException, client.oauth_start, "google")

        # Test success flow
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            self.assertIsNotNone(client.oauth_start("google"))

        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            client.oauth_start("facebook")
            expected_uri = f"{DEFAULT_BASE_URI}{EndpointsV1.oauthStart}"
            mock_get.assert_called_with(
                expected_uri,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Basic ZHVtbXk6",
                },
                params={"provider": "facebook"},
                allow_redirects=False,
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

        class AAA(Enum):
            DUMMY = 4

        self.assertRaises(
            AuthException, AuthClient._get_identifier_name_by_method, AAA.DUMMY
        )

    def test_compose_signup_url(self):
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
            AuthClient._compose_signup_magiclink_url(DeliveryMethod.EMAIL),
            "/v1/auth/signup/magiclink/email",
        )
        self.assertEqual(
            AuthClient._compose_signup_magiclink_url(DeliveryMethod.PHONE),
            "/v1/auth/signup/magiclink/sms",
        )
        self.assertEqual(
            AuthClient._compose_signup_magiclink_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/signup/magiclink/whatsapp",
        )

    def test_compose_signin_url(self):
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
            AuthClient._compose_signin_magiclink_url(DeliveryMethod.EMAIL),
            "/v1/auth/signin/magiclink/email",
        )
        self.assertEqual(
            AuthClient._compose_signin_magiclink_url(DeliveryMethod.PHONE),
            "/v1/auth/signin/magiclink/sms",
        )
        self.assertEqual(
            AuthClient._compose_signin_magiclink_url(DeliveryMethod.WHATSAPP),
            "/v1/auth/signin/magiclink/whatsapp",
        )

    def test_compose_verify_code_url(self):
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
        self.assertEqual(
            AuthClient._compose_verify_magiclink_url(),
            "/v1/auth/magiclink/verify",
        )

    def test_compose_refresh_token_url(self):
        self.assertEqual(
            AuthClient._compose_refresh_token_url(),
            "/v1/auth/refresh",
        )

    def test_compose_logout_url(self):
        self.assertEqual(
            AuthClient._compose_logout_url(),
            "/v1/auth/logoutall",
        )

    def test_logout(self):
        dummy_refresh_token = ""
        dummy_valid_jwt_token = ""
        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        self.assertRaises(AuthException, client.logout, None, None)

        # Test failed flow
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(
                AuthException, client.logout, dummy_valid_jwt_token, dummy_refresh_token
            )

        # Test success flow
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            self.assertIsNotNone(
                client.logout(dummy_valid_jwt_token, dummy_refresh_token)
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
                "dummy@dummy.com",
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

        # Test flow where username not set and we used the identifier as default
        signup_user_details = User(
            username="", name="john", phone="972525555555", email="dummy@dummy.com"
        )
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.sign_up_otp(
                    DeliveryMethod.EMAIL, "dummy@dummy.com", signup_user_details
                )
            )

        # test undefined enum value
        class Dummy(Enum):
            DUMMY = 7

        self.assertRaises(AuthException, AuthClient._compose_signin_url, Dummy.DUMMY)

    def test_sign_up_magiclink(self):
        signup_user_details = User(
            username="jhon", name="john", phone="972525555555", email="dummy@dummy.com"
        )

        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException,
            client.sign_up_magiclink,
            DeliveryMethod.EMAIL,
            "dummy@dummy",
            "http://test.me",
            signup_user_details,
        )
        self.assertRaises(
            AuthException,
            client.sign_up_magiclink,
            DeliveryMethod.EMAIL,
            "",
            "http://test.me",
            signup_user_details,
        )
        self.assertRaises(
            AuthException,
            client.sign_up_magiclink,
            DeliveryMethod.EMAIL,
            None,
            "http://test.me",
            signup_user_details,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.sign_up_magiclink,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
                signup_user_details,
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.sign_up_magiclink(
                    DeliveryMethod.EMAIL,
                    "dummy@dummy.com",
                    "http://test.me",
                    signup_user_details,
                )
            )

        # Test flow where username not set and we used the identifier as default
        signup_user_details = User(
            username="", name="john", phone="972525555555", email="dummy@dummy.com"
        )
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.sign_up_magiclink(
                    DeliveryMethod.EMAIL,
                    "dummy@dummy.com",
                    "http://test.me",
                    signup_user_details,
                )
            )

        # test undefined enum value
        class Dummy(Enum):
            DUMMY = 7

        self.assertRaises(
            AuthException, AuthClient._compose_signin_magiclink_url, Dummy.DUMMY
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
                AuthException,
                client.sign_in_otp,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.sign_in_otp(DeliveryMethod.EMAIL, "dummy@dummy.com")
            )

    def test_sign_in_magiclink(self):
        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        self.assertRaises(
            AuthException,
            client.sign_in_magiclink,
            DeliveryMethod.EMAIL,
            "dummy@dummy",
            "http://test.me",
        )
        self.assertRaises(
            AuthException,
            client.sign_in_magiclink,
            DeliveryMethod.EMAIL,
            "",
            "http://test.me",
        )
        self.assertRaises(
            AuthException,
            client.sign_in_magiclink,
            DeliveryMethod.EMAIL,
            None,
            "http://test.me",
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.sign_in_magiclink,
                DeliveryMethod.EMAIL,
                "dummy@dummy.com",
                "http://test.me",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.sign_in_magiclink(
                    DeliveryMethod.EMAIL, "dummy@dummy.com", "http://test.me"
                )
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
                "dummy@dummy.com",
                code,
            )

        # Test success flow
        valid_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjE5ODEzOTgxMTF9.GQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh"
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.cookies = {
                SESSION_COOKIE_NAME: valid_jwt_token,
                REFRESH_SESSION_COOKIE_NAME: "dummy refresh token",
            }
            self.assertIsNotNone(
                client.verify_code(DeliveryMethod.EMAIL, "dummy@dummy.com", code)
            )

    def test_verify_magiclink(self):
        code = "1234"

        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.verify_magiclink,
                code,
            )

        # Test success flow
        valid_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjE5ODEzOTgxMTF9.GQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh"
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.cookies = {
                SESSION_COOKIE_NAME: valid_jwt_token,
                REFRESH_SESSION_COOKIE_NAME: "dummy refresh token",
            }
            self.assertIsNotNone(client.verify_magiclink(code))

    def test_validate_session(self):
        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        dummy_refresh_token = ""

        invalid_header_jwt_token = "AyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImR1bW15In0.Bcz3xSxEcxgBSZOzqrTvKnb9-u45W-RlAbHSBL6E8zo2yJ9SYfODphdZ8tP5ARNTvFSPj2wgyu1SeiZWoGGPHPNMt4p65tPeVf5W8--d2aKXCc4KvAOOK3B_Cvjy_TO8"
        missing_kid_header_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImFhYSI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjE5ODEzOTgxMTF9.GQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh"
        invalid_payload_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjE5ODEzOTgxMTF9.AQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh"
        valid_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjE5ODEzOTgxMTF9.GQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh"

        self.assertRaises(
            AuthException,
            client.validate_session_request,
            missing_kid_header_jwt_token,
            dummy_refresh_token,
        )
        self.assertRaises(
            AuthException,
            client.validate_session_request,
            invalid_header_jwt_token,
            dummy_refresh_token,
        )
        self.assertRaises(
            AuthException,
            client.validate_session_request,
            invalid_payload_jwt_token,
            dummy_refresh_token,
        )
        self.assertIsNotNone(
            client.validate_session_request(valid_jwt_token, dummy_refresh_token)
        )

        # Test case where key id cannot be found
        client2 = AuthClient(self.dummy_project_id, None)
        with patch("requests.get") as mock_request:
            fake_key = deepcopy(self.public_key_dict)
            # overwrite the kid (so it will not be found)
            fake_key["kid"] = "dummy_kid"
            mock_request.return_value.text = json.dumps([fake_key])
            mock_request.return_value.ok = True
            self.assertRaises(
                AuthException,
                client2.validate_session_request,
                valid_jwt_token,
                dummy_refresh_token,
            )

        # Test case where we failed to load key
        client3 = AuthClient(self.dummy_project_id, None)
        with patch("requests.get") as mock_request:
            mock_request.return_value.text = """[{"kid": "dummy_kid"}]"""
            mock_request.return_value.ok = True
            self.assertRaises(
                AuthException,
                client3.validate_session_request,
                valid_jwt_token,
                dummy_refresh_token,
            )

        # Test case where header_alg != key[alg]
        self.public_key_dict["alg"] = "ES521"
        client4 = AuthClient(self.dummy_project_id, self.public_key_dict)
        with patch("requests.get") as mock_request:
            mock_request.return_value.text = """[{"kid": "dummy_kid"}]"""
            mock_request.return_value.ok = True
            self.assertRaises(
                AuthException,
                client4.validate_session_request,
                valid_jwt_token,
                dummy_refresh_token,
            )

        # Test case where header_alg != key[alg]
        client4 = AuthClient(self.dummy_project_id, None)
        self.assertRaises(
            AuthException,
            client4.validate_session_request,
            None,
            None,
        )

        #
        expired_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjExODEzOTgxMTF9.EdetpQro-frJV1St1mWGygRSzxf6Bg01NNR_Ipwy_CAQyGDmIQ6ITGQ620hfmjW5HDtZ9-0k7AZnwoLnb709QQgbHMFxlDpIOwtFIAJuU-CqaBDwsNWA1f1RNyPpLxop"
        valid_refresh_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjE5ODEzOTgxMTF9.GQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh"
        with patch("requests.get") as mock_request:
            mock_request.return_value.cookies = {SESSION_COOKIE_NAME: expired_jwt_token}
            mock_request.return_value.ok = True

            self.assertRaises(
                AuthException,
                client3.validate_session_request,
                expired_jwt_token,
                valid_refresh_token,
            )

    def test_exception_object(self):
        ex = AuthException(401, "dummy error type", "dummy error message")
        str_ex = str(ex)  # noqa: F841
        repr_ex = repr(ex)  # noqa: F841

    def test_expired_token(self):
        expired_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjExODEzOTgxMTF9.EdetpQro-frJV1St1mWGygRSzxf6Bg01NNR_Ipwy_CAQyGDmIQ6ITGQ620hfmjW5HDtZ9-0k7AZnwoLnb709QQgbHMFxlDpIOwtFIAJuU-CqaBDwsNWA1f1RNyPpLxop"
        dummy_refresh_token = "dummy refresh token"
        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        # Test fail flow
        with patch("requests.get") as mock_request:
            mock_request.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.validate_session_request,
                expired_jwt_token,
                dummy_refresh_token,
            )

        with patch("requests.get") as mock_request:
            mock_request.return_value.cookies = {"aaa": "aaa"}
            mock_request.return_value.ok = True
            self.assertRaises(
                AuthException,
                client.validate_session_request,
                expired_jwt_token,
                dummy_refresh_token,
            )

        # Test fail flow
        dummy_session_token = "dummy session token"
        dummy_client = AuthClient(self.dummy_project_id, self.public_key_dict)
        with patch("jwt.get_unverified_header") as mock_jwt_get_unverified_header:
            mock_jwt_get_unverified_header.return_value = {}
            self.assertRaises(
                AuthException,
                dummy_client.validate_session_request,
                dummy_session_token,
                dummy_refresh_token,
            )

        # Test success flow
        new_refreshed_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjE5ODEzOTgxMTF9.GQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh"
        dummy_refresh_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjE5ODEzOTgxMTF9.GQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh"
        with patch("requests.get") as mock_request:
            mock_request.return_value.cookies = {
                SESSION_COOKIE_NAME: new_refreshed_token
            }
            mock_request.return_value.ok = True
            claims, tokens = client.validate_session_request(
                expired_jwt_token, dummy_refresh_token
            )
            new_session_token = tokens[SESSION_COOKIE_NAME]
            self.assertEqual(
                new_session_token, new_refreshed_token, "Failed to refresh token"
            )

        expired_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjExODEzOTgxMTF9.EdetpQro-frJV1St1mWGygRSzxf6Bg01NNR_Ipwy_CAQyGDmIQ6ITGQ620hfmjW5HDtZ9-0k7AZnwoLnb709QQgbHMFxlDpIOwtFIAJuU-CqaBDwsNWA1f1RNyPpLxop"
        valid_refresh_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjE5ODEzOTgxMTF9.GQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh"
        new_refreshed_token = (
            expired_jwt_token  # the refreshed token should be invalid (or expired)
        )
        with patch("requests.get") as mock_request:
            mock_request.return_value.cookies = {
                SESSION_COOKIE_NAME: new_refreshed_token
            }
            mock_request.return_value.ok = True
            self.assertRaises(
                AuthException,
                dummy_client.validate_session_request,
                expired_jwt_token,
                valid_refresh_token,
            )

    def test_refresh_token(self):
        expired_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjExODEzOTgxMTF9.EdetpQro-frJV1St1mWGygRSzxf6Bg01NNR_Ipwy_CAQyGDmIQ6ITGQ620hfmjW5HDtZ9-0k7AZnwoLnb709QQgbHMFxlDpIOwtFIAJuU-CqaBDwsNWA1f1RNyPpLxop"
        dummy_refresh_token = "dummy refresh token"
        client = AuthClient(self.dummy_project_id, self.public_key_dict)

        # Test fail flow
        with patch("requests.get") as mock_request:
            mock_request.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.refresh_token,
                expired_jwt_token,
                dummy_refresh_token,
            )

        with patch("requests.get") as mock_request:
            mock_request.return_value.ok = True
            mock_request.return_value.cookies = {SESSION_COOKIE_NAME: None}
            self.assertRaises(
                AuthException,
                client.refresh_token,
                expired_jwt_token,
                dummy_refresh_token,
            )

    def test_public_key_load(self):
        # Test key without kty property
        invalid_public_key = deepcopy(self.public_key_dict)
        invalid_public_key.pop("kty")
        with self.assertRaises(AuthException) as cm:
            AuthClient(self.dummy_project_id, invalid_public_key)
        self.assertEqual(cm.exception.status_code, 400)

        # Test key without kid property
        invalid_public_key = deepcopy(self.public_key_dict)
        invalid_public_key.pop("kid")
        with self.assertRaises(AuthException) as cm:
            AuthClient(self.dummy_project_id, invalid_public_key)
        self.assertEqual(cm.exception.status_code, 400)

        # Test key with unknown algorithm
        invalid_public_key = deepcopy(self.public_key_dict)
        invalid_public_key["alg"] = "unknown algorithm"
        with self.assertRaises(AuthException) as cm:
            AuthClient(self.dummy_project_id, invalid_public_key)
        self.assertEqual(cm.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
