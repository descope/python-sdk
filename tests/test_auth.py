import json
import unittest
from enum import Enum
from unittest import mock
from unittest.mock import patch

from descope import AuthException, DeliveryMethod
from descope.auth import Auth
from descope.common import REFRESH_SESSION_TOKEN_NAME, SESSION_TOKEN_NAME


class TestAuth(unittest.TestCase):
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
        self.public_key_str = json.dumps(self.public_key_dict)

    def test_validate_phone(self):
        self.assertRaises(
            AuthException, Auth.validate_phone, method=DeliveryMethod.PHONE, phone=""
        )

        self.assertRaises(
            AuthException,
            Auth.validate_phone,
            method=DeliveryMethod.PHONE,
            phone="asd234234234",
        )

        self.assertRaises(
            AuthException,
            Auth.validate_phone,
            method=DeliveryMethod.EMAIL,
            phone="+1111111",
        )

        self.assertIsNone(
            Auth.validate_phone(method=DeliveryMethod.WHATSAPP, phone="+1111111")
        )

    def test_validate_email(self):
        self.assertRaises(AuthException, Auth.validate_email, email="")

        self.assertRaises(AuthException, Auth.validate_email, email="@dummy.com")

        self.assertIsNone(Auth.validate_email(email="dummy@dummy.com"))

    def test_validate_and_load_public_key(self):
        # test invalid json
        self.assertRaises(
            AuthException,
            Auth._validate_and_load_public_key,
            public_key="invalid json",
        )
        # test public key without kid property
        self.assertRaises(
            AuthException,
            Auth._validate_and_load_public_key,
            public_key={"test": "dummy"},
        )

        # test not dict object
        self.assertRaises(
            AuthException, Auth._validate_and_load_public_key, public_key=555
        )
        # test invalid dict
        self.assertRaises(
            AuthException,
            Auth._validate_and_load_public_key,
            public_key={"kid": "dummy"},
        )

    def test_fetch_public_key(self):
        auth = Auth(self.dummy_project_id, self.public_key_dict)
        valid_keys_response = """{"keys":[
    {
        "alg": "ES384",
        "crv": "P-384",
        "kid": "299psneX92K3vpbqPMRCnbZKb27",
        "kty": "EC",
        "use": "sig",
        "x": "435yhcD0tqH6z5M8kNFYEcEYXjzBQWiOvIOZO17rOatpXj-MbA6CKrktiblT4xMb",
        "y": "YMf1EIz68z2_RKBys5byWRUXlqNF_BhO5F0SddkaRtiqZ8M6n7ZnKl65JGN0EEGr"
    }
]}
        """

        # Test failed flows
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(AuthException, auth._fetch_public_keys)

        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            mock_get.return_value.text = "invalid json"
            self.assertRaises(AuthException, auth._fetch_public_keys)

        # test success flow
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            mock_get.return_value.text = valid_keys_response
            self.assertIsNone(auth._fetch_public_keys())

    def test_verify_delivery_method(self):
        self.assertEqual(
            Auth.verify_delivery_method(DeliveryMethod.EMAIL, "dummy@dummy.com", None),
            False,
        )

        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.EMAIL, "dummy@dummy.com", {"phone": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.EMAIL, "dummy@dummy.com", {"phone": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.EMAIL, "dummy@dummy.com", {"phone": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.verify_delivery_method(DeliveryMethod.EMAIL, "", {"phone": ""}), False
        )
        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.EMAIL, "dummy@dummy", {"phone": ""}
            ),
            False,
        )

        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.PHONE, "111111111111", {"email": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.PHONE, "+111111111111", {"email": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.PHONE, "++111111111111", {"email": ""}
            ),
            False,
        )
        self.assertEqual(
            Auth.verify_delivery_method(DeliveryMethod.PHONE, "asdsad", {"email": ""}),
            False,
        )
        self.assertEqual(
            Auth.verify_delivery_method(DeliveryMethod.PHONE, "", {"email": ""}), False
        )
        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.PHONE, "unvalid@phone.number", {"email": ""}
            ),
            False,
        )

        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.WHATSAPP, "111111111111", {"email": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.verify_delivery_method(DeliveryMethod.WHATSAPP, "", {"email": ""}),
            False,
        )
        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.WHATSAPP, "unvalid@phone.number", {"email": ""}
            ),
            False,
        )

        class AAA(Enum):
            DUMMY = 4

        self.assertEqual(
            Auth.verify_delivery_method(
                AAA.DUMMY, "unvalid@phone.number", {"phone": ""}
            ),
            False,
        )

    def test_get_login_id_name_by_method(self):
        user = {"email": "dummy@dummy.com", "phone": "11111111"}
        self.assertEqual(
            Auth.get_login_id_by_method(DeliveryMethod.EMAIL, user),
            ("email", "dummy@dummy.com"),
        )
        self.assertEqual(
            Auth.get_login_id_by_method(DeliveryMethod.PHONE, user),
            ("phone", "11111111"),
        )
        self.assertEqual(
            Auth.get_login_id_by_method(DeliveryMethod.WHATSAPP, user),
            ("whatsapp", "11111111"),
        )

        class AAA(Enum):
            DUMMY = 4

        self.assertRaises(AuthException, Auth.get_login_id_by_method, AAA.DUMMY, user)

    def test_compose_refresh_token_url(self):
        self.assertEqual(
            Auth._compose_refresh_token_url(),
            "/v1/auth/refresh",
        )

    def test_refresh_token(self):
        dummy_refresh_token = "dummy refresh token"
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test fail flow
        with patch("requests.post") as mock_request:
            mock_request.return_value.ok = False
            self.assertRaises(
                AuthException,
                auth.refresh_token,
                dummy_refresh_token,
            )

    def test_exchange_access_key(self):
        dummy_access_key = "dummy access key"
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test fail flow
        with patch("requests.post") as mock_request:
            mock_request.return_value.ok = False
            self.assertRaises(
                AuthException,
                auth.exchange_access_key,
                dummy_access_key,
            )

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL"
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            data = {"sessionJwt": valid_jwt_token}
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            jwt_response = auth.exchange_access_key(dummy_access_key)
            self.assertEqual(jwt_response["keyId"], "U2Cu0j0WPw3YOiPISJb52L0wUVMg")
            self.assertEqual(jwt_response["projectId"], "P2CtzUhdqpIF2ys9gg7ms06UvtC4")

    def test_adjust_properties(self):
        self.assertEqual(
            Auth.adjust_properties(self, jwt_response={}, user_jwt={}),
            {"keyId": None, "projectId": ""},
        )

        jwt_response = {
            SESSION_TOKEN_NAME: {
                "permissions": ["perm1"],
                "roles": ["role1"],
                "tenants": {"bla1": "bla1"},
                "iss": "123456",
                "sub": "user-id",
            },
            REFRESH_SESSION_TOKEN_NAME: {
                "permissions": ["perm2"],
                "roles": ["role2"],
                "tenants": {"bla2": "bla2"},
            },
        }

        self.assertEqual(
            Auth.adjust_properties(self, jwt_response=jwt_response, user_jwt=True),
            {
                "permissions": ["perm1"],
                "projectId": "123456",
                "refreshSessionToken": {
                    "permissions": ["perm2"],
                    "roles": ["role2"],
                    "tenants": {"bla2": "bla2"},
                },
                "roles": ["role1"],
                "sessionToken": {
                    "iss": "123456",
                    "permissions": ["perm1"],
                    "roles": ["role1"],
                    "sub": "user-id",
                    "tenants": {"bla1": "bla1"},
                },
                "tenants": {"bla1": "bla1"},
                "userId": "user-id",
            },
        )

        jwt_response = {
            SESSION_TOKEN_NAME: {
                "permissions": ["perm1"],
                "roles": ["role1"],
                "tenants": {"bla1": "bla1"},
                "sub": "user-id",
            },
            REFRESH_SESSION_TOKEN_NAME: {
                "permissions": ["perm2"],
                "roles": ["role2"],
                "tenants": {"bla2": "bla2"},
                "iss": "https://descope.com/bla/123456",
            },
        }

        self.assertEqual(
            Auth.adjust_properties(self, jwt_response=jwt_response, user_jwt=False),
            {
                "permissions": ["perm1"],
                "projectId": "123456",
                "refreshSessionToken": {
                    "iss": "https://descope.com/bla/123456",
                    "permissions": ["perm2"],
                    "roles": ["role2"],
                    "tenants": {"bla2": "bla2"},
                },
                "roles": ["role1"],
                "sessionToken": {
                    "permissions": ["perm1"],
                    "roles": ["role1"],
                    "sub": "user-id",
                    "tenants": {"bla1": "bla1"},
                },
                "tenants": {"bla1": "bla1"},
                "keyId": "user-id",
            },
        )


if __name__ == "__main__":
    unittest.main()
