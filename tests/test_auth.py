import json
import unittest
from enum import Enum
from unittest.mock import patch

from descope import AuthException, DeliveryMethod
from descope.auth import Auth


class TestAuth(unittest.TestCase):
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

    def test_get_identifier_name_by_method(self):
        user = {"email": "dummy@dummy.com", "phone": "11111111"}
        self.assertEqual(
            Auth.get_identifier_by_method(DeliveryMethod.EMAIL, user),
            ("email", "dummy@dummy.com"),
        )
        self.assertEqual(
            Auth.get_identifier_by_method(DeliveryMethod.PHONE, user),
            ("phone", "11111111"),
        )
        self.assertEqual(
            Auth.get_identifier_by_method(DeliveryMethod.WHATSAPP, user),
            ("whatsapp", "11111111"),
        )

        class AAA(Enum):
            DUMMY = 4

        self.assertRaises(AuthException, Auth.get_identifier_by_method, AAA.DUMMY, user)

    def test_compose_refresh_token_url(self):
        self.assertEqual(
            Auth._compose_refresh_token_url(),
            "/v1/auth/refresh",
        )

    def test_refresh_token(self):
        dummy_refresh_token = "dummy refresh token"
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test fail flow
        with patch("requests.get") as mock_request:
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
        with patch("requests.get") as mock_request:
            mock_request.return_value.ok = False
            self.assertRaises(
                AuthException,
                auth.exchange_access_key,
                dummy_access_key,
            )


if __name__ == "__main__":
    unittest.main()
