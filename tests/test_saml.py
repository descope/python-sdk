import unittest
from enum import Enum
from unittest.mock import patch

from descope import AuthException
from descope.auth import Auth
from descope.common import DEFAULT_BASE_URI, EndpointsV1

from descope.authmethod.saml import SAML

class TestSAML(unittest.TestCase):
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
        
    
    def test_compose_start_params(self):
        self.assertEqual(
            SAML._compose_start_params("tenant1", "http://dummy.com"),
            {"tenant": "tenant1",
            "redirectURL": "http://dummy.com"}
        )

    def test_saml_start(self):
        saml = SAML(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(AuthException, saml.start, "", "http://dummy.com")
        self.assertRaises(AuthException, saml.start, None, "http://dummy.com")
        self.assertRaises(AuthException, saml.start, "tenant1", "")
        self.assertRaises(AuthException, saml.start, "tenant1", None)

        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(AuthException, saml.start, "tenant1", "http://dummy.com")

        # Test success flow
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            self.assertIsNotNone(saml.start("tenant1", "http://dummy.com"))

        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            saml.start("tenant1", "http://dummy.com")
            expected_uri = f"{DEFAULT_BASE_URI}{EndpointsV1.authSAMLStart}"
            mock_get.assert_called_with(
                expected_uri,
                cookies=None,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Basic ZHVtbXk6",
                },
                params={"tenant": "tenant1",
                        "redirectURL": "http://dummy.com"},
                allow_redirects=None,
            )


if __name__ == "__main__":
    unittest.main()
