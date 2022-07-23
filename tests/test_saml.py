import json
import unittest
from copy import deepcopy
from enum import Enum
from unittest.mock import patch

from descope import SESSION_COOKIE_NAME, AuthClient, AuthException, DeliveryMethod
from descope.authhelper import AuthHelper
from descope.authmethod.saml import SAML
from descope.common import DEFAULT_BASE_URI, EndpointsV1


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
            SAML._compose_start_params("tenantID", "http://dummy.com"),
            {"tenantID": "tenantID",
            "redirectURL": "http://dummy.com"}
        )

    def test_saml_start(self):
        saml = SAML(AuthHelper(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(AuthException, saml.start, "", "http://dummy.com")
        self.assertRaises(AuthException, saml.start, None, "http://dummy.com")
        self.assertRaises(AuthException, saml.start, "tenantId", "")
        self.assertRaises(AuthException, saml.start, "tenantId", None)

        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(AuthException, saml.start, "tenantId", "http://dummy.com")

        # Test success flow
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            self.assertIsNotNone(saml.start("tenantId", "http://dummy.com"))

        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            saml.start("tenantId", "http://dummy.com")
            expected_uri = f"{DEFAULT_BASE_URI}{EndpointsV1.authSAMLStart}"
            mock_get.assert_called_with(
                expected_uri,
                cookies=None,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Basic ZHVtbXk6",
                },
                params={"tenantID": "tenantId",
                        "redirectURL": "http://dummy.com"},
                allow_redirects=None,
            )

  
    
if __name__ == "__main__":
    unittest.main()
