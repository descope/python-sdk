import unittest
from unittest.mock import patch

from descope import AuthException
from descope.auth import Auth
from descope.authmethod.oauth import OAuth
from descope.common import DEFAULT_BASE_URI, EndpointsV1


class TestOAuth(unittest.TestCase):
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
            OAuth._compose_start_params("google", "http://example.com"),
            {"provider": "google", "redirectURL": "http://example.com"},
        )

    def test_verify_oauth_providers(self):
        self.assertEqual(
            OAuth._verify_provider(""),
            False,
        )

        self.assertEqual(
            OAuth._verify_provider(None),
            False,
        )

        self.assertEqual(
            OAuth._verify_provider("unknown provider"),
            False,
        )

        self.assertEqual(
            OAuth._verify_provider("google"),
            True,
        )

    def test_oauth_start(self):
        oauth = OAuth(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(AuthException, oauth.start, "")

        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(AuthException, oauth.start, "google")

        # Test success flow
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            self.assertIsNotNone(oauth.start("google"))

        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            oauth.start("facebook")
            expected_uri = f"{DEFAULT_BASE_URI}{EndpointsV1.oauthStart}"
            mock_get.assert_called_with(
                expected_uri,
                cookies=None,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Basic ZHVtbXk6",
                },
                params={"provider": "facebook"},
                allow_redirects=False,
            )


if __name__ == "__main__":
    unittest.main()
