import json
import unittest
from unittest import mock
from unittest.mock import patch

from descope import AuthException
from descope.auth import Auth
from descope.authmethod.saml import SAML
from descope.common import EndpointsV1, LoginOptions

from . import common


class TestSAML(common.DescopeTest):
    def setUp(self) -> None:
        super().setUp()
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
            {"tenant": "tenant1", "redirectURL": "http://dummy.com"},
        )

    def test_saml_start(self):
        saml = SAML(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(AuthException, saml.start, "", "http://dummy.com")
        self.assertRaises(AuthException, saml.start, None, "http://dummy.com")
        self.assertRaises(AuthException, saml.start, "tenant1", "")
        self.assertRaises(AuthException, saml.start, "tenant1", None)

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, saml.start, "tenant1", "http://dummy.com")

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(saml.start("tenant1", "http://dummy.com"))

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            saml.start("tenant1", "http://dummy.com")
            expected_uri = (
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.auth_saml_start_path}"
            )
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
                params={"tenant": "tenant1", "redirectURL": "http://dummy.com"},
                data=json.dumps({}),
                allow_redirects=False,
                verify=True,
            )
            self.assertRaises(
                AuthException,
                saml.start,
                "tenant",
                "http://dummy.com",
                LoginOptions(mfa=True),
            )

    def test_saml_start_with_login_options(self):
        saml = SAML(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(AuthException, saml.start, "", "http://dummy.com")
        self.assertRaises(AuthException, saml.start, None, "http://dummy.com")
        self.assertRaises(AuthException, saml.start, "tenant1", "")
        self.assertRaises(AuthException, saml.start, "tenant1", None)

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, saml.start, "tenant1", "http://dummy.com")

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(saml.start("tenant1", "http://dummy.com"))

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            lo = LoginOptions(stepup=True, custom_claims={"k1": "v1"})
            saml.start("tenant1", "http://dummy.com", lo, "refresh")
            expected_uri = (
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.auth_saml_start_path}"
            )
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:refresh",
                },
                params={"tenant": "tenant1", "redirectURL": "http://dummy.com"},
                data=json.dumps(
                    {"stepup": True, "customClaims": {"k1": "v1"}, "mfa": False}
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_compose_exchange_params(self):
        self.assertEqual(Auth._compose_exchange_body("c1"), {"code": "c1"})

    def test_exchange_token(self):
        saml = SAML(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(AuthException, saml.exchange_token, "")
        self.assertRaises(AuthException, saml.exchange_token, None)

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, saml.exchange_token, "c1")

        # Test success flow
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.cookies = {}
            data = json.loads(
                """{"jwts": ["eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"], "user": {"loginIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
            )
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            saml.exchange_token("c1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.saml_exchange_token_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
                params=None,
                data=json.dumps({"code": "c1"}),
                allow_redirects=False,
                verify=True,
            )


if __name__ == "__main__":
    unittest.main()
