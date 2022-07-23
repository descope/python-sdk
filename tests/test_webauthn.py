import unittest
from unittest.mock import patch
import json

from descope import AuthException
from descope.authhelper import AuthHelper
from descope.authmethod.webauthn import WebauthN
from descope.common import DEFAULT_BASE_URI, EndpointsV1


class TestWebauthN(unittest.TestCase):
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
        
    
    def test_compose_signup_body(self):
        self.assertEqual(
            WebauthN._compose_signup_body("dummy@dummy.com", {"name": "dummy"}),
            {"user": {"externalId": "dummy@dummy.com",
            "name": "dummy"}}
        )

    def test_compose_sign_up_in_finish_body(self):
        self.assertEqual(
            WebauthN._compose_sign_up_in_finish_body("t01", "response01"),
            {"transactionID": "t01", "response": "response01"}
        )

    def test_compose_signin_body(self):
        self.assertEqual(
            WebauthN._compose_signin_body("dummy@dummy.com"),
            {"externalId": "dummy@dummy.com"}
        )

    def test_compose_add_device_start_body(self):
        self.assertEqual(
            WebauthN._compose_add_device_start_body("dummy@dummy.com"),
            {"externalId": "dummy@dummy.com"}
        )

    def test_compose_add_device_finish_body(self):
        self.assertEqual(
            WebauthN._compose_add_device_finish_body("t01", "response01"),
            {"transactionID": "t01", "response": "response01"}
        )

    def test_sign_up_start(self):
        webauthn = WebauthN(AuthHelper(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(AuthException, webauthn.sign_up_start, "")
        self.assertRaises(AuthException, webauthn.sign_up_start, None)

        with patch("requests.get") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, webauthn.sign_up_start, "dummy@dummy.com")

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(webauthn.sign_up_start("dummy@dummy.com"))

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            webauthn.sign_up_start("dummy@dummy.com")
            expected_uri = f"{DEFAULT_BASE_URI}{EndpointsV1.signUpAuthWebauthnStart}"
            mock_post.assert_called_with(
                expected_uri,
                cookies=None,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Basic ZHVtbXk6",
                },
                data=json.dumps({"user": {"externalId": "dummy@dummy.com"}}),
            )

    def test_sign_up_finish(self):
        webauthn = WebauthN(AuthHelper(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(AuthException, webauthn.sign_up_finish, "", "response01")
        self.assertRaises(AuthException, webauthn.sign_up_finish, None, "response01")
        self.assertRaises(AuthException, webauthn.sign_up_finish, "t01", "")
        self.assertRaises(AuthException, webauthn.sign_up_finish, "t01", None)

        with patch("requests.get") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, webauthn.sign_up_finish, "t01", "response01")

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            data = json.loads("""{"error": "", "jwts": {"DS": {"cookieDomain": "", "cookieExpiration": 1660388078, "cookieMaxAge": 2591999, "cookieName": "DS", "cookiePath": "/", "exp": 1657796678, "iat": 1657796078, "jwt": "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoxNjU3Nzk2Njc4LCJpYXQiOjE2NTc3OTYwNzgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJCdEVIa2dPdTAybG1NeHpQSWV4ZE10VXcxTSJ9.lTUKMIjkrdsfryREYrgz4jMV7M0-JF-Q-KNlI0xZhamYqnSYtvzdwAoYiyWamx22XrN5SZkcmVZ5bsx-g2C0p5VMbnmmxEaxcnsFJHqVAJUYEv5HGQHumN50DYSlLXXg", "projectId": "2Bt5WLccLUey1Dp7utptZb3Fx9K", "userId": "2BtEHkgOu02lmMxzPIexdMtUw1M"}, "DSR": {"cookieDomain": "", "cookieExpiration": 1660388078, "cookieMaxAge": 2591999, "cookieName": "DSR", "cookiePath": "/", "exp": 1660215278, "iat": 1657796078, "jwt": "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh", "projectId": "2Bt5WLccLUey1Dp7utptZb3Fx9K", "userId": "2BtEHkgOu02lmMxzPIexdMtUw1M"}}, "user": {"externalID": "guyp@descope.com", "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": True, "verifiedPhone": False}, "firstSeen": False}""")
            mock_post.return_value.data = data
            self.assertIsNotNone(webauthn.sign_up_finish("t01", "response01"))

        # with patch("requests.post") as mock_post:
        #     mock_post.return_value.ok = True
        #     webauthn.sign_up_start("dummy@dummy.com")
        #     expected_uri = f"{DEFAULT_BASE_URI}{EndpointsV1.signUpAuthWebauthnStart}"
        #     mock_post.assert_called_with(
        #         expected_uri,
        #         cookies=None,
        #         headers={
        #             "Content-Type": "application/json",
        #             "Authorization": "Basic ZHVtbXk6",
        #         },
        #         data=json.dumps({"user": {"externalId": "dummy@dummy.com"}}),
        #     )
  
    
if __name__ == "__main__":
    unittest.main()
