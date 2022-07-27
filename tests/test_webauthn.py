import json
import unittest
from unittest import mock
from unittest.mock import patch

from descope import AuthException
from descope.auth import Auth
from descope.authmethod.webauthn import WebauthN
from descope.common import DEFAULT_BASE_URL, EndpointsV1


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
            WebauthN._compose_signup_body(
                "dummy@dummy.com", {"name": "dummy"}, "https://example.com"
            ),
            {
                "user": {"externalId": "dummy@dummy.com", "name": "dummy"},
                "origin": "https://example.com",
            },
        )

    def test_compose_sign_up_in_finish_body(self):
        self.assertEqual(
            WebauthN._compose_sign_up_in_finish_body("t01", "response01"),
            {"transactionId": "t01", "response": "response01"},
        )

    def test_compose_signin_body(self):
        self.assertEqual(
            WebauthN._compose_signin_body("dummy@dummy.com", "https://example.com"),
            {"externalId": "dummy@dummy.com", "origin": "https://example.com"},
        )

    def test_compose_add_device_start_body(self):
        self.assertEqual(
            WebauthN._compose_add_device_start_body(
                "dummy@dummy.com", "https://example.com"
            ),
            {"externalId": "dummy@dummy.com", "origin": "https://example.com"},
        )

    def test_compose_add_device_finish_body(self):
        self.assertEqual(
            WebauthN._compose_add_device_finish_body("t01", "response01"),
            {"transactionId": "t01", "response": "response01"},
        )

    def test_sign_up_start(self):
        webauthn = WebauthN(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException, webauthn.sign_up_start, "", "https://example.com"
        )
        self.assertRaises(AuthException, webauthn.sign_up_start, "id1", "")

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, webauthn.sign_up_start, "id1", "https://example.com"
            )

        # Test success flow
        valid_response = json.loads(
            """{"transactionId": "2COHI3LIixYhf6Q7EECYt20zyMi", "options": "{'publicKey':{'challenge':'5GOywA7BHL1QceQOfxHKDrasuN8SkbbgXmB5ImVZ+QU=','rp':{'name':'comp6','id':'localhost'},'user':{'name”:”dummy@dummy.com','displayName”:”dummy”,”id':'VTJDT0hJNWlWOHJaZ3VURkpKMzV3bjEydHRkTw=='},'pubKeyCredParams':[{'type':'public-key','alg':-7},{'type':'public-key','alg':-35},{'type':'public-key','alg':-36},{'type':'public-key','alg':-257},{'type':'public-key','alg':-258},{'type':'public-key','alg':-259},{'type':'public-key','alg':-37},{'type':'public-key','alg':-38},{'type':'public-key','alg':-39},{'type':'public-key','alg':-8}],'authenticatorSelection':{'userVerification':'preferred'},'timeout':60000,'attestation':'none'}}"}"""
        )
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(webauthn.sign_up_start("id1", "https://example.com"))

        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = valid_response
            mock_post.return_value = my_mock_response
            res = webauthn.sign_up_start("id1", "https://example.com")

            expected_uri = f"{DEFAULT_BASE_URL}{EndpointsV1.signUpAuthWebauthnStart}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Basic ZHVtbXk6",
                },
                data=json.dumps(
                    {"user": {"externalId": "id1"}, "origin": "https://example.com"}
                ),
                verify=True,
            )
            self.assertEqual(res, valid_response)

    def test_sign_up_finish(self):
        webauthn = WebauthN(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(AuthException, webauthn.sign_up_finish, "", "response01")
        self.assertRaises(AuthException, webauthn.sign_up_finish, None, "response01")
        self.assertRaises(AuthException, webauthn.sign_up_finish, "t01", "")
        self.assertRaises(AuthException, webauthn.sign_up_finish, "t01", None)

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, webauthn.sign_up_finish, "t01", "response01"
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.cookies = {}
            data = json.loads(
                """{"jwts": ["eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"], "user": {"externalIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
            )
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            expected_uri = f"{DEFAULT_BASE_URL}{EndpointsV1.signUpAuthWebauthnFinish}"
            webauthn.sign_up_finish("t01", "response01")
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Basic ZHVtbXk6",
                },
                data=json.dumps({"transactionId": "t01", "response": "response01"}),
                verify=True,
            )
            self.assertIsNotNone(webauthn.sign_up_finish("t01", "response01"))

    def test_sign_in_start(self):
        webauthn = WebauthN(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException, webauthn.sign_in_start, "", "https://example.com"
        )
        self.assertRaises(AuthException, webauthn.sign_in_start, "id", "")

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                webauthn.sign_in_start,
                "id1",
                "https://example.com",
            )

        # Test success flow
        valid_response = json.loads(
            """{"transactionId": "2COHI3LIixYhf6Q7EECYt20zyMi", "options": "{'publicKey':{'challenge':'5GOywA7BHL1QceQOfxHKDrasuN8SkbbgXmB5ImVZ+QU=','rp':{'name':'comp6','id':'localhost'},'user':{'name”:”dummy@dummy.com','displayName”:”dummy”,”id':'VTJDT0hJNWlWOHJaZ3VURkpKMzV3bjEydHRkTw=='},'pubKeyCredParams':[{'type':'public-key','alg':-7},{'type':'public-key','alg':-35},{'type':'public-key','alg':-36},{'type':'public-key','alg':-257},{'type':'public-key','alg':-258},{'type':'public-key','alg':-259},{'type':'public-key','alg':-37},{'type':'public-key','alg':-38},{'type':'public-key','alg':-39},{'type':'public-key','alg':-8}],'authenticatorSelection':{'userVerification':'preferred'},'timeout':60000,'attestation':'none'}}"}"""
        )
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(
                webauthn.sign_in_start("dummy@dummy.com", "https://example.com")
            )

        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = valid_response
            mock_post.return_value = my_mock_response
            res = webauthn.sign_in_start("id1", "https://example.com")
            expected_uri = f"{DEFAULT_BASE_URL}{EndpointsV1.signInAuthWebauthnStart}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Basic ZHVtbXk6",
                },
                data=json.dumps({"externalId": "id1", "origin": "https://example.com"}),
                verify=True,
            )
            self.assertEqual(res, valid_response),

    def test_sign_in_finish(self):
        webauthn = WebauthN(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(AuthException, webauthn.sign_in_finish, "", "response01")
        self.assertRaises(AuthException, webauthn.sign_in_finish, None, "response01")
        self.assertRaises(AuthException, webauthn.sign_in_finish, "t01", "")
        self.assertRaises(AuthException, webauthn.sign_in_finish, "t01", None)

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, webauthn.sign_in_finish, "t01", "response01"
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.cookies = {}

            data = json.loads(
                """{"jwts": ["eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"], "user": {"externalIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
            )
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            expected_uri = f"{DEFAULT_BASE_URL}{EndpointsV1.signInAuthWebauthnFinish}"
            webauthn.sign_in_finish("t01", "response01")
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Basic ZHVtbXk6",
                },
                data=json.dumps({"transactionId": "t01", "response": "response01"}),
                verify=True,
            )
            self.assertIsNotNone(webauthn.sign_up_finish("t01", "response01"))

    def test_add_device_start(self):
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkVGVuYW50cyI6eyIiOm51bGx9LCJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwNjc5MjA4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MjA5MDA4NzIwOCwiaWF0IjoxNjU4MDg3MjA4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQzU1dnl4dzBzUkw2RmRNNjhxUnNDRGRST1YifQ.cWP5up4R5xeIl2qoG2NtfLH3Q5nRJVKdz-FDoAXctOQW9g3ceZQi6rZQ-TPBaXMKw68bijN3bLJTqxWW5WHzqRUeopfuzTcMYmC0wP2XGJkrdF6A8D5QW6acSGqglFgu"
        webauthn = WebauthN(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException, webauthn.add_device_start, "", "", "https://example.com"
        )
        self.assertRaises(
            AuthException, webauthn.add_device_start, None, "", "https://example.com"
        )
        self.assertRaises(
            AuthException,
            webauthn.add_device_start,
            "dummy@dummy.com",
            "",
            "https://example.com",
        )
        self.assertRaises(
            AuthException,
            webauthn.add_device_start,
            "dummy@dummy.com",
            None,
            "https://example.com",
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                webauthn.add_device_start,
                "dummy@dummy.com",
                valid_jwt_token,
                "https://example.com",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(
                webauthn.add_device_start(
                    "dummy@dummy.com", valid_jwt_token, "https://example.com"
                )
            )

        with patch("requests.post") as mock_post:
            valid_response = json.loads("{}")
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = valid_response
            mock_post.return_value = my_mock_response
            res = webauthn.add_device_start(
                "dummy@dummy.com", "asdasd", "https://example.com"
            )
            expected_uri = f"{DEFAULT_BASE_URL}{EndpointsV1.deviceAddAuthWebauthnStart}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Basic ZHVtbXk6YXNkYXNk",
                },
                data=json.dumps(
                    {"externalId": "dummy@dummy.com", "origin": "https://example.com"}
                ),
                verify=True,
            )
            self.assertEqual(res, valid_response)

    def test_add_device_finish(self):
        webauthn = WebauthN(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(AuthException, webauthn.add_device_finish, "", "response01")
        self.assertRaises(AuthException, webauthn.add_device_finish, None, "response01")
        self.assertRaises(AuthException, webauthn.add_device_finish, "t01", "")
        self.assertRaises(AuthException, webauthn.add_device_finish, "t01", None)

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, webauthn.add_device_finish, "t01", "response01"
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.cookies = {}
            data = json.loads(
                """{"jwts": ["eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"], "user": {"externalIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
            )
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            expected_uri = (
                f"{DEFAULT_BASE_URL}{EndpointsV1.deviceAddAuthWebauthnFinish}"
            )
            webauthn.add_device_finish("t01", "response01")
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Basic ZHVtbXk6",
                },
                data=json.dumps({"transactionId": "t01", "response": "response01"}),
                verify=True,
            )
            self.assertIsNotNone(webauthn.sign_up_finish("t01", "response01"))


if __name__ == "__main__":
    unittest.main()
