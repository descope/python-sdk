import json
import unittest
from unittest import mock
from unittest.mock import patch

from descope import AuthException
from descope.auth import Auth
from descope.authmethod.webauthn import WebAuthn
from descope.common import DEFAULT_TIMEOUT_SECONDS, EndpointsV1, LoginOptions

from . import common
from .async_test_base import (
    parameterized_sync_async_subcase,
    HTTPMockHelper,
    MethodTestHelper,
)


class TestWebauthN(common.DescopeTest):
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

    def test_compose_signup_body(self):
        self.assertEqual(
            WebAuthn._compose_sign_up_start_body(
                "dummy@dummy.com", {"name": "dummy"}, "https://example.com"
            ),
            {
                "user": {"loginId": "dummy@dummy.com", "name": "dummy"},
                "origin": "https://example.com",
            },
        )

    def test_compose_sign_up_in_finish_body(self):
        self.assertEqual(
            WebAuthn._compose_sign_up_in_finish_body("t01", "response01"),
            {"transactionId": "t01", "response": "response01"},
        )

    def test_compose_signin_body(self):
        self.assertEqual(
            WebAuthn._compose_sign_in_start_body(
                "dummy@dummy.com", "https://example.com"
            ),
            {
                "loginId": "dummy@dummy.com",
                "origin": "https://example.com",
                "loginOptions": {},
            },
        )

    def test_compose_signup_or_in_body(self):
        self.assertEqual(
            WebAuthn._compose_sign_up_or_in_start_body(
                "dummy@dummy.com", "https://example.com"
            ),
            {
                "loginId": "dummy@dummy.com",
                "origin": "https://example.com",
            },
        )

    def test_compose_update_start_body(self):
        self.assertEqual(
            WebAuthn._compose_update_start_body(
                "dummy@dummy.com", "https://example.com"
            ),
            {"loginId": "dummy@dummy.com", "origin": "https://example.com"},
        )

    def test_compose_update_finish_body(self):
        self.assertEqual(
            WebAuthn._compose_update_finish_body("t01", "response01"),
            {"transactionId": "t01", "response": "response01"},
        )

    @parameterized_sync_async_subcase("sign_up_start", "sign_up_start_async")
    def test_sign_up_start(self, method_name, is_async):
        webauthn = WebAuthn(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "",
            "https://example.com",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "id1",
            "",
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                webauthn,
                method_name,
                "id1",
                "https://example.com",
            )

        # Test success flow
        valid_response = json.loads(
            """{"transactionId": "2COHI3LIixYhf6Q7EECYt20zyMi", "options": "{'publicKey':{'challenge':'5GOywA7BHL1QceQOfxHKDrasuN8SkbbgXmB5ImVZ+QU=','rp':{'name':'comp6','id':'localhost'},'user':{'name”:”dummy@dummy.com','displayName”:”dummy”,”id':'VTJDT0hJNWlWOHJaZ3VURkpKMzV3bjEydHRkTw=='},'pubKeyCredParams':[{'type':'public-key','alg':-7},{'type':'public-key','alg':-35},{'type':'public-key','alg':-36},{'type':'public-key','alg':-257},{'type':'public-key','alg':-258},{'type':'public-key','alg':-259},{'type':'public-key','alg':-37},{'type':'public-key','alg':-38},{'type':'public-key','alg':-39},{'type':'public-key','alg':-8}],'authenticatorSelection':{'userVerification':'preferred'},'timeout':60000,'attestation':'none'}}"}"""
        )
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            self.assertIsNotNone(
                MethodTestHelper.call_method(
                    webauthn, method_name, "id1", "https://example.com"
                )
            )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: valid_response
        ) as mock_post:
            res = MethodTestHelper.call_method(
                webauthn, method_name, "id1", "https://example.com"
            )

            expected_uri = f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_webauthn_start_path}"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"user": {"loginId": "id1"}, "origin": "https://example.com"},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res, valid_response)

    @parameterized_sync_async_subcase("sign_up_finish", "sign_up_finish_async")
    def test_sign_up_finish(self, method_name, is_async):
        webauthn = WebAuthn(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "",
            "response01",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            None,
            "response01",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "t01",
            "",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "t01",
            None,
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                webauthn,
                method_name,
                "t01",
                "response01",
            )

        # Test success flow
        data = json.loads(
            """{"refreshJwt": "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL",
             "user": {"loginIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false},
              "firstSeen": false,
              "cookieDomain": "test",
              "cookiePath": "/",
              "cookieMaxAge": 30,
              "cookieExpiration": 100
              }
              """
        )
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, cookies={}, json=lambda: data
        ) as mock_post:
            expected_uri = f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_webauthn_finish_path}"
            MethodTestHelper.call_method(webauthn, method_name, "t01", "response01")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"transactionId": "t01", "response": "response01"},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertIsNotNone(
                MethodTestHelper.call_method(webauthn, method_name, "t01", "response01")
            )

    @parameterized_sync_async_subcase("sign_in_start", "sign_in_start_async")
    def test_sign_in_start(self, method_name, is_async):
        webauthn = WebAuthn(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException, webauthn.sign_in_start, "", "https://example.com"
        )
        self.assertRaises(AuthException, webauthn.sign_in_start, "id", "")

        with patch("httpx.post") as mock_post:
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
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(
                webauthn.sign_in_start("dummy@dummy.com", "https://example.com")
            )
            self.assertRaises(
                AuthException,
                webauthn.sign_in_start,
                "id",
                "origin",
                LoginOptions(mfa=True),
            )

        with patch("httpx.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = valid_response
            mock_post.return_value = my_mock_response
            res = webauthn.sign_in_start("id1", "https://example.com")
            expected_uri = f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_webauthn_start_path}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "id1",
                    "origin": "https://example.com",
                    "loginOptions": {},
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res, valid_response)

    @parameterized_sync_async_subcase("sign_in_start", "sign_in_start_async")
    def test_sign_in_start_with_login_options(self, method_name, is_async):
        webauthn = WebAuthn(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException, webauthn.sign_in_start, "", "https://example.com"
        )
        self.assertRaises(AuthException, webauthn.sign_in_start, "id", "")

        with patch("httpx.post") as mock_post:
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
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(
                webauthn.sign_in_start("dummy@dummy.com", "https://example.com")
            )

        with patch("httpx.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = valid_response
            mock_post.return_value = my_mock_response
            lo = LoginOptions(stepup=True, custom_claims={"k1": "v1"})
            res = webauthn.sign_in_start("id1", "https://example.com", lo, "refresh")
            expected_uri = f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_webauthn_start_path}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:refresh",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "id1",
                    "origin": "https://example.com",
                    "loginOptions": {
                        "stepup": True,
                        "customClaims": {"k1": "v1"},
                        "mfa": False,
                    },
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res, valid_response)

    @parameterized_sync_async_subcase("sign_in_finish", "sign_in_finish_async")
    def test_sign_in_finish(self, method_name, is_async):
        webauthn = WebAuthn(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "",
            "response01",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            None,
            "response01",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "t01",
            "",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "t01",
            None,
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                webauthn,
                method_name,
                "t01",
                "response01",
            )

        # Test success flow
        data = json.loads(
            """{"refreshJwt": "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL", "user": {"loginIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
        )
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, cookies={}, json=lambda: data
        ) as mock_post:
            expected_uri = f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_auth_webauthn_finish_path}"
            MethodTestHelper.call_method(webauthn, method_name, "t01", "response01")

            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"transactionId": "t01", "response": "response01"},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertIsNotNone(
                MethodTestHelper.call_method(webauthn, method_name, "t01", "response01")
            )

    @parameterized_sync_async_subcase(
        "sign_up_or_in_start", "sign_up_or_in_start_async"
    )
    def test_sign_up_or_in_start(self, method_name, is_async):
        webauthn = WebAuthn(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "",
            "https://example.com",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "id",
            "",
        )

        # Test HTTP failure
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                webauthn,
                method_name,
                "id1",
                "https://example.com",
            )

        # Test success flow
        valid_response = json.loads(
            """{"create": true, "transactionId": "2COHI3LIixYhf6Q7EECYt20zyMi", "options": "{'publicKey':{'challenge':'5GOywA7BHL1QceQOfxHKDrasuN8SkbbgXmB5ImVZ+QU=','rp':{'name':'comp6','id':'localhost'},'user':{'name”:”dummy@dummy.com','displayName”:”dummy”,”id':'VTJDT0hJNWlWOHJaZ3VURkpKMzV3bjEydHRkTw=='},'pubKeyCredParams':[{'type':'public-key','alg':-7},{'type':'public-key','alg':-35},{'type':'public-key','alg':-36},{'type':'public-key','alg':-257},{'type':'public-key','alg':-258},{'type':'public-key','alg':-259},{'type':'public-key','alg':-37},{'type':'public-key','alg':-38},{'type':'public-key','alg':-39},{'type':'public-key','alg':-8}],'authenticatorSelection':{'userVerification':'preferred'},'timeout':60000,'attestation':'none'}}"}"""
        )
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: valid_response
        ) as mock_post:
            res = MethodTestHelper.call_method(
                webauthn, method_name, "id1", "https://example.com"
            )
            expected_uri = f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_or_in_auth_webauthn_start_path}"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "id1",
                    "origin": "https://example.com",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res, valid_response)

    @parameterized_sync_async_subcase("update_start", "update_start_async")
    def test_update_start(self, method_name, is_async):
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkVGVuYW50cyI6eyIiOm51bGx9LCJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwNjc5MjA4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MjA5MDA4NzIwOCwiaWF0IjoxNjU4MDg3MjA4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQzU1dnl4dzBzUkw2RmRNNjhxUnNDRGRST1YifQ.cWP5up4R5xeIl2qoG2NtfLH3Q5nRJVKdz-FDoAXctOQW9g3ceZQi6rZQ-TPBaXMKw68bijN3bLJTqxWW5WHzqRUeopfuzTcMYmC0wP2XGJkrdF6A8D5QW6acSGqglFgu"
        webauthn = WebAuthn(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "",
            "",
            "https://example.com",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            None,
            "",
            "https://example.com",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "dummy@dummy.com",
            "",
            "https://example.com",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "dummy@dummy.com",
            None,
            "https://example.com",
        )

        # Test HTTP failure
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                webauthn,
                method_name,
                "dummy@dummy.com",
                valid_jwt_token,
                "https://example.com",
            )

        # Test success flow
        valid_response = json.loads("{}")
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: valid_response
        ) as mock_post:
            res = MethodTestHelper.call_method(
                webauthn,
                method_name,
                "dummy@dummy.com",
                "asdasd",
                "https://example.com",
            )
            expected_uri = f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_auth_webauthn_start_path}"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:asdasd",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"loginId": "dummy@dummy.com", "origin": "https://example.com"},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(res, valid_response)

    @parameterized_sync_async_subcase("update_finish", "update_finish_async")
    def test_update_finish(self, method_name, is_async):
        webauthn = WebAuthn(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "",
            "response01",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            None,
            "response01",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "t01",
            "",
        )
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            webauthn,
            method_name,
            "t01",
            None,
        )

        # Test HTTP failure
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                webauthn,
                method_name,
                "t01",
                "response01",
            )

        # Test success flow
        data = json.loads(
            """{"refreshJwt": "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL", "user": {"loginIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
        )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: data
        ) as mock_post:
            expected_uri = f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_auth_webauthn_finish_path}"
            result = MethodTestHelper.call_method(
                webauthn, method_name, "t01", "response01"
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"transactionId": "t01", "response": "response01"},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            # Note: update_finish_async returns None, so we don't test the return value


if __name__ == "__main__":
    unittest.main()
