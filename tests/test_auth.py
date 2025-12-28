import json
import unittest
from enum import Enum
from http import HTTPStatus
from types import SimpleNamespace
from unittest import mock
from unittest.mock import patch

import jwt

from descope import (
    API_RATE_LIMIT_RETRY_AFTER_HEADER,
    ERROR_TYPE_API_RATE_LIMIT,
    ERROR_TYPE_SERVER_ERROR,
    AccessKeyLoginOptions,
    AuthException,
    DeliveryMethod,
    RateLimitException,
)
from descope.auth import Auth
from descope.common import (
    DEFAULT_TIMEOUT_SECONDS,
    REFRESH_SESSION_TOKEN_NAME,
    SESSION_TOKEN_NAME,
    EndpointsV1,
)

from . import common


class TestAuth(common.DescopeTest):
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
        self.public_key_str = json.dumps(self.public_key_dict)

    def test_validate_phone(self):
        self.assertRaises(
            AuthException, Auth.validate_phone, method=DeliveryMethod.SMS, phone=""
        )

        self.assertRaises(
            AuthException,
            Auth.validate_phone,
            method=DeliveryMethod.SMS,
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
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )
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

    def test_empty_project_id(self):
        self.assertRaises(AuthException, Auth, http_client=self.make_http_client())

    def test_base_url_for_project_id(self):
        self.assertEqual("https://api.descope.com", Auth.base_url_for_project_id(""))
        self.assertEqual(
            "https://api.descope.com", Auth.base_url_for_project_id("Puse")
        )
        self.assertEqual(
            "https://api.descope.com", Auth.base_url_for_project_id("Puse1ar")
        )
        self.assertEqual(
            "https://api.descope.com",
            Auth.base_url_for_project_id("P2aAc4T2V93bddihGEx2Ryhc8e5Z"),
        )
        self.assertEqual(
            "https://api.use1.descope.com",
            Auth.base_url_for_project_id("Puse12aAc4T2V93bddihGEx2Ryhc8e5Z"),
        )
        self.assertEqual(
            "https://api.use1.descope.com",
            Auth.base_url_for_project_id("Puse12aAc4T2V93bddihGEx2Ryhc8e5Zfoobar"),
        )

    def test_verify_delivery_method(self):
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.EMAIL, "dummy@dummy.com", None
            ),
            False,
        )

        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.EMAIL, "dummy@dummy.com", {"phone": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.EMAIL, "dummy@dummy.com", {"phone": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.EMAIL, "dummy@dummy.com", {"phone": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.EMAIL, "", {"phone": ""}
            ),
            False,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.EMAIL, "dummy@dummy", {"phone": ""}
            ),
            False,
        )

        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.SMS, "111111111111", {"email": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.SMS, "+111111111111", {"email": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.SMS, "++111111111111", {"email": ""}
            ),
            False,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.SMS, "asdsad", {"email": ""}
            ),
            False,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.SMS, "", {"email": ""}
            ),
            False,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.SMS, "unvalid@phone.number", {"email": ""}
            ),
            False,
        )

        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.VOICE, "111111111111", {"email": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.VOICE, "+111111111111", {"email": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.VOICE, "++111111111111", {"email": ""}
            ),
            False,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.VOICE, "asdsad", {"email": ""}
            ),
            False,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.VOICE, "", {"email": ""}
            ),
            False,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.VOICE, "unvalid@phone.number", {"email": ""}
            ),
            False,
        )

        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.WHATSAPP, "111111111111", {"email": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.WHATSAPP, "", {"email": ""}
            ),
            False,
        )
        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
                DeliveryMethod.WHATSAPP, "unvalid@phone.number", {"email": ""}
            ),
            False,
        )

        class AAA(Enum):
            DUMMY = 4

        self.assertEqual(
            Auth.adjust_and_verify_delivery_method(
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
            Auth.get_login_id_by_method(DeliveryMethod.SMS, user),
            ("phone", "11111111"),
        )
        self.assertEqual(
            Auth.get_login_id_by_method(DeliveryMethod.VOICE, user),
            ("voice", "11111111"),
        )
        self.assertEqual(
            Auth.get_login_id_by_method(DeliveryMethod.WHATSAPP, user),
            ("whatsapp", "11111111"),
        )

        class AAA(Enum):
            DUMMY = 4

        self.assertRaises(AuthException, Auth.get_login_id_by_method, AAA.DUMMY, user)

    def test_refresh_session(self):
        dummy_refresh_token = "dummy refresh token"
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

        # Test fail flow
        with patch("requests.post") as mock_request:
            mock_request.return_value.ok = False
            self.assertRaises(
                AuthException,
                auth.refresh_session,
                dummy_refresh_token,
            )

    def test_validate_session_and_refresh_input(self):
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

        # Bad input for session
        with self.assertRaises(AuthException):
            auth.validate_and_refresh_session(None, None)

        # Test validate_session with Ratelimit exception
        with patch("requests.get") as mock_request:
            mock_request.return_value.ok = False
            mock_request.return_value.status_code = 429
            mock_request.return_value.json.return_value = {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            }
            mock_request.return_value.headers = {
                API_RATE_LIMIT_RETRY_AFTER_HEADER: "10"
            }
            ds = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg5NzI4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoxNjU3Nzk4MzI4LCJpYXQiOjE2NTc3OTc3MjgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJCdEVIa2dPdTAybG1NeHpQSWV4ZE10VXcxTSJ9.i-JoPoYmXl3jeLTARvYnInBiRdTT4uHZ3X3xu_n1dhUb1Qy_gqK7Ru8ErYXeENdfPOe4mjShc_HsVyb5PjE2LMFmb58WR8wixtn0R-u_MqTpuI_422Dk6hMRjTFEVRWu"
            with self.assertRaises(RateLimitException) as cm:
                auth.validate_session(ds)
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, "E130429")
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(
                the_exception.error_description, "https://docs.descope.com/rate-limit"
            )
            self.assertEqual(the_exception.error_message, "API rate limit exceeded.")
            self.assertEqual(
                the_exception.rate_limit_parameters,
                {API_RATE_LIMIT_RETRY_AFTER_HEADER: 10},
            )

        # Test refresh_session with Ratelimit exception
        with patch("requests.get") as mock_request:
            mock_request.return_value.ok = False
            mock_request.return_value.status_code = 429
            mock_request.return_value.json.return_value = {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            }
            mock_request.return_value.headers = {
                API_RATE_LIMIT_RETRY_AFTER_HEADER: "10"
            }
            dsr = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg5NzI4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoxNjU3Nzk4MzI4LCJpYXQiOjE2NTc3OTc3MjgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJCdEVIa2dPdTAybG1NeHpQSWV4ZE10VXcxTSJ9.i-JoPoYmXl3jeLTARvYnInBiRdTT4uHZ3X3xu_n1dhUb1Qy_gqK7Ru8ErYXeENdfPOe4mjShc_HsVyb5PjE2LMFmb58WR8wixtn0R-u_MqTpuI_422Dk6hMRjTFEVRWu"
            with self.assertRaises(RateLimitException) as cm:
                auth.refresh_session(dsr)
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, "E130429")
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(
                the_exception.error_description, "https://docs.descope.com/rate-limit"
            )
            self.assertEqual(the_exception.error_message, "API rate limit exceeded.")
            self.assertEqual(
                the_exception.rate_limit_parameters,
                {API_RATE_LIMIT_RETRY_AFTER_HEADER: 10},
            )

    def test_exchange_access_key(self):
        dummy_access_key = "dummy access key"
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

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
            jwt_response = auth.exchange_access_key(
                access_key=dummy_access_key,
                login_options=AccessKeyLoginOptions(custom_claims={"k1": "v1"}),
            )
            self.assertEqual(jwt_response["keyId"], "U2Cu0j0WPw3YOiPISJb52L0wUVMg")
            self.assertEqual(jwt_response["projectId"], "P2CtzUhdqpIF2ys9gg7ms06UvtC4")

            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.exchange_auth_access_key_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:dummy access key",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"loginOptions": {"customClaims": {"k1": "v1"}}},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_exchange_token_success_and_empty_code(self):
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

        # Empty code -> error
        with self.assertRaises(AuthException):
            auth.exchange_token("/oauth/exchange", "")

        # Success path
        with patch("requests.post") as mock_post:
            net_resp = mock.Mock()
            net_resp.ok = True
            net_resp.cookies = {"DSR": "cookie_token"}
            # Make validator return claims
            auth._validate_token = lambda token, audience=None: {
                "iss": "https://issuer/PX",
                "sub": "user-x",
            }
            net_resp.json.return_value = {
                "sessionJwt": "s1",
                "refreshJwt": "r1",
                "user": {"id": "user-x"},
                "firstSeen": True,
            }
            mock_post.return_value = net_resp
            out = auth.exchange_token("/oauth/exchange", code="abc")
            self.assertEqual(out["projectId"], "PX")
            self.assertEqual(out["userId"], "user-x")

    def test_validate_session_success(self):
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )
        # Stub validator to bypass network
        auth._validate_token = lambda token, audience=None: {
            "iss": "P123",
            "sub": "u123",
            "permissions": ["p1"],
            "roles": ["r1"],
            "tenants": {"t1": {}},
        }
        res = auth.validate_session("token-session")
        self.assertEqual(res["projectId"], "P123")
        self.assertEqual(res["userId"], "u123")
        self.assertEqual(res["permissions"], ["p1"])
        self.assertIn(SESSION_TOKEN_NAME, res)

    def test_select_tenant_success(self):
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )
        # Missing refresh token
        with self.assertRaises(AuthException):
            auth.select_tenant("tenant1", "")

        # Success network path
        with patch("requests.post") as mock_post:
            net_resp = mock.Mock()
            net_resp.ok = True
            net_resp.cookies = {"DSR": "cookie_r"}
            # validator stub
            auth._validate_token = lambda token, audience=None: {
                "iss": "P77",
                "sub": "u77",
            }
            net_resp.json.return_value = {
                "sessionJwt": "s77",
                "refreshJwt": "r77",
            }
            mock_post.return_value = net_resp
            out = auth.select_tenant("tenant1", refresh_token="r0")
            self.assertEqual(out["projectId"], "P77")
            self.assertIn(SESSION_TOKEN_NAME, out)

    def test_compose_url_invalid_method(self):
        class Dummy(Enum):
            X = 1

        with self.assertRaises(AuthException):
            Auth.compose_url("/base", Dummy.X)

    def test_validate_token_header_errors(self):
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )
        # Empty token
        with self.assertRaises(AuthException):
            auth._validate_token("")

        # Garbage token -> header parse error
        with self.assertRaises(AuthException):
            auth._validate_token("not-a-jwt")

        # Missing alg -> mock header dict without alg
        with patch("descope.auth.jwt.get_unverified_header") as mock_hdr:
            mock_hdr.return_value = {"kid": "kid1"}
            with self.assertRaises(AuthException) as cm:
                auth._validate_token("any.token.value")
            self.assertIn("missing property: alg", str(cm.exception).lower())

        # Missing kid -> mock header dict without kid
        with patch("descope.auth.jwt.get_unverified_header") as mock_hdr:
            mock_hdr.return_value = {"alg": "ES384"}
            with self.assertRaises(AuthException) as cm2:
                auth._validate_token("any.token.value")
            self.assertIn("missing property: kid", str(cm2.exception).lower())

        # Algorithm mismatch after fetching keys (kid found but alg different)
        with patch("descope.auth.jwt.get_unverified_header") as mock_hdr:
            mock_hdr.return_value = {
                "alg": "RS256",
                "kid": self.public_key_dict["kid"],
            }
            with self.assertRaises(AuthException) as cm3:
                auth._validate_token("any.token.value")
            self.assertIn("does not match", str(cm3.exception))

    def test_extract_masked_address_default(self):
        # Unknown method should return empty string
        class DummyMethod(Enum):
            OTHER = 999

        self.assertEqual(Auth.extract_masked_address({}, DummyMethod.OTHER), "")

    def test_extract_masked_address_known_methods(self):
        resp = {"maskedPhone": "+1-***-***-1234", "maskedEmail": "a***@b.com"}
        self.assertEqual(
            Auth.extract_masked_address(resp, DeliveryMethod.SMS), "+1-***-***-1234"
        )
        self.assertEqual(
            Auth.extract_masked_address(resp, DeliveryMethod.EMAIL), "a***@b.com"
        )

    def test_adjust_properties(self):
        self.assertEqual(
            Auth.adjust_properties(self, jwt_response={}, user_jwt={}),
            {
                "keyId": "",
                "permissions": [],
                "projectId": "",
                "roles": [],
                "tenants": {},
            },
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

    def test_api_rate_limit_exception(self):
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

        # Test do_post
        with patch("requests.post") as mock_request:
            mock_request.return_value.ok = False
            mock_request.return_value.status_code = 429
            mock_request.return_value.json.return_value = {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            }
            mock_request.return_value.headers = {
                API_RATE_LIMIT_RETRY_AFTER_HEADER: "10"
            }
            with self.assertRaises(RateLimitException) as cm:
                auth.http_client.post(
                    "http://test.com", body={}, params=None, pswd=None
                )
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, "E130429")
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(
                the_exception.error_description, "https://docs.descope.com/rate-limit"
            )
            self.assertEqual(the_exception.error_message, "API rate limit exceeded.")
            self.assertEqual(
                the_exception.rate_limit_parameters,
                {API_RATE_LIMIT_RETRY_AFTER_HEADER: 10},
            )

        # Test do_get
        with patch("requests.get") as mock_request:
            mock_request.return_value.ok = False
            mock_request.return_value.status_code = 429
            mock_request.return_value.json.return_value = {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            }
            mock_request.return_value.headers = {
                API_RATE_LIMIT_RETRY_AFTER_HEADER: "10"
            }
            with self.assertRaises(RateLimitException) as cm:
                auth.http_client.get(
                    uri="http://test.com", params=False, allow_redirects=True
                )
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, "E130429")
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(
                the_exception.error_description, "https://docs.descope.com/rate-limit"
            )
            self.assertEqual(the_exception.error_message, "API rate limit exceeded.")
            self.assertEqual(
                the_exception.rate_limit_parameters,
                {API_RATE_LIMIT_RETRY_AFTER_HEADER: 10},
            )

        # Test do_delete
        with patch("requests.delete") as mock_request:
            mock_request.return_value.ok = False
            mock_request.return_value.status_code = 429
            mock_request.return_value.json.return_value = {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            }
            mock_request.return_value.headers = {
                API_RATE_LIMIT_RETRY_AFTER_HEADER: "10"
            }
            with self.assertRaises(RateLimitException) as cm:
                auth.http_client.delete("http://test.com")
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, "E130429")
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(
                the_exception.error_description, "https://docs.descope.com/rate-limit"
            )
            self.assertEqual(the_exception.error_message, "API rate limit exceeded.")
            self.assertEqual(
                the_exception.rate_limit_parameters,
                {API_RATE_LIMIT_RETRY_AFTER_HEADER: 10},
            )

        # Test do_delete with params and pswd
        with patch("requests.delete") as mock_delete:
            network_resp = mock.Mock()
            network_resp.ok = True

            mock_delete.return_value = network_resp
            auth.http_client.delete("/a/b", params={"key": "value"}, pswd="pswd")

            mock_delete.assert_called_with(
                "http://127.0.0.1/a/b",
                params={"key": "value"},
                json=None,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{'pswd'}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test _fetch_public_keys rate limit
        with patch("requests.get") as mock_request:
            mock_request.return_value.ok = False
            mock_request.return_value.status_code = 429
            mock_request.return_value.json.return_value = {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            }
            mock_request.return_value.headers = {
                API_RATE_LIMIT_RETRY_AFTER_HEADER: "10"
            }
            with self.assertRaises(RateLimitException) as cm:
                auth._fetch_public_keys()
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, "E130429")
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(
                the_exception.error_description, "https://docs.descope.com/rate-limit"
            )
            self.assertEqual(the_exception.error_message, "API rate limit exceeded.")
            self.assertEqual(
                the_exception.rate_limit_parameters,
                {API_RATE_LIMIT_RETRY_AFTER_HEADER: 10},
            )

    def test_api_rate_limit_invalid_header(self):
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

        # Test do_post empty body
        with patch("requests.post") as mock_request:
            mock_request.return_value.ok = False
            mock_request.return_value.status_code = 429
            mock_request.return_value.json.return_value = {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            }
            mock_request.return_value.headers = {
                API_RATE_LIMIT_RETRY_AFTER_HEADER: "hello"
            }
            with self.assertRaises(RateLimitException) as cm:
                auth.http_client.post(
                    "http://test.com", body={}, params=None, pswd=None
                )
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, "E130429")
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(
                the_exception.error_description, "https://docs.descope.com/rate-limit"
            )
            self.assertEqual(the_exception.error_message, "API rate limit exceeded.")
            self.assertEqual(
                the_exception.rate_limit_parameters,
                {API_RATE_LIMIT_RETRY_AFTER_HEADER: 0},
            )

    def test_api_rate_limit_invalid_response_body(self):
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

        # Test do_post empty body
        with patch("requests.post") as mock_request:
            mock_request.return_value.ok = False
            mock_request.return_value.status_code = 429
            mock_request.return_value.json.return_value = "aaa"
            with self.assertRaises(RateLimitException) as cm:
                auth.http_client.post(
                    "http://test.com", body={}, params=None, pswd=None
                )
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, HTTPStatus.TOO_MANY_REQUESTS)
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_description, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_message, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.rate_limit_parameters, {})

    def test_api_rate_limit_empty_response_body(self):
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

        # Test do_post empty body
        with patch("requests.post") as mock_request:
            mock_request.return_value.ok = False
            mock_request.return_value.status_code = 429
            mock_request.return_value.json.return_value = ""
            with self.assertRaises(RateLimitException) as cm:
                auth.http_client.post(
                    "http://test.com", body={}, params=None, pswd=None
                )
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, HTTPStatus.TOO_MANY_REQUESTS)
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_description, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_message, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.rate_limit_parameters, {})

    def test_api_rate_limit_none_response_body(self):
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

        # Test do_post empty body
        with patch("requests.post") as mock_request:
            mock_request.return_value.ok = False
            mock_request.return_value.status_code = 429
            mock_request.return_value.json.return_value = None
            with self.assertRaises(RateLimitException) as cm:
                auth.http_client.post(
                    "http://test.com", body={}, params=None, pswd=None
                )
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, HTTPStatus.TOO_MANY_REQUESTS)
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_description, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_message, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.rate_limit_parameters, {})

    def test_raise_from_response(self):
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )
        with patch("requests.get") as mock_request:
            mock_request.return_value.ok = False
            mock_request.return_value.status_code = 400
            mock_request.return_value.error_type = ERROR_TYPE_SERVER_ERROR
            mock_request.return_value.text = """{"errorCode":"E062108","errorDescription":"User not found","errorMessage":"Cannot find user"}"""
            with self.assertRaises(AuthException) as cm:
                auth.http_client.get(
                    uri="http://test.com", params=False, allow_redirects=True
                )
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, 400)
            self.assertEqual(the_exception.error_type, ERROR_TYPE_SERVER_ERROR)
            self.assertEqual(
                the_exception.error_message,
                """{"errorCode":"E062108","errorDescription":"User not found","errorMessage":"Cannot find user"}""",
            )

    def test_validate_session_audience_auto_detection(self):
        """Test that validate_session automatically detects audience when token audience matches project ID"""
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

        with patch("jwt.get_unverified_header") as mock_get_header, patch(
            "jwt.decode"
        ) as mock_decode:
            mock_get_header.return_value = {
                "alg": "ES384",
                "kid": self.public_key_dict["kid"],
            }
            mock_decode.side_effect = [
                {"aud": self.dummy_project_id, "sub": "user123", "exp": 9999999999},
                {"aud": self.dummy_project_id, "sub": "user123", "exp": 9999999999},
            ]

            with patch.object(
                auth,
                "public_keys",
                {self.public_key_dict["kid"]: (mock.Mock(), "ES384")},
            ):
                with patch.object(auth, "_fetch_public_keys"):
                    auth.validate_session("dummy_token")

                    self.assertEqual(mock_decode.call_count, 2)
                    first_call = mock_decode.call_args_list[0]
                    self.assertIn("options", first_call.kwargs)
                    self.assertIn("verify_aud", first_call.kwargs["options"])
                    self.assertFalse(first_call.kwargs["options"]["verify_aud"])
                    second_call = mock_decode.call_args_list[1]
                    self.assertEqual(
                        second_call.kwargs["audience"], self.dummy_project_id
                    )

    def test_validate_session_audience_auto_detection_list(self):
        """Test that validate_session automatically detects audience when token audience is a list containing project ID"""
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

        with patch("jwt.get_unverified_header") as mock_get_header, patch(
            "jwt.decode"
        ) as mock_decode:
            mock_get_header.return_value = {
                "alg": "ES384",
                "kid": self.public_key_dict["kid"],
            }
            mock_decode.side_effect = [
                {
                    "aud": [self.dummy_project_id, "other-audience"],
                    "sub": "user123",
                    "exp": 9999999999,
                },
                {
                    "aud": [self.dummy_project_id, "other-audience"],
                    "sub": "user123",
                    "exp": 9999999999,
                },
            ]

            with patch.object(
                auth,
                "public_keys",
                {self.public_key_dict["kid"]: (mock.Mock(), "ES384")},
            ):
                with patch.object(auth, "_fetch_public_keys"):
                    auth.validate_session("dummy_token")

                    self.assertEqual(mock_decode.call_count, 2)
                    second_call = mock_decode.call_args_list[1]
                    self.assertEqual(
                        second_call.kwargs["audience"], self.dummy_project_id
                    )

    def test_validate_session_audience_auto_detection_no_match(self):
        """Test that validate_session does not auto-detect audience when token audience doesn't match project ID"""
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

        with patch("jwt.get_unverified_header") as mock_get_header, patch(
            "jwt.decode"
        ) as mock_decode:
            mock_get_header.return_value = {
                "alg": "ES384",
                "kid": self.public_key_dict["kid"],
            }
            mock_decode.side_effect = [
                {"aud": "different-project-id", "sub": "user123", "exp": 9999999999},
                {"aud": "different-project-id", "sub": "user123", "exp": 9999999999},
            ]

            with patch.object(
                auth,
                "public_keys",
                {self.public_key_dict["kid"]: (mock.Mock(), "ES384")},
            ):
                with patch.object(auth, "_fetch_public_keys"):
                    auth.validate_session("dummy_token")

                    self.assertEqual(mock_decode.call_count, 2)
                    second_call = mock_decode.call_args_list[1]
                    self.assertIsNone(second_call.kwargs["audience"])

    def test_validate_session_explicit_audience(self):
        """Test that validate_session uses explicit audience parameter instead of auto-detection"""
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )
        explicit_audience = "explicit-audience"

        with patch("jwt.get_unverified_header") as mock_get_header, patch(
            "jwt.decode"
        ) as mock_decode:
            mock_get_header.return_value = {
                "alg": "ES384",
                "kid": self.public_key_dict["kid"],
            }
            mock_decode.return_value = {
                "aud": explicit_audience,
                "sub": "user123",
                "exp": 9999999999,
            }

            with patch.object(
                auth,
                "public_keys",
                {self.public_key_dict["kid"]: (mock.Mock(), "ES384")},
            ):
                with patch.object(auth, "_fetch_public_keys"):
                    auth.validate_session("dummy_token", audience=explicit_audience)

                    self.assertEqual(mock_decode.call_count, 1)
                    call_args = mock_decode.call_args
                    self.assertEqual(call_args.kwargs["audience"], explicit_audience)

    def test_validate_and_refresh_session_audience_auto_detection(self):
        """Test that validate_and_refresh_session automatically detects audience when token audience matches project ID"""
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

        with patch("jwt.get_unverified_header") as mock_get_header, patch(
            "jwt.decode"
        ) as mock_decode:
            mock_get_header.return_value = {
                "alg": "ES384",
                "kid": self.public_key_dict["kid"],
            }
            mock_decode.side_effect = [
                {"aud": self.dummy_project_id, "sub": "user123", "exp": 9999999999},
                {"aud": self.dummy_project_id, "sub": "user123", "exp": 9999999999},
            ]

            with patch.object(
                auth,
                "public_keys",
                {self.public_key_dict["kid"]: (mock.Mock(), "ES384")},
            ):
                with patch.object(auth, "_fetch_public_keys"):
                    with patch("requests.post") as mock_post:
                        mock_post.return_value.ok = True
                        mock_post.return_value.json.return_value = {
                            "sessionJwt": "new_token"
                        }
                        mock_post.return_value.cookies = {}

                        auth.validate_and_refresh_session(
                            "dummy_session_token", "dummy_refresh_token"
                        )

                        self.assertEqual(mock_decode.call_count, 2)
                        first_call = mock_decode.call_args_list[0]
                        self.assertIn("options", first_call.kwargs)
                        self.assertIn("verify_aud", first_call.kwargs["options"])
                        self.assertFalse(first_call.kwargs["options"]["verify_aud"])
                        second_call = mock_decode.call_args_list[1]
                        self.assertEqual(
                            second_call.kwargs["audience"], self.dummy_project_id
                        )

    def test_validate_session_audience_mismatch_fails(self):
        """Test that validate_session fails when token audience doesn't match project ID and no explicit audience is provided"""
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

        with patch("jwt.get_unverified_header") as mock_get_header, patch(
            "jwt.decode"
        ) as mock_decode:
            mock_get_header.return_value = {
                "alg": "ES384",
                "kid": self.public_key_dict["kid"],
            }
            # First call succeeds (for audience detection), second call fails (for validation with None audience)
            mock_decode.side_effect = [
                {
                    "aud": "different-project-id",
                    "sub": "user123",
                    "exp": 9999999999,
                },  # First call for audience detection
                jwt.InvalidAudienceError(
                    "Invalid audience"
                ),  # Second call fails because audience doesn't match
            ]

            with patch.object(
                auth,
                "public_keys",
                {self.public_key_dict["kid"]: (mock.Mock(), "ES384")},
            ):
                with patch.object(auth, "_fetch_public_keys"):
                    with self.assertRaises(jwt.InvalidAudienceError) as cm:
                        auth.validate_session("dummy_token")

                    # Verify the error is about invalid audience
                    self.assertIn("Invalid audience", str(cm.exception))
                    self.assertEqual(mock_decode.call_count, 2)

    def test_http_client_authorization_header_variants(self):
        # Base client without management key
        client = self.make_http_client()
        headers = client.get_default_headers()
        self.assertEqual(headers["Authorization"], f"Bearer {self.dummy_project_id}")

        # With password/pswd only
        headers = client.get_default_headers(pswd="sekret")
        self.assertEqual(
            headers["Authorization"], f"Bearer {self.dummy_project_id}:sekret"
        )

        # With management key only
        client2 = self.make_http_client(management_key="mkey")
        headers2 = client2.get_default_headers()
        self.assertEqual(
            headers2["Authorization"], f"Bearer {self.dummy_project_id}:mkey"
        )

        # With both pswd and management key
        headers3 = client2.get_default_headers(pswd="sekret")
        self.assertEqual(
            headers3["Authorization"],
            f"Bearer {self.dummy_project_id}:sekret:mkey",
        )

    def test_compose_url_success(self):
        base = "/otp/send"
        self.assertEqual(Auth.compose_url(base, DeliveryMethod.EMAIL), f"{base}/email")
        self.assertEqual(Auth.compose_url(base, DeliveryMethod.SMS), f"{base}/sms")
        self.assertEqual(Auth.compose_url(base, DeliveryMethod.VOICE), f"{base}/voice")
        self.assertEqual(
            Auth.compose_url(base, DeliveryMethod.WHATSAPP), f"{base}/whatsapp"
        )

    def test_internal_rate_limit_helpers(self):
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )

        class Resp:
            def __init__(self, ok, status_code, body, headers):
                self.ok = ok
                self.status_code = status_code
                self._body = body
                self.headers = headers
                self.text = "txt"

            def json(self):
                return self._body

        # _parse_retry_after
        self.assertEqual(
            auth._parse_retry_after({API_RATE_LIMIT_RETRY_AFTER_HEADER: "7"}), 7
        )
        self.assertEqual(
            auth._parse_retry_after({API_RATE_LIMIT_RETRY_AFTER_HEADER: "x"}), 0
        )

        # _raise_rate_limit_exception with valid JSON
        r1 = Resp(
            ok=False,
            status_code=429,
            body={
                "errorCode": "E130429",
                "errorDescription": "https://docs",
                "errorMessage": "rate",
            },
            headers={API_RATE_LIMIT_RETRY_AFTER_HEADER: "3"},
        )
        with self.assertRaises(RateLimitException) as cm:
            auth._raise_rate_limit_exception(r1)
        ex = cm.exception
        self.assertEqual(ex.status_code, "E130429")
        self.assertEqual(ex.error_type, ERROR_TYPE_API_RATE_LIMIT)
        self.assertEqual(ex.error_description, "https://docs")
        self.assertEqual(ex.error_message, "rate")
        self.assertEqual(
            ex.rate_limit_parameters, {API_RATE_LIMIT_RETRY_AFTER_HEADER: 3}
        )

        # _raise_rate_limit_exception with invalid JSON
        r2 = Resp(False, 429, "not-a-dict", {API_RATE_LIMIT_RETRY_AFTER_HEADER: "x"})
        with self.assertRaises(RateLimitException) as cm2:
            auth._raise_rate_limit_exception(r2)
        ex2 = cm2.exception
        self.assertEqual(ex2.status_code, HTTPStatus.TOO_MANY_REQUESTS)
        self.assertEqual(ex2.error_type, ERROR_TYPE_API_RATE_LIMIT)
        self.assertEqual(ex2.error_description, ERROR_TYPE_API_RATE_LIMIT)
        self.assertEqual(ex2.error_message, ERROR_TYPE_API_RATE_LIMIT)

        # _raise_from_response with non-429
        r3 = Resp(False, 400, {}, {})
        with self.assertRaises(AuthException):
            auth._raise_from_response(r3)

        # _raise_from_response with 429 invokes rate-limit handler
        r4 = Resp(
            False,
            429,
            {"errorCode": "E130", "errorDescription": "d", "errorMessage": "m"},
            {API_RATE_LIMIT_RETRY_AFTER_HEADER: "2"},
        )
        with self.assertRaises(RateLimitException):
            auth._raise_from_response(r4)

    def test_validate_and_refresh_session_refresh_path(self):
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            http_client=self.make_http_client(),
        )
        # Force validate_session to fail
        with patch.object(
            Auth,
            "validate_session",
            side_effect=AuthException(400, ERROR_TYPE_SERVER_ERROR, "e"),
        ):
            # Stub refresh network
            with patch("requests.post") as mock_post:
                net_resp = mock.Mock()
                net_resp.ok = True
                net_resp.cookies = {"DSR": "cookie"}
                auth._validate_token = lambda token, audience=None: {
                    "iss": "P1",
                    "sub": "u1",
                }
                net_resp.json.return_value = {"sessionJwt": "s", "refreshJwt": "r"}
                mock_post.return_value = net_resp
                out = auth.validate_and_refresh_session("bad", refresh_token="r0")
                self.assertEqual(out["projectId"], "P1")

    def test_validate_token_public_key_not_found(self):
        auth = Auth(
            self.dummy_project_id,
            None,
            http_client=self.make_http_client(),
        )
        # ensure public keys empty and fetching sets nothing
        auth.public_keys = {}
        with patch.object(
            Auth,
            "_fetch_public_keys",
            side_effect=lambda self=auth: setattr(auth, "public_keys", {}),
        ):
            with patch("descope.auth.jwt.get_unverified_header") as mock_hdr:
                mock_hdr.return_value = {"alg": "ES384", "kid": "unknown"}
                with self.assertRaises(AuthException) as cm:
                    auth._validate_token("any")
                self.assertIn("public key not found", str(cm.exception).lower())

    def test_validate_token_decode_time_errors(self):
        auth = Auth(
            self.dummy_project_id,
            None,
            http_client=self.make_http_client(),
        )
        # Prepare a fake key entry and matching header
        auth.public_keys = {"kid": (SimpleNamespace(key="k"), "ES384")}
        with patch("descope.auth.jwt.get_unverified_header") as mock_hdr, patch(
            "descope.auth.jwt.decode"
        ) as mock_dec:
            mock_hdr.return_value = {"alg": "ES384", "kid": "kid"}
            from jwt import ImmatureSignatureError

            mock_dec.side_effect = ImmatureSignatureError("early")
            with self.assertRaises(AuthException) as cm:
                auth._validate_token("tok")
            self.assertEqual(cm.exception.status_code, 400)

    def test_validate_token_success(self):
        auth = Auth(
            self.dummy_project_id,
            None,
            http_client=self.make_http_client(),
        )
        auth.public_keys = {"kid": (SimpleNamespace(key="k"), "ES384")}
        with patch("descope.auth.jwt.get_unverified_header") as mock_hdr, patch(
            "descope.auth.jwt.decode"
        ) as mock_dec:
            mock_hdr.return_value = {"alg": "ES384", "kid": "kid"}
            mock_dec.return_value = {"sub": "u"}
            out = auth._validate_token("tok")
            self.assertEqual(out["jwt"], "tok")


if __name__ == "__main__":
    unittest.main()
