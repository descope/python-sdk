import asyncio
import json
import os
import unittest
from enum import Enum
from http import HTTPStatus
from unittest import mock
from unittest.mock import patch

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
from .async_test_base import (
    parameterized_sync_async_subcase,
    HTTPMockHelper,
    MethodTestHelper,
)


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

    @parameterized_sync_async_subcase("_fetch_public_keys", "_fetch_public_keys_async")
    def test_fetch_public_key(self, method_name, is_async):
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
        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=False
        ) as mock_get:
            self.assertRaises(
                AuthException, MethodTestHelper.call_method, auth, method_name
            )

        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=True, text="invalid json"
        ) as mock_get:
            self.assertRaises(
                AuthException, MethodTestHelper.call_method, auth, method_name
            )

        # test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=True, text=valid_keys_response
        ) as mock_get:
            self.assertIsNone(MethodTestHelper.call_method(auth, method_name))

    def test_project_id_from_env(self):
        os.environ["DESCOPE_PROJECT_ID"] = self.dummy_project_id
        Auth()

    def test_project_id_from_env_without_env(self):
        os.environ["DESCOPE_PROJECT_ID"] = ""
        self.assertRaises(AuthException, Auth)

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

    def test_get_method_string(self):
        self.assertEqual(
            Auth.get_method_string(DeliveryMethod.EMAIL),
            "email",
        )
        self.assertEqual(
            Auth.get_method_string(DeliveryMethod.SMS),
            "sms",
        )
        self.assertEqual(
            Auth.get_method_string(DeliveryMethod.VOICE),
            "voice",
        )
        self.assertEqual(
            Auth.get_method_string(DeliveryMethod.WHATSAPP),
            "whatsapp",
        )
        self.assertEqual(
            Auth.get_method_string(DeliveryMethod.EMBEDDED),
            "Embedded",
        )

        class AAA(Enum):
            DUMMY = 4

        self.assertRaises(AuthException, Auth.get_method_string, AAA.DUMMY)

    @parameterized_sync_async_subcase("refresh_session", "refresh_session_async")
    def test_refresh_session(self, method_name, is_async):
        dummy_refresh_token = "dummy refresh token"
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test fail flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_request:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                auth,
                method_name,
                dummy_refresh_token,
            )

    @parameterized_sync_async_subcase("validate_session", "validate_session_async")
    def test_validate_session_and_refresh_input(self, method_name, is_async):
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Bad input for session - this should test validate_and_refresh_session
        with self.assertRaises(AuthException):
            MethodTestHelper.call_method(
                auth,
                "validate_and_refresh_session" + ("_async" if is_async else ""),
                None,
                None,
            )

        # Test validate_session with Ratelimit exception
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="get",
            ok=False,
            status_code=429,
            json=lambda: {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            },
            headers={API_RATE_LIMIT_RETRY_AFTER_HEADER: "10"},
        ) as mock_request:
            ds = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg5NzI4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoxNjU3Nzk4MzI4LCJpYXQiOjE2NTc3OTc3MjgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJCdEVIa2dPdTAybG1NeHpQSWV4ZE10VXcxTSJ9.i-JoPoYmXl3jeLTARvYnInBiRdTT4uHZ3X3xu_n1dhUb1Qy_gqK7Ru8ErYXeENdfPOe4mjShc_HsVyb5PjE2LMFmb58WR8wixtn0R-u_MqTpuI_422Dk6hMRjTFEVRWu"
            with self.assertRaises(RateLimitException) as cm:
                MethodTestHelper.call_method(auth, method_name, ds)
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

    @parameterized_sync_async_subcase("refresh_session", "refresh_session_async")
    def test_refresh_session_and_refresh_input(self, method_name, is_async):
        auth = Auth(self.dummy_project_id, self.public_key_dict)
        # Test refresh_session with Ratelimit exception
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="get",
            ok=False,
            status_code=429,
            json=lambda: {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            },
            headers={API_RATE_LIMIT_RETRY_AFTER_HEADER: "10"},
        ):
            dsr = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg5NzI4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoxNjU3Nzk4MzI4LCJpYXQiOjE2NTc3OTc3MjgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJCdEVIa2dPdTAybG1NeHpQSWV4ZE10VXcxTSJ9.i-JoPoYmXl3jeLTARvYnInBiRdTT4uHZ3X3xu_n1dhUb1Qy_gqK7Ru8ErYXeENdfPOe4mjShc_HsVyb5PjE2LMFmb58WR8wixtn0R-u_MqTpuI_422Dk6hMRjTFEVRWu"
            with self.assertRaises(RateLimitException) as cm:
                MethodTestHelper.call_method(auth, method_name, dsr)
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

    @parameterized_sync_async_subcase(
        "exchange_access_key", "exchange_access_key_async"
    )
    def test_exchange_access_key(self, method_name, is_async):
        dummy_access_key = "dummy access key"
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test fail flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_request:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                auth,
                method_name,
                dummy_access_key,
            )

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL"
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"sessionJwt": valid_jwt_token},
        ) as mock_post:
            jwt_response = MethodTestHelper.call_method(
                auth,
                method_name,
                access_key=dummy_access_key,
                login_options=AccessKeyLoginOptions(custom_claims={"k1": "v1"}),
            )
            self.assertEqual(jwt_response["keyId"], "U2Cu0j0WPw3YOiPISJb52L0wUVMg")
            self.assertEqual(jwt_response["projectId"], "P2CtzUhdqpIF2ys9gg7ms06UvtC4")

            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.exchange_auth_access_key_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:dummy access key",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"loginOptions": {"customClaims": {"k1": "v1"}}},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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

    @parameterized_sync_async_subcase("do_post", "do_post_async")
    def test_api_rate_limit_exception_post(self, method_name, is_async):
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test do_post
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=False,
            status_code=429,
            json=lambda: {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            },
            headers={API_RATE_LIMIT_RETRY_AFTER_HEADER: "10"},
        ) as mock_request:
            with self.assertRaises(RateLimitException) as cm:
                MethodTestHelper.call_method(
                    auth, method_name, "http://test.com", {}, None, None
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

    @parameterized_sync_async_subcase("do_get", "do_get_async")
    def test_api_rate_limit_exception_get(self, method_name, is_async):
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test do_get
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="get",
            ok=False,
            status_code=429,
            json=lambda: {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            },
            headers={API_RATE_LIMIT_RETRY_AFTER_HEADER: "10"},
        ) as mock_request:
            with self.assertRaises(RateLimitException) as cm:
                MethodTestHelper.call_method(
                    auth,
                    method_name,
                    uri="http://test.com",
                    params=False,
                    follow_redirects=None,
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

    @parameterized_sync_async_subcase("do_delete", "do_delete_async")
    def test_api_rate_limit_exception_delete(self, method_name, is_async):
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test do_delete
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="delete",
            ok=False,
            status_code=429,
            json=lambda: {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            },
            headers={API_RATE_LIMIT_RETRY_AFTER_HEADER: "10"},
        ) as mock_request:
            with self.assertRaises(RateLimitException) as cm:
                MethodTestHelper.call_method(auth, method_name, "http://test.com")
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

    @parameterized_sync_async_subcase("do_delete", "do_delete_async")
    def test_api_rate_limit_exception_delete_with_params(self, method_name, is_async):
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test do_delete with params and pswd
        with HTTPMockHelper.mock_http_call(
            is_async, method="delete", ok=True
        ) as mock_delete:
            MethodTestHelper.call_method(
                auth,
                method_name,
                "/a/b",
                params={"key": "value"},
                pswd="pswd",
            )

            HTTPMockHelper.assert_http_call(
                mock_delete,
                is_async,
                "http://127.0.0.1/a/b",
                params={"key": "value"},
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{'pswd'}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("_fetch_public_keys", "_fetch_public_keys_async")
    def test_fetch_public_keys_rate_limit(self, method_name, is_async):
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test _fetch_public_keys rate limit
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="get",
            ok=False,
            status_code=429,
            json=lambda: {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            },
            headers={API_RATE_LIMIT_RETRY_AFTER_HEADER: "10"},
        ) as mock_request:
            with self.assertRaises(RateLimitException) as cm:
                MethodTestHelper.call_method(auth, method_name)
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

    @parameterized_sync_async_subcase("do_post", "do_post_async")
    def test_api_rate_limit_invalid_header(self, method_name, is_async):
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test do_post empty body
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=False,
            status_code=429,
            json=lambda: {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            },
            headers={API_RATE_LIMIT_RETRY_AFTER_HEADER: "hello"},
        ) as mock_request:
            with self.assertRaises(RateLimitException) as cm:
                MethodTestHelper.call_method(
                    auth, method_name, "http://test.com", {}, None, None
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

    @parameterized_sync_async_subcase("do_post", "do_post_async")
    def test_api_rate_limit_invalid_response_body(self, method_name, is_async):
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test do_post empty body
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False, status_code=429, json=lambda: "aaa"
        ) as mock_request:
            with self.assertRaises(RateLimitException) as cm:
                MethodTestHelper.call_method(
                    auth, method_name, "http://test.com", {}, None, None
                )
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, HTTPStatus.TOO_MANY_REQUESTS)
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_description, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_message, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.rate_limit_parameters, {})

    @parameterized_sync_async_subcase("do_post", "do_post_async")
    def test_api_rate_limit_empty_response_body(self, method_name, is_async):
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test do_post empty body
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False, status_code=429, json=lambda: ""
        ) as mock_request:
            with self.assertRaises(RateLimitException) as cm:
                MethodTestHelper.call_method(
                    auth, method_name, "http://test.com", {}, None, None
                )
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, HTTPStatus.TOO_MANY_REQUESTS)
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_description, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_message, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.rate_limit_parameters, {})

    @parameterized_sync_async_subcase("do_post", "do_post_async")
    def test_api_rate_limit_none_response_body(self, method_name, is_async):
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test do_post empty body
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False, status_code=429, json=lambda: None
        ) as mock_request:
            with self.assertRaises(RateLimitException) as cm:
                MethodTestHelper.call_method(
                    auth, method_name, "http://test.com", {}, None, None
                )
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, HTTPStatus.TOO_MANY_REQUESTS)
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_description, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_message, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.rate_limit_parameters, {})

    @parameterized_sync_async_subcase("do_get", "do_get_async")
    def test_raise_from_response(self, method_name, is_async):
        auth = Auth(self.dummy_project_id, self.public_key_dict)
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="get",
            ok=False,
            status_code=400,
            error_type=ERROR_TYPE_SERVER_ERROR,
            text="""{"errorCode":"E062108","errorDescription":"User not found","errorMessage":"Cannot find user"}""",
        ) as mock_request:
            with self.assertRaises(AuthException) as cm:
                MethodTestHelper.call_method(
                    auth,
                    method_name,
                    uri="http://test.com",
                    params=False,
                    follow_redirects=None,
                )
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, 400)
            self.assertEqual(the_exception.error_type, ERROR_TYPE_SERVER_ERROR)
            self.assertEqual(
                the_exception.error_message,
                """{"errorCode":"E062108","errorDescription":"User not found","errorMessage":"Cannot find user"}""",
            )

    @parameterized_sync_async_subcase("do_patch", "do_patch_async")
    def test_do_patch_method(self, method_name, is_async):
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test do_patch method with successful response
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="patch",
            ok=True,
            status_code=200,
            json=lambda: {"success": True},
        ) as mock_patch:
            result = MethodTestHelper.call_method(
                auth,
                method_name,
                "http://test.com",
                {"data": "test"},
                None,
                None,
            )
            self.assertIsNotNone(result)

        # Test do_patch method with rate limit exception
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="patch",
            ok=False,
            status_code=429,
            json=lambda: {
                "errorCode": "E130429",
                "errorDescription": "https://docs.descope.com/rate-limit",
                "errorMessage": "API rate limit exceeded.",
            },
            headers={API_RATE_LIMIT_RETRY_AFTER_HEADER: "10"},
        ) as mock_patch:
            with self.assertRaises(RateLimitException) as cm:
                MethodTestHelper.call_method(
                    auth,
                    method_name,
                    "http://test.com",
                    {"data": "test"},
                    None,
                    None,
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

    def test_async_context_manager_lifecycle(self):
        """Test that async context manager properly manages client lifecycle"""
        auth = Auth(self.dummy_project_id, self.public_key_str)

        async def _test():
            # Initially no async client
            self.assertIsNone(auth._async_client)

            # Test __aenter__
            enter_result = await auth.__aenter__()
            self.assertEqual(enter_result, auth)  # Should return self
            self.assertIsNotNone(auth._async_client)  # Client should be created

            # Test __aexit__
            await auth.__aexit__(None, None, None)
            self.assertIsNone(auth._async_client)  # Client should be cleaned up

        asyncio.run(_test())

    def test_async_context_manager_with_statement(self):
        """Test async context manager using 'async with' statement"""
        auth = Auth(self.dummy_project_id, self.public_key_str)

        async def _test():
            self.assertIsNone(auth._async_client)

            async with auth as auth_ctx:
                # Inside context: client should be created
                self.assertIsNotNone(auth._async_client)
                self.assertEqual(auth_ctx, auth)

            # After context: client should be cleaned up
            self.assertIsNone(auth._async_client)

        asyncio.run(_test())

    def test_async_context_manager_exception_handling(self):
        """Test async context manager properly cleans up on exception"""
        auth = Auth(self.dummy_project_id, self.public_key_str)

        async def _test():
            try:
                async with auth:
                    # Inside context: client should be created
                    self.assertIsNotNone(auth._async_client)
                    raise ValueError("Test exception")
            except ValueError:
                pass  # Expected exception

            # After exception: client should still be cleaned up
            self.assertIsNone(auth._async_client)

        asyncio.run(_test())

    def test_async_context_manager_multiple_entries(self):
        """Test async context manager can be used multiple times"""
        auth = Auth(self.dummy_project_id, self.public_key_str)

        async def _test():
            # First use
            async with auth:
                self.assertIsNotNone(auth._async_client)

            self.assertIsNone(auth._async_client)

            # Second use
            async with auth:
                self.assertIsNotNone(auth._async_client)

            self.assertIsNone(auth._async_client)

        asyncio.run(_test())

    @patch("httpx.AsyncClient")
    def test_async_context_manager_client_creation(self, mock_async_client):
        """Test that async context manager creates client with correct parameters"""
        auth = Auth(self.dummy_project_id, self.public_key_str)
        mock_client_instance = mock.AsyncMock()
        mock_async_client.return_value = mock_client_instance

        async def _test():
            async with auth:
                # Verify client was created with correct parameters
                mock_async_client.assert_called_once_with(
                    verify=auth.secure, timeout=auth.timeout_seconds
                )

                # Verify client is set
                self.assertEqual(auth._async_client, mock_client_instance)

            # Verify cleanup was called
            mock_client_instance.aclose.assert_called_once()

        asyncio.run(_test())

    @patch("httpx.AsyncClient")
    def test_async_context_manager_cleanup_on_none_client(self, mock_async_client):
        """Test async context manager handles None client gracefully"""
        auth = Auth(self.dummy_project_id, self.public_key_str)
        mock_client_instance = mock.AsyncMock()
        mock_async_client.return_value = mock_client_instance

        async def _test():
            # Manually set client to None before exit
            await auth.__aenter__()
            auth._async_client = None

            # Should not raise exception
            await auth.__aexit__(None, None, None)

        asyncio.run(_test())


if __name__ == "__main__":
    unittest.main()
