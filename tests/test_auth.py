import json
import os
import unittest
from enum import Enum
from http import HTTPStatus
from unittest import mock
from unittest.mock import patch
import certifi

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
from descope.future_utils import futu_await
from tests.testutils import SSLMatcher, mock_http_call

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

    async def test_validate_phone(self):
        with self.assertRaises(AuthException):
            await futu_await(Auth.validate_phone(method=DeliveryMethod.SMS, phone=""))

        with self.assertRaises(AuthException):

            await futu_await(
                Auth.validate_phone(
                    method=DeliveryMethod.SMS,
                    phone="asd234234234",
                )
            )

        with self.assertRaises(AuthException):

            await futu_await(
                Auth.validate_phone(
                    method=DeliveryMethod.EMAIL,
                    phone="+1111111",
                )
            )

        self.assertIsNone(
            Auth.validate_phone(method=DeliveryMethod.WHATSAPP, phone="+1111111")
        )

    async def test_validate_email(self):
        with self.assertRaises(AuthException):
            await futu_await(Auth.validate_email(email=""))

        with self.assertRaises(AuthException):
            await futu_await(Auth.validate_email(email="@dummy.com"))

        self.assertIsNone(Auth.validate_email(email="dummy@dummy.com"))

    async def test_validate_and_load_public_key(self):
        # test invalid json
        with self.assertRaises(AuthException):
            await futu_await(
                Auth._validate_and_load_public_key(
                    public_key="invalid json",
                )
            )
        # test public key without kid property
        with self.assertRaises(AuthException):
            await futu_await(
                Auth._validate_and_load_public_key(
                    public_key={"test": "dummy"},
                )
            )

        # test not dict object
        with self.assertRaises(AuthException):
            await futu_await(Auth._validate_and_load_public_key(public_key=555))
        # test invalid dict
        with self.assertRaises(AuthException):
            await futu_await(
                Auth._validate_and_load_public_key(
                    public_key={"kid": "dummy"},
                )
            )

    async def test_fetch_public_key(self):
        auth = Auth(
            self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
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
        with mock_http_call(
            False, "get"
        ) as mock_get:  # Always use sync mocking for _fetch_public_keys
            mock_get.return_value.is_success = False
            with self.assertRaises(AuthException):
                auth._fetch_public_keys_sync()

        with mock_http_call(
            False, "get"
        ) as mock_get:  # Always use sync mocking for _fetch_public_keys
            mock_get.return_value.is_success = True
            mock_get.return_value.text = "invalid json"
            with self.assertRaises(AuthException):
                auth._fetch_public_keys_sync()

        # test success flow
        with mock_http_call(
            False, "get"
        ) as mock_get:  # Always use sync mocking for _fetch_public_keys
            mock_get.return_value.is_success = True
            mock_get.return_value.text = valid_keys_response
            self.assertIsNone(auth._fetch_public_keys_sync())

    async def test_project_id_from_env(self):
        os.environ["DESCOPE_PROJECT_ID"] = self.dummy_project_id
        Auth()

    async def test_project_id_from_env_without_env(self):
        os.environ["DESCOPE_PROJECT_ID"] = ""
        with self.assertRaises(AuthException):
            await futu_await(Auth())

    async def test_base_url_for_project_id(self):
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

    async def test_verify_delivery_method(self):
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

    async def test_get_login_id_name_by_method(self):
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

        with self.assertRaises(AuthException):
            await futu_await(Auth.get_login_id_by_method(AAA.DUMMY, user))

    async def test_get_method_string(self):
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

        with self.assertRaises(AuthException):
            await futu_await(Auth.get_method_string(AAA.DUMMY))

    async def test_refresh_session(self):
        dummy_refresh_token = "dummy refresh token"
        auth = Auth(
            self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
        )

        # Test fail flow
        with mock_http_call(self.async_test, "post") as mock_request:
            mock_request.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    auth.refresh_session(
                        dummy_refresh_token,
                    )
                )

    async def test_validate_session_and_refresh_input(self):
        auth = Auth(
            self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
        )

        # Bad input for session
        with self.assertRaises(AuthException):
            auth.validate_and_refresh_session(None, None)

        # Test validate_session with Ratelimit exception
        with mock_http_call(
            False, "get"
        ) as mock_request:  # Use sync mocking for _fetch_public_keys
            mock_request.return_value.is_success = False
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
        with mock_http_call(
            False, "get"
        ) as mock_request:  # Use sync mocking for _fetch_public_keys
            mock_request.return_value.is_success = False
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

    async def test_exchange_access_key(self):
        dummy_access_key = "dummy access key"
        auth = Auth(
            self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
        )

        # Test fail flow
        with mock_http_call(self.async_test, "post") as mock_request:
            mock_request.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    auth.exchange_access_key(
                        dummy_access_key,
                    )
                )

        # Test success flow
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3R6VWhkcXBJRjJ5czlnZzdtczA2VXZ0QzQiLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0Mzc1OTYsImlhdCI6MTY1OTYzNzU5NiwiaXNzIjoiUDJDdHpVaGRxcElGMnlzOWdnN21zMDZVdnRDNCIsInN1YiI6IlUyQ3UwajBXUHczWU9pUElTSmI1Mkwwd1VWTWcifQ.WLnlHugvzZtrV9OzBB7SjpCLNRvKF3ImFpVyIN5orkrjO2iyAKg_Rb4XHk9sXGC1aW8puYzLbhE1Jv3kk2hDcKggfE8OaRNRm8byhGFZHnvPJwcP_Ya-aRmfAvCLcKOL"
        with mock_http_call(self.async_test, "post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            data = {"sessionJwt": valid_jwt_token}
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response
            jwt_response = await futu_await(
                auth.exchange_access_key(
                    access_key=dummy_access_key,
                    login_options=AccessKeyLoginOptions(custom_claims={"k1": "v1"}),
                )
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
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_adjust_properties(self):
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

    async def test_api_rate_limit_exception(self):
        auth = Auth(
            self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
        )

        # Test do_post
        with mock_http_call(self.async_test, "post") as mock_request:
            mock_request.return_value.is_success = False
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
                await futu_await(auth.do_post("http://test.com", {}, None, None))
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
        with mock_http_call(self.async_test, "get") as mock_request:
            mock_request.return_value.is_success = False
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
                await futu_await(
                    auth.do_get(
                        uri="http://test.com", params=False, follow_redirects=None
                    )
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
        with mock_http_call(self.async_test, "delete") as mock_request:
            mock_request.return_value.is_success = False
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
                await futu_await(auth.do_delete("http://test.com"))
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
        with mock_http_call(self.async_test, "delete") as mock_delete:
            network_resp = mock.Mock()
            network_resp.is_success = True

            mock_delete.return_value = network_resp
            await futu_await(
                auth.do_delete("/a/b", params={"key": "value"}, pswd="pswd")
            )

            # Verify that do_delete was called
            mock_delete.assert_called_once()

        # _fetch_public_keys is always sync
        with mock_http_call(False, "get") as mock_request:
            mock_request.return_value.is_success = False
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
                auth._fetch_public_keys_sync()
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

    async def test_api_rate_limit_invalid_header(self):
        auth = Auth(
            self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
        )

        # Test do_post empty body
        with mock_http_call(self.async_test, "post") as mock_request:
            mock_request.return_value.is_success = False
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
                await futu_await(auth.do_post("http://test.com", {}, None, None))
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

    async def test_api_rate_limit_invalid_response_body(self):
        auth = Auth(
            self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
        )

        # Test do_post empty body
        with mock_http_call(self.async_test, "post") as mock_request:
            mock_request.return_value.is_success = False
            mock_request.return_value.status_code = 429
            mock_request.return_value.json.return_value = "aaa"
            with self.assertRaises(RateLimitException) as cm:
                await futu_await(auth.do_post("http://test.com", {}, None, None))
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, HTTPStatus.TOO_MANY_REQUESTS)
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_description, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_message, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.rate_limit_parameters, {})

    async def test_api_rate_limit_empty_response_body(self):
        auth = Auth(
            self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
        )

        # Test do_post empty body
        with mock_http_call(self.async_test, "post") as mock_request:
            mock_request.return_value.is_success = False
            mock_request.return_value.status_code = 429
            mock_request.return_value.json.return_value = ""
            with self.assertRaises(RateLimitException) as cm:
                await futu_await(auth.do_post("http://test.com", {}, None, None))
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, HTTPStatus.TOO_MANY_REQUESTS)
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_description, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_message, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.rate_limit_parameters, {})

    async def test_api_rate_limit_none_response_body(self):
        auth = Auth(
            self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
        )

        # Test do_post empty body
        with mock_http_call(self.async_test, "post") as mock_request:
            mock_request.return_value.is_success = False
            mock_request.return_value.status_code = 429
            mock_request.return_value.json.return_value = None
            with self.assertRaises(RateLimitException) as cm:
                await futu_await(auth.do_post("http://test.com", {}, None, None))
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, HTTPStatus.TOO_MANY_REQUESTS)
            self.assertEqual(the_exception.error_type, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_description, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.error_message, ERROR_TYPE_API_RATE_LIMIT)
            self.assertEqual(the_exception.rate_limit_parameters, {})

    async def test_raise_from_response(self):
        auth = Auth(
            self.dummy_project_id, self.public_key_dict, async_mode=self.async_test
        )
        with mock_http_call(self.async_test, "get") as mock_request:
            mock_request.return_value.is_success = False
            mock_request.return_value.status_code = 400
            mock_request.return_value.error_type = ERROR_TYPE_SERVER_ERROR
            mock_request.return_value.text = """{"errorCode":"E062108","errorDescription":"User not found","errorMessage":"Cannot find user"}"""
            with self.assertRaises(AuthException) as cm:
                await futu_await(
                    auth.do_get(
                        uri="http://test.com", params=False, follow_redirects=None
                    )
                )
            the_exception = cm.exception
            self.assertEqual(the_exception.status_code, 400)
            self.assertEqual(the_exception.error_type, ERROR_TYPE_SERVER_ERROR)
            self.assertEqual(
                the_exception.error_message,
                """{"errorCode":"E062108","errorDescription":"User not found","errorMessage":"Cannot find user"}""",
            )

    async def test_ssl_configuration_skip_verify(self):
        """Test SSL configuration when skip_verify=True"""
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            skip_verify=True,
            async_mode=self.async_test,
        )

        # Verify that verify=False is set in http_client_kwargs
        self.assertEqual(auth.http_client_kwargs["verify"], False)
        self.assertEqual(auth.http_client_kwargs["timeout"], DEFAULT_TIMEOUT_SECONDS)

    async def test_ssl_configuration_default_context(self):
        """Test SSL configuration with default SSL context"""
        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            skip_verify=False,
            async_mode=self.async_test,
        )

        # Verify that verify is an SSLContext object using SSLMatcher
        ssl_matcher = SSLMatcher()
        self.assertTrue(ssl_matcher == auth.http_client_kwargs["verify"])
        self.assertEqual(auth.http_client_kwargs["timeout"], DEFAULT_TIMEOUT_SECONDS)

    async def test_ssl_configuration_with_custom_cert_file(self):
        """Test SSL configuration with custom SSL_CERT_FILE environment variable"""
        import ssl
        import certifi

        with patch.dict(os.environ, {"SSL_CERT_FILE": "/custom/cert.pem"}):
            with patch("ssl.create_default_context") as mock_create_context:
                mock_ssl_ctx = mock.Mock()
                mock_create_context.return_value = mock_ssl_ctx

                auth = Auth(
                    self.dummy_project_id,
                    self.public_key_dict,
                    skip_verify=False,
                    async_mode=self.async_test,
                )

                # Verify ssl.create_default_context was called with custom cert file
                mock_create_context.assert_called_once_with(
                    cafile="/custom/cert.pem", capath=None
                )
                self.assertEqual(auth.http_client_kwargs["verify"], mock_ssl_ctx)

    async def test_ssl_configuration_with_custom_cert_dir(self):
        """Test SSL configuration with custom SSL_CERT_DIR environment variable"""
        with patch.dict(os.environ, {"SSL_CERT_DIR": "/custom/certs"}):
            with patch("ssl.create_default_context") as mock_create_context:
                mock_ssl_ctx = mock.Mock()
                mock_create_context.return_value = mock_ssl_ctx

                auth = Auth(
                    self.dummy_project_id,
                    self.public_key_dict,
                    skip_verify=False,
                    async_mode=self.async_test,
                )

                # Verify ssl.create_default_context was called with custom cert dir
                mock_create_context.assert_called_once_with(
                    cafile=certifi.where(), capath="/custom/certs"
                )
                self.assertEqual(auth.http_client_kwargs["verify"], mock_ssl_ctx)

    async def test_ssl_configuration_with_requests_ca_bundle(self):
        """Test SSL configuration with REQUESTS_CA_BUNDLE environment variable"""
        with patch.dict(os.environ, {"REQUESTS_CA_BUNDLE": "/custom/bundle.pem"}):
            with patch("ssl.create_default_context") as mock_create_context:
                mock_ssl_ctx = mock.Mock()
                mock_create_context.return_value = mock_ssl_ctx

                auth = Auth(
                    self.dummy_project_id,
                    self.public_key_dict,
                    skip_verify=False,
                    async_mode=self.async_test,
                )

                # Verify ssl.create_default_context was called
                mock_create_context.assert_called_once()

                # Verify load_cert_chain was called on the SSL context
                mock_ssl_ctx.load_cert_chain.assert_called_once_with(
                    certfile="/custom/bundle.pem"
                )
                self.assertEqual(auth.http_client_kwargs["verify"], mock_ssl_ctx)

    async def test_ssl_configuration_with_all_env_vars(self):
        """Test SSL configuration with all SSL environment variables set"""
        with patch.dict(
            os.environ,
            {
                "SSL_CERT_FILE": "/custom/cert.pem",
                "SSL_CERT_DIR": "/custom/certs",
                "REQUESTS_CA_BUNDLE": "/custom/bundle.pem",
            },
        ):
            with patch("ssl.create_default_context") as mock_create_context:
                mock_ssl_ctx = mock.Mock()
                mock_create_context.return_value = mock_ssl_ctx

                auth = Auth(
                    self.dummy_project_id,
                    self.public_key_dict,
                    skip_verify=False,
                    async_mode=self.async_test,
                )

                # Verify ssl.create_default_context was called with all custom values
                mock_create_context.assert_called_once_with(
                    cafile="/custom/cert.pem", capath="/custom/certs"
                )

                # Verify load_cert_chain was called
                mock_ssl_ctx.load_cert_chain.assert_called_once_with(
                    certfile="/custom/bundle.pem"
                )
                self.assertEqual(auth.http_client_kwargs["verify"], mock_ssl_ctx)

    async def test_ssl_configuration_custom_timeout(self):
        """Test SSL configuration with custom timeout"""
        custom_timeout = 30.0

        auth = Auth(
            self.dummy_project_id,
            self.public_key_dict,
            skip_verify=True,
            timeout_seconds=custom_timeout,
            async_mode=self.async_test,
        )

        # Verify custom timeout is set
        self.assertEqual(auth.http_client_kwargs["timeout"], custom_timeout)
        self.assertEqual(auth.http_client_kwargs["verify"], False)


if __name__ == "__main__":
    unittest.main()
