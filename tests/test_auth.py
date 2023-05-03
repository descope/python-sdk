import json
import unittest
from enum import Enum
from unittest import mock
from unittest.mock import patch

from descope import (
    API_RATE_LIMIT_RETRY_AFTER_HEADER,
    ERROR_TYPE_API_RATE_LIMIT,
    AuthException,
    DeliveryMethod,
    RateLimitException,
)
from descope.auth import Auth
from descope.common import REFRESH_SESSION_TOKEN_NAME, SESSION_TOKEN_NAME

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

    def test_verify_delivery_method(self):
        self.assertEqual(
            Auth.verify_delivery_method(DeliveryMethod.EMAIL, "dummy@dummy.com", None),
            False,
        )

        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.EMAIL, "dummy@dummy.com", {"phone": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.EMAIL, "dummy@dummy.com", {"phone": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.EMAIL, "dummy@dummy.com", {"phone": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.verify_delivery_method(DeliveryMethod.EMAIL, "", {"phone": ""}), False
        )
        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.EMAIL, "dummy@dummy", {"phone": ""}
            ),
            False,
        )

        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.SMS, "111111111111", {"email": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.SMS, "+111111111111", {"email": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.SMS, "++111111111111", {"email": ""}
            ),
            False,
        )
        self.assertEqual(
            Auth.verify_delivery_method(DeliveryMethod.SMS, "asdsad", {"email": ""}),
            False,
        )
        self.assertEqual(
            Auth.verify_delivery_method(DeliveryMethod.SMS, "", {"email": ""}), False
        )
        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.SMS, "unvalid@phone.number", {"email": ""}
            ),
            False,
        )

        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.WHATSAPP, "111111111111", {"email": ""}
            ),
            True,
        )
        self.assertEqual(
            Auth.verify_delivery_method(DeliveryMethod.WHATSAPP, "", {"email": ""}),
            False,
        )
        self.assertEqual(
            Auth.verify_delivery_method(
                DeliveryMethod.WHATSAPP, "unvalid@phone.number", {"email": ""}
            ),
            False,
        )

        class AAA(Enum):
            DUMMY = 4

        self.assertEqual(
            Auth.verify_delivery_method(
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
            "phone",
        )
        self.assertEqual(
            Auth.get_method_string(DeliveryMethod.WHATSAPP),
            "whatsapp",
        )

        class AAA(Enum):
            DUMMY = 4

        self.assertRaises(AuthException, Auth.get_method_string, AAA.DUMMY)

    def test_refresh_session(self):
        dummy_refresh_token = "dummy refresh token"
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Test fail flow
        with patch("requests.post") as mock_request:
            mock_request.return_value.ok = False
            self.assertRaises(
                AuthException,
                auth.refresh_session,
                dummy_refresh_token,
            )

    def test_validate_session_and_refresh_input(self):
        auth = Auth(self.dummy_project_id, self.public_key_dict)

        # Bad input for session
        self.assertRaises(
            AuthException,
            auth.validate_and_refresh_session,
        )

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
        auth = Auth(self.dummy_project_id, self.public_key_dict)

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
            jwt_response = auth.exchange_access_key(dummy_access_key)
            self.assertEqual(jwt_response["keyId"], "U2Cu0j0WPw3YOiPISJb52L0wUVMg")
            self.assertEqual(jwt_response["projectId"], "P2CtzUhdqpIF2ys9gg7ms06UvtC4")

    def test_adjust_properties(self):
        self.assertEqual(
            Auth.adjust_properties(self, jwt_response={}, user_jwt={}),
            {"keyId": None, "projectId": ""},
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
        auth = Auth(self.dummy_project_id, self.public_key_dict)

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
                auth.do_post("http://test.com", {}, None, None)
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
                auth.do_get("http://test.com", False, None)
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


if __name__ == "__main__":
    unittest.main()
