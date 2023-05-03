import json
import unittest
from copy import deepcopy
from unittest import mock
from unittest.mock import patch

from descope import (
    API_RATE_LIMIT_RETRY_AFTER_HEADER,
    ERROR_TYPE_API_RATE_LIMIT,
    SESSION_COOKIE_NAME,
    AuthException,
    DescopeClient,
    RateLimitException,
)
from descope.common import SESSION_TOKEN_NAME

from . import common


class TestDescopeClient(common.DescopeTest):
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
        self.public_key_str = json.dumps(self.public_key_dict)

    def test_descope_client(self):
        self.assertRaises(
            AuthException, DescopeClient, project_id=None, public_key="dummy"
        )
        self.assertRaises(
            AuthException, DescopeClient, project_id="", public_key="dummy"
        )

        with patch("os.getenv") as mock_getenv:
            mock_getenv.return_value = ""
            self.assertRaises(
                AuthException, DescopeClient, project_id=None, public_key="dummy"
            )

        self.assertIsNotNone(
            AuthException, DescopeClient(project_id="dummy", public_key=None)
        )
        self.assertIsNotNone(
            AuthException, DescopeClient(project_id="dummy", public_key="")
        )
        self.assertRaises(
            AuthException,
            DescopeClient,
            project_id="dummy",
            public_key="not dict object",
        )
        self.assertIsNotNone(
            DescopeClient(project_id="dummy", public_key=self.public_key_str)
        )

    def test_mgmt(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)
        self.assertRaises(AuthException, lambda: client.mgmt)

    def test_logout(self):
        dummy_refresh_token = ""
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        self.assertRaises(AuthException, client.logout, None)

        # Test failed flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.logout, dummy_refresh_token)

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(client.logout(dummy_refresh_token))

    def test_logout_all(self):
        dummy_refresh_token = ""
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        self.assertRaises(AuthException, client.logout_all, None)

        # Test failed flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.logout_all, dummy_refresh_token)

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(client.logout_all(dummy_refresh_token))

    def test_me(self):
        dummy_refresh_token = ""
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        self.assertRaises(AuthException, client.me, None)

        # Test failed flow
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(AuthException, client.me, dummy_refresh_token)

        # Test success flow
        with patch("requests.get") as mock_get:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            data = json.loads(
                """{"name": "Testy McTester", "email": "testy@tester.com"}"""
            )
            my_mock_response.json.return_value = data
            mock_get.return_value = my_mock_response
            user_response = client.me(dummy_refresh_token)
            self.assertIsNotNone(user_response)
            self.assertEqual(data["name"], user_response["name"])

    def test_validate_session(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        invalid_header_jwt_token = "AyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImR1bW15In0.Bcz3xSxEcxgBSZOzqrTvKnb9-u45W-RlAbHSBL6E8zo2yJ9SYfODphdZ8tP5ARNTvFSPj2wgyu1SeiZWoGGPHPNMt4p65tPeVf5W8--d2aKXCc4KvAOOK3B_Cvjy_TO8"
        missing_kid_header_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImFhYSI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjE5ODEzOTgxMTF9.GQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh"
        invalid_payload_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoxNjU3Nzk2Njc4LCJpYXQiOjE2NTc3OTYwNzgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJCdEVIa2dPdTAybG1NeHpQSWV4ZE10VXcxTSJ9.lTUKMIjkrdsfryREYrgz4jMV7M0-JF-Q-KNlI0xZhamYqnSYtvzdwAoYiyWamx22XrN5SZkcmVZ5bsx-g2C0p5VMbnmmxEaxcnsFJHqVAJUYEv5HGQHumN50DYSlLXXg"

        self.assertRaises(
            AuthException,
            client.validate_session,
            missing_kid_header_jwt_token,
        )
        self.assertRaises(
            AuthException,
            client.validate_session,
            invalid_header_jwt_token,
        )
        self.assertRaises(
            AuthException,
            client.validate_session,
            invalid_payload_jwt_token,
        )

        # Test case where header_alg != key[alg]
        client4 = DescopeClient(self.dummy_project_id, None)
        self.assertRaises(
            AuthException,
            client4.validate_session,
            None,
        )

    def test_validate_session_valid_tokens(self):
        client = DescopeClient(
            self.dummy_project_id,
            {
                "alg": "ES384",
                "crv": "P-384",
                "kid": "P2CuC9yv2UGtGI1o84gCZEb9qEQW",
                "kty": "EC",
                "use": "sig",
                "x": "DCjjyS7blnEmenLyJVwmH6yMnp7MlEggfk1kLtOv_Khtpps_Mq4K9brqsCwQhGUP",
                "y": "xKy4IQ2FaLEzrrl1KE5mKbioLhj1prYFk1itdTOr6Xpy1fgq86kC7v-Y2F2vpcDc",
            },
        )

        dummy_refresh_token = "refresh"
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0NDMwNjEsImlhdCI6MTY1OTY0MzA2MSwiaXNzIjoiUDJDdUM5eXYyVUd0R0kxbzg0Z0NaRWI5cUVRVyIsInN1YiI6IlUyQ3VDUHVKZ1BXSEdCNVA0R21mYnVQR2hHVm0ifQ.mRo9FihYMR3qnQT06Mj3CJ5X0uTCEcXASZqfLLUv0cPCLBtBqYTbuK-ZRDnV4e4N6zGCNX2a3jjpbyqbViOxICCNSxJsVb-sdsSujtEXwVMsTTLnpWmNsMbOUiKmoME0"

        try:
            client.validate_session(valid_jwt_token)
        except AuthException:
            self.fail("Should pass validation")

        self.assertIsNotNone(
            client.validate_and_refresh_session(valid_jwt_token, dummy_refresh_token)
        )

        # Test case where key id cannot be found
        client2 = DescopeClient(self.dummy_project_id, None)
        with patch("requests.get") as mock_request:
            fake_key = deepcopy(self.public_key_dict)
            # overwrite the kid (so it will not be found)
            fake_key["kid"] = "dummy_kid"
            mock_request.return_value.text = json.dumps([fake_key])
            mock_request.return_value.ok = True
            self.assertRaises(
                AuthException,
                client2.validate_and_refresh_session,
                valid_jwt_token,
                dummy_refresh_token,
            )

        # Test case where we failed to load key
        client3 = DescopeClient(self.dummy_project_id, None)
        with patch("requests.get") as mock_request:
            mock_request.return_value.text = """[{"kid": "dummy_kid"}]"""
            mock_request.return_value.ok = True
            self.assertRaises(
                AuthException,
                client3.validate_and_refresh_session,
                valid_jwt_token,
                dummy_refresh_token,
            )

        # Test case where header_alg != key[alg]
        self.public_key_dict["alg"] = "ES521"
        client4 = DescopeClient(self.dummy_project_id, self.public_key_dict)
        with patch("requests.get") as mock_request:
            mock_request.return_value.text = """[{"kid": "dummy_kid"}]"""
            mock_request.return_value.ok = True
            self.assertRaises(
                AuthException,
                client4.validate_and_refresh_session,
                valid_jwt_token,
                dummy_refresh_token,
            )

        # Test case where header_alg != key[alg]
        client4 = DescopeClient(self.dummy_project_id, None)
        self.assertRaises(
            AuthException,
            client4.validate_and_refresh_session,
            None,
            None,
        )

        #
        expired_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEUyIsImV4cCI6MTY1OTY0NDI5OCwiaWF0IjoxNjU5NjQ0Mjk3LCJpc3MiOiJQMkN1Qzl5djJVR3RHSTFvODRnQ1pFYjlxRVFXIiwic3ViIjoiVTJDdUNQdUpnUFdIR0I1UDRHbWZidVBHaEdWbSJ9.wBuOnIQI_z3SXOszqsWCg8ilOPdE5ruWYHA3jkaeQ3uX9hWgCTd69paFajc-xdMYbqlIF7JHji7T9oVmkCUJvDNgRZRZO9boMFANPyXitLOK4aX3VZpMJBpFxdrWV3GE"
        valid_refresh_token = valid_jwt_token
        with patch("requests.get") as mock_request:
            mock_request.return_value.cookies = {SESSION_COOKIE_NAME: expired_jwt_token}
            mock_request.return_value.ok = True

            self.assertRaises(
                AuthException,
                client3.validate_and_refresh_session,
                expired_jwt_token,
                valid_refresh_token,
            )

    def test_exception_object(self):
        ex = AuthException(401, "dummy-type", "dummy error message")
        self.assertIsNotNone(str(ex))
        self.assertIsNotNone(repr(ex))
        self.assertEqual(ex.status_code, 401)
        self.assertEqual(ex.error_type, "dummy-type")
        self.assertEqual(ex.error_message, "dummy error message")

    def test_api_rate_limit_exception_object(self):
        ex = RateLimitException(
            429,
            ERROR_TYPE_API_RATE_LIMIT,
            "API rate limit exceeded description",
            "API rate limit exceeded",
            {API_RATE_LIMIT_RETRY_AFTER_HEADER: "9"},
        )
        self.assertIsNotNone(str(ex))
        self.assertIsNotNone(repr(ex))
        self.assertEqual(ex.status_code, 429)
        self.assertEqual(ex.error_type, ERROR_TYPE_API_RATE_LIMIT)
        self.assertEqual(ex.error_description, "API rate limit exceeded description")
        self.assertEqual(ex.error_message, "API rate limit exceeded")
        self.assertEqual(
            ex.rate_limit_parameters.get(API_RATE_LIMIT_RETRY_AFTER_HEADER, ""), "9"
        )

    def test_expired_token(self):
        expired_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg5NzI4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoxNjU3Nzk4MzI4LCJpYXQiOjE2NTc3OTc3MjgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJCdEVIa2dPdTAybG1NeHpQSWV4ZE10VXcxTSJ9.i-JoPoYmXl3jeLTARvYnInBiRdTT4uHZ3X3xu_n1dhUb1Qy_gqK7Ru8ErYXeENdfPOe4mjShc_HsVyb5PjE2LMFmb58WR8wixtn0R-u_MqTpuI_422Dk6hMRjTFEVRWu"
        dummy_refresh_token = "dummy refresh token"
        client = DescopeClient(
            self.dummy_project_id,
            {
                "alg": "ES384",
                "crv": "P-384",
                "kid": "P2CuC9yv2UGtGI1o84gCZEb9qEQW",
                "kty": "EC",
                "use": "sig",
                "x": "DCjjyS7blnEmenLyJVwmH6yMnp7MlEggfk1kLtOv_Khtpps_Mq4K9brqsCwQhGUP",
                "y": "xKy4IQ2FaLEzrrl1KE5mKbioLhj1prYFk1itdTOr6Xpy1fgq86kC7v-Y2F2vpcDc",
            },
        )

        # Test fail flow
        with patch("requests.get") as mock_request:
            mock_request.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.validate_session,
                expired_jwt_token,
            )

        with patch("requests.get") as mock_request:
            mock_request.return_value.cookies = {"aaa": "aaa"}
            mock_request.return_value.ok = True
            self.assertRaises(
                AuthException,
                client.validate_session,
                expired_jwt_token,
            )

        # Test fail flow
        dummy_session_token = "dummy session token"
        dummy_client = DescopeClient(self.dummy_project_id, self.public_key_dict)
        with patch("jwt.get_unverified_header") as mock_jwt_get_unverified_header:
            mock_jwt_get_unverified_header.return_value = {}
            self.assertRaises(
                AuthException,
                dummy_client.validate_and_refresh_session,
                dummy_session_token,
                dummy_refresh_token,
            )

        # Test success flow
        new_session_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEUyIsImV4cCI6MjQ5MzA2MTQxNSwiaWF0IjoxNjU5NjQzMDYxLCJpc3MiOiJQMkN1Qzl5djJVR3RHSTFvODRnQ1pFYjlxRVFXIiwic3ViIjoiVTJDdUNQdUpnUFdIR0I1UDRHbWZidVBHaEdWbSJ9.gMalOv1GhqYVsfITcOc7Jv_fibX1Iof6AFy2KCVmyHmU2KwATT6XYXsHjBFFLq262Pg-LS1IX9f_DV3ppzvb1pSY4ccsP6WDGd1vJpjp3wFBP9Sji6WXL0SCCJUFIyJR"
        valid_refresh_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0NDMwNjEsImlhdCI6MTY1OTY0MzA2MSwiaXNzIjoiUDJDdUM5eXYyVUd0R0kxbzg0Z0NaRWI5cUVRVyIsInN1YiI6IlUyQ3VDUHVKZ1BXSEdCNVA0R21mYnVQR2hHVm0ifQ.mRo9FihYMR3qnQT06Mj3CJ5X0uTCEcXASZqfLLUv0cPCLBtBqYTbuK-ZRDnV4e4N6zGCNX2a3jjpbyqbViOxICCNSxJsVb-sdsSujtEXwVMsTTLnpWmNsMbOUiKmoME0"
        expired_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEUyIsImV4cCI6MTY1OTY0NDI5OCwiaWF0IjoxNjU5NjQ0Mjk3LCJpc3MiOiJQMkN1Qzl5djJVR3RHSTFvODRnQ1pFYjlxRVFXIiwic3ViIjoiVTJDdUNQdUpnUFdIR0I1UDRHbWZidVBHaEdWbSJ9.wBuOnIQI_z3SXOszqsWCg8ilOPdE5ruWYHA3jkaeQ3uX9hWgCTd69paFajc-xdMYbqlIF7JHji7T9oVmkCUJvDNgRZRZO9boMFANPyXitLOK4aX3VZpMJBpFxdrWV3GE"
        with patch("requests.post") as mock_request:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"sessionJwt": new_session_token}
            mock_request.return_value = my_mock_response
            mock_request.return_value.cookies = {}

            # Refresh because of expiration
            resp = client.validate_and_refresh_session(
                expired_token, valid_refresh_token
            )

            new_session_token_from_request = resp[SESSION_TOKEN_NAME]["jwt"]
            self.assertEqual(
                new_session_token_from_request,
                new_session_token,
                "Failed to refresh token",
            )

            # Refresh explicitly
            resp = client.refresh_session(valid_refresh_token)

            new_session_token_from_request = resp[SESSION_TOKEN_NAME]["jwt"]
            self.assertEqual(
                new_session_token_from_request,
                new_session_token,
                "Failed to refresh token",
            )

        expired_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEUyIsImV4cCI6MTY1OTY0NDI5OCwiaWF0IjoxNjU5NjQ0Mjk3LCJpc3MiOiJQMkN1Qzl5djJVR3RHSTFvODRnQ1pFYjlxRVFXIiwic3ViIjoiVTJDdUNQdUpnUFdIR0I1UDRHbWZidVBHaEdWbSJ9.wBuOnIQI_z3SXOszqsWCg8ilOPdE5ruWYHA3jkaeQ3uX9hWgCTd69paFajc-xdMYbqlIF7JHji7T9oVmkCUJvDNgRZRZO9boMFANPyXitLOK4aX3VZpMJBpFxdrWV3GE"
        valid_refresh_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ.eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0NDMwNjEsImlhdCI6MTY1OTY0MzA2MSwiaXNzIjoiUDJDdUM5eXYyVUd0R0kxbzg0Z0NaRWI5cUVRVyIsInN1YiI6IlUyQ3VDUHVKZ1BXSEdCNVA0R21mYnVQR2hHVm0ifQ.mRo9FihYMR3qnQT06Mj3CJ5X0uTCEcXASZqfLLUv0cPCLBtBqYTbuK-ZRDnV4e4N6zGCNX2a3jjpbyqbViOxICCNSxJsVb-sdsSujtEXwVMsTTLnpWmNsMbOUiKmoME0"
        new_refreshed_token = (
            expired_jwt_token  # the refreshed token should be invalid (or expired)
        )
        with patch("requests.get") as mock_request:
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.json.return_value = {"sessionJwt": new_refreshed_token}
            mock_request.return_value = my_mock_response
            mock_request.return_value.cookies = {}
            self.assertRaises(
                AuthException,
                dummy_client.validate_and_refresh_session,
                expired_jwt_token,
                valid_refresh_token,
            )

    def test_public_key_load(self):
        # Test key without kty property
        invalid_public_key = deepcopy(self.public_key_dict)
        invalid_public_key.pop("kty")
        with self.assertRaises(AuthException) as cm:
            DescopeClient(self.dummy_project_id, invalid_public_key)
        self.assertEqual(cm.exception.status_code, 500)

        # Test key without kid property
        invalid_public_key = deepcopy(self.public_key_dict)
        invalid_public_key.pop("kid")
        with self.assertRaises(AuthException) as cm:
            DescopeClient(self.dummy_project_id, invalid_public_key)
        self.assertEqual(cm.exception.status_code, 500)

        # Test key with unknown algorithm
        invalid_public_key = deepcopy(self.public_key_dict)
        invalid_public_key["alg"] = "unknown algorithm"
        with self.assertRaises(AuthException) as cm:
            DescopeClient(self.dummy_project_id, invalid_public_key)
        self.assertEqual(cm.exception.status_code, 500)

    def test_client_properties(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)
        self.assertIsNotNone(client)
        self.assertIsNotNone(client.magiclink, "Empty Magiclink object")
        self.assertIsNotNone(client.otp, "Empty otp object")
        self.assertIsNotNone(client.totp, "Empty totp object")
        self.assertIsNotNone(client.oauth, "Empty oauth object")
        self.assertIsNotNone(client.saml, "Empty saml object")
        self.assertIsNotNone(client.webauthn, "Empty webauthN object")

    def test_validate_permissions(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)
        jwt_response = {}
        self.assertFalse(client.validate_permissions(jwt_response, ["Perm 1"]))

        jwt_response = {"permissions": []}
        self.assertFalse(client.validate_permissions(jwt_response, ["Perm 1"]))
        self.assertTrue(client.validate_permissions(jwt_response, []))

        jwt_response = {"permissions": ["Perm 1"]}
        self.assertTrue(client.validate_permissions(jwt_response, "Perm 1"))
        self.assertTrue(client.validate_permissions(jwt_response, ["Perm 1"]))
        self.assertFalse(client.validate_permissions(jwt_response, ["Perm 2"]))

        # Tenant level
        jwt_response = {"tenants": {}}
        self.assertFalse(
            client.validate_tenant_permissions(jwt_response, "t1", ["Perm 2"])
        )

        jwt_response = {"tenants": {"t1": {}}}
        self.assertFalse(
            client.validate_tenant_permissions(jwt_response, "t1", ["Perm 2"])
        )

        jwt_response = {"tenants": {"t1": {"permissions": "Perm 1"}}}
        self.assertTrue(
            client.validate_tenant_permissions(jwt_response, "t1", ["Perm 1"])
        )
        self.assertFalse(
            client.validate_tenant_permissions(jwt_response, "t1", ["Perm 2"])
        )
        self.assertFalse(
            client.validate_tenant_permissions(jwt_response, "t1", ["Perm 1", "Perm 2"])
        )

    def test_validate_roles(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)
        jwt_response = {}
        self.assertFalse(client.validate_roles(jwt_response, ["Role 1"]))

        jwt_response = {"roles": []}
        self.assertFalse(client.validate_roles(jwt_response, ["Role 1"]))
        self.assertTrue(client.validate_roles(jwt_response, []))

        jwt_response = {"roles": ["Role 1"]}
        self.assertTrue(client.validate_roles(jwt_response, "Role 1"))
        self.assertTrue(client.validate_roles(jwt_response, ["Role 1"]))
        self.assertFalse(client.validate_roles(jwt_response, ["Role 2"]))

        # Tenant level
        jwt_response = {"tenants": {}}
        self.assertFalse(client.validate_tenant_roles(jwt_response, "t1", ["Perm 2"]))

        jwt_response = {"tenants": {"t1": {}}}
        self.assertFalse(client.validate_tenant_roles(jwt_response, "t1", ["Perm 2"]))

        jwt_response = {"tenants": {"t1": {"roles": "Role 1"}}}
        self.assertTrue(client.validate_tenant_roles(jwt_response, "t1", ["Role 1"]))
        self.assertFalse(client.validate_tenant_roles(jwt_response, "t1", ["Role 2"]))
        self.assertFalse(
            client.validate_tenant_roles(jwt_response, "t1", ["Role 1", "Role 2"])
        )

    def test_exchange_access_key_empty_param(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)
        with self.assertRaises(AuthException) as cm:
            client.exchange_access_key("")
        self.assertEqual(cm.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
