import json
import unittest
from copy import deepcopy
from enum import Enum
from unittest.mock import patch

from descope import SESSION_COOKIE_NAME, DescopeClient, AuthException, DeliveryMethod
from descope.common import REFRESH_SESSION_COOKIE_NAME

class TestDescopeClient(unittest.TestCase):
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
        self.public_key_str = json.dumps(self.public_key_dict)

    def test_descope_client(self):
        self.assertRaises(
            AuthException, DescopeClient, project_id=None, public_key="dummy"
        )
        self.assertRaises(AuthException, DescopeClient, project_id="", public_key="dummy")

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
            AuthException, DescopeClient, project_id="dummy", public_key="not dict object"
        )
        self.assertIsNotNone(
            DescopeClient(project_id="dummy", public_key=self.public_key_str)
        )

    def test_logout(self):
        dummy_refresh_token = ""
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        self.assertRaises(AuthException, client.logout, None)

        # Test failed flow
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(
                AuthException, client.logout, dummy_refresh_token
            )

        # Test success flow
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            self.assertIsNotNone(
                client.logout(dummy_refresh_token)
            )    

    def test_validate_session(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        dummy_refresh_token = ""

        invalid_header_jwt_token = "AyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImR1bW15In0.Bcz3xSxEcxgBSZOzqrTvKnb9-u45W-RlAbHSBL6E8zo2yJ9SYfODphdZ8tP5ARNTvFSPj2wgyu1SeiZWoGGPHPNMt4p65tPeVf5W8--d2aKXCc4KvAOOK3B_Cvjy_TO8"
        missing_kid_header_jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImFhYSI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjE5ODEzOTgxMTF9.GQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh"
        invalid_payload_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoxNjU3Nzk2Njc4LCJpYXQiOjE2NTc3OTYwNzgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJCdEVIa2dPdTAybG1NeHpQSWV4ZE10VXcxTSJ9.lTUKMIjkrdsfryREYrgz4jMV7M0-JF-Q-KNlI0xZhamYqnSYtvzdwAoYiyWamx22XrN5SZkcmVZ5bsx-g2C0p5VMbnmmxEaxcnsFJHqVAJUYEv5HGQHumN50DYSlLXXg"
        valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkVGVuYW50cyI6eyIiOm51bGx9LCJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwNjc5MjA4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoyMDkwMDg3MjA4LCJpYXQiOjE2NTgwODcyMDgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJDNTV2eXh3MHNSTDZGZE02OHFSc0NEZFJPViJ9.E8f9CHePkAA7JDqerO6cWbAA29MqIBipqMpitR6xsRYl4-Wm4f7DtekV9fJF3SYaftrTuVM0W965tq634_ltzj0rhd7gm6N7AcNVRtdstTQJHuuCDKVJEho-qtv2ZMVX"

        self.assertRaises(
            AuthException,
            client.validate_session_request,
            missing_kid_header_jwt_token,
            dummy_refresh_token,
        )
        self.assertRaises(
            AuthException,
            client.validate_session_request,
            invalid_header_jwt_token,
            dummy_refresh_token,
        )
        self.assertRaises(
            AuthException,
            client.validate_session_request,
            invalid_payload_jwt_token,
            dummy_refresh_token,
        )
        self.assertIsNotNone(
            client.validate_session_request(valid_jwt_token, dummy_refresh_token)
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
                client2.validate_session_request,
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
                client3.validate_session_request,
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
                client4.validate_session_request,
                valid_jwt_token,
                dummy_refresh_token,
            )

        # Test case where header_alg != key[alg]
        client4 = DescopeClient(self.dummy_project_id, None)
        self.assertRaises(
            AuthException,
            client4.validate_session_request,
            None,
            None,
        )

        #
        expired_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoxNjU3Nzk2Njc4LCJpYXQiOjE2NTc3OTYwNzgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJCdEVIa2dPdTAybG1NeHpQSWV4ZE10VXcxTSJ9.lTUKMIjkrdsfryREYrgz4jMV7M0-JF-Q-KNlI0xZhamYqnSYtvzdwAoYiyWamx22XrN5SZkcmVZ5bsx-g2C0p5VMbnmmxEaxcnsFJHqVAJUYEv5HGQHumN50DYSlLXXg"
        valid_refresh_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkVGVuYW50cyI6eyIiOm51bGx9LCJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwNjc5MjA4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MjA5MDA4NzIwOCwiaWF0IjoxNjU4MDg3MjA4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQzU1dnl4dzBzUkw2RmRNNjhxUnNDRGRST1YifQ.cWP5up4R5xeIl2qoG2NtfLH3Q5nRJVKdz-FDoAXctOQW9g3ceZQi6rZQ-TPBaXMKw68bijN3bLJTqxWW5WHzqRUeopfuzTcMYmC0wP2XGJkrdF6A8D5QW6acSGqglFgu"
        with patch("requests.get") as mock_request:
            mock_request.return_value.cookies = {SESSION_COOKIE_NAME: expired_jwt_token}
            mock_request.return_value.ok = True

            self.assertRaises(
                AuthException,
                client3.validate_session_request,
                expired_jwt_token,
                valid_refresh_token,
            )

    def test_exception_object(self):
        ex = AuthException(401, "dummy error type", "dummy error message")
        str_ex = str(ex)  # noqa: F841
        repr_ex = repr(ex)  # noqa: F841

    def test_expired_token(self):
        expired_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg5NzI4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoxNjU3Nzk4MzI4LCJpYXQiOjE2NTc3OTc3MjgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJCdEVIa2dPdTAybG1NeHpQSWV4ZE10VXcxTSJ9.i-JoPoYmXl3jeLTARvYnInBiRdTT4uHZ3X3xu_n1dhUb1Qy_gqK7Ru8ErYXeENdfPOe4mjShc_HsVyb5PjE2LMFmb58WR8wixtn0R-u_MqTpuI_422Dk6hMRjTFEVRWu"
        dummy_refresh_token = "dummy refresh token"
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test fail flow
        with patch("requests.get") as mock_request:
            mock_request.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.validate_session_request,
                expired_jwt_token,
                dummy_refresh_token,
            )

        with patch("requests.get") as mock_request:
            mock_request.return_value.cookies = {"aaa": "aaa"}
            mock_request.return_value.ok = True
            self.assertRaises(
                AuthException,
                client.validate_session_request,
                expired_jwt_token,
                dummy_refresh_token,
            )

        # Test fail flow
        dummy_session_token = "dummy session token"
        dummy_client = DescopeClient(self.dummy_project_id, self.public_key_dict)
        with patch("jwt.get_unverified_header") as mock_jwt_get_unverified_header:
            mock_jwt_get_unverified_header.return_value = {}
            self.assertRaises(
                AuthException,
                dummy_client.validate_session_request,
                dummy_session_token,
                dummy_refresh_token,
            )

        # Test success flow
        new_session_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkVGVuYW50cyI6eyIiOm51bGx9LCJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwNjc5MjA4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoyMDkwMDg3MjA4LCJpYXQiOjE2NTgwODcyMDgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJDNTV2eXh3MHNSTDZGZE02OHFSc0NEZFJPViJ9.E8f9CHePkAA7JDqerO6cWbAA29MqIBipqMpitR6xsRYl4-Wm4f7DtekV9fJF3SYaftrTuVM0W965tq634_ltzj0rhd7gm6N7AcNVRtdstTQJHuuCDKVJEho-qtv2ZMVX"
        valid_refresh_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkVGVuYW50cyI6eyIiOm51bGx9LCJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwNjc5MjA4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MjA5MDA4NzIwOCwiaWF0IjoxNjU4MDg3MjA4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQzU1dnl4dzBzUkw2RmRNNjhxUnNDRGRST1YifQ.cWP5up4R5xeIl2qoG2NtfLH3Q5nRJVKdz-FDoAXctOQW9g3ceZQi6rZQ-TPBaXMKw68bijN3bLJTqxWW5WHzqRUeopfuzTcMYmC0wP2XGJkrdF6A8D5QW6acSGqglFgu"
        expired_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEUyIsImNvb2tpZVBhdGgiOiIvIiwiZXhwIjoxNjU3Nzk2Njc4LCJpYXQiOjE2NTc3OTYwNzgsImlzcyI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInN1YiI6IjJCdEVIa2dPdTAybG1NeHpQSWV4ZE10VXcxTSJ9.lTUKMIjkrdsfryREYrgz4jMV7M0-JF-Q-KNlI0xZhamYqnSYtvzdwAoYiyWamx22XrN5SZkcmVZ5bsx-g2C0p5VMbnmmxEaxcnsFJHqVAJUYEv5HGQHumN50DYSlLXXg"
        with patch("requests.get") as mock_request:
            mock_request.return_value.cookies = {
                REFRESH_SESSION_COOKIE_NAME: new_session_token
            }
            mock_request.return_value.ok = True
            resp = client.validate_session_request(expired_token, valid_refresh_token)

            new_session_token_from_request = resp[SESSION_COOKIE_NAME]["jwt"]
            self.assertEqual(
                new_session_token_from_request,
                new_session_token,
                "Failed to refresh token",
            )

        expired_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0BBBBB9UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"
        valid_refresh_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkVGVuYW50cyI6eyIiOm51bGx9LCJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwNjc5MjA4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MjA5MDA4NzIwOCwiaWF0IjoxNjU4MDg3MjA4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQzU1dnl4dzBzUkw2RmRNNjhxUnNDRGRST1YifQ.cWP5up4R5xeIl2qoG2NtfLH3Q5nRJVKdz-FDoAXctOQW9g3ceZQi6rZQ-TPBaXMKw68bijN3bLJTqxWW5WHzqRUeopfuzTcMYmC0wP2XGJkrdF6A8D5QW6acSGqglFgu"
        new_refreshed_token = (
            expired_jwt_token  # the refreshed token should be invalid (or expired)
        )
        with patch("requests.get") as mock_request:
            mock_request.return_value.cookies = {
                REFRESH_SESSION_COOKIE_NAME: new_refreshed_token
            }
            mock_request.return_value.ok = True
            self.assertRaises(
                AuthException,
                dummy_client.validate_session_request,
                expired_jwt_token,
                valid_refresh_token,
            )

    def test_public_key_load(self):
        # Test key without kty property
        invalid_public_key = deepcopy(self.public_key_dict)
        invalid_public_key.pop("kty")
        with self.assertRaises(AuthException) as cm:
            DescopeClient(self.dummy_project_id, invalid_public_key)
        self.assertEqual(cm.exception.status_code, 400)

        # Test key without kid property
        invalid_public_key = deepcopy(self.public_key_dict)
        invalid_public_key.pop("kid")
        with self.assertRaises(AuthException) as cm:
            DescopeClient(self.dummy_project_id, invalid_public_key)
        self.assertEqual(cm.exception.status_code, 400)

        # Test key with unknown algorithm
        invalid_public_key = deepcopy(self.public_key_dict)
        invalid_public_key["alg"] = "unknown algorithm"
        with self.assertRaises(AuthException) as cm:
            DescopeClient(self.dummy_project_id, invalid_public_key)
        self.assertEqual(cm.exception.status_code, 400)

    def test_client_properties(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)
        self.assertIsNotNone(client)
        self.assertIsNotNone(client.magiclink, "Empty Magiclink object")
        self.assertIsNotNone(client.otp, "Empty otp object")
        self.assertIsNotNone(client.totp, "Empty totp object")
        self.assertIsNotNone(client.oauth, "Empty oauth object")
        self.assertIsNotNone(client.saml, "Empty saml object")
        self.assertIsNotNone(client.webauthn, "Empty webauthN object")


if __name__ == "__main__":
    unittest.main()
