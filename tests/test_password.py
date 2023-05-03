import json
from unittest import mock
from unittest.mock import patch

from descope import AuthException
from descope.auth import Auth
from descope.authmethod.password import Password  # noqa: F401
from descope.common import EndpointsV1

from . import common


class TestPassword(common.DescopeTest):
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

    def test_sign_up(self):
        signup_user_details = {
            "username": "jhon",
            "name": "john",
            "phone": "972525555555",
            "email": "dummy@dummy.com",
        }

        password = Password(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            password.sign_up,
            "",
            None,
            signup_user_details,
        )

        self.assertRaises(
            AuthException,
            password.sign_up,
            None,
            None,
            signup_user_details,
        )

        self.assertRaises(
            AuthException,
            password.sign_up,
            "login_id",
            "",
            signup_user_details,
        )

        self.assertRaises(
            AuthException,
            password.sign_up,
            "login_id",
            None,
            signup_user_details,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                password.sign_up,
                "dummy@dummy.com",
                "123456",
                signup_user_details,
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.cookies = {}
            data = json.loads(
                """{"jwts": ["eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"], "user": {"loginIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
            )
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response

            self.assertIsNotNone(
                password.sign_up("dummy@dummy.com", "123456", signup_user_details)
            )

            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_up_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
                        "password": "123456",
                        "user": {
                            "username": "jhon",
                            "name": "john",
                            "phone": "972525555555",
                            "email": "dummy@dummy.com",
                        },
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_sign_in(self):
        password = Password(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            password.sign_in,
            "",
            None,
        )

        self.assertRaises(
            AuthException,
            password.sign_in,
            None,
            None,
        )

        self.assertRaises(
            AuthException,
            password.sign_in,
            "login_id",
            "",
        )

        self.assertRaises(
            AuthException,
            password.sign_in,
            "login_id",
            None,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                password.sign_in,
                "dummy@dummy.com",
                "123456",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.cookies = {}
            data = json.loads(
                """{"jwts": ["eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwMzg4MDc4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MTY2MDIxNTI3OCwiaWF0IjoxNjU3Nzk2MDc4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQnRFSGtnT3UwMmxtTXh6UElleGRNdFV3MU0ifQ.oAnvJ7MJvCyL_33oM7YCF12JlQ0m6HWRuteUVAdaswfnD4rHEBmPeuVHGljN6UvOP4_Cf0559o39UHVgm3Fwb-q7zlBbsu_nP1-PRl-F8NJjvBgC5RsAYabtJq7LlQmh"], "user": {"loginIds": ["guyp@descope.com"], "name": "", "email": "guyp@descope.com", "phone": "", "verifiedEmail": true, "verifiedPhone": false}, "firstSeen": false}"""
            )
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response

            self.assertIsNotNone(password.sign_in("dummy@dummy.com", "123456"))

            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.sign_in_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
                        "password": "123456",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_send_reset(self):
        password = Password(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            password.send_reset,
            "",
        )

        self.assertRaises(
            AuthException,
            password.send_reset,
            None,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                password.send_reset,
                "dummy@dummy.com",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.cookies = {}
            data = json.loads(
                """{"resetMethod": "magiclink", "maskedEmail": "du***@***my.com"}"""
            )
            my_mock_response.json.return_value = data
            mock_post.return_value = my_mock_response

            self.assertIsNotNone(
                password.send_reset("dummy@dummy.com", "https://redirect.here.com")
            )

            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.send_reset_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
                        "redirectUrl": "https://redirect.here.com",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_update(self):
        password = Password(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            password.update,
            "",
            None,
            None,
        )

        self.assertRaises(
            AuthException,
            password.update,
            None,
            None,
            None,
        )

        self.assertRaises(
            AuthException,
            password.update,
            "login_id",
            "",
            None,
        )

        self.assertRaises(
            AuthException,
            password.update,
            "login_id",
            None,
            None,
        )

        self.assertRaises(
            AuthException,
            password.update,
            "login_id",
            "123456",
            "",
        )

        self.assertRaises(
            AuthException,
            password.update,
            "login_id",
            "123456",
            None,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                password.update,
                "dummy@dummy.com",
                "1234567",
                "refresh_token",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            valid_jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJCdDVXTGNjTFVleTFEcDd1dHB0WmIzRng5SyIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkVGVuYW50cyI6eyIiOm51bGx9LCJjb29raWVEb21haW4iOiIiLCJjb29raWVFeHBpcmF0aW9uIjoxNjYwNjc5MjA4LCJjb29raWVNYXhBZ2UiOjI1OTE5OTksImNvb2tpZU5hbWUiOiJEU1IiLCJjb29raWVQYXRoIjoiLyIsImV4cCI6MjA5MDA4NzIwOCwiaWF0IjoxNjU4MDg3MjA4LCJpc3MiOiIyQnQ1V0xjY0xVZXkxRHA3dXRwdFpiM0Z4OUsiLCJzdWIiOiIyQzU1dnl4dzBzUkw2RmRNNjhxUnNDRGRST1YifQ.cWP5up4R5xeIl2qoG2NtfLH3Q5nRJVKdz-FDoAXctOQW9g3ceZQi6rZQ-TPBaXMKw68bijN3bLJTqxWW5WHzqRUeopfuzTcMYmC0wP2XGJkrdF6A8D5QW6acSGqglFgu"
            self.assertIsNone(
                password.update("dummy@dummy.com", "123456", valid_jwt_token)
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.update_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{valid_jwt_token}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
                        "newPassword": "123456",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_replace(self):
        password = Password(Auth(self.dummy_project_id, self.public_key_dict))

        # Test failed flows
        self.assertRaises(
            AuthException,
            password.replace,
            "",
            None,
            None,
        )

        self.assertRaises(
            AuthException,
            password.replace,
            None,
            None,
            None,
        )

        self.assertRaises(
            AuthException,
            password.replace,
            "login_id",
            "",
            None,
        )

        self.assertRaises(
            AuthException,
            password.replace,
            "login_id",
            None,
            None,
        )

        self.assertRaises(
            AuthException,
            password.replace,
            "login_id",
            "123456",
            "",
        )

        self.assertRaises(
            AuthException,
            password.replace,
            "login_id",
            "123456",
            None,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                password.replace,
                "dummy@dummy.com",
                "123456",
                "1234567",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(password.replace("dummy@dummy.com", "123456", "1234567"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.replace_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "dummy@dummy.com",
                        "oldPassword": "123456",
                        "newPassword": "1234567",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_policy(self):
        password = Password(Auth(self.dummy_project_id, self.public_key_dict))

        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(
                AuthException,
                password.get_policy,
            )

        # Test success flow
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = True
            my_mock_response = mock.Mock()
            my_mock_response.ok = True
            my_mock_response.cookies = {}
            data = json.loads("""{"minLength": 8, "lowercase": true}""")
            my_mock_response.json.return_value = data
            mock_get.return_value = my_mock_response
            self.assertIsNotNone(password.get_policy())
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{EndpointsV1.password_policy_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}",
                },
                params=None,
                allow_redirects=None,
                verify=True,
            )
