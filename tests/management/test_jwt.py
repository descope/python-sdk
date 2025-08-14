import json
from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtLoginOptions, MgmtV1

from .. import common


class TestJWT(common.DescopeTest):
    def setUp(self) -> None:
        super().setUp()
        self.dummy_project_id = "dummy"
        self.dummy_management_key = "key"
        self.public_key_dict = {
            "alg": "ES384",
            "crv": "P-384",
            "kid": "P2CtzUhdqpIF2ys9gg7ms06UvtC4",
            "kty": "EC",
            "use": "sig",
            "x": "pX1l7nT2turcK5_Cdzos8SKIhpLh1Wy9jmKAVyMFiOCURoj-WQX1J0OUQqMsQO0s",
            "y": "B0_nWAv2pmG_PzoH3-bSYZZzLNKUA0RoE2SH7DaS0KV4rtfWZhYd0MEr0xfdGKx0",
        }

    def test_update_jwt(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, client.mgmt.jwt.update_jwt, "jwt", {"k1": "v1"}, 0
            )

            self.assertRaises(
                AuthException, client.mgmt.jwt.update_jwt, "", {"k1": "v1"}, 0
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"jwt": "response"}""")
            mock_post.return_value = network_resp
            resp = client.mgmt.jwt.update_jwt("test", {"k1": "v1"}, 40)
            self.assertEqual(resp, "response")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.update_jwt_path}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "jwt": "test",
                    "customClaims": {"k1": "v1"},
                    "refreshDuration": 40,
                },
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

            resp = client.mgmt.jwt.update_jwt("test", {"k1": "v1"})
            self.assertEqual(resp, "response")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.update_jwt_path}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "jwt": "test",
                    "customClaims": {"k1": "v1"},
                    "refreshDuration": 0,
                },
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_impersonate(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, client.mgmt.jwt.impersonate, "imp1", "imp2", False
            )

            self.assertRaises(
                AuthException, client.mgmt.jwt.impersonate, "", "imp2", False
            )

            self.assertRaises(
                AuthException, client.mgmt.jwt.impersonate, "imp1", "", False
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"jwt": "response"}""")
            mock_post.return_value = network_resp
            resp = client.mgmt.jwt.impersonate("imp1", "imp2", True)
            self.assertEqual(resp, "response")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.impersonate_path}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "imp2",
                    "impersonatorId": "imp1",
                    "validateConsent": True,
                    "customClaims": None,
                    "selectedTenant": None,
                    "refreshDuration": None,
                },
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_stop_impersonation(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.jwt.stop_impersonation,
                "",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"jwt": "response"}""")
            mock_post.return_value = network_resp
            resp = client.mgmt.jwt.stop_impersonation("jwtstr")
            self.assertEqual(resp, "response")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.stop_impersonation_path}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "jwt": "jwtstr",
                    "customClaims": None,
                    "selectedTenant": None,
                    "refreshDuration": None,
                },
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_sign_in(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        self.assertRaises(AuthException, client.mgmt.jwt.sign_in, "")

        self.assertRaises(
            AuthException,
            client.mgmt.jwt.sign_in,
            "loginId",
            MgmtLoginOptions(mfa=True),
        )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"jwt": "response"}""")
            mock_post.return_value = network_resp
            client.mgmt.jwt.sign_in("loginId")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.mgmt_sign_in_path}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "loginId",
                    "stepup": False,
                    "mfa": False,
                    "revokeOtherSessions": None,
                    "customClaims": None,
                    "jwt": None,
                    "refreshDuration": None,
                },
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_sign_up(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        self.assertRaises(AuthException, client.mgmt.jwt.sign_up, "")

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"jwt": "response"}""")
            mock_post.return_value = network_resp
            client.mgmt.jwt.sign_up("loginId")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.mgmt_sign_up_path}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "loginId",
                    "user": {
                        "name": None,
                        "givenName": None,
                        "middleName": None,
                        "familyName": None,
                        "phone": None,
                        "email": None,
                        "emailVerified": None,
                        "phoneVerified": None,
                        "ssoAppId": None,
                    },
                    "emailVerified": None,
                    "phoneVerified": None,
                    "ssoAppId": None,
                    "customClaims": None,
                    "refreshDuration": None,
                },
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_sign_up_or_in(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        self.assertRaises(AuthException, client.mgmt.jwt.sign_up_or_in, "")

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"jwt": "response"}""")
            mock_post.return_value = network_resp
            client.mgmt.jwt.sign_up_or_in("loginId")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.mgmt_sign_up_or_in_path}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "loginId",
                    "user": {
                        "name": None,
                        "givenName": None,
                        "middleName": None,
                        "familyName": None,
                        "phone": None,
                        "email": None,
                        "emailVerified": None,
                        "phoneVerified": None,
                        "ssoAppId": None,
                    },
                    "emailVerified": None,
                    "phoneVerified": None,
                    "ssoAppId": None,
                    "customClaims": None,
                    "refreshDuration": None,
                },
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_anonymous(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"jwt": "response"}""")
            mock_post.return_value = network_resp
            client.mgmt.jwt.anonymous({"k1": "v1"}, "id")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.anonymous_path}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "customClaims": {"k1": "v1"},
                    "selectedTenant": "id",
                    "refreshDuration": None,
                },
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
