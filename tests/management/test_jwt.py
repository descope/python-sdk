import json
from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtLoginOptions, MgmtV1

from .. import common
from ..async_test_base import (
    parameterized_sync_async_subcase,
    HTTPMockHelper,
    MethodTestHelper,
)


class TestUser(common.DescopeTest):
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

    @parameterized_sync_async_subcase("update_jwt", "update_jwt_async")
    def test_update_jwt(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.jwt,
                method_name,
                "jwt",
                {"k1": "v1"},
                0,
            )

            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.jwt,
                method_name,
                "",
                {"k1": "v1"},
                0,
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: json.loads("""{"jwt": "response"}"""),
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                client.mgmt.jwt, method_name, "test", {"k1": "v1"}, 40
            )
            self.assertEqual(resp, "response")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.update_jwt_path}"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

            resp = MethodTestHelper.call_method(
                client.mgmt.jwt, method_name, "test", {"k1": "v1"}
            )
            self.assertEqual(resp, "response")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.update_jwt_path}"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("impersonate", "impersonate_async")
    def test_impersonate(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.jwt,
                method_name,
                "imp1",
                "imp2",
                False,
            )

            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.jwt,
                method_name,
                "",
                "imp2",
                False,
            )

            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.jwt,
                method_name,
                "imp1",
                "",
                False,
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: json.loads("""{"jwt": "response"}"""),
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                client.mgmt.jwt, method_name, "imp1", "imp2", True
            )
            self.assertEqual(resp, "response")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.impersonate_path}"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("stop_impersonation", "stop_impersonation_async")
    def test_stop_impersonation(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.jwt,
                method_name,
                "",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: json.loads("""{"jwt": "response"}"""),
        ) as mock_post:
            resp = MethodTestHelper.call_method(client.mgmt.jwt, method_name, "jwtstr")
            self.assertEqual(resp, "response")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.stop_impersonation_path}"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("sign_in", "sign_in_async")
    def test_sign_in(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.mgmt.jwt,
            method_name,
            "",
        )

        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.mgmt.jwt,
            method_name,
            "loginId",
            MgmtLoginOptions(mfa=True),
        )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: json.loads("""{"jwt": "response"}"""),
        ) as mock_post:
            MethodTestHelper.call_method(client.mgmt.jwt, method_name, "loginId")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.mgmt_sign_in_path}"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("sign_up", "sign_up_async")
    def test_sign_up(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.mgmt.jwt,
            method_name,
            "",
        )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: json.loads("""{"jwt": "response"}"""),
        ) as mock_post:
            MethodTestHelper.call_method(client.mgmt.jwt, method_name, "loginId")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.mgmt_sign_up_path}"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("sign_up_or_in", "sign_up_or_in_async")
    def test_sign_up_or_in(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        self.assertRaises(
            AuthException,
            MethodTestHelper.call_method,
            client.mgmt.jwt,
            method_name,
            "",
        )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: json.loads("""{"jwt": "response"}"""),
        ) as mock_post:
            MethodTestHelper.call_method(client.mgmt.jwt, method_name, "loginId")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.mgmt_sign_up_or_in_path}"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("anonymous", "anonymous_async")
    def test_anonymous(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: json.loads("""{"jwt": "response"}"""),
        ) as mock_post:
            MethodTestHelper.call_method(
                client.mgmt.jwt, method_name, {"k1": "v1"}, "id"
            )
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.anonymous_path}"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
