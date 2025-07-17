import json
from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtV1

from .. import common
from ..async_test_base import (
    parameterized_sync_async_subcase,
    HTTPMockHelper,
    MethodTestHelper,
)


class TestRole(common.DescopeTest):
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

    @parameterized_sync_async_subcase("create", "create_async")
    def test_create(self, method_name, is_async):
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
                client.mgmt.role,
                method_name,
                "name",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            self.assertIsNone(
                MethodTestHelper.call_method(
                    client.mgmt.role,
                    method_name,
                    "R1",
                    "Something",
                    ["P1"],
                    "t1",
                    True,
                )
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.role_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "R1",
                    "description": "Something",
                    "permissionNames": ["P1"],
                    "tenantId": "t1",
                    "default": True,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("update", "update_async")
    def test_update(self, method_name, is_async):
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
                client.mgmt.role,
                method_name,
                "name",
                "new-name",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            self.assertIsNone(
                MethodTestHelper.call_method(
                    client.mgmt.role,
                    method_name,
                    "name",
                    "new-name",
                    "new-description",
                    ["P1", "P2"],
                    "t1",
                    True,
                )
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.role_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "name",
                    "newName": "new-name",
                    "description": "new-description",
                    "permissionNames": ["P1", "P2"],
                    "tenantId": "t1",
                    "default": True,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("delete", "delete_async")
    def test_delete(self, method_name, is_async):
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
                client.mgmt.role,
                method_name,
                "name",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            self.assertIsNone(
                MethodTestHelper.call_method(
                    client.mgmt.role,
                    method_name,
                    "name",
                )
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.role_delete_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"name": "name", "tenantId": None},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("load_all", "load_all_async")
    def test_load_all(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=False
        ) as mock_get:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.role,
                method_name,
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="get",
            ok=True,
            json=lambda: json.loads(
                """
                {
                    "roles": [
                        {"name": "R1", "permissionNames": ["P1", "P2"]},
                        {"name": "R2"}
                    ]
                }
                """
            ),
        ) as mock_get:
            resp = MethodTestHelper.call_method(
                client.mgmt.role,
                method_name,
            )
            roles = resp["roles"]
            self.assertEqual(len(roles), 2)
            self.assertEqual(roles[0]["name"], "R1")
            self.assertEqual(roles[1]["name"], "R2")
            permissions = roles[0]["permissionNames"]
            self.assertEqual(len(permissions), 2)
            self.assertEqual(permissions[0], "P1")
            self.assertEqual(permissions[1], "P2")
            HTTPMockHelper.assert_http_call(
                mock_get,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.role_load_all_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                follow_redirects=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("search", "search_async")
    def test_search(self, method_name, is_async):
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
                client.mgmt.role,
                method_name,
                ["t"],
                ["r"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: json.loads(
                """
                {
                    "roles": [
                        {"name": "R1", "permissionNames": ["P1", "P2"]},
                        {"name": "R2"}
                    ]
                }
                """
            ),
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                client.mgmt.role,
                method_name,
                ["t"],
                ["r"],
                "x",
                ["p1", "p2"],
            )
            roles = resp["roles"]
            self.assertEqual(len(roles), 2)
            self.assertEqual(roles[0]["name"], "R1")
            self.assertEqual(roles[1]["name"], "R2")
            permissions = roles[0]["permissionNames"]
            self.assertEqual(len(permissions), 2)
            self.assertEqual(permissions[0], "P1")
            self.assertEqual(permissions[1], "P2")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.role_search_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantIds": ["t"],
                    "roleNames": ["r"],
                    "roleNameLike": "x",
                    "permissionNames": ["p1", "p2"],
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with include_project_roles parameter for full coverage
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: json.loads(
                """
                {
                    "roles": [
                        {"name": "R1", "permissionNames": ["P1", "P2"]},
                        {"name": "R2"}
                    ]
                }
                """
            ),
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                client.mgmt.role,
                method_name,
                ["t"],
                ["r"],
                "x",
                ["p1", "p2"],
                True,  # include_project_roles
            )
            roles = resp["roles"]
            self.assertEqual(len(roles), 2)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.role_search_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantIds": ["t"],
                    "roleNames": ["r"],
                    "roleNameLike": "x",
                    "permissionNames": ["p1", "p2"],
                    "includeProjectRoles": True,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
