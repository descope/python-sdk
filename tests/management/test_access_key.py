import json
from unittest import mock
from unittest.mock import patch

from descope import AssociatedTenant, AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtV1

from .. import common
from ..async_test_base import (
    parameterized_sync_async_subcase,
    HTTPMockHelper,
    MethodTestHelper,
)


class TestAccessKey(common.DescopeTest):
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
                client.mgmt.access_key,
                method_name,
                "key-name",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: json.loads("""{"key": {"id": "ak1"}, "cleartext": "abc"}"""),
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                client.mgmt.access_key,
                method_name,
                name="key-name",
                expire_time=123456789,
                key_tenants=[
                    AssociatedTenant("tenant1"),
                    AssociatedTenant("tenant2", ["role1", "role2"]),
                ],
                user_id="userid",
                custom_claims={"k1": "v1"},
                description="this is my access key",
                permitted_ips=["10.0.0.1", "192.168.1.0/24"],
            )
            access_key = resp["key"]
            self.assertEqual(access_key["id"], "ak1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.access_key_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "key-name",
                    "expireTime": 123456789,
                    "roleNames": [],
                    "keyTenants": [
                        {"tenantId": "tenant1", "roleNames": []},
                        {"tenantId": "tenant2", "roleNames": ["role1", "role2"]},
                    ],
                    "userId": "userid",
                    "customClaims": {"k1": "v1"},
                    "description": "this is my access key",
                    "permittedIps": ["10.0.0.1", "192.168.1.0/24"],
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("load", "load_async")
    def test_load(self, method_name, is_async):
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
                client.mgmt.access_key,
                method_name,
                "key-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="get",
            ok=True,
            json=lambda: json.loads("""{"key": {"id": "ak1"}}"""),
        ) as mock_get:
            resp = MethodTestHelper.call_method(
                client.mgmt.access_key, method_name, "key-id"
            )
            access_key = resp["key"]
            self.assertEqual(access_key["id"], "ak1")
            HTTPMockHelper.assert_http_call(
                mock_get,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.access_key_load_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"id": "key-id"},
                follow_redirects=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "search_all_access_keys", "search_all_access_keys_async"
    )
    def test_search_all_users(self, method_name, is_async):
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
                client.mgmt.access_key,
                method_name,
                ["t1, t2"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: json.loads("""{"keys": [{"id": "ak1"}, {"id": "ak2"}]}"""),
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                client.mgmt.access_key, method_name, ["t1, t2"]
            )
            keys = resp["keys"]
            self.assertEqual(len(keys), 2)
            self.assertEqual(keys[0]["id"], "ak1")
            self.assertEqual(keys[1]["id"], "ak2")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.access_keys_search_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantIds": ["t1, t2"],
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
                client.mgmt.access_key,
                method_name,
                "key-id",
                "new-name",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.access_key,
                method_name,
                "key-id",
                name="new-name",
                description=None,
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.access_key_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "id": "key-id",
                    "name": "new-name",
                    "description": None,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("deactivate", "deactivate_async")
    def test_deactivate(self, method_name, is_async):
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
                client.mgmt.access_key,
                method_name,
                "key-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.access_key, method_name, "ak1"
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.access_key_deactivate_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "id": "ak1",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("activate", "activate_async")
    def test_activate(self, method_name, is_async):
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
                client.mgmt.access_key,
                method_name,
                "key-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.access_key, method_name, "ak1"
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.access_key_activate_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "id": "ak1",
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
                client.mgmt.access_key,
                method_name,
                "key-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.access_key, method_name, "ak1"
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.access_key_delete_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "id": "ak1",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
