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


class TestTenant(common.DescopeTest):
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
                client.mgmt.tenant,
                method_name,
                "valid-name",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"id": "t1"}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                client.mgmt.tenant, method_name, "name", "t1", ["domain.com"]
            )
            self.assertEqual(resp["id"], "t1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "name",
                    "id": "t1",
                    "selfProvisioningDomains": ["domain.com"],
                    "enforceSSO": False,
                    "disabled": False,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with custom attributes
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"id": "t1"}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                client.mgmt.tenant,
                method_name,
                "name",
                "t1",
                ["domain.com"],
                {"k1": "v1"},
                enforce_sso=True,
                disabled=True,
            )
            self.assertEqual(resp["id"], "t1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "name",
                    "id": "t1",
                    "selfProvisioningDomains": ["domain.com"],
                    "customAttributes": {"k1": "v1"},
                    "enforceSSO": True,
                    "disabled": True,
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
                client.mgmt.tenant,
                method_name,
                "valid-id",
                "valid-name",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.tenant,
                method_name,
                "t1",
                "new-name",
                ["domain.com"],
                enforce_sso=True,
                disabled=True,
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "new-name",
                    "id": "t1",
                    "selfProvisioningDomains": ["domain.com"],
                    "enforceSSO": True,
                    "disabled": True,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with custom attributes
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.tenant,
                method_name,
                "t1",
                "new-name",
                ["domain.com"],
                {"k1": "v1"},
                enforce_sso=True,
                disabled=True,
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "new-name",
                    "id": "t1",
                    "selfProvisioningDomains": ["domain.com"],
                    "customAttributes": {"k1": "v1"},
                    "enforceSSO": True,
                    "disabled": True,
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
                client.mgmt.tenant,
                method_name,
                "valid-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.tenant, method_name, "t1", True
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_delete_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"id": "t1", "cascade": True},
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
                client.mgmt.tenant,
                method_name,
                "valid-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="get",
            ok=True,
            json=lambda: {
                "id": "t1",
                "name": "tenant1",
                "selfProvisioningDomains": ["domain1.com"],
                "createdTime": 172606520,
            },
        ) as mock_get:
            resp = MethodTestHelper.call_method(client.mgmt.tenant, method_name, "t1")
            self.assertEqual(resp["name"], "tenant1")
            self.assertEqual(resp["createdTime"], 172606520)
            HTTPMockHelper.assert_http_call(
                mock_get,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_load_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"id": "t1"},
                follow_redirects=None,
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
                client.mgmt.tenant,
                method_name,
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="get",
            ok=True,
            json=lambda: {
                "tenants": [
                    {
                        "id": "t1",
                        "name": "tenant1",
                        "selfProvisioningDomains": ["domain1.com"],
                        "createdTime": 172606520,
                    },
                    {
                        "id": "t2",
                        "name": "tenant2",
                        "selfProvisioningDomains": ["domain1.com"],
                        "createdTime": 172606520,
                    },
                ]
            },
        ) as mock_get:
            resp = MethodTestHelper.call_method(client.mgmt.tenant, method_name)
            tenants = resp["tenants"]
            self.assertEqual(len(tenants), 2)
            self.assertEqual(tenants[0]["name"], "tenant1")
            self.assertEqual(tenants[1]["name"], "tenant2")
            self.assertEqual(tenants[0]["createdTime"], 172606520)
            HTTPMockHelper.assert_http_call(
                mock_get,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_load_all_path}",
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

    @parameterized_sync_async_subcase("search_all", "search_all_async")
    def test_search_all(self, method_name, is_async):
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
                client.mgmt.tenant,
                method_name,
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {
                "tenants": [
                    {
                        "id": "t1",
                        "name": "tenant1",
                        "selfProvisioningDomains": ["domain1.com"],
                    },
                    {
                        "id": "t2",
                        "name": "tenant2",
                        "selfProvisioningDomains": ["domain1.com"],
                    },
                ]
            },
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                client.mgmt.tenant,
                method_name,
                ids=["id1"],
                names=["name1"],
                custom_attributes={"k1": "v1"},
                self_provisioning_domains=["spd1"],
            )
            tenants = resp["tenants"]
            self.assertEqual(len(tenants), 2)
            self.assertEqual(tenants[0]["name"], "tenant1")
            self.assertEqual(tenants[1]["name"], "tenant2")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_search_all_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "tenantIds": ["id1"],
                    "tenantNames": ["name1"],
                    "tenantSelfProvisioningDomains": ["spd1"],
                    "customAttributes": {"k1": "v1"},
                },
                follow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
