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


class TestGroup(common.DescopeTest):
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

    @parameterized_sync_async_subcase("load_all_groups", "load_all_groups_async")
    def test_load_all_groups(self, method_name, is_async):
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
                client.mgmt.group,
                method_name,
                "tenant_id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.group, method_name, "someTenantId"
            )
            self.assertIsNotNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.group_load_all_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "someTenantId",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "load_all_groups_for_members", "load_all_groups_for_members_async"
    )
    def test_load_all_groups_for_members(self, method_name, is_async):
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
                client.mgmt.group,
                method_name,
                "tenant_id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.group,
                method_name,
                "someTenantId",
                ["one", "two"],
                ["three", "four"],
            )
            self.assertIsNotNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.group_load_all_for_member_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "someTenantId",
                    "loginIds": ["three", "four"],
                    "userIds": ["one", "two"],
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "load_all_group_members", "load_all_group_members_async"
    )
    def test_load_all_group_members(self, method_name, is_async):
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
                client.mgmt.group,
                method_name,
                "tenant_id",
                "group_id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.group, method_name, "someTenantId", "someGroupId"
            )
            self.assertIsNotNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.group_load_all_group_members_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "someTenantId",
                    "groupId": "someGroupId",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
