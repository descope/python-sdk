from datetime import datetime
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


class TestAudit(common.DescopeTest):
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

    @parameterized_sync_async_subcase("search", "search_async")
    def test_search(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed search
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.audit,
                method_name,
                "data",
            )

        # Test success search
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {
                "audits": [
                    {
                        "projectId": "p",
                        "userId": "u1",
                        "action": "a1",
                        "externalIds": ["e1"],
                        "occurred": str(datetime.now().timestamp() * 1000),
                    },
                    {
                        "projectId": "p",
                        "userId": "u2",
                        "action": "a2",
                        "externalIds": ["e2"],
                        "occurred": str(datetime.now().timestamp() * 1000),
                    },
                ]
            },
        ) as mock_post:
            resp = MethodTestHelper.call_method(client.mgmt.audit, method_name)
            audits = resp["audits"]
            self.assertEqual(len(audits), 2)
            self.assertEqual(audits[0]["loginIds"][0], "e1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.audit_search}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"noTenants": False},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("search", "search_async")
    def test_search_comprehensive_parameters(self, method_name, is_async):
        """Test search with all parameter combinations to improve coverage"""
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test with all parameters
        from_ts = datetime(2023, 1, 1)
        to_ts = datetime(2023, 12, 31)

        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"audits": []},
        ) as mock_post:
            MethodTestHelper.call_method(
                client.mgmt.audit,
                method_name,
                user_ids=["user1", "user2"],
                actions=["login", "logout"],
                excluded_actions=["failed_login"],
                devices=["Mobile", "Desktop"],
                methods=["otp", "password"],
                geos=["US", "IL"],
                remote_addresses=["192.168.1.1"],
                login_ids=["user@example.com"],
                tenants=["tenant1"],
                no_tenants=True,
                text="search text",
                from_ts=from_ts,
                to_ts=to_ts,
            )

            expected_body = {
                "noTenants": True,
                "userIds": ["user1", "user2"],
                "actions": ["login", "logout"],
                "excludedActions": ["failed_login"],
                "devices": ["Mobile", "Desktop"],
                "methods": ["otp", "password"],
                "geos": ["US", "IL"],
                "remoteAddresses": ["192.168.1.1"],
                "externalIds": ["user@example.com"],
                "tenants": ["tenant1"],
                "text": "search text",
                "from": int(from_ts.timestamp() * 1000),
                "to": int(to_ts.timestamp() * 1000),
            }

            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.audit_search}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json=expected_body,
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("create_event", "create_event_async")
    def test_create_event(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed search
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.audit,
                method_name,
                "a",
                "b",
                "c",
                "d",
            )

        # Test success search
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {}
        ) as mock_post:
            MethodTestHelper.call_method(
                client.mgmt.audit,
                method_name,
                action="pencil.created",
                user_id="user-id",
                actor_id="actor-id",
                tenant_id="tenant-id",
                type="info",
                data={"some": "data"},
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.audit_create_event}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "action": "pencil.created",
                    "userId": "user-id",
                    "actorId": "actor-id",
                    "tenantId": "tenant-id",
                    "type": "info",
                    "data": {"some": "data"},
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("create_event", "create_event_async")
    def test_create_event_optional_parameters(self, method_name, is_async):
        """Test create_event with optional parameters to improve coverage"""
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test without optional parameters
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {}
        ) as mock_post:
            MethodTestHelper.call_method(
                client.mgmt.audit,
                method_name,
                action="test.action",
                type="info",
                actor_id="actor123",
                tenant_id="tenant123",
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.audit_create_event}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "action": "test.action",
                    "type": "info",
                    "actorId": "actor123",
                    "tenantId": "tenant123",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test with user_id but no data
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {}
        ) as mock_post:
            MethodTestHelper.call_method(
                client.mgmt.audit,
                method_name,
                action="test.action2",
                type="warn",
                actor_id="actor456",
                tenant_id="tenant456",
                user_id="user789",
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.audit_create_event}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "action": "test.action2",
                    "type": "warn",
                    "actorId": "actor456",
                    "tenantId": "tenant456",
                    "userId": "user789",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test with data but no user_id
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {}
        ) as mock_post:
            MethodTestHelper.call_method(
                client.mgmt.audit,
                method_name,
                action="test.action3",
                type="error",
                actor_id="actor789",
                tenant_id="tenant789",
                data={"key": "value", "count": 42},
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.audit_create_event}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "action": "test.action3",
                    "type": "error",
                    "actorId": "actor789",
                    "tenantId": "tenant789",
                    "data": {"key": "value", "count": 42},
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
