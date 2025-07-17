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


class TestFGA(common.DescopeTest):
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

    @parameterized_sync_async_subcase("save_schema", "save_schema_async")
    def test_save_schema(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed save_schema
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.fga,
                method_name,
                "",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.fga, method_name, "model AuthZ 1.0"
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_save_schema}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"dsl": "model AuthZ 1.0"},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("create_relations", "create_relations_async")
    def test_create_relations(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed create_relations
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.fga,
                method_name,
                [],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.fga,
                method_name,
                [
                    {
                        "resource": "r",
                        "resourceType": "rt",
                        "relation": "rel",
                        "target": "u",
                        "targetType": "ty",
                    }
                ],
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_create_relations}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tuples": [
                        {
                            "resource": "r",
                            "resourceType": "rt",
                            "relation": "rel",
                            "target": "u",
                            "targetType": "ty",
                        }
                    ]
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("delete_relations", "delete_relations_async")
    def test_delete_relations(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed delete_relations
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.fga,
                method_name,
                [],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.fga,
                method_name,
                [
                    {
                        "resource": "r",
                        "resourceType": "rt",
                        "relation": "rel",
                        "target": "u",
                        "targetType": "ty",
                    }
                ],
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_delete_relations}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tuples": [
                        {
                            "resource": "r",
                            "resourceType": "rt",
                            "relation": "rel",
                            "target": "u",
                            "targetType": "ty",
                        }
                    ]
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("check", "check_async")
    def test_check(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed has_relations
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.fga,
                method_name,
                [],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {
                "tuples": [
                    {
                        "tuple": {
                            "resource": "r",
                            "resourceType": "rt",
                            "relation": "rel",
                            "target": "u",
                            "targetType": "ty",
                        },
                        "allowed": True,
                    }
                ]
            },
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.fga,
                method_name,
                [
                    {
                        "resource": "r",
                        "resourceType": "rt",
                        "relation": "rel",
                        "target": "u",
                        "targetType": "ty",
                    }
                ],
            )
            self.assertIsNotNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_check}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tuples": [
                        {
                            "resource": "r",
                            "resourceType": "rt",
                            "relation": "rel",
                            "target": "u",
                            "targetType": "ty",
                        }
                    ]
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "load_resources_details", "load_resources_details_async"
    )
    def test_load_resources_details(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test error case
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            ids = [{"resourceId": "r1", "resourceType": "type1"}]
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.fga,
                method_name,
                ids,
            )

        # Test success case
        response_body = {
            "resourcesDetails": [
                {"resourceId": "r1", "resourceType": "type1", "displayName": "Name1"},
                {"resourceId": "r2", "resourceType": "type2", "displayName": "Name2"},
            ]
        }
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: response_body
        ) as mock_post:
            ids = [
                {"resourceId": "r1", "resourceType": "type1"},
                {"resourceId": "r2", "resourceType": "type2"},
            ]
            details = MethodTestHelper.call_method(client.mgmt.fga, method_name, ids)
            self.assertEqual(details, response_body["resourcesDetails"])
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_resources_load}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"resourceIdentifiers": ids},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "save_resources_details", "save_resources_details_async"
    )
    def test_save_resources_details(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )
        details = [
            {"resourceId": "r1", "resourceType": "type1", "displayName": "Name1"}
        ]

        # Test error case
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.fga,
                method_name,
                details,
            )

        # Test success case
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(client.mgmt.fga, method_name, details)
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_resources_save}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"resourcesDetails": details},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
